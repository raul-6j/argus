"""Tests for POST/GET /v1/scan/async and webhook delivery (F19)."""

from __future__ import annotations

import hashlib
import hmac
import json
import time
from unittest import mock

import pytest

from src.api.public.keys import generate_api_key
from src.api.public.models import ApiKey
from tests.api.test_detect import _FAILED_FETCH_ARTIFACTS, _LEGIT_RAW_FEATURES, _fake_feature_vector

# Network touchpoints live in the shared scan core (src.api.verdict); the
# webhook-URL SSRF check stays on the route module that performs it.
MODULE = "src.api.verdict"
ROUTES_MODULE = "src.api.public.routes"


@pytest.fixture
def api_key_pair(app):
    """Mint a real, DB-backed API key + its webhook_secret directly."""
    session_factory = app.extensions["argus_auth"]["session_factory"]

    from src.api.auth.models import User
    from src.api.auth.utils import hash_password

    session = session_factory()
    try:
        owner = User(email=f"asynctest_{id(object())}@example.com", password_hash=hash_password("x"), email_verified=True)
        session.add(owner)
        session.commit()
        owner_id = owner.id
    finally:
        session.close()

    raw_key, key_hash, key_prefix = generate_api_key()
    webhook_secret = "test-webhook-secret-" + key_prefix
    session = session_factory()
    try:
        db_key = ApiKey(
            key_hash=key_hash, key_prefix=key_prefix, owner_user_id=owner_id, tier="free",
            webhook_secret=webhook_secret,
        )
        session.add(db_key)
        session.commit()
    finally:
        session.close()

    return raw_key, webhook_secret


@pytest.fixture
def api_key(api_key_pair):
    return api_key_pair[0]


def _auth(key: str) -> dict:
    return {"Authorization": f"Bearer {key}"}


def _mock_extraction():
    fv = _fake_feature_vector("https://example.com", _LEGIT_RAW_FEATURES)
    return mock.patch(f"{MODULE}.extract_features", return_value=fv), mock.patch(
        f"{MODULE}.page_artifacts.fetch", return_value=_FAILED_FETCH_ARTIFACTS
    )


def _mock_safe_webhook_url():
    """Async job submission validates webhook_url with a real DNS-based SSRF
    check (src.utils.ssrf.is_safe_fetch_url) -- mocked here so tests using an
    example.com-style placeholder don't depend on real network access,
    matching this suite's existing "mock every network touchpoint"
    convention."""
    return mock.patch(f"{ROUTES_MODULE}.is_safe_fetch_url", return_value=True)


def _poll_until_done(client, key, job_id, timeout_s=8.0):
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        resp = client.get(f"/v1/scan/async/{job_id}", headers=_auth(key))
        body = resp.get_json()
        if body["status"] in ("completed", "failed"):
            return body
        time.sleep(0.02)
    raise AssertionError(f"job {job_id} did not finish within {timeout_s}s (last status={body['status']!r})")


def _poll_until_webhook_done(client, key, job_id, timeout_s=15.0):
    """Like _poll_until_done, but also waits for webhook delivery to settle.

    Job status flips to "completed"/"failed" *before* webhook delivery runs
    (same background thread, sequential steps) -- polling on job status
    alone would let the test's `with mock.patch(...)` block exit (reverting
    the requests.post mock) while delivery is still retrying in the
    background thread, letting later attempts hit the real network.
    """
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        resp = client.get(f"/v1/scan/async/{job_id}", headers=_auth(key))
        body = resp.get_json()
        if body["status"] in ("completed", "failed") and body["webhook_status"] != "pending":
            return body
        time.sleep(0.02)
    raise AssertionError(
        f"job {job_id} did not finish within {timeout_s}s "
        f"(last status={body['status']!r}, webhook_status={body['webhook_status']!r})"
    )


class TestV1ScanAsyncSubmit:
    def test_requires_auth(self, client):
        resp = client.post("/v1/scan/async", json={"url": "https://example.com"})
        assert resp.status_code == 401

    def test_returns_202_and_job_id(self, client, api_key):
        m1, m2 = _mock_extraction()
        with m1, m2, _mock_safe_webhook_url():
            resp = client.post(
                "/v1/scan/async", json={"url": "https://example.com"}, headers=_auth(api_key)
            )
            assert resp.status_code == 202
            body = resp.get_json()
            assert body["job_id"].startswith("job_")
            assert body["status"] == "queued"
            assert "latency_ms" in body
            _poll_until_done(client, api_key, body["job_id"])

    def test_invalid_url_400(self, client, api_key):
        resp = client.post("/v1/scan/async", json={"url": "ftp://bad"}, headers=_auth(api_key))
        assert resp.status_code == 400

    def test_ssrf_webhook_url_rejected_400(self, client, api_key):
        """http://127.0.0.1/... resolves locally (no real network access
        needed) to a loopback address -- rejected without mocking
        is_safe_fetch_url, unlike the other tests in this file."""
        resp = client.post(
            "/v1/scan/async",
            json={"url": "https://example.com", "webhook_url": "http://127.0.0.1:8080/hook"},
            headers=_auth(api_key),
        )
        assert resp.status_code == 400


class TestV1ScanAsyncStatus:
    def test_job_completes_with_full_result(self, client, api_key):
        m1, m2 = _mock_extraction()
        with m1, m2, _mock_safe_webhook_url():
            create_resp = client.post(
                "/v1/scan/async", json={"url": "https://example.com"}, headers=_auth(api_key)
            )
            job_id = create_resp.get_json()["job_id"]
            body = _poll_until_done(client, api_key, job_id)

        assert body["status"] == "completed"
        assert body["result"]["url"] == "https://example.com"
        assert body["result"]["label"] in ("phishing", "legitimate")
        assert body["webhook_status"] is None  # no webhook_url was set
        assert "latency_ms" in body

    def test_unknown_job_404(self, client, api_key):
        resp = client.get("/v1/scan/async/job_doesnotexist", headers=_auth(api_key))
        assert resp.status_code == 404

    def test_job_owned_by_other_key_is_404(self, client, api_key, app):
        # Mint a second, independent key.
        from src.api.auth.models import User
        from src.api.auth.utils import hash_password

        session_factory = app.extensions["argus_auth"]["session_factory"]
        session = session_factory()
        try:
            owner2 = User(email=f"other_{id(object())}@example.com", password_hash=hash_password("x"), email_verified=True)
            session.add(owner2)
            session.commit()
            owner2_id = owner2.id
        finally:
            session.close()

        raw_key2, key_hash2, key_prefix2 = generate_api_key()
        session = session_factory()
        try:
            session.add(ApiKey(key_hash=key_hash2, key_prefix=key_prefix2, owner_user_id=owner2_id, tier="free"))
            session.commit()
        finally:
            session.close()

        m1, m2 = _mock_extraction()
        with m1, m2, _mock_safe_webhook_url():
            create_resp = client.post(
                "/v1/scan/async", json={"url": "https://example.com"}, headers=_auth(api_key)
            )
            job_id = create_resp.get_json()["job_id"]
            _poll_until_done(client, api_key, job_id)

        resp = client.get(f"/v1/scan/async/{job_id}", headers=_auth(raw_key2))
        assert resp.status_code == 404


class TestWebhookDelivery:
    def test_successful_delivery_is_signed_and_marked_delivered(self, client, api_key_pair):
        api_key, webhook_secret = api_key_pair
        captured = {}

        def _fake_post(url, data=None, headers=None, timeout=None, allow_redirects=None):
            captured["url"] = url
            captured["data"] = data
            captured["headers"] = headers
            return mock.Mock(status_code=200)

        m1, m2 = _mock_extraction()
        with m1, m2, _mock_safe_webhook_url(), mock.patch(
            "src.api.public.webhooks.requests.post", side_effect=_fake_post
        ):
            create_resp = client.post(
                "/v1/scan/async",
                json={"url": "https://example.com", "webhook_url": "https://webhook.example.com/hook"},
                headers=_auth(api_key),
            )
            job_id = create_resp.get_json()["job_id"]
            body = _poll_until_webhook_done(client, api_key, job_id)

        assert body["webhook_status"] == "delivered"
        assert body["webhook_attempts"] == 1
        assert captured["url"] == "https://webhook.example.com/hook"

        expected_sig = hmac.new(webhook_secret.encode(), captured["data"], hashlib.sha256).hexdigest()
        assert captured["headers"]["X-Argus-Signature"] == f"sha256={expected_sig}"

        payload = json.loads(captured["data"])
        assert payload["job_id"] == job_id
        assert payload["status"] == "completed"
        assert payload["result"]["url"] == "https://example.com"

    def test_failed_delivery_marks_webhook_failed_but_job_result_intact(self, client, app, api_key_pair):
        """Retry/backoff mechanics themselves are covered deterministically
        by TestDeliverWebhookRetries below (calling deliver_webhook directly,
        no threading involved). This test only checks the async-job wiring:
        a failed delivery doesn't touch the job's own status/result. Forcing
        max_attempts=1 here (rather than the real default of 3) keeps this
        to a single delivery attempt -- with 3 sequential attempts, the real
        background job thread doing 3 mocked HTTP calls could occasionally
        still be mid-retry when this test's own `with mock.patch(...)` block
        exits (a real, observed flake: later attempts hit the real network
        once the mock reverted), the same class of race already fixed twice
        elsewhere in this feature -- single-attempt closes that window
        entirely rather than papering over it with a longer timeout.
        """
        api_key, _ = api_key_pair
        webhook_config = app.extensions["argus"]["config"].setdefault("webhook_delivery", {})

        m1, m2 = _mock_extraction()
        with m1, m2, _mock_safe_webhook_url(), mock.patch.dict(
            webhook_config, {"max_attempts": 1}
        ), mock.patch("src.api.public.webhooks.requests.post", return_value=mock.Mock(status_code=500)):
            create_resp = client.post(
                "/v1/scan/async",
                json={"url": "https://example.com", "webhook_url": "https://webhook.example.com/hook"},
                headers=_auth(api_key),
            )
            job_id = create_resp.get_json()["job_id"]
            body = _poll_until_webhook_done(client, api_key, job_id)

        assert body["webhook_status"] == "failed"
        assert body["webhook_attempts"] == 1
        assert body["status"] == "completed"
        assert body["result"]["url"] == "https://example.com"


class TestDeliverWebhookRetries:
    """Retry/backoff mechanics of deliver_webhook itself, tested directly --
    deterministic, no threading, no real HTTP, no shared background executor."""

    def test_all_attempts_fail_returns_failed_with_attempt_count(self):
        from src.api.public.webhooks import deliver_webhook

        with mock.patch(
            "src.api.public.webhooks.requests.post", return_value=mock.Mock(status_code=500)
        ) as post_mock, mock.patch("src.api.public.webhooks.time.sleep") as sleep_mock:
            status, attempts = deliver_webhook(
                "https://webhook.example.com/hook", {"job_id": "job_x"}, "secret",
                {"max_attempts": 3, "retry_backoff_s": [0, 2, 8]},
            )

        assert status == "failed"
        assert attempts == 3
        assert post_mock.call_count == 3
        # Backoff sleeps happen before attempts 2 and 3, not before attempt 1.
        assert sleep_mock.call_args_list == [mock.call(2), mock.call(8)]

    def test_succeeds_on_second_attempt(self):
        from src.api.public.webhooks import deliver_webhook

        responses = [mock.Mock(status_code=500), mock.Mock(status_code=200)]
        with mock.patch("src.api.public.webhooks.requests.post", side_effect=responses), mock.patch(
            "src.api.public.webhooks.time.sleep"
        ):
            status, attempts = deliver_webhook(
                "https://webhook.example.com/hook", {"job_id": "job_x"}, "secret",
                {"max_attempts": 3, "retry_backoff_s": [0, 2, 8]},
            )

        assert status == "delivered"
        assert attempts == 2

    def test_connection_errors_are_treated_like_non_2xx_responses(self):
        import requests

        from src.api.public.webhooks import deliver_webhook

        with mock.patch(
            "src.api.public.webhooks.requests.post", side_effect=requests.ConnectionError("boom")
        ), mock.patch("src.api.public.webhooks.time.sleep"):
            status, attempts = deliver_webhook(
                "https://webhook.example.com/hook", {"job_id": "job_x"}, "secret",
                {"max_attempts": 2, "retry_backoff_s": [0, 1]},
            )

        assert status == "failed"
        assert attempts == 2
