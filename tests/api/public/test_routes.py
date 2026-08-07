"""Tests for /v1/* (Phase 2, C3)."""

from __future__ import annotations

from unittest import mock

import pytest

from src.api.public.keys import generate_api_key
from src.api.public.models import ApiKey
from tests.api.test_detect import _FAILED_FETCH_ARTIFACTS, _LEGIT_RAW_FEATURES, _fake_feature_vector

# The scan pipeline (fetch + feature extraction) lives in the shared
# src.api.verdict core, which every scanning endpoint runs through -- that
# is where the network touchpoints have to be stubbed.
MODULE = "src.api.verdict"


@pytest.fixture
def api_key(app):
    """Mint a real, DB-backed API key directly (faster/more isolated than
    going through the full signup->login->mint-key HTTP flow for every
    test that just needs *a* valid key)."""
    session_factory = app.extensions["argus_auth"]["session_factory"]

    # A throwaway owner user row -- api_keys.owner_user_id is a real FK.
    from src.api.auth.models import User
    from src.api.auth.utils import hash_password

    session = session_factory()
    try:
        owner = User(email=f"v1test_{id(object())}@example.com", password_hash=hash_password("x"), email_verified=True)
        session.add(owner)
        session.commit()
        owner_id = owner.id
    finally:
        session.close()

    raw_key, key_hash, key_prefix = generate_api_key()
    session = session_factory()
    try:
        db_key = ApiKey(key_hash=key_hash, key_prefix=key_prefix, owner_user_id=owner_id, tier="free")
        session.add(db_key)
        session.commit()
    finally:
        session.close()

    return raw_key


def _mock_extraction():
    fv = _fake_feature_vector("https://example.com", _LEGIT_RAW_FEATURES)
    return mock.patch(f"{MODULE}.extract_features", return_value=fv), mock.patch(
        f"{MODULE}.page_artifacts.fetch", return_value=_FAILED_FETCH_ARTIFACTS
    )


class TestV1Health:
    def test_no_auth_required(self, client):
        resp = client.get("/v1/health")
        assert resp.status_code == 200
        body = resp.get_json()
        assert body["status"] == "ok"
        assert body["version"] == "v1"
        assert "latency_ms" in body


class TestApiKeyAuth:
    def test_missing_key_401(self, client):
        resp = client.post("/v1/scan", json={"url": "https://example.com"})
        assert resp.status_code == 401

    def test_malformed_header_401(self, client):
        resp = client.post(
            "/v1/scan", json={"url": "https://example.com"}, headers={"Authorization": "NotBearer x"}
        )
        assert resp.status_code == 401

    def test_invalid_key_401(self, client):
        resp = client.post(
            "/v1/scan", json={"url": "https://example.com"}, headers={"Authorization": "Bearer argus_bogus"}
        )
        assert resp.status_code == 401

    def test_valid_key_succeeds(self, client, api_key):
        m1, m2 = _mock_extraction()
        with m1, m2:
            resp = client.post(
                "/v1/scan", json={"url": "https://example.com"}, headers={"Authorization": f"Bearer {api_key}"}
            )
        assert resp.status_code == 200

    def test_revoked_key_401(self, app, client, api_key):
        session_factory = app.extensions["argus_auth"]["session_factory"]
        session = session_factory()
        try:
            from src.api.public.keys import hash_api_key

            db_key = session.query(ApiKey).filter_by(key_hash=hash_api_key(api_key)).one()
            db_key.revoked = True
            session.commit()
        finally:
            session.close()

        resp = client.post(
            "/v1/scan", json={"url": "https://example.com"}, headers={"Authorization": f"Bearer {api_key}"}
        )
        assert resp.status_code == 401


class TestV1Scan:
    def test_returns_detect_shaped_response(self, client, api_key):
        m1, m2 = _mock_extraction()
        with m1, m2:
            resp = client.post(
                "/v1/scan", json={"url": "https://example.com"}, headers={"Authorization": f"Bearer {api_key}"}
            )
        assert resp.status_code == 200
        body = resp.get_json()
        assert body["url"] == "https://example.com"
        assert body["label"] in ("phishing", "legitimate")
        assert "latency_ms" in body

    def test_invalid_url_400(self, client, api_key):
        resp = client.post(
            "/v1/scan", json={"url": "ftp://bad"}, headers={"Authorization": f"Bearer {api_key}"}
        )
        assert resp.status_code == 400

    def test_does_not_persist_a_scan_report(self, app, client, api_key):
        """Unlike POST /scan, /v1/scan is stateless."""
        from src.api.scan.models import Scan

        session_factory = app.extensions["argus_auth"]["session_factory"]
        session = session_factory()
        before_count = session.query(Scan).count()
        session.close()

        m1, m2 = _mock_extraction()
        with m1, m2:
            client.post(
                "/v1/scan", json={"url": "https://example.com"}, headers={"Authorization": f"Bearer {api_key}"}
            )

        session = session_factory()
        after_count = session.query(Scan).count()
        session.close()
        assert after_count == before_count


class TestV1ScanBatch:
    def test_mixed_valid_invalid_urls(self, client, api_key):
        m1, m2 = _mock_extraction()
        with m1, m2:
            resp = client.post(
                "/v1/scan/batch",
                json={"urls": ["https://example.com", "ftp://bad"]},
                headers={"Authorization": f"Bearer {api_key}"},
            )
        assert resp.status_code == 200
        body = resp.get_json()
        assert body["count"] == 2
        assert "label" in body["results"][0]
        assert "error" in body["results"][1]

    def test_empty_urls_list_400(self, client, api_key):
        resp = client.post(
            "/v1/scan/batch", json={"urls": []}, headers={"Authorization": f"Bearer {api_key}"}
        )
        assert resp.status_code == 400

    def test_over_batch_max_is_rejected_by_schema(self, client, api_key):
        resp = client.post(
            "/v1/scan/batch",
            json={"urls": [f"https://example{i}.com" for i in range(51)]},
            headers={"Authorization": f"Bearer {api_key}"},
        )
        assert resp.status_code == 400

    def test_one_url_erroring_does_not_fail_the_batch(self, client, api_key):
        fv = _fake_feature_vector("https://example.com", _LEGIT_RAW_FEATURES)
        with mock.patch(f"{MODULE}.extract_features", side_effect=[RuntimeError("boom"), fv]), mock.patch(
            f"{MODULE}.page_artifacts.fetch", return_value=_FAILED_FETCH_ARTIFACTS
        ):
            resp = client.post(
                "/v1/scan/batch",
                json={"urls": ["https://example.com", "https://example2.com"], "enrich": True},
                headers={"Authorization": f"Bearer {api_key}"},
            )
        assert resp.status_code == 200
        body = resp.get_json()
        assert body["count"] == 2
        assert "error" in body["results"][0]
        assert "label" in body["results"][1]


class TestV1Explain:
    def test_returns_explain_shaped_response(self, client, api_key):
        m1, m2 = _mock_extraction()
        with m1, m2:
            resp = client.post(
                "/v1/explain", json={"url": "https://example.com"}, headers={"Authorization": f"Bearer {api_key}"}
            )
        assert resp.status_code == 200
        body = resp.get_json()
        assert len(body["top5_features"]) == 5
        assert "plain_explanation" in body
        assert isinstance(body["signals"], list)

    def test_missing_key_401(self, client):
        resp = client.post("/v1/explain", json={"url": "https://example.com"})
        assert resp.status_code == 401
