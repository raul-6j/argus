"""Tests for the enrichment wall-clock bound shared by every scanning endpoint.

Before this, only ``/detect`` ran enrichment on the bounded thread pool.
``/v1/scan``, ``/v1/scan/batch``, ``/v1/explain``, ``POST /scan`` and async
scan jobs all called ``page_artifacts.fetch()`` inline on the request thread
with no outer bound. Because ``requests``' timeout is per socket *operation*
rather than per request, a server trickling bytes could hold one of those
workers for as long as it cared to (slowloris) — the inner timeouts never fire.

The bound now lives in :func:`src.api.verdict.extract`, so it covers every one
of those call sites by construction. What differs per endpoint is the *policy*
on timeout, and that is what most of these tests pin down: ``/detect`` degrades
to a lexical-only verdict (as it always has), while the ``/v1`` and ``/scan``
endpoints report an honest 504 rather than passing off a verdict reached
without ever inspecting the page.
"""

from __future__ import annotations

import concurrent.futures
from unittest import mock

import pytest

from src.api.verdict import enrichment_timeout_s
from tests.api.public.test_routes import api_key  # noqa: F401 - fixture re-export
from tests.api.test_detect import _LEGIT_RAW_FEATURES, _fake_feature_vector

MODULE = "src.api.verdict"


@pytest.fixture
def timing_out_executor(app):
    """Make every enrichment submission time out, without any real waiting."""
    future = mock.Mock()
    future.result.side_effect = concurrent.futures.TimeoutError()
    executor = app.extensions["argus"]["executor"]
    with mock.patch.object(executor, "submit", return_value=future):
        yield future


class TestConfiguredBound:
    def test_default_is_fifteen_seconds(self):
        assert enrichment_timeout_s({}) == 15.0

    def test_config_overrides_the_default(self):
        assert enrichment_timeout_s({"config": {"enrichment_timeout_s": 3}}) == 3.0

    def test_shipped_config_sets_a_bound(self, app):
        """An unbounded enrichment path is the defect; the shipped config must
        not silently reintroduce it."""
        assert enrichment_timeout_s(app.extensions["argus"]) > 0


class TestTimeoutIsEnforced:
    def test_enrichment_is_submitted_to_the_bounded_pool(self, client, app):
        """The fix, stated directly: enrichment runs on the pool with a
        timeout, not inline on the request thread."""
        fv = _fake_feature_vector("https://example.com", _LEGIT_RAW_FEATURES)
        executor = app.extensions["argus"]["executor"]

        real_submit = executor.submit
        with mock.patch.object(
            executor, "submit", side_effect=real_submit
        ) as m_submit, mock.patch(f"{MODULE}.extract_features", return_value=fv), mock.patch(
            f"{MODULE}.page_artifacts.fetch"
        ):
            client.post("/detect", json={"url": "https://example.com", "enrich": True})

        m_submit.assert_called_once()

    def test_timed_out_future_is_cancelled(self, client, timing_out_executor):
        """A call that times out while still queued behind a saturated pool
        must be dropped, not left to occupy a worker later for a result nobody
        is waiting for."""
        fv = _fake_feature_vector("https://example.com", _LEGIT_RAW_FEATURES)
        with mock.patch(f"{MODULE}.extract_features", return_value=fv):
            client.post("/detect", json={"url": "https://example.com", "enrich": True})

        timing_out_executor.cancel.assert_called_once()


class TestPerEndpointPolicy:
    def test_detect_degrades_to_lexical_only(self, client, timing_out_executor):
        """Unchanged behaviour: the extension's passive per-tab check must
        return *something* rather than erroring."""
        fv = _fake_feature_vector("https://example.com", _LEGIT_RAW_FEATURES)
        with mock.patch(f"{MODULE}.extract_features", return_value=fv) as m_extract:
            resp = client.post("/detect", json={"url": "https://example.com", "enrich": True})

        assert resp.status_code == 200
        m_extract.assert_called_once_with("https://example.com")

    def test_v1_scan_returns_504(self, client, api_key, timing_out_executor):  # noqa: F811
        """A programmatic caller about to act on the verdict is told the page
        was never fetched, rather than handed a lexical-only guess dressed up
        as a full scan."""
        resp = client.post(
            "/v1/scan",
            json={"url": "https://example.com", "enrich": True},
            headers={"Authorization": f"Bearer {api_key}"},
        )
        assert resp.status_code == 504
        assert "error" in resp.get_json()

    def test_v1_explain_returns_504(self, client, api_key, timing_out_executor):  # noqa: F811
        resp = client.post(
            "/v1/explain",
            json={"url": "https://example.com"},
            headers={"Authorization": f"Bearer {api_key}"},
        )
        assert resp.status_code == 504

    def test_v1_batch_reports_a_per_item_error(self, client, api_key, timing_out_executor):  # noqa: F811
        """One slow target must not fail the whole batch — the pre-existing
        per-item error contract still holds."""
        resp = client.post(
            "/v1/scan/batch",
            json={"urls": ["https://example.com"], "enrich": True},
            headers={"Authorization": f"Bearer {api_key}"},
        )
        assert resp.status_code == 200
        assert "error" in resp.get_json()["results"][0]

    def test_public_scan_returns_504_and_stores_nothing(self, client, app, timing_out_executor):
        """``POST /scan`` persists a shareable permalink, so a lexical-only
        fallback would publish a verdict reached without inspecting the page."""
        from src.api.scan.models import Scan

        session_factory = app.extensions["argus_auth"]["session_factory"]
        session = session_factory()
        try:
            before = session.query(Scan).count()
        finally:
            session.close()

        resp = client.post("/scan", json={"url": "https://example.com"})
        assert resp.status_code == 504

        session = session_factory()
        try:
            assert session.query(Scan).count() == before
        finally:
            session.close()


class TestFailurePolicy:
    def test_v1_scan_propagates_an_enrichment_error(self, client, api_key):  # noqa: F811
        """Non-timeout failures keep their pre-existing per-endpoint semantics:
        unifying the *bound* must not quietly unify the *error handling* too."""
        with mock.patch(
            f"{MODULE}._run_enriched_extraction", side_effect=RuntimeError("boom")
        ):
            resp = client.post(
                "/v1/scan/batch",
                json={"urls": ["https://example.com"], "enrich": True},
                headers={"Authorization": f"Bearer {api_key}"},
            )
        assert resp.status_code == 200
        assert "boom" in resp.get_json()["results"][0]["error"]

    def test_detect_swallows_an_enrichment_error(self, client):
        fv = _fake_feature_vector("https://example.com", _LEGIT_RAW_FEATURES)
        with mock.patch(
            f"{MODULE}._run_enriched_extraction", side_effect=RuntimeError("boom")
        ), mock.patch(f"{MODULE}.extract_features", return_value=fv):
            resp = client.post("/detect", json={"url": "https://example.com", "enrich": True})
        assert resp.status_code == 200

    def test_fast_path_never_touches_the_pool(self, client, app):
        """enrich=false must stay synchronous and network-free — the bound is
        for the slow path only."""
        fv = _fake_feature_vector("https://example.com", _LEGIT_RAW_FEATURES)
        executor = app.extensions["argus"]["executor"]
        with mock.patch.object(executor, "submit") as m_submit, mock.patch(
            f"{MODULE}.extract_features", return_value=fv
        ):
            resp = client.post("/detect", json={"url": "https://example.com"})
        assert resp.status_code == 200
        m_submit.assert_not_called()
