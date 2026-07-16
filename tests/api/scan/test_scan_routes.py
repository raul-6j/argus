"""Tests for POST /scan and GET /scan/<scan_id> (Phase 2, C1)."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from unittest import mock

from src.api.scan.models import Scan
from src.data.loaders import normalize_url
from tests.api.test_detect import _FAILED_FETCH_ARTIFACTS, _LEGIT_RAW_FEATURES, _fake_feature_vector

MODULE = "src.api.scan.routes"


def _mock_extraction(client_url="https://example.com"):
    fv = _fake_feature_vector(client_url, _LEGIT_RAW_FEATURES)
    return mock.patch(f"{MODULE}.extract_features", return_value=fv), mock.patch(
        f"{MODULE}.page_artifacts.fetch", return_value=_FAILED_FETCH_ARTIFACTS
    )


class TestCreateScan:
    def test_valid_url_returns_201_with_report(self, client):
        m1, m2 = _mock_extraction()
        with m1, m2:
            resp = client.post("/scan", json={"url": "https://example.com"})
        assert resp.status_code == 201
        body = resp.get_json()
        assert body["scan_id"].startswith("s_")
        assert body["url"] == "https://example.com"
        assert body["label"] in ("phishing", "legitimate")
        assert "risk_score" in body
        assert isinstance(body["signals"], list)
        assert isinstance(body["plain_explanation"], str)
        assert body["report_url"] == f"/app/scan.html?id={body['scan_id']}"
        assert "expires_at" in body
        assert "latency_ms" in body

    def test_missing_url_400(self, client):
        resp = client.post("/scan", json={})
        assert resp.status_code == 400

    def test_invalid_scheme_400(self, client):
        resp = client.post("/scan", json={"url": "ftp://example.com"})
        assert resp.status_code == 400

    def test_no_body_400(self, client):
        resp = client.post("/scan", data="not json", content_type="text/plain")
        assert resp.status_code == 400

    def test_each_scan_gets_a_unique_id(self, client):
        m1, m2 = _mock_extraction()
        with m1, m2:
            r1 = client.post("/scan", json={"url": "https://example.com"})
            r2 = client.post("/scan", json={"url": "https://example.com"})
        assert r1.get_json()["scan_id"] != r2.get_json()["scan_id"]

    def test_scan_id_is_not_sequential_or_guessable(self, client):
        """Opaque id -- not a small integer, not derived from the URL."""
        m1, m2 = _mock_extraction()
        with m1, m2:
            resp = client.post("/scan", json={"url": "https://example.com"})
        scan_id = resp.get_json()["scan_id"]
        assert len(scan_id) > 10
        assert scan_id != "s_1"

    def test_prefilter_hit_short_circuits_without_feature_extraction(self, app, client):
        bad_url = "http://scan-prefilter-test.example.com/login"
        original = app.extensions["argus"]["threat_intel"]
        app.extensions["argus"]["threat_intel"] = {
            "enabled": True,
            "phishtank_index": frozenset({normalize_url(bad_url)}),
        }
        try:
            with mock.patch(f"{MODULE}.extract_features") as m_extract:
                resp = client.post("/scan", json={"url": bad_url})
            m_extract.assert_not_called()
        finally:
            app.extensions["argus"]["threat_intel"] = original

        assert resp.status_code == 201
        body = resp.get_json()
        assert body["label"] == "phishing"
        assert body["confidence"] == 1.0
        assert body["signals"] == []


class TestGetScan:
    def test_round_trip_create_then_fetch(self, client):
        m1, m2 = _mock_extraction()
        with m1, m2:
            create_resp = client.post("/scan", json={"url": "https://example.com"})
        scan_id = create_resp.get_json()["scan_id"]

        get_resp = client.get(f"/scan/{scan_id}")
        assert get_resp.status_code == 200
        body = get_resp.get_json()
        assert body["scan_id"] == scan_id
        assert body["url"] == "https://example.com"
        assert body["label"] == create_resp.get_json()["label"]
        assert "created_at" in body

    def test_unknown_scan_id_404(self, client):
        resp = client.get("/scan/s_does_not_exist_at_all")
        assert resp.status_code == 404
        assert "error" in resp.get_json()

    def test_expired_scan_is_404_and_purged(self, app, client):
        session_factory = app.extensions["argus_auth"]["session_factory"]
        session = session_factory()
        try:
            expired = Scan(
                scan_id="s_expired_test_case",
                url="https://example.com",
                label="legitimate",
                confidence=0.9,
                risk_score=0.1,
                signals_json="[]",
                plain_explanation="test",
                source="model",
                created_at=datetime.now(timezone.utc) - timedelta(days=10),
                expires_at=datetime.now(timezone.utc) - timedelta(days=1),
            )
            session.add(expired)
            session.commit()
        finally:
            session.close()

        resp = client.get("/scan/s_expired_test_case")
        assert resp.status_code == 404

        # Lazy purge: the row should now be gone.
        session2 = session_factory()
        try:
            assert session2.query(Scan).filter_by(scan_id="s_expired_test_case").one_or_none() is None
        finally:
            session2.close()
