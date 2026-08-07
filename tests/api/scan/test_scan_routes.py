"""Tests for POST /scan, GET /scan/<scan_id>, /scan/history, and the export
endpoints (Phase 2, C1; Phase 4, F11/F13)."""

from __future__ import annotations

import csv
import io
import json
from datetime import datetime, timedelta, timezone
from unittest import mock

from src.api.scan.models import Scan, UserScan
from src.api.threat_intel.providers import PhishTankProvider
from src.data.loaders import normalize_url
from tests.api.test_detect import _FAILED_FETCH_ARTIFACTS, _LEGIT_RAW_FEATURES, _fake_feature_vector

# The fetch + feature-extraction pipeline lives in the shared scan core
# (src.api.verdict), which POST /scan runs through -- that is where the
# network touchpoints have to be stubbed.
MODULE = "src.api.verdict"


def _mock_extraction(client_url="https://example.com"):
    fv = _fake_feature_vector(client_url, _LEGIT_RAW_FEATURES)
    return mock.patch(f"{MODULE}.extract_features", return_value=fv), mock.patch(
        f"{MODULE}.page_artifacts.fetch", return_value=_FAILED_FETCH_ARTIFACTS
    )


def _signup_login(client, email: str) -> dict:
    """Sign up, verify, and log in a fresh user; return its auth header."""
    password = "correct-horse-1"
    otp = client.post("/auth/signup", json={"email": email, "password": password}).get_json()["dev_otp"]
    client.post("/auth/verify-otp", json={"email": email, "otp": otp})
    tokens = client.post("/auth/login", json={"email": email, "password": password}).get_json()
    return {"Authorization": f"Bearer {tokens['access_token']}"}


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
            "providers": [PhishTankProvider(frozenset({normalize_url(bad_url)}))],
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


class TestCreateScanOptionalAuth:
    def test_anonymous_scan_unaffected(self, client):
        """No Authorization header -- behaves exactly like before, no UserScan row."""
        m1, m2 = _mock_extraction()
        with m1, m2:
            resp = client.post("/scan", json={"url": "https://example.com"})
        assert resp.status_code == 201
        assert "risk_band" in resp.get_json()

    def test_invalid_token_falls_back_to_anonymous(self, client):
        """A garbage/expired token never breaks the scan -- optional_auth, not require_auth."""
        m1, m2 = _mock_extraction()
        with m1, m2:
            resp = client.post(
                "/scan",
                json={"url": "https://example.com"},
                headers={"Authorization": "Bearer not-a-real-jwt"},
            )
        assert resp.status_code == 201

    def test_logged_in_scan_recorded_in_history(self, client):
        headers = _signup_login(client, "scan_history_user@example.com")
        m1, m2 = _mock_extraction()
        with m1, m2:
            create_resp = client.post("/scan", json={"url": "https://example.com"}, headers=headers)
        assert create_resp.status_code == 201

        history_resp = client.get("/scan/history", headers=headers)
        assert history_resp.status_code == 200
        rows = history_resp.get_json()["scans"]
        assert len(rows) == 1
        assert rows[0]["url"] == "https://example.com"
        assert rows[0]["scan_id"] == create_resp.get_json()["scan_id"]
        assert rows[0]["risk_band"] == create_resp.get_json()["risk_band"]


class TestScanHistory:
    def test_requires_auth(self, client):
        resp = client.get("/scan/history")
        assert resp.status_code == 401

    def test_only_lists_own_scans(self, client):
        alice = _signup_login(client, "history_alice@example.com")
        bob = _signup_login(client, "history_bob@example.com")

        m1, m2 = _mock_extraction()
        with m1, m2:
            client.post("/scan", json={"url": "https://example.com"}, headers=alice)

        bob_history = client.get("/scan/history", headers=bob).get_json()["scans"]
        assert bob_history == []

        alice_history = client.get("/scan/history", headers=alice).get_json()["scans"]
        assert len(alice_history) == 1

    def test_newest_first_and_limit(self, app, client):
        headers = _signup_login(client, "history_limit_user@example.com")
        # Look up the user id the same way create_scan does (via g.user_id
        # after decoding the token) -- simplest is to just create a scan
        # first, then read back its owner_user_id for building fixture rows.
        m1, m2 = _mock_extraction()
        with m1, m2:
            first = client.post("/scan", json={"url": "https://example.com"}, headers=headers)
        session_factory = app.extensions["argus_auth"]["session_factory"]
        with session_factory() as lookup_session:
            owner_user_id = (
                lookup_session.query(UserScan)
                .filter_by(scan_id=first.get_json()["scan_id"])
                .one()
                .owner_user_id
            )

        session = session_factory()
        try:
            for i in range(3):
                session.add(
                    UserScan(
                        owner_user_id=owner_user_id,
                        scan_id=None,
                        url=f"https://example{i}.com",
                        label="legitimate",
                        confidence=0.9,
                        risk_score=0.1,
                        risk_band="low",
                        signals_json="[]",
                        plain_explanation="test",
                        source="model",
                        created_at=datetime.now(timezone.utc) + timedelta(seconds=i + 1),
                    )
                )
            session.commit()
        finally:
            session.close()

        resp = client.get("/scan/history?limit=2", headers=headers)
        rows = resp.get_json()["scans"]
        assert len(rows) == 2
        assert rows[0]["url"] == "https://example2.com"  # newest first

    def test_limit_is_clamped(self, client):
        headers = _signup_login(client, "history_clamp_user@example.com")
        resp = client.get("/scan/history?limit=9999", headers=headers)
        assert resp.status_code == 200
        resp2 = client.get("/scan/history?limit=not-a-number", headers=headers)
        assert resp2.status_code == 400


class TestExportScan:
    def test_json_export(self, client):
        m1, m2 = _mock_extraction()
        with m1, m2:
            create_resp = client.post("/scan", json={"url": "https://example.com"})
        scan_id = create_resp.get_json()["scan_id"]

        resp = client.get(f"/scan/{scan_id}/export?format=json")
        assert resp.status_code == 200
        assert resp.mimetype == "application/json"
        body = json.loads(resp.data)
        assert body["scan_id"] == scan_id

    def test_csv_export(self, client):
        m1, m2 = _mock_extraction()
        with m1, m2:
            create_resp = client.post("/scan", json={"url": "https://example.com"})
        scan_id = create_resp.get_json()["scan_id"]

        resp = client.get(f"/scan/{scan_id}/export?format=csv")
        assert resp.status_code == 200
        assert resp.mimetype == "text/csv"
        rows = list(csv.reader(io.StringIO(resp.data.decode("utf-8"))))
        assert rows[0][0] == "scan_id"
        assert rows[1][0] == scan_id

    def test_pdf_export(self, client):
        m1, m2 = _mock_extraction()
        with m1, m2:
            create_resp = client.post("/scan", json={"url": "https://example.com"})
        scan_id = create_resp.get_json()["scan_id"]

        resp = client.get(f"/scan/{scan_id}/export?format=pdf")
        assert resp.status_code == 200
        assert resp.mimetype == "application/pdf"
        assert resp.data.startswith(b"%PDF")

    def test_unsupported_format_400(self, client):
        m1, m2 = _mock_extraction()
        with m1, m2:
            create_resp = client.post("/scan", json={"url": "https://example.com"})
        scan_id = create_resp.get_json()["scan_id"]

        resp = client.get(f"/scan/{scan_id}/export?format=xml")
        assert resp.status_code == 400

    def test_unknown_scan_id_404(self, client):
        resp = client.get("/scan/s_does_not_exist/export?format=json")
        assert resp.status_code == 404

    def test_no_auth_required(self, client):
        """Same permission model as GET /scan/<id> -- no login needed."""
        m1, m2 = _mock_extraction()
        with m1, m2:
            create_resp = client.post("/scan", json={"url": "https://example.com"})
        scan_id = create_resp.get_json()["scan_id"]

        resp = client.get(f"/scan/{scan_id}/export?format=json")
        assert resp.status_code == 200


class TestExportHistoryScan:
    def test_requires_auth(self, client):
        resp = client.get("/scan/history/1/export?format=json")
        assert resp.status_code == 401

    def test_owner_can_export(self, client):
        headers = _signup_login(client, "export_owner@example.com")
        m1, m2 = _mock_extraction()
        with m1, m2:
            client.post("/scan", json={"url": "https://example.com"}, headers=headers)
        item_id = client.get("/scan/history", headers=headers).get_json()["scans"][0]["id"]

        resp = client.get(f"/scan/history/{item_id}/export?format=csv", headers=headers)
        assert resp.status_code == 200
        assert resp.mimetype == "text/csv"

    def test_other_users_scan_is_404_not_403(self, client):
        """No enumeration signal -- same 404-not-403 convention as api_key routes."""
        owner_headers = _signup_login(client, "export_owner2@example.com")
        stranger_headers = _signup_login(client, "export_stranger@example.com")
        m1, m2 = _mock_extraction()
        with m1, m2:
            client.post("/scan", json={"url": "https://example.com"}, headers=owner_headers)
        item_id = client.get("/scan/history", headers=owner_headers).get_json()["scans"][0]["id"]

        resp = client.get(f"/scan/history/{item_id}/export?format=json", headers=stranger_headers)
        assert resp.status_code == 404
