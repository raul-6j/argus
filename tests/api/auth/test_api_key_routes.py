"""Tests for /auth/api-keys (Phase 2, C3) — key management under JWT auth."""

from __future__ import annotations

import pytest


@pytest.fixture
def access_token(client):
    """Sign up, verify, log in, return a valid JWT access token."""
    email, password = "apikeyowner@example.com", "correct-horse-1"
    otp = client.post("/auth/signup", json={"email": email, "password": password}).get_json()["dev_otp"]
    client.post("/auth/verify-otp", json={"email": email, "otp": otp})
    login = client.post("/auth/login", json={"email": email, "password": password})
    return login.get_json()["access_token"]


@pytest.fixture
def other_access_token(client):
    """A second, distinct user -- for IDOR tests."""
    email, password = "otherowner@example.com", "correct-horse-2"
    otp = client.post("/auth/signup", json={"email": email, "password": password}).get_json()["dev_otp"]
    client.post("/auth/verify-otp", json={"email": email, "otp": otp})
    login = client.post("/auth/login", json={"email": email, "password": password})
    return login.get_json()["access_token"]


def _auth(token: str) -> dict:
    return {"Authorization": f"Bearer {token}"}


class TestCreateApiKey:
    def test_requires_auth(self, client):
        resp = client.post("/auth/api-keys")
        assert resp.status_code == 401

    def test_returns_raw_key_once(self, client, access_token):
        resp = client.post("/auth/api-keys", headers=_auth(access_token))
        assert resp.status_code == 201
        body = resp.get_json()
        assert body["api_key"].startswith("argus_")
        assert body["key_prefix"]
        assert body["api_key"].startswith(body["key_prefix"])
        assert body["tier"] == "free"
        assert "latency_ms" in body

    def test_each_call_mints_a_distinct_key(self, client, access_token):
        r1 = client.post("/auth/api-keys", headers=_auth(access_token))
        r2 = client.post("/auth/api-keys", headers=_auth(access_token))
        assert r1.get_json()["api_key"] != r2.get_json()["api_key"]

    def test_returns_a_distinct_webhook_secret(self, client, access_token):
        """F19: webhook_secret is minted alongside the key and shown once,
        the same way the raw key itself is."""
        resp = client.post("/auth/api-keys", headers=_auth(access_token))
        body = resp.get_json()
        assert body["webhook_secret"]
        assert body["webhook_secret"] != body["api_key"]

        second = client.post("/auth/api-keys", headers=_auth(access_token)).get_json()
        assert second["webhook_secret"] != body["webhook_secret"]


class TestListApiKeys:
    def test_requires_auth(self, client):
        resp = client.get("/auth/api-keys")
        assert resp.status_code == 401

    def test_never_returns_raw_key(self, client, access_token):
        client.post("/auth/api-keys", headers=_auth(access_token))
        resp = client.get("/auth/api-keys", headers=_auth(access_token))
        assert resp.status_code == 200
        body = resp.get_json()
        assert len(body["keys"]) >= 1
        for key in body["keys"]:
            assert set(key.keys()) == {"key_prefix", "tier", "revoked", "created_at", "last_used_at"}
            assert "api_key" not in key

    def test_only_lists_own_keys(self, client, access_token, other_access_token):
        client.post("/auth/api-keys", headers=_auth(access_token))
        other_resp = client.get("/auth/api-keys", headers=_auth(other_access_token))
        assert other_resp.get_json()["keys"] == []


class TestRevokeApiKey:
    def test_requires_auth(self, client):
        resp = client.delete("/auth/api-keys/argus_abcd")
        assert resp.status_code == 401

    def test_revoke_own_key(self, client, access_token):
        create_resp = client.post("/auth/api-keys", headers=_auth(access_token))
        prefix = create_resp.get_json()["key_prefix"]

        resp = client.delete(f"/auth/api-keys/{prefix}", headers=_auth(access_token))
        assert resp.status_code == 200
        assert resp.get_json()["revoked"] is True

        # Reflected in the list.
        list_resp = client.get("/auth/api-keys", headers=_auth(access_token))
        matching = [k for k in list_resp.get_json()["keys"] if k["key_prefix"] == prefix]
        assert matching[0]["revoked"] is True

    def test_revoking_someone_elses_key_is_404_not_403(self, client, access_token, other_access_token):
        """IDOR test: a key that exists but belongs to another user must
        look identical to a non-existent one -- 404, not 403 (mirrors the
        vault's g.user_id-scoped IDOR-safe pattern)."""
        create_resp = client.post("/auth/api-keys", headers=_auth(access_token))
        prefix = create_resp.get_json()["key_prefix"]

        resp = client.delete(f"/auth/api-keys/{prefix}", headers=_auth(other_access_token))
        assert resp.status_code == 404

        # And the original owner's key must still be usable (untouched).
        list_resp = client.get("/auth/api-keys", headers=_auth(access_token))
        matching = [k for k in list_resp.get_json()["keys"] if k["key_prefix"] == prefix]
        assert matching[0]["revoked"] is False

    def test_revoking_nonexistent_key_404(self, client, access_token):
        resp = client.delete("/auth/api-keys/argus_doesnotexist", headers=_auth(access_token))
        assert resp.status_code == 404
