"""Tests for GET/PUT /vault (Task 8.3) -- S10: server-authoritative
versioning, server never decrypts."""

from __future__ import annotations

import pytest

from src.api.vault.routes import MAX_CIPHERTEXT_CHARS


@pytest.fixture
def auth_headers(client):
    """Sign up, verify, and log in a fresh user; return its auth header."""
    email, password = "vault_user@example.com", "correct-horse-1"
    otp = client.post("/auth/signup", json={"email": email, "password": password}).get_json()["dev_otp"]
    client.post("/auth/verify-otp", json={"email": email, "otp": otp})
    tokens = client.post("/auth/login", json={"email": email, "password": password}).get_json()
    return {"Authorization": f"Bearer {tokens['access_token']}"}


def test_get_vault_empty_by_default(client, auth_headers):
    resp = client.get("/vault", headers=auth_headers)
    assert resp.status_code == 200
    assert resp.get_json() == {"ciphertext": None, "version": 0}


def test_put_vault_creates_entry_at_version_1(client, auth_headers):
    resp = client.put(
        "/vault", json={"ciphertext": "b3BhcXVlLWJsb2I=", "version": 0}, headers=auth_headers
    )
    assert resp.status_code == 200
    assert resp.get_json()["version"] == 1

    get_resp = client.get("/vault", headers=auth_headers)
    assert get_resp.get_json() == {"ciphertext": "b3BhcXVlLWJsb2I=", "version": 1}


def test_put_vault_wrong_version_returns_409(client, auth_headers):
    client.put("/vault", json={"ciphertext": "Zmlyc3Q=", "version": 0}, headers=auth_headers)

    conflict_resp = client.put(
        "/vault", json={"ciphertext": "c3RhbGU=", "version": 0}, headers=auth_headers
    )
    assert conflict_resp.status_code == 409
    body = conflict_resp.get_json()
    assert body["current_version"] == 1
    assert body["current_ciphertext"] == "Zmlyc3Q="


def test_put_vault_correct_version_after_conflict_succeeds(client, auth_headers):
    client.put("/vault", json={"ciphertext": "Zmlyc3Q=", "version": 0}, headers=auth_headers)
    conflict = client.put(
        "/vault", json={"ciphertext": "c3RhbGU=", "version": 0}, headers=auth_headers
    ).get_json()

    retry_resp = client.put(
        "/vault",
        json={"ciphertext": "bWVyZ2Vk", "version": conflict["current_version"]},
        headers=auth_headers,
    )
    assert retry_resp.status_code == 200
    assert retry_resp.get_json()["version"] == 2


def test_vault_requires_auth(client):
    assert client.get("/vault").status_code == 401
    assert client.put("/vault", json={"ciphertext": "eA==", "version": 0}).status_code == 401


def test_s10_server_stores_only_opaque_ciphertext(client, auth_headers, db_session):
    """S10: the server-side row is exactly the client-supplied string --
    there's no decryption, no plaintext field, nothing to invert."""
    from src.api.vault.models import VaultEntry

    ciphertext = "dGhpcy1pcy1qdXN0LWJhc2U2NC1sb29raW5nLW9wYXF1ZS1kYXRh"
    client.put("/vault", json={"ciphertext": ciphertext, "version": 0}, headers=auth_headers)

    entry = db_session.query(VaultEntry).one()
    assert entry.ciphertext == ciphertext
    # The model has no field capable of holding a decryption key or
    # plaintext -- only ciphertext/version/updated_at.
    column_names = {c.name for c in VaultEntry.__table__.columns}
    assert column_names == {"user_id", "ciphertext", "version", "updated_at"}


def test_put_vault_invalid_body_400(client, auth_headers):
    resp = client.put("/vault", json={"ciphertext": "x"}, headers=auth_headers)  # missing version
    assert resp.status_code == 400


def test_put_vault_rejects_oversize_ciphertext(client, auth_headers):
    """Unbounded blob storage (CWE-770): the app-wide MAX_CONTENT_LENGTH bounds
    one request, but only this cap bounds what an authenticated user can
    accumulate in the database across many of them."""
    oversize = "a" * (MAX_CIPHERTEXT_CHARS + 1)
    resp = client.put(
        "/vault", json={"ciphertext": oversize, "version": 0}, headers=auth_headers
    )
    assert resp.status_code == 400
    assert "ciphertext" in resp.get_json()["error"]


def test_put_vault_accepts_ciphertext_at_the_limit(client, auth_headers):
    """The cap is a safety ceiling, not a functional limit — a blob exactly at
    the boundary must still store cleanly."""
    at_limit = "a" * MAX_CIPHERTEXT_CHARS
    resp = client.put(
        "/vault", json={"ciphertext": at_limit, "version": 0}, headers=auth_headers
    )
    assert resp.status_code == 200
    assert resp.get_json()["version"] == 1
