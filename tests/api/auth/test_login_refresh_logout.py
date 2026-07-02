"""Tests for POST /auth/login, /auth/refresh, /auth/logout (Task 8.1).

Covers: login/refresh/logout happy path, S2 (logout revokes), S3 (reuse
detection revokes the whole token family).
"""

from __future__ import annotations

import pytest


@pytest.fixture
def verified_user(client):
    """Sign up + verify a user, returning (email, password)."""
    email, password = "signed_in@example.com", "correct-horse-1"
    otp = client.post("/auth/signup", json={"email": email, "password": password}).get_json()["dev_otp"]
    client.post("/auth/verify-otp", json={"email": email, "otp": otp})
    return email, password


def test_login_unverified_user_rejected(client):
    email, password = "unverified@example.com", "correct-horse-1"
    client.post("/auth/signup", json={"email": email, "password": password})
    resp = client.post("/auth/login", json={"email": email, "password": password})
    assert resp.status_code == 401


def test_login_success_returns_token_pair(client, verified_user):
    email, password = verified_user
    resp = client.post("/auth/login", json={"email": email, "password": password})
    assert resp.status_code == 200
    body = resp.get_json()
    assert "access_token" in body
    assert "refresh_token" in body
    assert body["expires_in"] == 900


def test_login_wrong_password_generic_error(client, verified_user):
    email, _ = verified_user
    resp = client.post("/auth/login", json={"email": email, "password": "wrong-password"})
    assert resp.status_code == 401
    assert resp.get_json()["error"] == "Invalid email or password."


def test_login_unknown_email_same_generic_error(client, verified_user):
    """No enumeration: unknown-email error is identical to wrong-password error."""
    resp = client.post("/auth/login", json={"email": "ghost@example.com", "password": "whatever1"})
    assert resp.status_code == 401
    assert resp.get_json()["error"] == "Invalid email or password."


def test_refresh_rotates_tokens(client, verified_user):
    email, password = verified_user
    tokens = client.post("/auth/login", json={"email": email, "password": password}).get_json()

    resp = client.post("/auth/refresh", json={"refresh_token": tokens["refresh_token"]})
    assert resp.status_code == 200
    new_tokens = resp.get_json()
    assert new_tokens["refresh_token"] != tokens["refresh_token"]
    assert new_tokens["access_token"] != tokens["access_token"]


def test_refresh_invalid_token_401(client):
    resp = client.post("/auth/refresh", json={"refresh_token": "not-a-real-token"})
    assert resp.status_code == 401


def test_s3_refresh_reuse_revokes_entire_family(client, verified_user):
    """S3: presenting an already-rotated (used) refresh token again must
    revoke the whole family -- including the token that legitimately
    replaced it."""
    email, password = verified_user
    tokens = client.post("/auth/login", json={"email": email, "password": password}).get_json()

    rotated = client.post("/auth/refresh", json={"refresh_token": tokens["refresh_token"]}).get_json()

    # Reusing the old (now-used) token is rejected...
    reuse_resp = client.post("/auth/refresh", json={"refresh_token": tokens["refresh_token"]})
    assert reuse_resp.status_code == 401
    assert "reuse" in reuse_resp.get_json()["error"]

    # ...and so is the legitimately-rotated token, because the whole family
    # was revoked as a precaution (the reuse is a theft signal, not
    # necessarily on THIS specific token).
    legit_resp = client.post("/auth/refresh", json={"refresh_token": rotated["refresh_token"]})
    assert legit_resp.status_code == 401


def test_s2_logout_revokes_refresh_token(client, verified_user):
    """S2: a refresh token must stop working after logout."""
    email, password = verified_user
    tokens = client.post("/auth/login", json={"email": email, "password": password}).get_json()

    logout_resp = client.post("/auth/logout", json={"refresh_token": tokens["refresh_token"]})
    assert logout_resp.status_code == 200

    refresh_resp = client.post("/auth/refresh", json={"refresh_token": tokens["refresh_token"]})
    assert refresh_resp.status_code == 401


def test_logout_unknown_token_still_succeeds(client):
    """Idempotent/no-info-leak: logging out an unrecognized token is still a 200."""
    resp = client.post("/auth/logout", json={"refresh_token": "never-issued-token"})
    assert resp.status_code == 200
