"""Tests for S6 (SECRET_KEY fail-closed) and the @require_auth middleware."""

from __future__ import annotations

import os
from unittest import mock

import pytest

from src.api.auth.utils import get_secret_key


def test_s6_get_secret_key_raises_when_unset():
    with mock.patch.dict(os.environ, {}, clear=True):
        with pytest.raises(RuntimeError, match="SECRET_KEY"):
            get_secret_key()


def test_s6_get_secret_key_raises_when_empty_string():
    with mock.patch.dict(os.environ, {"SECRET_KEY": ""}, clear=True):
        with pytest.raises(RuntimeError, match="SECRET_KEY"):
            get_secret_key()


def test_s6_create_app_fails_closed_without_secret_key(tmp_path):
    """The app factory itself must refuse to start, not just the helper function."""
    import yaml

    from src.api.app import PROJECT_ROOT, create_app

    api_config = yaml.safe_load((PROJECT_ROOT / "configs" / "api_config.yaml").open())
    api_config["database_url"] = "sqlite:///:memory:"
    config_path = tmp_path / "api_config.yaml"
    config_path.write_text(yaml.safe_dump(api_config))

    with mock.patch.dict(os.environ, {}, clear=True):
        with pytest.raises(RuntimeError, match="SECRET_KEY"):
            create_app(config_path=str(config_path))


def test_require_auth_rejects_missing_header(client):
    resp = client.get("/vault")
    assert resp.status_code == 401


def test_require_auth_rejects_malformed_header(client):
    resp = client.get("/vault", headers={"Authorization": "NotBearer xyz"})
    assert resp.status_code == 401


def test_require_auth_rejects_garbage_token(client):
    resp = client.get("/vault", headers={"Authorization": "Bearer not-a-real-jwt"})
    assert resp.status_code == 401


def test_require_auth_rejects_token_signed_with_wrong_key(client):
    import jwt

    forged = jwt.encode({"sub": "1"}, "wrong-secret-key", algorithm="HS256")
    resp = client.get("/vault", headers={"Authorization": f"Bearer {forged}"})
    assert resp.status_code == 401


def test_require_auth_accepts_valid_token(client):
    email, password = "middleware_test@example.com", "correct-horse-1"
    otp = client.post("/auth/signup", json={"email": email, "password": password}).get_json()["dev_otp"]
    client.post("/auth/verify-otp", json={"email": email, "otp": otp})
    tokens = client.post("/auth/login", json={"email": email, "password": password}).get_json()

    resp = client.get("/vault", headers={"Authorization": f"Bearer {tokens['access_token']}"})
    assert resp.status_code == 200
