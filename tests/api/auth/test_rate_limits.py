"""Tests for the auth-specific rate limits (Task 8.1/8.2) -- a dedicated,
freshly-built app per test module so its request count isn't polluted by
(or doesn't pollute) the shared session app used by the rest of tests/api/.

This also regression-tests a real bug found during manual verification:
`limiter.limit(...)` returns a *new* wrapped function rather than mutating
the view in place, so applying it to an already-registered blueprint view
requires writing the result back into `app.view_functions[endpoint]` --
discarding it (as an earlier version of app.py did) silently applies no
limit at all.
"""

from __future__ import annotations

import pytest
import yaml

from tests.api.conftest import PROJECT_ROOT, _MODEL_PATH


@pytest.fixture(scope="module")
def fresh_app(tmp_path_factory):
    if not _MODEL_PATH.is_file():
        pytest.skip("Run scripts/train.py + scripts/evaluate.py first — no trained model available.")

    api_config = yaml.safe_load((PROJECT_ROOT / "configs" / "api_config.yaml").open())
    api_config["database_url"] = "sqlite:///:memory:"
    api_config["auth_dev_return_otp"] = True

    tmp_dir = tmp_path_factory.mktemp("auth_rate_limit_config")
    config_path = tmp_dir / "api_config.yaml"
    config_path.write_text(yaml.safe_dump(api_config))

    from src.api.app import create_app

    return create_app(config_path=str(config_path))


@pytest.fixture
def fresh_client(fresh_app):
    return fresh_app.test_client()


def test_signup_rate_limited_after_5_per_minute(fresh_client):
    for i in range(5):
        resp = fresh_client.post(
            "/auth/signup", json={"email": f"burst{i}@example.com", "password": "password123"}
        )
        assert resp.status_code == 200

    resp = fresh_client.post(
        "/auth/signup", json={"email": "burst6@example.com", "password": "password123"}
    )
    assert resp.status_code == 429


def test_login_rate_limited_after_10_per_minute(fresh_client):
    for _ in range(10):
        resp = fresh_client.post(
            "/auth/login", json={"email": "nonexistent@example.com", "password": "whatever12"}
        )
        assert resp.status_code == 401  # rejected on credentials, not yet rate-limited

    resp = fresh_client.post(
        "/auth/login", json={"email": "nonexistent@example.com", "password": "whatever12"}
    )
    assert resp.status_code == 429


def test_verify_otp_rate_limited_after_10_per_minute(fresh_client):
    for _ in range(10):
        resp = fresh_client.post(
            "/auth/verify-otp", json={"email": "nonexistent2@example.com", "otp": "000000"}
        )
        assert resp.status_code == 400  # rejected on OTP, not yet rate-limited

    resp = fresh_client.post(
        "/auth/verify-otp", json={"email": "nonexistent2@example.com", "otp": "000000"}
    )
    assert resp.status_code == 429
