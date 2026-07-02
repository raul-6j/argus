"""Tests for CORS — locked to the configured extension origin only."""

from __future__ import annotations

import yaml

from tests.api.conftest import PROJECT_ROOT

_API_CONFIG = yaml.safe_load((PROJECT_ROOT / "configs" / "api_config.yaml").open())
_ALLOWED_ORIGIN = _API_CONFIG["cors_origins"][0]


def test_allowed_origin_gets_cors_header(client):
    resp = client.get("/health", headers={"Origin": _ALLOWED_ORIGIN})
    assert resp.headers.get("Access-Control-Allow-Origin") == _ALLOWED_ORIGIN


def test_disallowed_origin_gets_no_cors_header(client):
    resp = client.get("/health", headers={"Origin": "https://evil.example.com"})
    assert resp.headers.get("Access-Control-Allow-Origin") is None
