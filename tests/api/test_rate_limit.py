"""Tests for rate limiting — a dedicated low-limit app instance so this
doesn't interfere with (or get interfered with by) the shared session app's
request count in other test modules."""

from __future__ import annotations

import json

import pytest
import yaml

from tests.api.conftest import _MODEL_PATH, PROJECT_ROOT


@pytest.fixture(scope="module")
def low_limit_app(tmp_path_factory):
    if not _MODEL_PATH.is_file():
        pytest.skip("Run scripts/train.py + scripts/evaluate.py first — no trained model available.")

    api_config = yaml.safe_load((PROJECT_ROOT / "configs" / "api_config.yaml").open())
    api_config["rate_limit"] = "2 per minute"
    api_config["rate_limit_storage_uri"] = "memory://"

    tmp_dir = tmp_path_factory.mktemp("rate_limit_config")
    config_path = tmp_dir / "api_config.yaml"
    config_path.write_text(yaml.safe_dump(api_config))

    from src.api.app import create_app

    return create_app(config_path=str(config_path))


@pytest.fixture
def low_limit_client(low_limit_app):
    return low_limit_app.test_client()


def test_returns_429_after_cap(low_limit_client):
    r1 = low_limit_client.get("/health")
    r2 = low_limit_client.get("/health")
    r3 = low_limit_client.get("/health")
    assert r1.status_code == 200
    assert r2.status_code == 200
    assert r3.status_code == 429
    assert "error" in json.loads(r3.data)
