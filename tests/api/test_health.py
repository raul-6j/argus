"""Tests for GET /health."""

from __future__ import annotations


def test_health_returns_200(client):
    resp = client.get("/health")
    assert resp.status_code == 200


def test_health_body_shape(client):
    body = client.get("/health").get_json()
    assert body["status"] == "ok"
    assert body["model_loaded"] is True
    assert "latency_ms" in body
    assert isinstance(body["latency_ms"], (int, float))
