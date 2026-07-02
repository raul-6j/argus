"""Tests for POST /explain."""

from __future__ import annotations

from unittest import mock

from tests.api.test_detect import _LEGIT_RAW_FEATURES, _fake_feature_vector

MODULE = "src.api.detect"


def test_explain_returns_top5(client):
    fv = _fake_feature_vector("https://example.com", _LEGIT_RAW_FEATURES)
    with mock.patch(f"{MODULE}.extract_features", return_value=fv):
        resp = client.post("/explain", json={"url": "https://example.com"})
    assert resp.status_code == 200
    body = resp.get_json()
    assert body["url"] == "https://example.com"
    assert len(body["top5_features"]) == 5
    assert "latency_ms" in body
    for item in body["top5_features"]:
        assert set(item.keys()) == {"feature", "shap_value", "feature_value"}


def test_explain_ordered_by_abs_shap_descending(client):
    fv = _fake_feature_vector("https://example.com", _LEGIT_RAW_FEATURES)
    with mock.patch(f"{MODULE}.extract_features", return_value=fv):
        resp = client.post("/explain", json={"url": "https://example.com"})
    magnitudes = [abs(item["shap_value"]) for item in resp.get_json()["top5_features"]]
    assert magnitudes == sorted(magnitudes, reverse=True)


def test_explain_always_enriches(client):
    """Unlike /detect, /explain has no enrich flag — it always fetches HTML/domain."""
    fv = _fake_feature_vector("https://example.com", _LEGIT_RAW_FEATURES)
    with mock.patch(f"{MODULE}.extract_features", return_value=fv) as m:
        client.post("/explain", json={"url": "https://example.com"})
    m.assert_called_once_with("https://example.com", fetch_html=True, include_domain=True)


def test_explain_missing_url_400(client):
    resp = client.post("/explain", json={})
    assert resp.status_code == 400
    assert "error" in resp.get_json()


def test_explain_invalid_url_400(client):
    resp = client.post("/explain", json={"url": "ftp://example.com"})
    assert resp.status_code == 400
