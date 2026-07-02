"""Tests for POST /detect.

extract_features is mocked at the src.api.detect call site — no real
network I/O in these tests.
"""

from __future__ import annotations

from unittest import mock

from src.features.pipeline import FeatureVector
from src.models.contract import FEATURE_ORDER

MODULE = "src.api.detect"

# Raw live-extractor-shaped features (same shape feature_adapter tests use),
# not already-bucketed contract values — adapt_to_training_contract() does
# that conversion inside the endpoint.
_LEGIT_RAW_FEATURES = {
    "has_ip_address": False,
    "has_shortening": False,
    "has_at_symbol": False,
    "num_hyphens_in_hostname": 0,
    "num_subdomains": 1,
    "has_favicon": True,
    "has_port": False,
    "has_https": True,
    "internal_tag_link_ratio": 1.0,
    "form_action_is_empty_or_blank": False,
    "form_action_is_external": False,
    "form_submits_to_email": False,
    "has_onmouseover": False,
    "has_right_click_disabled": False,
    "has_suspicious_popup": False,
    "has_iframe": False,
    "domain_age_days": 3000,
    "days_until_expiry": 400,
    "has_dns_a_record": True,
}


def _fake_feature_vector(url: str, features: dict) -> FeatureVector:
    return FeatureVector(
        url=url,
        features=features,
        feature_order=tuple(FEATURE_ORDER),
        model_version="test",
        extraction_time_ms=1.0,
        components_run=["lexical"],
    )


def test_detect_valid_url_returns_prediction(client):
    fv = _fake_feature_vector("https://example.com", _LEGIT_RAW_FEATURES)
    with mock.patch(f"{MODULE}.extract_features", return_value=fv):
        resp = client.post("/detect", json={"url": "https://example.com"})
    assert resp.status_code == 200
    body = resp.get_json()
    assert body["url"] == "https://example.com"
    assert body["label"] in ("phishing", "legitimate")
    assert body["verdict"] == body["label"]
    assert 0.0 <= body["confidence"] <= 1.0
    assert body["source"] == "model"
    assert isinstance(body["latency_ms"], (int, float))


def test_detect_missing_url_400(client):
    resp = client.post("/detect", json={})
    assert resp.status_code == 400
    assert "error" in resp.get_json()


def test_detect_invalid_scheme_400(client):
    resp = client.post("/detect", json={"url": "ftp://example.com"})
    assert resp.status_code == 400
    assert "scheme" in resp.get_json()["error"]


def test_detect_localhost_rejected_400(client):
    resp = client.post("/detect", json={"url": "http://localhost"})
    assert resp.status_code == 400
    assert "localhost" in resp.get_json()["error"]


def test_detect_no_body_400(client):
    resp = client.post("/detect", data="not json", content_type="text/plain")
    assert resp.status_code == 400


def test_detect_default_enrich_false_no_network(client):
    """Without enrich, extract_features is called with no fetch/domain kwargs."""
    fv = _fake_feature_vector("https://example.com", _LEGIT_RAW_FEATURES)
    with mock.patch(f"{MODULE}.extract_features", return_value=fv) as m:
        client.post("/detect", json={"url": "https://example.com"})
    m.assert_called_once_with("https://example.com")


def test_detect_enrich_true_uses_executor(client):
    """enrich=true submits the full extraction to the persistent thread pool."""
    fv = _fake_feature_vector("https://example.com", _LEGIT_RAW_FEATURES)
    with mock.patch(f"{MODULE}.extract_features", return_value=fv) as m:
        resp = client.post("/detect", json={"url": "https://example.com", "enrich": True})
    assert resp.status_code == 200
    m.assert_called_once_with(
        "https://example.com", fetch_html=True, include_domain=True
    )


def test_detect_enrichment_timeout_falls_back(app, client):
    """A timed-out enrichment falls back to a lexical-only (fast) extraction,
    never surfaces as an error to the caller."""
    import concurrent.futures

    fallback_fv = _fake_feature_vector("https://example.com", _LEGIT_RAW_FEATURES)

    fake_future = mock.Mock()
    fake_future.result.side_effect = concurrent.futures.TimeoutError()
    fake_executor = app.extensions["argus"]["executor"]

    with mock.patch.object(fake_executor, "submit", return_value=fake_future) as m_submit, mock.patch(
        f"{MODULE}.extract_features", return_value=fallback_fv
    ) as m_extract:
        resp = client.post("/detect", json={"url": "https://example.com", "enrich": True})

    assert resp.status_code == 200
    m_submit.assert_called_once()
    # Fallback call: lexical-only, single positional arg, no fetch/domain kwargs.
    m_extract.assert_called_once_with("https://example.com")


def test_all_detect_responses_have_latency_ms(client):
    fv = _fake_feature_vector("https://example.com", _LEGIT_RAW_FEATURES)
    with mock.patch(f"{MODULE}.extract_features", return_value=fv):
        resp = client.post("/detect", json={"url": "https://example.com"})
    assert "latency_ms" in resp.get_json()
