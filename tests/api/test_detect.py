"""Tests for POST /detect.

extract_features is mocked at the src.api.detect call site — no real
network I/O in these tests.
"""

from __future__ import annotations

from unittest import mock

import pytest

from src.api.threat_intel.providers import PhishTankProvider
from src.data.loaders import normalize_url
from src.features.page_artifacts import PageArtifacts
from src.features.pipeline import FeatureVector
from src.models.contract import FEATURE_ORDER

MODULE = "src.api.detect"

# A page_artifacts.fetch() double whose fetch "fails" (html=None) -- keeps
# enrich=true tests network-free and detection-signal-neutral by default,
# same spirit as mocking extract_features for the model path.
_FAILED_FETCH_ARTIFACTS = PageArtifacts(
    requested_url="https://example.com", html=None, fetch_error="mocked: no network in tests"
)

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
    with mock.patch(f"{MODULE}.extract_features", return_value=fv) as m, mock.patch(
        f"{MODULE}.page_artifacts.fetch", return_value=_FAILED_FETCH_ARTIFACTS
    ):
        resp = client.post("/detect", json={"url": "https://example.com", "enrich": True})
    assert resp.status_code == 200
    m.assert_called_once_with(
        "https://example.com", html=None, include_domain=True
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


# --------------------------------------------------------------------------- #
# Detection fusion layer wiring (Phase 1, DEC-A)
# --------------------------------------------------------------------------- #


def test_detect_fast_path_omits_signals_and_risk_score(client):
    """The default (enrich=false) response has no risk_score/signals keys at
    all -- additive fields never appear on the pre-Phase-1 fast path."""
    fv = _fake_feature_vector("https://example.com", _LEGIT_RAW_FEATURES)
    with mock.patch(f"{MODULE}.extract_features", return_value=fv):
        resp = client.post("/detect", json={"url": "https://example.com"})
    body = resp.get_json()
    assert "risk_score" not in body
    assert "signals" not in body


def test_detect_enrich_true_includes_signals_and_risk_score(client):
    """enrich=true with the fusion layer enabled adds risk_score + signals."""
    fv = _fake_feature_vector("https://example.com", _LEGIT_RAW_FEATURES)
    with mock.patch(f"{MODULE}.extract_features", return_value=fv), mock.patch(
        f"{MODULE}.page_artifacts.fetch", return_value=_FAILED_FETCH_ARTIFACTS
    ):
        resp = client.post("/detect", json={"url": "https://example.com", "enrich": True})
    body = resp.get_json()
    assert "risk_score" in body
    assert isinstance(body["signals"], list)
    # typosquat always runs even when the page fetch fails -- neutral here
    # since "example.com" isn't a look-alike of any reference brand.
    assert any(s["name"] == "typosquat" for s in body["signals"])


def test_detect_typosquat_signal_triggers_and_flips_verdict(client):
    """A look-alike domain the model alone would score below-threshold is
    caught by the typosquat signal and flips the fused verdict to phishing.

    Uses a deliberately borderline (not maximally-legitimate) raw feature
    set so the fusion math robustly crosses the 0.30 threshold — this is
    the DEC-018 failure mode being closed: domain-level signals alone are
    ambiguous/clean, but the URL itself is a clear look-alike.
    """
    borderline_features = dict(_LEGIT_RAW_FEATURES)
    borderline_features.update(
        num_hyphens_in_hostname=1,
        internal_tag_link_ratio=0.6,
        domain_age_days=200,
        days_until_expiry=200,
    )
    fv = _fake_feature_vector("https://paypal-secure-login.net", borderline_features)
    with mock.patch(f"{MODULE}.extract_features", return_value=fv), mock.patch(
        f"{MODULE}.page_artifacts.fetch", return_value=_FAILED_FETCH_ARTIFACTS
    ):
        resp = client.post(
            "/detect", json={"url": "https://paypal-secure-login.net", "enrich": True}
        )
    body = resp.get_json()
    assert resp.status_code == 200
    assert body["label"] == "phishing"
    assert body["source"] == "fusion"
    typo_signals = [s for s in body["signals"] if s["name"] == "typosquat"]
    assert len(typo_signals) == 1
    assert typo_signals[0]["triggered"] is True
    assert typo_signals[0]["evidence"]["impersonated_brand"] == "PayPal"


def test_detect_fusion_disabled_matches_legacy_model_only_behavior(app, client):
    """With detection disabled, enrich=true reproduces the exact pre-Phase-1
    model-only response shape (no risk_score/signals keys)."""
    argus = app.extensions["argus"]
    original_detection = argus["detection"]
    argus["detection"] = {"enabled": False, "config": {"enabled": False}, "brand_index": None}
    try:
        fv = _fake_feature_vector("https://example.com", _LEGIT_RAW_FEATURES)
        with mock.patch(f"{MODULE}.extract_features", return_value=fv), mock.patch(
            f"{MODULE}.page_artifacts.fetch", return_value=_FAILED_FETCH_ARTIFACTS
        ):
            resp = client.post("/detect", json={"url": "https://example.com", "enrich": True})
        body = resp.get_json()
        assert body["source"] == "model"
        assert "risk_score" not in body
        assert "signals" not in body
    finally:
        argus["detection"] = original_detection


# --------------------------------------------------------------------------- #
# threat-intel pre-filter short-circuit (Phase 9, Task 9.1, DEC-010)
# --------------------------------------------------------------------------- #


@pytest.fixture
def _restore_threat_intel(app):
    """Save/restore app.extensions['argus']['threat_intel'].

    `app` is session-scoped and shared by every test in tests/api/ — a test
    that swaps in a fake pre-filter index must put the real one back
    afterward, or it would leak into every later test in the session.
    """
    original = app.extensions["argus"]["threat_intel"]
    yield
    app.extensions["argus"]["threat_intel"] = original


def test_prefilter_match_short_circuits_without_calling_model(app, client, _restore_threat_intel):
    bad_url = "http://phish-prefilter-test.example.com/login"
    app.extensions["argus"]["threat_intel"] = {
        "enabled": True,
        "providers": [PhishTankProvider(frozenset({normalize_url(bad_url)}))],
    }

    with mock.patch(f"{MODULE}.extract_features") as m_extract:
        resp = client.post("/detect", json={"url": bad_url})

    assert resp.status_code == 200
    body = resp.get_json()
    assert body["label"] == "phishing"
    assert body["verdict"] == "phishing"
    assert body["confidence"] == 1.0
    assert body["source"] == "phishtank"
    assert "latency_ms" in body
    m_extract.assert_not_called()


def test_prefilter_miss_falls_through_to_model(app, client, _restore_threat_intel):
    app.extensions["argus"]["threat_intel"] = {
        "enabled": True,
        "providers": [PhishTankProvider(frozenset({normalize_url("http://some-other-phish.example.com/")}))],
    }
    fv = _fake_feature_vector("https://example.com", _LEGIT_RAW_FEATURES)

    with mock.patch(f"{MODULE}.extract_features", return_value=fv) as m_extract:
        resp = client.post("/detect", json={"url": "https://example.com"})

    assert resp.status_code == 200
    assert resp.get_json()["source"] == "model"
    m_extract.assert_called_once()


def test_prefilter_disabled_falls_through_to_model(app, client, _restore_threat_intel):
    bad_url = "http://phish-prefilter-test.example.com/login"
    app.extensions["argus"]["threat_intel"] = {
        "enabled": False,
        "providers": [PhishTankProvider(frozenset({normalize_url(bad_url)}))],
    }
    fv = _fake_feature_vector(bad_url, _LEGIT_RAW_FEATURES)

    with mock.patch(f"{MODULE}.extract_features", return_value=fv) as m_extract:
        resp = client.post("/detect", json={"url": bad_url})

    assert resp.status_code == 200
    assert resp.get_json()["source"] == "model"
    m_extract.assert_called_once()
