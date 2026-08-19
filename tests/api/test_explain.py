"""Tests for POST /explain."""

from __future__ import annotations

from unittest import mock

from src.features.page_artifacts import PageArtifacts
from src.models.contract import FEATURE_ORDER, MISSING, ModelInput
from tests.api.test_detect import _FAILED_FETCH_ARTIFACTS, _LEGIT_RAW_FEATURES, _fake_feature_vector

MODULE = "src.api.verdict"  # the shared extraction seam these tests patch


def test_explain_returns_top5(client):
    fv = _fake_feature_vector("https://example.com", _LEGIT_RAW_FEATURES)
    with mock.patch(f"{MODULE}.extract_features", return_value=fv), mock.patch(
        f"{MODULE}.page_artifacts.fetch", return_value=_FAILED_FETCH_ARTIFACTS
    ):
        resp = client.post("/explain", json={"url": "https://example.com"})
    assert resp.status_code == 200
    body = resp.get_json()
    assert body["url"] == "https://example.com"
    assert len(body["top5_features"]) == 5
    assert "latency_ms" in body
    for item in body["top5_features"]:
        assert set(item.keys()) == {"feature", "shap_value", "feature_value"}


def test_explain_response_is_valid_json_with_missing_features(client):
    """A feature the live extractor genuinely couldn't measure is NaN in the
    model contract's ``MISSING`` sentinel (DEC-040) -- correct for the
    pipeline's imputer, but `jsonify` used to emit that as a bare `NaN`
    token, which is not valid JSON and breaks any strict JSON.parse caller
    (every browser, including this project's own extension -- found live
    via the popup's "Why?" button crashing on it). Forces a MISSING value
    via a patched adapter (rather than relying on a specific raw-feature
    fixture happening to produce one) and asserts on the raw response
    bytes, not `get_json()` -- Python's own `json` module is lenient about
    `NaN` by default and would silently accept the very token a real
    client's `fetch().json()` rejects, defeating the point of this
    regression guard."""
    fv = _fake_feature_vector("https://example.com", _LEGIT_RAW_FEATURES)
    # Every feature is MISSING, not just one. /explain returns only the top 5
    # by |SHAP| (explain.py's `attributions[:5]`), and the production model is
    # an SVM, so attribution runs through SHAP's *stochastic* KernelExplainer.
    # Forcing a single feature and then looking for it in the top 5 made the
    # assertion depend on where that one feature happened to rank, which is
    # not stable across runs. With all of them missing, whichever five surface
    # must every one of them be null, so the guard holds regardless of ranking.
    model_input = ModelInput(
        values=dict.fromkeys(FEATURE_ORDER, MISSING),
        unavailable=list(FEATURE_ORDER),
    )
    with mock.patch(f"{MODULE}.extract_features", return_value=fv), mock.patch(
        f"{MODULE}.page_artifacts.fetch", return_value=_FAILED_FETCH_ARTIFACTS
    ), mock.patch("src.api.detect.adapt_to_training_contract", return_value=model_input):
        resp = client.post("/explain", json={"url": "https://example.com"})
    assert resp.status_code == 200
    raw_text = resp.get_data(as_text=True)
    assert "NaN" not in raw_text
    top5 = resp.get_json()["top5_features"]
    assert len(top5) == 5
    assert all(item["feature_value"] is None for item in top5)


def test_explain_ordered_by_abs_shap_descending(client):
    fv = _fake_feature_vector("https://example.com", _LEGIT_RAW_FEATURES)
    with mock.patch(f"{MODULE}.extract_features", return_value=fv), mock.patch(
        f"{MODULE}.page_artifacts.fetch", return_value=_FAILED_FETCH_ARTIFACTS
    ):
        resp = client.post("/explain", json={"url": "https://example.com"})
    magnitudes = [abs(item["shap_value"]) for item in resp.get_json()["top5_features"]]
    assert magnitudes == sorted(magnitudes, reverse=True)


def test_explain_always_enriches(client):
    """Unlike /detect, /explain has no enrich flag — it always fetches the
    page once (P1.0) and passes the resulting HTML into extract_features."""
    fv = _fake_feature_vector("https://example.com", _LEGIT_RAW_FEATURES)
    fetched_artifacts = PageArtifacts(
        requested_url="https://example.com",
        html="<html><title>t</title></html>",
        final_url="https://example.com",
    )
    with mock.patch(f"{MODULE}.extract_features", return_value=fv) as m, mock.patch(
        f"{MODULE}.page_artifacts.fetch", return_value=fetched_artifacts
    ) as m_fetch:
        client.post("/explain", json={"url": "https://example.com"})
    m_fetch.assert_called_once_with("https://example.com")
    m.assert_called_once_with(
        "https://example.com", html="<html><title>t</title></html>", include_domain=True
    )


def test_explain_missing_url_400(client):
    resp = client.post("/explain", json={})
    assert resp.status_code == 400
    assert "error" in resp.get_json()


def test_explain_invalid_url_400(client):
    resp = client.post("/explain", json={"url": "ftp://example.com"})
    assert resp.status_code == 400


# --------------------------------------------------------------------------- #
# Detection fusion layer wiring (Phase 1, B2/DEC-A)
# --------------------------------------------------------------------------- #


def test_explain_always_includes_signals_and_plain_explanation(client):
    fv = _fake_feature_vector("https://example.com", _LEGIT_RAW_FEATURES)
    with mock.patch(f"{MODULE}.extract_features", return_value=fv), mock.patch(
        f"{MODULE}.page_artifacts.fetch", return_value=_FAILED_FETCH_ARTIFACTS
    ):
        resp = client.post("/explain", json={"url": "https://example.com"})
    body = resp.get_json()
    assert isinstance(body["signals"], list)
    assert isinstance(body["plain_explanation"], str)
    assert body["plain_explanation"] != ""


def test_explain_plain_explanation_reflects_triggered_signal(client):
    fv = _fake_feature_vector("https://paypal-secure-login.net", _LEGIT_RAW_FEATURES)
    with mock.patch(f"{MODULE}.extract_features", return_value=fv), mock.patch(
        f"{MODULE}.page_artifacts.fetch", return_value=_FAILED_FETCH_ARTIFACTS
    ):
        resp = client.post("/explain", json={"url": "https://paypal-secure-login.net"})
    body = resp.get_json()
    assert any(s["name"] == "typosquat" and s["triggered"] for s in body["signals"])
    assert "PayPal" in body["plain_explanation"]


def test_explain_disabled_detection_still_returns_signals_key(app, client):
    """Even with the fusion layer disabled, /explain always includes an
    (empty) signals list and a SHAP-only plain_explanation."""
    argus = app.extensions["argus"]
    original_detection = argus["detection"]
    argus["detection"] = {"enabled": False, "config": {"enabled": False}, "brand_index": None}
    try:
        fv = _fake_feature_vector("https://example.com", _LEGIT_RAW_FEATURES)
        with mock.patch(f"{MODULE}.extract_features", return_value=fv), mock.patch(
            f"{MODULE}.page_artifacts.fetch", return_value=_FAILED_FETCH_ARTIFACTS
        ):
            resp = client.post("/explain", json={"url": "https://example.com"})
        body = resp.get_json()
        assert body["signals"] == []
        assert isinstance(body["plain_explanation"], str)
    finally:
        argus["detection"] = original_detection
