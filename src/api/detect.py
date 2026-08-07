"""``/detect`` and ``/explain`` blueprint (Phase 6, Task 6.1/6.2).

Every view here reads its model/explainer/config from
``current_app.extensions["argus"]`` — populated once at startup by
``create_app()`` (Task 6.1: "Load model + SHAP explainer ONCE at startup, not
per-request"). Enrichment (HTML fetch + WHOIS/DNS) always runs behind the
persistent thread pool with a hard timeout, and degrades gracefully to a
lexical-only prediction rather than blocking or crashing (Task 6.2).
"""

from __future__ import annotations

import logging
import time
from concurrent.futures import TimeoutError as FuturesTimeoutError

from flask import Blueprint, current_app, jsonify, request
from marshmallow import ValidationError

from src.api.route_utils import check_url, error, latency_ms, risk_bands_config
from src.api.schemas import DetectRequestSchema, ExplainRequestSchema
from src.api.verdict import model_proba, prefilter_source, resolve_verdict
from src.detection.explanation import explain_plain
from src.detection.types import risk_band_for_score
from src.features import page_artifacts
from src.features.pipeline import extract_features
from src.models.explain import explain_single
from src.models.feature_adapter import adapt_to_training_contract
from src.serving.cache import cache_key

logger = logging.getLogger(__name__)

detect_bp = Blueprint("detect", __name__)

# Overall wall-clock bound on the enrichment path (HTML fetch + WHOIS/DNS),
# enforced by the persistent thread pool independent of the internal
# per-fetch timeouts inside src.features.pipeline/domain_intel. This is
# defense-in-depth: even if an internal timeout misbehaves, the request
# thread is guaranteed to get control back within this bound.
_ENRICHMENT_TIMEOUT_S: float = 15.0

_detect_request_schema = DetectRequestSchema()
_explain_request_schema = ExplainRequestSchema()


def _run_enriched_extraction(url: str):
    """Fetch the page once and extract features from the shared HTML (P1.0).

    Reuses the single fetched HTML for both the live-extractor's HTML tier
    and the Phase-1 detection signals (favicon match, brand mismatch) —
    avoiding a second outbound fetch of the same untrusted page. See
    ``src/features/page_artifacts.py`` and
    ``docs/ARCHITECTURE_CHANGE_PLAN.md`` §3.

    Returns:
        A tuple ``(FeatureVector, PageArtifacts)``.
    """
    artifacts = page_artifacts.fetch(url)
    fv = extract_features(url, html=artifacts.html, include_domain=True)
    return fv, artifacts


def _extract_with_bound(url: str, enrich: bool):
    """Run feature extraction, bounded by the persistent thread pool's timeout.

    Args:
        url: The (already-validated) URL to extract features from.
        enrich: Whether to run the HTML/domain-intel tiers (slow path).

    Returns:
        A tuple ``(FeatureVector, Optional[PageArtifacts])`` —
        ``PageArtifacts`` is ``None`` on the fast (lexical-only) path, where
        no page was fetched. Falls back to a lexical-only (fast,
        synchronous, no network) extraction if enrichment times out or
        raises — enrichment failures never surface as an error to the
        caller.
    """
    if not enrich:
        return extract_features(url), None

    executor = current_app.extensions["argus"]["executor"]
    future = executor.submit(_run_enriched_extraction, url)
    try:
        return future.result(timeout=_ENRICHMENT_TIMEOUT_S)
    except FuturesTimeoutError:
        logger.warning("Enrichment timed out for %r; falling back to lexical-only", url)
        return extract_features(url), None
    except Exception as exc:  # noqa: BLE001 - enrichment must never crash the request
        logger.warning("Enrichment failed for %r: %s; falling back to lexical-only", url, exc)
        return extract_features(url), None


@detect_bp.post("/detect")
def detect():
    """Predict phishing/legitimate for a URL.

    Request:  ``{"url": "https://example.com", "enrich": false}``
    Response: ``{"url", "label", "confidence", "verdict", "source", "latency_ms"}``,
        plus ``risk_score`` and ``signals`` (Phase 1, DEC-A) when
        ``enrich: true`` and the detection fusion layer is enabled.

    Before running the ML model, checks the threat-intel pre-filter
    (DEC-010 — currently a local PhishTank snapshot). A match short-circuits
    straight to ``{"label": "phishing", "source": "phishtank"}`` with no
    feature extraction or model inference — deliberately skips the HTML
    enrichment fetch too, since a known-bad match needs no further
    confirmation and there is no reason to fetch a known-malicious page.

    When ``enrich: true``, the fetched page is additionally run through the
    Phase-1 detection fusion layer (typosquat/homograph, favicon match,
    brand-vs-domain mismatch — see ``src/detection/``), which can override
    or adjust the model's own verdict; ``source`` reflects what actually
    decided the label (``"model"``, ``"fusion"``, or a specific signal name
    for a hard override). The default ``enrich: false`` fast path is
    completely unaffected by the fusion layer.
    """
    start = time.perf_counter()
    body = request.get_json(silent=True) or {}
    try:
        data = _detect_request_schema.load(body)
    except ValidationError as exc:
        return error(f"invalid request: {exc.messages}", 400)

    url = data["url"]
    ok, reason = check_url(url)
    if not ok:
        return error(reason, 400)

    argus = current_app.extensions["argus"]

    # Always checked BEFORE any cache lookup below -- a URL already
    # known-bad short-circuits regardless of what might be cached for it, so
    # a newly-blocklisted URL is never masked by a stale cached
    # "legitimate" verdict (Phase 2, G1).
    source = prefilter_source(url, argus)
    if source is not None:
        return jsonify(
            url=url,
            label="phishing",
            confidence=1.0,
            verdict="phishing",
            source=source,
            latency_ms=latency_ms(start),
        )

    cache = argus.get("cache")
    key = cache_key(url, data["enrich"]) if cache is not None else None
    cached = cache.get(key) if cache is not None else None
    if cached is not None:
        return jsonify(url=url, latency_ms=latency_ms(start), **cached)

    enrich = data["enrich"]
    fv, artifacts = _extract_with_bound(url, enrich)
    model_input = adapt_to_training_contract(fv.features)

    # The detection fusion layer (Phase 1, DEC-A) only runs on the enriched
    # path — page-dependent signals (favicon match, brand mismatch) need the
    # fetched page, and the default hostname-only fast path must stay
    # byte-for-byte unchanged from before Phase 1. That fast path also
    # deliberately omits risk_score/risk_band/signals from the response
    # entirely, rather than reporting them as model-only values.
    verdict = resolve_verdict(
        url,
        proba=model_proba(model_input, argus),
        artifacts=artifacts,
        html_features=fv.features,
        argus=argus,
        use_detection=bool(enrich),
    )
    response = {
        "url": url,
        "latency_ms": None,
        "label": verdict.label,
        "confidence": verdict.confidence,
        "verdict": verdict.label,
        "source": verdict.source,
    }
    if verdict.fused:
        response["risk_score"] = verdict.risk_score
        response["risk_band"] = verdict.risk_band(argus)
        response["signals"] = verdict.signals

    if cache is not None:
        cacheable = {k: v for k, v in response.items() if k not in ("url", "latency_ms")}
        cache.set(key, cacheable)

    response["latency_ms"] = latency_ms(start)
    return jsonify(**response)


@detect_bp.post("/explain")
def explain():
    """Return the top-5 SHAP feature attributions for a URL's prediction.

    Request:  ``{"url": "https://example.com"}``
    Response: ``{"url", "top5_features", "latency_ms"}``
    """
    start = time.perf_counter()
    body = request.get_json(silent=True) or {}
    try:
        data = _explain_request_schema.load(body)
    except ValidationError as exc:
        return error(f"invalid request: {exc.messages}", 400)

    url = data["url"]
    ok, reason = check_url(url)
    if not ok:
        return error(reason, 400)

    argus = current_app.extensions["argus"]
    # /explain always enriches — a lexical-only explanation would mostly cite
    # features the model treats as "missing input, defaulted to phishing"
    # (see feature_adapter's conservative-default policy), which is not a
    # meaningful "why" answer for the user.
    fv, artifacts = _extract_with_bound(url, enrich=True)
    model_input = adapt_to_training_contract(fv.features)

    top5 = explain_single(
        model_input.values, argus["pipeline"], argus["explainer"], argus["model_type"]
    )

    # Phase 1 (B2): always compute a fused verdict + plain-language sentence
    # for /explain, even when the fusion layer is disabled — falls back to
    # a SHAP-only sentence with no signals in that case.
    verdict = resolve_verdict(
        url,
        proba=model_proba(model_input, argus),
        artifacts=artifacts,
        html_features=fv.features,
        argus=argus,
        use_detection=True,
    )

    return jsonify(
        url=url,
        top5_features=top5,
        signals=verdict.signals,
        risk_score=verdict.risk_score,
        risk_band=risk_band_for_score(verdict.risk_score, risk_bands_config(argus)),
        plain_explanation=explain_plain(top5, verdict.signals, verdict.label),
        latency_ms=latency_ms(start),
    )
