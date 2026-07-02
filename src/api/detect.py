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

from src.api.schemas import DetectRequestSchema, ExplainRequestSchema
from src.features.pipeline import extract_features
from src.models.explain import explain_single
from src.models.feature_adapter import adapt_to_training_contract
from src.utils.validators import validate_url

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


def _error(message: str, status: int):
    return jsonify(error=message), status


def _extract_with_bound(url: str, enrich: bool):
    """Run feature extraction, bounded by the persistent thread pool's timeout.

    Args:
        url: The (already-validated) URL to extract features from.
        enrich: Whether to run the HTML/domain-intel tiers (slow path).

    Returns:
        A :class:`~src.features.pipeline.FeatureVector`. Falls back to a
        lexical-only (fast, synchronous, no network) extraction if enrichment
        times out or raises — enrichment failures never surface as an error
        to the caller.
    """
    if not enrich:
        return extract_features(url)

    executor = current_app.extensions["argus"]["executor"]
    future = executor.submit(extract_features, url, fetch_html=True, include_domain=True)
    try:
        return future.result(timeout=_ENRICHMENT_TIMEOUT_S)
    except FuturesTimeoutError:
        logger.warning("Enrichment timed out for %r; falling back to lexical-only", url)
        return extract_features(url)
    except Exception as exc:  # noqa: BLE001 - enrichment must never crash the request
        logger.warning("Enrichment failed for %r: %s; falling back to lexical-only", url, exc)
        return extract_features(url)


@detect_bp.post("/detect")
def detect():
    """Predict phishing/legitimate for a URL.

    Request:  ``{"url": "https://example.com", "enrich": false}``
    Response: ``{"url", "label", "confidence", "verdict", "source", "latency_ms"}``
    """
    start = time.perf_counter()
    body = request.get_json(silent=True) or {}
    try:
        data = _detect_request_schema.load(body)
    except ValidationError as exc:
        return _error(f"invalid request: {exc.messages}", 400)

    url = data["url"]
    ok, reason = validate_url(url, allow_localhost=current_app.config.get("ALLOW_LOCALHOST", False))
    if not ok:
        return _error(reason, 400)

    argus = current_app.extensions["argus"]
    fv = _extract_with_bound(url, data["enrich"])
    model_input = adapt_to_training_contract(fv.features)
    proba = argus["pipeline"].predict_proba([model_input.to_vector()])[0][1]
    is_phishing = bool(proba >= argus["threshold"])
    label = "phishing" if is_phishing else "legitimate"

    latency_ms = round((time.perf_counter() - start) * 1000, 3)
    return jsonify(
        url=url,
        label=label,
        confidence=float(proba if is_phishing else 1 - proba),
        verdict=label,
        source="model",
        latency_ms=latency_ms,
    )


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
        return _error(f"invalid request: {exc.messages}", 400)

    url = data["url"]
    ok, reason = validate_url(url, allow_localhost=current_app.config.get("ALLOW_LOCALHOST", False))
    if not ok:
        return _error(reason, 400)

    argus = current_app.extensions["argus"]
    # /explain always enriches — a lexical-only explanation would mostly cite
    # features the model treats as "missing input, defaulted to phishing"
    # (see feature_adapter's conservative-default policy), which is not a
    # meaningful "why" answer for the user.
    fv = _extract_with_bound(url, enrich=True)
    model_input = adapt_to_training_contract(fv.features)

    top5 = explain_single(
        model_input.values, argus["pipeline"], argus["explainer"], argus["model_type"]
    )

    latency_ms = round((time.perf_counter() - start) * 1000, 3)
    return jsonify(url=url, top5_features=top5, latency_ms=latency_ms)
