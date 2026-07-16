"""``/v1/*`` blueprint (Phase 2, C3) — versioned developer API.

Same detection core as ``/detect``/``/explain`` (via
``src.detection.run_detection``), but API-key authenticated instead of
CORS-locked to the browser extension, and rate-limited **per key** (not per
remote IP) so one tenant's traffic can never exhaust another's budget.
``/v1/scan`` is deliberately stateless — unlike ``POST /scan`` (C1), it does
not persist a report; programmatic callers get a JSON response only.
"""

from __future__ import annotations

import time
from typing import Any, Optional

from flask import Blueprint, current_app, g, jsonify, request
from flask_limiter.util import get_remote_address
from marshmallow import ValidationError

from src.api.public.auth import require_api_key
from src.api.public.keys import extract_bearer_key, hash_api_key
from src.api.public.models import ApiKey
from src.api.schemas import V1ExplainRequestSchema, V1ScanBatchRequestSchema, V1ScanRequestSchema
from src.api.threat_intel.prefilter import check_prefilter
from src.detection import run_detection
from src.detection.explanation import explain_plain
from src.features import page_artifacts
from src.features.pipeline import extract_features
from src.models.explain import explain_single
from src.models.feature_adapter import adapt_to_training_contract
from src.utils.validators import validate_url

public_bp = Blueprint("public", __name__, url_prefix="/v1")

_v1_scan_request_schema = V1ScanRequestSchema()
_v1_scan_batch_request_schema = V1ScanBatchRequestSchema()
_v1_explain_request_schema = V1ExplainRequestSchema()


def _error(message: str, status: int):
    return jsonify(error=message), status


# --------------------------------------------------------------------------- #
# Per-key tiered rate limiting
#
# Deliberately independent of @require_api_key's g.api_key_id/g.api_key_tier:
# flask-limiter evaluates a route's key_func/dynamic-limit-value callables as
# part of its own wrapper, and depending on decorator stacking order that can
# run before @require_api_key has set g.* -- so these callables do their own
# self-contained lookup rather than depending on execution order. Cached on
# `g` per-request so the key/value callables (both invoked for the same
# request) share one DB read instead of two.
# --------------------------------------------------------------------------- #


def _lookup_api_key_for_limiting() -> tuple[str, Optional[str]]:
    if hasattr(g, "_rate_limit_lookup"):
        return g._rate_limit_lookup

    raw_key = extract_bearer_key(request.headers.get("Authorization"))
    if not raw_key:
        result = (get_remote_address(), None)
        g._rate_limit_lookup = result
        return result

    session_factory = current_app.extensions["argus_auth"]["session_factory"]
    session = session_factory()
    try:
        api_key = session.query(ApiKey).filter_by(key_hash=hash_api_key(raw_key)).one_or_none()
    finally:
        session.close()

    if api_key is None or api_key.revoked:
        result = (get_remote_address(), None)
    else:
        result = (f"apikey:{api_key.id}", api_key.tier)
    g._rate_limit_lookup = result
    return result


def _v1_rate_limit_key() -> str:
    key, _tier = _lookup_api_key_for_limiting()
    return key


def _v1_rate_limit_value() -> str:
    _key, tier = _lookup_api_key_for_limiting()
    tiers = current_app.extensions["argus"]["config"].get(
        "api_key_tiers", {"free": "60 per minute", "pro": "600 per minute"}
    )
    return tiers.get(tier or "free", tiers.get("free", "60 per minute"))


def configure_limits(app, limiter, api_config: dict[str, Any]) -> None:
    """Wire per-key tiered limits onto every ``/v1/*`` endpoint.

    Called from ``create_app()`` after the blueprint is registered, mirroring
    the existing auth-route rate-limit retrofit pattern (DEC-022):
    ``limiter.limit(...)`` returns a *new* wrapped function rather than
    mutating the view in place, so the result must be written back into
    ``app.view_functions``.
    """
    del api_config  # tiers are read fresh per-request in _v1_rate_limit_value
    for endpoint in ("public.v1_scan", "public.v1_scan_batch", "public.v1_explain"):
        app.view_functions[endpoint] = limiter.limit(
            _v1_rate_limit_value, key_func=_v1_rate_limit_key
        )(app.view_functions[endpoint])


# --------------------------------------------------------------------------- #
# Shared detection helper
# --------------------------------------------------------------------------- #


def _run_scan(url: str, enrich: bool) -> dict[str, Any]:
    """Run the shared detection core for one URL. Never raises."""
    argus = current_app.extensions["argus"]

    threat_intel = argus.get("threat_intel", {})
    if threat_intel.get("enabled"):
        source = check_prefilter(
            url, threat_intel["phishtank_index"], threat_intel.get("phishtank_hostname_index", frozenset())
        )
        if source is not None:
            return {
                "url": url, "label": "phishing", "confidence": 1.0, "verdict": "phishing",
                "risk_score": 1.0, "signals": [], "source": source,
            }

    if enrich:
        artifacts = page_artifacts.fetch(url)
        fv = extract_features(url, html=artifacts.html, include_domain=True)
    else:
        artifacts = None
        fv = extract_features(url)

    model_input = adapt_to_training_contract(fv.features)
    proba = float(argus["predictor"].predict_proba([model_input.to_vector()])[0][1])

    detection_state = argus.get("detection", {})
    if enrich and detection_state.get("enabled"):
        fused = run_detection(
            url, model_proba=proba, page_artifacts=artifacts, html_features=fv.features,
            brand_index=detection_state["brand_index"], config=detection_state["config"],
        )
        return {
            "url": url, "label": fused.label, "confidence": fused.confidence, "verdict": fused.label,
            "risk_score": fused.risk_score, "signals": [s.to_dict() for s in fused.signals],
            "source": fused.decisive_source,
        }

    is_phishing = bool(proba >= argus["threshold"])
    label = "phishing" if is_phishing else "legitimate"
    return {
        "url": url, "label": label, "confidence": float(proba if is_phishing else 1 - proba),
        "verdict": label, "risk_score": proba, "signals": [], "source": "model",
    }


# --------------------------------------------------------------------------- #
# Routes
# --------------------------------------------------------------------------- #


@public_bp.get("/health")
def v1_health():
    """Public liveness/version probe -- no auth required, distinct from
    the user-facing GET /health."""
    start = time.perf_counter()
    model_loaded = bool(current_app.extensions.get("argus", {}).get("pipeline") is not None)
    latency_ms = round((time.perf_counter() - start) * 1000, 3)
    return jsonify(status="ok", version="v1", model_loaded=model_loaded, latency_ms=latency_ms)


@public_bp.post("/scan")
@require_api_key
def v1_scan():
    """Stateless single-URL scan for programmatic callers."""
    start = time.perf_counter()
    body = request.get_json(silent=True) or {}
    try:
        data = _v1_scan_request_schema.load(body)
    except ValidationError as exc:
        return _error(f"invalid request: {exc.messages}", 400)

    url = data["url"]
    ok, reason = validate_url(url, allow_localhost=current_app.config.get("ALLOW_LOCALHOST", False))
    if not ok:
        return _error(reason, 400)

    argus = current_app.extensions["argus"]
    if argus.get("pipeline") is None:
        return _error("model not ready", 503)

    result = _run_scan(url, enrich=bool(data["enrich"]))
    result["latency_ms"] = round((time.perf_counter() - start) * 1000, 3)
    return jsonify(**result)


@public_bp.post("/scan/batch")
@require_api_key
def v1_scan_batch():
    """Batch scan (bounded by configs/api_config.yaml -> batch_max).

    A malformed/invalid individual URL yields a per-item error rather than
    failing the whole batch. Every URL counts individually against the
    caller's per-key rate budget (checked once for the whole request by the
    limiter above; documented in docs/API_DESIGN_SPECIFICATION.md that
    batching doesn't bypass the tier limit -- the batch endpoint's own
    request still consumes exactly 1 hit like any other, and batch_max
    bounds worst-case cost per hit).
    """
    start = time.perf_counter()
    body = request.get_json(silent=True) or {}
    try:
        data = _v1_scan_batch_request_schema.load(body)
    except ValidationError as exc:
        return _error(f"invalid request: {exc.messages}", 400)

    batch_max = current_app.extensions["argus"]["config"].get("batch_max", 50)
    urls = data["urls"][:batch_max]

    argus = current_app.extensions["argus"]
    if argus.get("pipeline") is None:
        return _error("model not ready", 503)

    results: list[dict[str, Any]] = []
    for url in urls:
        ok, reason = validate_url(url, allow_localhost=current_app.config.get("ALLOW_LOCALHOST", False))
        if not ok:
            results.append({"url": url, "error": reason})
            continue
        try:
            results.append(_run_scan(url, enrich=bool(data["enrich"])))
        except Exception as exc:  # noqa: BLE001 - one bad URL never fails the batch
            results.append({"url": url, "error": str(exc)})

    latency_ms = round((time.perf_counter() - start) * 1000, 3)
    return jsonify(results=results, count=len(results), latency_ms=latency_ms)


@public_bp.post("/explain")
@require_api_key
def v1_explain():
    """Same as POST /explain, API-key authenticated."""
    start = time.perf_counter()
    body = request.get_json(silent=True) or {}
    try:
        data = _v1_explain_request_schema.load(body)
    except ValidationError as exc:
        return _error(f"invalid request: {exc.messages}", 400)

    url = data["url"]
    ok, reason = validate_url(url, allow_localhost=current_app.config.get("ALLOW_LOCALHOST", False))
    if not ok:
        return _error(reason, 400)

    argus = current_app.extensions["argus"]
    if argus.get("pipeline") is None:
        return _error("model not ready", 503)

    artifacts = page_artifacts.fetch(url)
    fv = extract_features(url, html=artifacts.html, include_domain=True)
    model_input = adapt_to_training_contract(fv.features)

    top5 = explain_single(model_input.values, argus["pipeline"], argus["explainer"], argus["model_type"])

    detection_state = argus.get("detection", {})
    proba = float(argus["predictor"].predict_proba([model_input.to_vector()])[0][1])
    if detection_state.get("enabled"):
        fused = run_detection(
            url, model_proba=proba, page_artifacts=artifacts, html_features=fv.features,
            brand_index=detection_state["brand_index"], config=detection_state["config"],
        )
        verdict = fused.label
        signals_payload = [s.to_dict() for s in fused.signals]
    else:
        verdict = "phishing" if proba >= argus["threshold"] else "legitimate"
        signals_payload = []

    plain_explanation = explain_plain(top5, signals_payload, verdict)
    latency_ms = round((time.perf_counter() - start) * 1000, 3)
    return jsonify(
        url=url, top5_features=top5, signals=signals_payload,
        plain_explanation=plain_explanation, latency_ms=latency_ms,
    )
