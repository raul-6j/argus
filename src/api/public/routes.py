"""``/v1/*`` blueprint (Phase 2, C3) — versioned developer API.

Same detection core as ``/detect``/``/explain`` (via
``src.detection.run_detection``), but API-key authenticated instead of
CORS-locked to the browser extension, and rate-limited **per key** (not per
remote IP) so one tenant's traffic can never exhaust another's budget.
``/v1/scan`` is deliberately stateless — unlike ``POST /scan`` (C1), it does
not persist a report; programmatic callers get a JSON response only.
"""

from __future__ import annotations

import json
import time
from concurrent.futures import TimeoutError as FuturesTimeoutError
from typing import Any, Optional

from flask import Blueprint, current_app, g, jsonify, request
from flask_limiter.util import get_remote_address
from marshmallow import ValidationError

from src.api.public.auth import require_api_key
from src.api.public.jobs import execute_job, generate_job_id
from src.api.public.keys import extract_bearer_key, hash_api_key
from src.api.public.models import ApiKey, ScanJob
from src.api.route_utils import (
    check_url,
    db_session,
    enrichment_timed_out,
    error,
    latency_ms,
    model_not_ready,
    risk_bands_config,
)
from src.api.schemas import (
    V1ExplainRequestSchema,
    V1ScanAsyncRequestSchema,
    V1ScanBatchRequestSchema,
    V1ScanRequestSchema,
)
from src.api.verdict import extract, model_proba, resolve_verdict, run_scan
from src.detection.explanation import explain_plain
from src.detection.types import risk_band_for_score
from src.models.explain import explain_single
from src.models.feature_adapter import adapt_to_training_contract
from src.utils.ssrf import is_safe_fetch_url

public_bp = Blueprint("public", __name__, url_prefix="/v1")

_v1_scan_request_schema = V1ScanRequestSchema()
_v1_scan_batch_request_schema = V1ScanBatchRequestSchema()
_v1_explain_request_schema = V1ExplainRequestSchema()
_v1_scan_async_request_schema = V1ScanAsyncRequestSchema()


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
    for endpoint in (
        "public.v1_scan",
        "public.v1_scan_batch",
        "public.v1_explain",
        "public.v1_scan_async",
        "public.v1_scan_async_status",
    ):
        app.view_functions[endpoint] = limiter.limit(
            _v1_rate_limit_value, key_func=_v1_rate_limit_key
        )(app.view_functions[endpoint])


# --------------------------------------------------------------------------- #
# Routes
#
# The scan pipeline itself (pre-filter -> fetch -> extract -> fuse) lives in
# src.api.verdict, shared with /detect, /explain and POST /scan.
# --------------------------------------------------------------------------- #


@public_bp.get("/health")
def v1_health():
    """Public liveness/version probe -- no auth required, distinct from
    the user-facing GET /health."""
    start = time.perf_counter()
    model_loaded = bool(current_app.extensions.get("argus", {}).get("pipeline") is not None)
    return jsonify(
        status="ok", version="v1", model_loaded=model_loaded, latency_ms=latency_ms(start)
    )


@public_bp.post("/scan")
@require_api_key
def v1_scan():
    """Stateless single-URL scan for programmatic callers."""
    start = time.perf_counter()
    body = request.get_json(silent=True) or {}
    try:
        data = _v1_scan_request_schema.load(body)
    except ValidationError as exc:
        return error(f"invalid request: {exc.messages}", 400)

    url = data["url"]
    ok, reason = check_url(url)
    if not ok:
        return error(reason, 400)

    if (not_ready := model_not_ready()) is not None:
        return not_ready

    try:
        result = run_scan(url, enrich=bool(data["enrich"]))
    except FuturesTimeoutError:
        # The enrichment wall-clock bound (src.api.verdict.extract) fired. 504
        # rather than a lexical-only verdict: a programmatic caller acting on
        # this result deserves to know the page was never actually inspected.
        return enrichment_timed_out()
    result["latency_ms"] = latency_ms(start)
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
        return error(f"invalid request: {exc.messages}", 400)

    batch_max = current_app.extensions["argus"]["config"].get("batch_max", 50)
    urls = data["urls"][:batch_max]

    if (not_ready := model_not_ready()) is not None:
        return not_ready

    enrich = bool(data["enrich"])
    results: list[dict[str, Any]] = []
    for url in urls:
        ok, reason = check_url(url)
        if not ok:
            results.append({"url": url, "error": reason})
            continue
        try:
            results.append(run_scan(url, enrich=enrich))
        except Exception as exc:  # noqa: BLE001 - one bad URL never fails the batch
            results.append({"url": url, "error": str(exc)})

    return jsonify(results=results, count=len(results), latency_ms=latency_ms(start))


@public_bp.post("/explain")
@require_api_key
def v1_explain():
    """Same as POST /explain, API-key authenticated."""
    start = time.perf_counter()
    body = request.get_json(silent=True) or {}
    try:
        data = _v1_explain_request_schema.load(body)
    except ValidationError as exc:
        return error(f"invalid request: {exc.messages}", 400)

    url = data["url"]
    ok, reason = check_url(url)
    if not ok:
        return error(reason, 400)

    if (not_ready := model_not_ready()) is not None:
        return not_ready

    argus = current_app.extensions["argus"]
    try:
        fv, artifacts = extract(url, enrich=True)
    except FuturesTimeoutError:
        return enrichment_timed_out()
    model_input = adapt_to_training_contract(fv.features)

    top5 = explain_single(model_input.values, argus["pipeline"], argus["explainer"], argus["model_type"])

    verdict = resolve_verdict(
        url,
        proba=model_proba(model_input, argus),
        artifacts=artifacts,
        html_features=fv.features,
        argus=argus,
        # /explain always fuses when the layer is enabled, regardless of any
        # per-request enrich flag -- a SHAP-only "why" would cite features
        # the adapter defaulted, which isn't a meaningful answer.
        use_detection=True,
    )
    return jsonify(
        url=url, top5_features=top5, signals=verdict.signals,
        risk_score=verdict.risk_score,
        risk_band=risk_band_for_score(verdict.risk_score, risk_bands_config(argus)),
        plain_explanation=explain_plain(top5, verdict.signals, verdict.label),
        latency_ms=latency_ms(start),
    )


# --------------------------------------------------------------------------- #
# Async scan jobs + webhooks (F19)
# --------------------------------------------------------------------------- #


@public_bp.post("/scan/async")
@require_api_key
def v1_scan_async():
    """Submit a scan job to run in the background; returns a ``job_id``
    immediately instead of blocking for the full detection pipeline.

    Poll ``GET /v1/scan/async/<job_id>`` for the result, or pass
    ``webhook_url`` to also get a signed POST callback on completion.
    """
    start = time.perf_counter()
    body = request.get_json(silent=True) or {}
    try:
        data = _v1_scan_async_request_schema.load(body)
    except ValidationError as exc:
        return error(f"invalid request: {exc.messages}", 400)

    url = data["url"]
    ok, reason = check_url(url)
    if not ok:
        return error(reason, 400)

    webhook_url = data["webhook_url"]
    if webhook_url and not is_safe_fetch_url(webhook_url):
        return error("webhook_url must be a public http(s) URL", 400)

    if (not_ready := model_not_ready()) is not None:
        return not_ready

    session = db_session()
    try:
        job = ScanJob(
            job_id=generate_job_id(),
            owner_api_key_id=g.api_key_id,
            url=url,
            enrich=bool(data["enrich"]),
            status="queued",
            webhook_url=webhook_url,
            webhook_status="pending" if webhook_url else None,
        )
        session.add(job)
        session.commit()
        job_id = job.job_id
    finally:
        session.close()

    argus = current_app.extensions["argus"]
    argus["job_executor"].submit(execute_job, current_app._get_current_object(), job_id)

    return jsonify(job_id=job_id, status="queued", latency_ms=latency_ms(start)), 202


@public_bp.get("/scan/async/<job_id>")
@require_api_key
def v1_scan_async_status(job_id: str):
    """Poll an async scan job's status/result.

    404 (not 403) for a job that exists but belongs to another key --
    matches ``revoke_api_key``'s established "don't confirm existence to a
    non-owner" convention.
    """
    start = time.perf_counter()
    session = db_session()
    try:
        job = (
            session.query(ScanJob)
            .filter_by(job_id=job_id, owner_api_key_id=g.api_key_id)
            .one_or_none()
        )
        if job is None:
            return error("job not found", 404)

        payload: dict[str, Any] = {
            "job_id": job.job_id,
            "status": job.status,
            "url": job.url,
            "webhook_status": job.webhook_status,
            "webhook_attempts": job.webhook_attempts,
            "created_at": job.created_at.isoformat(),
            "completed_at": job.completed_at.isoformat() if job.completed_at else None,
        }
        if job.status == "completed":
            payload["result"] = json.loads(job.result_json)
        elif job.status == "failed":
            payload["error"] = job.error
    finally:
        session.close()

    payload["latency_ms"] = latency_ms(start)
    return jsonify(**payload)
