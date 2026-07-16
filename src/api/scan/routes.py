"""``/scan`` blueprint (Phase 2, C1) — public URL scan + shareable report.

Unlike ``/detect``, this endpoint is meant to be used *without* the browser
extension: a stranger pastes a URL, gets a full enriched verdict, and can
share the resulting report via a permalink. Always enriches (full page
fetch + the whole Phase-1/2 detection fusion layer) since there's no
hostname-only privacy default to preserve here — the caller explicitly
submitted a URL to be scanned, unlike the extension's passive per-tab
check.

Persists a ``scans`` row so ``GET /scan/<scan_id>`` can serve the same
report later. No requester identity is ever stored (§ privacy — see
``models.py``).
"""

from __future__ import annotations

import json
import secrets
import time
from datetime import datetime, timedelta, timezone

from flask import Blueprint, current_app, jsonify, request
from marshmallow import ValidationError

from src.api.schemas import ScanRequestSchema
from src.api.scan.models import Scan
from src.api.threat_intel.prefilter import check_prefilter
from src.detection import run_detection
from src.detection.explanation import explain_plain
from src.features import page_artifacts
from src.features.pipeline import extract_features
from src.models.feature_adapter import adapt_to_training_contract
from src.utils.validators import validate_url

scan_bp = Blueprint("scan", __name__, url_prefix="/scan")

_scan_request_schema = ScanRequestSchema()

# Opaque, non-sequential id -- prevents enumeration of other users' reports
# (a sequential integer PK would make /scan/1, /scan/2, ... trivially
# guessable). "s_" prefix mirrors the api_keys "argus_" convention: a
# recognizable, non-secret shape, not a security boundary on its own.
_SCAN_ID_PREFIX = "s_"
_SCAN_ID_BYTES = 9  # -> 12 url-safe base64 chars


def _generate_scan_id() -> str:
    return _SCAN_ID_PREFIX + secrets.token_urlsafe(_SCAN_ID_BYTES)


def _session():
    return current_app.extensions["argus_auth"]["session_factory"]()


def _error(message: str, status: int):
    return jsonify(error=message), status


@scan_bp.post("")
def create_scan():
    """Run a full enriched scan and persist a shareable report.

    Request:  ``{"url": "https://example.com"}``
    Response: ``201`` with ``{"scan_id", "url", "label", "confidence",
    "risk_score", "signals", "plain_explanation", "report_url",
    "expires_at", "latency_ms"}``.
    """
    start = time.perf_counter()
    body = request.get_json(silent=True) or {}
    try:
        data = _scan_request_schema.load(body)
    except ValidationError as exc:
        return _error(f"invalid request: {exc.messages}", 400)

    url = data["url"]
    ok, reason = validate_url(url, allow_localhost=current_app.config.get("ALLOW_LOCALHOST", False))
    if not ok:
        return _error(reason, 400)

    argus = current_app.extensions["argus"]
    if argus.get("pipeline") is None:
        return _error("model not ready", 503)

    threat_intel = argus.get("threat_intel", {})
    prefilter_source = None
    if threat_intel.get("enabled"):
        prefilter_source = check_prefilter(
            url,
            threat_intel["phishtank_index"],
            threat_intel.get("phishtank_hostname_index", frozenset()),
        )

    if prefilter_source is not None:
        label = "phishing"
        confidence = 1.0
        risk_score = 1.0
        signals_payload: list[dict] = []
        source = prefilter_source
        plain_explanation = "This URL matches a known-phishing entry in ARGUS's threat-intelligence feed."
    else:
        artifacts = page_artifacts.fetch(url)
        fv = extract_features(url, html=artifacts.html, include_domain=True)
        model_input = adapt_to_training_contract(fv.features)
        proba = float(argus["predictor"].predict_proba([model_input.to_vector()])[0][1])

        detection_state = argus.get("detection", {})
        if detection_state.get("enabled"):
            fused = run_detection(
                url,
                model_proba=proba,
                page_artifacts=artifacts if artifacts.ok else None,
                html_features=fv.features,
                brand_index=detection_state["brand_index"],
                config=detection_state["config"],
            )
            label = fused.label
            confidence = fused.confidence
            risk_score = fused.risk_score
            signals_payload = [s.to_dict() for s in fused.signals]
            source = fused.decisive_source
        else:
            is_phishing = bool(proba >= argus["threshold"])
            label = "phishing" if is_phishing else "legitimate"
            confidence = float(proba if is_phishing else 1 - proba)
            risk_score = proba
            signals_payload = []
            source = "model"

        plain_explanation = explain_plain(None, signals_payload, label)

    ttl_days = argus["config"].get("scan_store", {}).get("ttl_days", 7)
    now = datetime.now(timezone.utc)
    expires_at = now + timedelta(days=ttl_days)
    scan_id = _generate_scan_id()

    session = _session()
    try:
        scan = Scan(
            scan_id=scan_id,
            url=url,
            label=label,
            confidence=confidence,
            risk_score=risk_score,
            signals_json=json.dumps(signals_payload),
            plain_explanation=plain_explanation,
            source=source,
            created_at=now,
            expires_at=expires_at,
        )
        session.add(scan)
        session.commit()
    finally:
        session.close()

    latency_ms = round((time.perf_counter() - start) * 1000, 3)
    return (
        jsonify(
            scan_id=scan_id,
            url=url,
            label=label,
            confidence=confidence,
            risk_score=risk_score,
            signals=signals_payload,
            plain_explanation=plain_explanation,
            report_url=f"/app/scan.html?id={scan_id}",
            expires_at=expires_at.isoformat(),
            latency_ms=latency_ms,
        ),
        201,
    )


@scan_bp.get("/<scan_id>")
def get_scan(scan_id: str):
    """Fetch a previously-created, still-unexpired shareable report."""
    start = time.perf_counter()
    session = _session()
    try:
        scan = session.query(Scan).filter_by(scan_id=scan_id).one_or_none()
        if scan is None:
            return _error("scan not found", 404)

        now = datetime.now(timezone.utc)
        expires_at = scan.expires_at
        if expires_at.tzinfo is None:
            expires_at = expires_at.replace(tzinfo=timezone.utc)
        if expires_at < now:
            # Lazy purge: an expired report is deleted on the read that
            # discovers it, rather than requiring a separate cron job to
            # ever run for correctness (a scheduled purge is still
            # recommended for storage hygiene, but isn't load-bearing).
            session.delete(scan)
            session.commit()
            return _error("scan not found", 404)

        latency_ms = round((time.perf_counter() - start) * 1000, 3)
        return jsonify(
            scan_id=scan.scan_id,
            url=scan.url,
            label=scan.label,
            confidence=scan.confidence,
            risk_score=scan.risk_score,
            signals=json.loads(scan.signals_json),
            plain_explanation=scan.plain_explanation,
            source=scan.source,
            created_at=scan.created_at.isoformat(),
            expires_at=scan.expires_at.isoformat(),
            latency_ms=latency_ms,
        )
    finally:
        session.close()
