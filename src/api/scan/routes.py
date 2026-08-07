"""``/scan`` blueprint (Phase 2, C1; Phase 4, F11/F13) — public URL scan +
shareable report, per-user history, and report export.

Unlike ``/detect``, this endpoint is meant to be used *without* the browser
extension: a stranger pastes a URL, gets a full enriched verdict, and can
share the resulting report via a permalink. Always enriches (full page
fetch + the whole Phase-1/2 detection fusion layer) since there's no
hostname-only privacy default to preserve here — the caller explicitly
submitted a URL to be scanned, unlike the extension's passive per-tab
check.

Persists a ``scans`` row so ``GET /scan/<scan_id>`` can serve the same
report later. No requester identity is ever stored on that row (§ privacy —
see ``models.py``) — that stays true for every caller, logged in or not.

If the caller *is* logged in (a valid ``Authorization: Bearer`` JWT — see
``@optional_auth``), an additional ``user_scans`` row is written, linked to
their account, so ``GET /scan/history`` can list it later (Phase 4, F11).
This is purely additive: an anonymous ``POST /scan`` behaves exactly as
before.
"""

from __future__ import annotations

import json
import secrets
import time
from concurrent.futures import TimeoutError as FuturesTimeoutError
from datetime import datetime, timedelta, timezone
from typing import Optional

from flask import Blueprint, current_app, g, jsonify, request
from marshmallow import ValidationError

from src.api.auth.middleware import optional_auth, require_auth
from src.api.auth.utils import as_aware_utc
from src.api.route_utils import (
    check_url,
    db_session,
    enrichment_timed_out,
    error,
    latency_ms,
    model_not_ready,
    risk_bands_config,
)
from src.api.scan.export import EXPORT_FORMATS, build_export
from src.api.scan.models import Scan, UserScan
from src.api.schemas import ScanRequestSchema
from src.api.verdict import extract, model_proba, prefilter_source, resolve_verdict
from src.detection.explanation import explain_plain
from src.detection.types import risk_band_for_score
from src.models.feature_adapter import adapt_to_training_contract

scan_bp = Blueprint("scan", __name__, url_prefix="/scan")

_scan_request_schema = ScanRequestSchema()

_HISTORY_DEFAULT_LIMIT = 50
_HISTORY_MAX_LIMIT = 200

# Opaque, non-sequential id -- prevents enumeration of other users' reports
# (a sequential integer PK would make /scan/1, /scan/2, ... trivially
# guessable). "s_" prefix mirrors the api_keys "argus_" convention: a
# recognizable, non-secret shape, not a security boundary on its own.
_SCAN_ID_PREFIX = "s_"
_SCAN_ID_BYTES = 9  # -> 12 url-safe base64 chars


def _generate_scan_id() -> str:
    return _SCAN_ID_PREFIX + secrets.token_urlsafe(_SCAN_ID_BYTES)


@scan_bp.post("")
@optional_auth
def create_scan():
    """Run a full enriched scan and persist a shareable report.

    Request:  ``{"url": "https://example.com"}``
    Response: ``201`` with ``{"scan_id", "url", "label", "confidence",
    "risk_score", "signals", "plain_explanation", "report_url",
    "expires_at", "latency_ms"}``.

    If a valid ``Authorization: Bearer`` JWT is presented (``@optional_auth``
    sets ``g.user_id``), also records this scan in the caller's own history
    (Phase 4, F11) — anonymous callers are unaffected.
    """
    start = time.perf_counter()
    body = request.get_json(silent=True) or {}
    try:
        data = _scan_request_schema.load(body)
    except ValidationError as exc:
        return error(f"invalid request: {exc.messages}", 400)

    url = data["url"]
    ok, reason = check_url(url)
    if not ok:
        return error(reason, 400)

    if (not_ready := model_not_ready()) is not None:
        return not_ready

    argus = current_app.extensions["argus"]
    source = prefilter_source(url, argus)
    if source is not None:
        label = "phishing"
        confidence = 1.0
        risk_score = 1.0
        signals_payload: list[dict] = []
        plain_explanation = "This URL matches a known-phishing entry in ARGUS's threat-intelligence feed."
    else:
        try:
            fv, artifacts = extract(url, enrich=True)
        except FuturesTimeoutError:
            # Bounded by enrichment_timeout_s (src.api.verdict.extract). This
            # endpoint persists a shareable report, so a lexical-only fallback
            # would store — and permalink — a verdict reached without ever
            # inspecting the page. 504 and store nothing.
            return enrichment_timed_out()
        verdict = resolve_verdict(
            url,
            proba=model_proba(adapt_to_training_contract(fv.features), argus),
            artifacts=artifacts,
            html_features=fv.features,
            argus=argus,
            use_detection=True,
        )
        label = verdict.label
        confidence = verdict.confidence
        risk_score = verdict.risk_score
        signals_payload = verdict.signals
        source = verdict.source
        plain_explanation = explain_plain(None, signals_payload, label)

    risk_band = risk_band_for_score(risk_score, risk_bands_config(argus))

    ttl_days = argus["config"].get("scan_store", {}).get("ttl_days", 7)
    now = datetime.now(timezone.utc)
    expires_at = now + timedelta(days=ttl_days)
    scan_id = _generate_scan_id()

    session = db_session()
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
        if g.user_id is not None:
            session.add(
                UserScan(
                    owner_user_id=g.user_id,
                    scan_id=scan_id,
                    url=url,
                    label=label,
                    confidence=confidence,
                    risk_score=risk_score,
                    risk_band=risk_band,
                    signals_json=json.dumps(signals_payload),
                    plain_explanation=plain_explanation,
                    source=source,
                    created_at=now,
                )
            )
        session.commit()
    finally:
        session.close()

    return (
        jsonify(
            scan_id=scan_id,
            url=url,
            label=label,
            confidence=confidence,
            risk_score=risk_score,
            risk_band=risk_band,
            signals=signals_payload,
            plain_explanation=plain_explanation,
            report_url=f"/app/scan.html?id={scan_id}",
            expires_at=expires_at.isoformat(),
            latency_ms=latency_ms(start),
        ),
        201,
    )


def _scan_report_dict(scan: Scan) -> dict:
    """Shared report shape for ``GET /scan/<id>`` and its export endpoint."""
    return {
        "scan_id": scan.scan_id,
        "url": scan.url,
        "label": scan.label,
        "confidence": scan.confidence,
        "risk_score": scan.risk_score,
        "risk_band": risk_band_for_score(scan.risk_score, risk_bands_config()),
        "signals": json.loads(scan.signals_json),
        "plain_explanation": scan.plain_explanation,
        "source": scan.source,
        "created_at": scan.created_at.isoformat(),
        "expires_at": scan.expires_at.isoformat(),
    }


def _user_scan_report_dict(scan: UserScan) -> dict:
    """Shared report shape for ``GET /scan/history`` rows and their export."""
    created_at = as_aware_utc(scan.created_at)
    return {
        "id": scan.id,
        "scan_id": scan.scan_id,
        "url": scan.url,
        "label": scan.label,
        "confidence": scan.confidence,
        "risk_score": scan.risk_score,
        "risk_band": scan.risk_band,
        "signals": json.loads(scan.signals_json),
        "plain_explanation": scan.plain_explanation,
        "source": scan.source,
        "created_at": created_at.isoformat() if created_at else None,
    }


def _fetch_live_scan(session, scan_id: str) -> Optional[Scan]:
    """Look up a still-unexpired ``Scan`` row, lazily purging it if expired."""
    scan = session.query(Scan).filter_by(scan_id=scan_id).one_or_none()
    if scan is None:
        return None

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
        return None
    return scan


@scan_bp.get("/history")
@require_auth
def scan_history():
    """List the caller's own scan history, newest first (Phase 4, F11).

    Query params: ``?limit=`` (default 50, max 200). Risk-band distribution
    and detection-source breakdown are deliberately not computed server-side
    — the dashboard derives them client-side from this same list, rather than
    adding a speculative aggregation endpoint nothing else needs yet.
    """
    start = time.perf_counter()
    try:
        limit = int(request.args.get("limit", _HISTORY_DEFAULT_LIMIT))
    except ValueError:
        return error("limit must be an integer", 400)
    limit = max(1, min(limit, _HISTORY_MAX_LIMIT))

    session = db_session()
    try:
        rows = (
            session.query(UserScan)
            .filter_by(owner_user_id=g.user_id)
            .order_by(UserScan.created_at.desc())
            .limit(limit)
            .all()
        )
        return jsonify(
            scans=[_user_scan_report_dict(row) for row in rows],
            latency_ms=latency_ms(start),
        )
    finally:
        session.close()


def _export_response(report: dict):
    fmt = request.args.get("format", "json")
    if fmt not in EXPORT_FORMATS:
        return error(f"format must be one of {EXPORT_FORMATS}", 400)
    content, mimetype, filename = build_export(report, fmt)
    response = current_app.response_class(content, mimetype=mimetype)
    response.headers["Content-Disposition"] = f'attachment; filename="{filename}"'
    return response


@scan_bp.get("/<scan_id>/export")
def export_scan(scan_id: str):
    """Export a shareable report (``?format=json|csv|pdf``, Phase 4, F13).

    Same permission model as ``GET /scan/<scan_id>`` — no auth required; if
    you have the link, you can export it.
    """
    session = db_session()
    try:
        scan = _fetch_live_scan(session, scan_id)
        if scan is None:
            return error("scan not found", 404)
        return _export_response(_scan_report_dict(scan))
    finally:
        session.close()


@scan_bp.get("/history/<int:item_id>/export")
@require_auth
def export_history_scan(item_id: int):
    """Export one of the caller's own history entries (Phase 4, F13)."""
    session = db_session()
    try:
        scan = (
            session.query(UserScan)
            .filter_by(id=item_id, owner_user_id=g.user_id)
            .one_or_none()
        )
        if scan is None:
            return error("scan not found", 404)
        return _export_response(_user_scan_report_dict(scan))
    finally:
        session.close()


@scan_bp.get("/<scan_id>")
def get_scan(scan_id: str):
    """Fetch a previously-created, still-unexpired shareable report."""
    start = time.perf_counter()
    session = db_session()
    try:
        scan = _fetch_live_scan(session, scan_id)
        if scan is None:
            return error("scan not found", 404)
        return jsonify(latency_ms=latency_ms(start), **_scan_report_dict(scan))
    finally:
        session.close()
