"""Async scan job orchestration (F19).

``execute_job`` runs on ``app.extensions["argus"]["job_executor"]`` -- a
dedicated ``ThreadPoolExecutor`` (see ``src.api.app``), separate from the
enrichment pool used by the synchronous ``/v1/scan`` path, so a burst of
async submissions can never starve (or be starved by) enrichment work
sharing one process.

Runs outside any Flask request context: there is no ``g``/``request`` to
read, so everything this needs (URL, ``enrich`` flag, owning API key id) is
looked up from the ``ScanJob`` row itself, and ``app.app_context()`` is
pushed explicitly so ``current_app`` (read by the shared
:func:`src.api.verdict.run_scan` core) resolves correctly.
"""

from __future__ import annotations

import json
import logging
import secrets
from datetime import datetime, timezone
from typing import Any

from flask import Flask

from src.api.public.models import ApiKey, ScanJob
from src.api.public.webhooks import deliver_webhook
from src.api.verdict import run_scan

logger = logging.getLogger(__name__)

_JOB_ID_PREFIX = "job_"
_JOB_ID_RANDOM_BYTES = 16


def generate_job_id() -> str:
    """Generate a new opaque, non-sequential job id (same shape as API keys'
    ``key_prefix``-style opacity: not enumerable, no information leaked)."""
    return _JOB_ID_PREFIX + secrets.token_urlsafe(_JOB_ID_RANDOM_BYTES)


def execute_job(app: Flask, job_id: str) -> None:
    """Run one scan job to completion and, if requested, deliver a webhook.

    Submitted to the job executor at request time via
    ``executor.submit(execute_job, current_app._get_current_object(), job_id)``
    -- the standard Flask idiom for handing the real app object into a
    background thread that outlives the request.

    A ``ThreadPoolExecutor`` worker silently swallows any exception that
    escapes its target callable unless something calls ``.result()`` on the
    returned future (which nothing here does) -- so every step that can
    raise is wrapped, and a failure is persisted as ``status="failed"``
    rather than leaving the job stuck at ``"running"`` forever.

    DB access happens in short, separate sessions around the one slow step
    (``run_scan`` -- a real network fetch/detection run) rather than one
    session held open for the whole function, so a slow scan on one job
    never blocks another thread's DB access for longer than necessary (see
    ``src.api.db.create_session_factory``, which transparently serializes
    ``Session``s against a ``sqlite:///:memory:`` test engine).
    """
    with app.app_context():
        session_factory = app.extensions["argus_auth"]["session_factory"]

        session = session_factory()
        try:
            job = session.query(ScanJob).filter_by(job_id=job_id).one_or_none()
            if job is None:
                logger.error("execute_job called for unknown job_id=%s", job_id)
                return
            job.status = "running"
            session.commit()
            url, enrich, webhook_url = job.url, job.enrich, job.webhook_url
        finally:
            session.close()

        try:
            result = run_scan(url, enrich=enrich)
            status, result_json, error = "completed", json.dumps(result), None
        except Exception as exc:  # noqa: BLE001 - must never leave a job stuck "running"
            logger.error("Async scan job %s failed: %s", job_id, exc)
            status, result_json, error = "failed", None, str(exc)

        session = session_factory()
        try:
            job = session.query(ScanJob).filter_by(job_id=job_id).one()
            job.status = status
            job.result_json = result_json
            job.error = error
            job.completed_at = datetime.now(timezone.utc)
            session.commit()
        finally:
            session.close()

        if webhook_url:
            _run_webhook_delivery(app, session_factory, job_id)


def _run_webhook_delivery(app: Flask, session_factory, job_id: str) -> None:
    """Best-effort webhook delivery -- never affects the job's own status/result.

    The actual HTTP call (``deliver_webhook``, up to a few seconds of
    network I/O + backoff sleeps) deliberately happens between two short
    DB sessions, not inside one held open the whole time -- same reasoning
    as ``execute_job`` splitting its own DB access around ``_run_scan``.
    """
    try:
        session = session_factory()
        try:
            job = session.query(ScanJob).filter_by(job_id=job_id).one()
            owner_key = session.query(ApiKey).filter_by(id=job.owner_api_key_id).one_or_none()
            if owner_key is None or not owner_key.webhook_secret:
                logger.error(
                    "Cannot deliver webhook for job %s: owning key or its secret is missing.", job_id
                )
                job.webhook_status = "failed"
                session.commit()
                return

            payload: dict[str, Any] = {
                "job_id": job.job_id,
                "status": job.status,
                "url": job.url,
                "completed_at": job.completed_at.isoformat() if job.completed_at else None,
            }
            if job.status == "completed":
                payload["result"] = json.loads(job.result_json)
            else:
                payload["error"] = job.error
            webhook_url, secret = job.webhook_url, owner_key.webhook_secret
        finally:
            session.close()

        webhook_config = app.extensions["argus"]["config"].get("webhook_delivery", {})
        status, attempts = deliver_webhook(webhook_url, payload, secret, webhook_config)

        session = session_factory()
        try:
            job = session.query(ScanJob).filter_by(job_id=job_id).one()
            job.webhook_status = status
            job.webhook_attempts = attempts
            session.commit()
        finally:
            session.close()
    except Exception as exc:  # noqa: BLE001 - webhook delivery must never crash the worker thread
        logger.error("Webhook delivery bookkeeping failed for job %s: %s", job_id, exc)
        session = session_factory()
        try:
            job = session.query(ScanJob).filter_by(job_id=job_id).one_or_none()
            if job is not None:
                job.webhook_status = "failed"
                session.commit()
        finally:
            session.close()
