"""``@require_api_key`` decorator (Phase 2, C3).

Mirrors ``src.api.auth.middleware.require_auth``'s shape (read a bearer
header, verify, attach to ``flask.g``, 401 on failure) but for the ``/v1/*``
developer API's key-based auth instead of end-user JWT auth. On success,
sets ``flask.g.api_key_id`` and ``flask.g.api_key_tier`` before calling the
view, and updates ``ApiKey.last_used_at``.
"""

from __future__ import annotations

from datetime import datetime, timezone
from functools import wraps

from flask import current_app, g, jsonify, request

from src.api.public.keys import extract_bearer_key, hash_api_key
from src.api.public.models import ApiKey


def require_api_key(view):
    """Require a valid, non-revoked ``Authorization: Bearer argus_<key>`` header.

    On success, sets ``flask.g.api_key_id`` (int) and ``flask.g.api_key_tier``
    (str) before calling the view. On failure, short-circuits with a 401
    JSON error — the view never runs.
    """

    @wraps(view)
    def wrapped(*args, **kwargs):
        raw_key = extract_bearer_key(request.headers.get("Authorization"))
        if not raw_key:
            return jsonify(error="missing or malformed Authorization header"), 401

        session_factory = current_app.extensions["argus_auth"]["session_factory"]
        session = session_factory()
        try:
            key_hash = hash_api_key(raw_key)
            api_key = session.query(ApiKey).filter_by(key_hash=key_hash).one_or_none()
            if api_key is None or api_key.revoked:
                return jsonify(error="invalid or revoked API key"), 401

            g.api_key_id = api_key.id
            g.api_key_tier = api_key.tier

            # Best-effort last-used tracking -- never blocks or fails the
            # request if this write has a problem.
            try:
                api_key.last_used_at = datetime.now(timezone.utc)
                session.commit()
            except Exception:  # noqa: BLE001
                session.rollback()
        finally:
            session.close()

        return view(*args, **kwargs)

    return wrapped
