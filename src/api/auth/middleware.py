"""``@require_auth`` / ``@optional_auth`` decorators (Phase 8, Task 8.1; Phase 4, F11).

Reads ``Authorization: Bearer <jwt>`` from the request, decodes it with the
app's SECRET_KEY, and attaches the authenticated user ID to ``flask.g``.
Every view wrapped with ``@require_auth`` can read ``g.user_id``.

``@optional_auth`` is the same decode logic used by an endpoint that must
stay usable by anonymous callers (e.g. the public webapp's ``POST /scan``) but
opportunistically attaches identity when a valid token is presented, instead
of rejecting the request outright.
"""

from __future__ import annotations

from functools import wraps

import jwt
from flask import current_app, g, jsonify, request

from src.api.auth.utils import decode_access_token


def require_auth(view):
    """Require a valid ``Authorization: Bearer <access_token>`` header.

    On success, sets ``flask.g.user_id`` (int) before calling the view.
    On failure, short-circuits with a 401 JSON error — the view never runs.
    """

    @wraps(view)
    def wrapped(*args, **kwargs):
        auth_header = request.headers.get("Authorization", "")
        if not auth_header.startswith("Bearer "):
            return jsonify(error="missing or malformed Authorization header"), 401

        token = auth_header[len("Bearer ") :].strip()
        secret_key = current_app.extensions["argus_auth"]["secret_key"]
        try:
            payload = decode_access_token(token, secret_key)
        except jwt.ExpiredSignatureError:
            return jsonify(error="access token expired"), 401
        except jwt.PyJWTError:
            return jsonify(error="invalid access token"), 401

        g.user_id = int(payload["sub"])
        return view(*args, **kwargs)

    return wrapped


def optional_auth(view):
    """Attach ``flask.g.user_id`` if a valid bearer token is present.

    Unlike :func:`require_auth`, a missing, malformed, expired, or invalid
    token never short-circuits the request — ``g.user_id`` is simply left
    ``None`` and the view runs as if the caller were anonymous.
    """

    @wraps(view)
    def wrapped(*args, **kwargs):
        g.user_id = None
        auth_header = request.headers.get("Authorization", "")
        if auth_header.startswith("Bearer "):
            token = auth_header[len("Bearer ") :].strip()
            secret_key = current_app.extensions["argus_auth"]["secret_key"]
            try:
                payload = decode_access_token(token, secret_key)
                g.user_id = int(payload["sub"])
            except jwt.PyJWTError:
                pass
        return view(*args, **kwargs)

    return wrapped
