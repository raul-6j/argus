"""``@require_auth`` decorator (Phase 8, Task 8.1).

Reads ``Authorization: Bearer <jwt>`` from the request, decodes it with the
app's SECRET_KEY, and attaches the authenticated user ID to ``flask.g``.
Every view wrapped with this decorator can read ``g.user_id``.
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
