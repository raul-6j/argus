"""Small helpers shared by every ARGUS blueprint.

Each of these existed as a near-identical private copy in four to six
blueprint modules (``detect``, ``scan``, ``public``, ``auth``,
``auth.api_key_routes``, ``vault``). They are collected here so the shape of
an error body, the way ``latency_ms`` is computed (Iron Law #4), and the way
a DB session is opened are defined exactly once — previously, changing any
of them meant finding and editing every copy.

Deliberately thin: these wrap existing behaviour verbatim rather than adding
policy of their own, so every route keeps the response bytes it had before.
"""

from __future__ import annotations

import time
from typing import Any, Optional

from flask import current_app, jsonify

from src.utils.validators import validate_url


def error(message: str, status: int, **extra: Any):
    """Build the API's standard JSON error response.

    Args:
        message: Human-readable error text, rendered as ``{"error": ...}``.
        status: HTTP status code.
        **extra: Additional top-level keys merged into the body (used by the
            vault blueprint, which returns a ``code`` alongside the message).

    Returns:
        A ``(response, status)`` tuple ready to return from a view.
    """
    return jsonify(error=message, **extra), status


def latency_ms(start: float) -> float:
    """Milliseconds elapsed since ``start``, rounded the way every endpoint
    reports it (Iron Law #4: every response carries ``latency_ms``).

    Args:
        start: A :func:`time.perf_counter` reading taken at request entry.
    """
    return round((time.perf_counter() - start) * 1000, 3)


def db_session():
    """Open a new SQLAlchemy session from the app's configured factory.

    Callers remain responsible for ``.close()`` (every existing call site
    already does so in a ``finally:``) — see
    ``src.api.db.create_session_factory`` for why session lifetime is
    load-bearing under the test suite's ``StaticPool`` engine.
    """
    return current_app.extensions["argus_auth"]["session_factory"]()


def check_url(url: str) -> tuple[bool, str]:
    """Validate a caller-supplied URL under the app's localhost policy.

    Wraps :func:`src.utils.validators.validate_url` with the
    ``ALLOW_LOCALHOST`` lookup that every URL-accepting endpoint repeated
    verbatim, so the policy is read from one place.

    Returns:
        ``(ok, reason)`` — ``reason`` is the 400-able message when not ok.
    """
    return validate_url(url, allow_localhost=current_app.config.get("ALLOW_LOCALHOST", False))


def model_not_ready():
    """The shared 503 for a request that needs a model that never loaded.

    Returns:
        The ``(response, 503)`` tuple, or ``None`` when the model *is*
        loaded — letting callers write ``if (resp := model_not_ready()):
        return resp``.
    """
    if current_app.extensions.get("argus", {}).get("pipeline") is None:
        return error("model not ready", 503)
    return None


def detection_config(argus: Optional[dict[str, Any]] = None) -> dict[str, Any]:
    """The loaded ``detection_config.yaml`` contents, or ``{}`` if disabled/absent.

    Args:
        argus: The ``app.extensions["argus"]`` dict, if the caller already
            has it in hand; looked up from ``current_app`` otherwise.
    """
    if argus is None:
        argus = current_app.extensions["argus"]
    return argus.get("detection", {}).get("config", {})


def risk_bands_config(argus: Optional[dict[str, Any]] = None):
    """``detection_config.yaml``'s ``risk_bands`` list, or ``None`` to use the
    calibrated defaults in :data:`src.detection.types.DEFAULT_RISK_BANDS`."""
    return detection_config(argus).get("risk_bands")
