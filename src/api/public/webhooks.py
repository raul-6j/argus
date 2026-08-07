"""Webhook signing + delivery for async scan jobs (F19).

Bounded, in-process retries only -- no persistent retry queue/scheduler.
Mirrors the precedent set by F7's threat-intel hot-reload (DEC-035): ARGUS
deliberately keeps long-horizon scheduling/redelivery external rather than
building an in-process job scheduler. A webhook endpoint that's down for
hours needs the caller to notice and fall back to polling
``GET /v1/scan/async/<job_id>`` -- which always holds the authoritative
result regardless of webhook outcome -- not ARGUS silently retrying forever.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import logging
import time
from typing import Any

import requests

logger = logging.getLogger(__name__)

_DEFAULT_TIMEOUT_S = 5
_DEFAULT_MAX_ATTEMPTS = 3
_DEFAULT_RETRY_BACKOFF_S = (0, 2, 8)


def sign_payload(secret: str, body: bytes) -> str:
    """HMAC-SHA256-sign a webhook body.

    Same reasoning as ``src.api.auth.utils.hash_token``: this only needs to
    prove possession of the shared secret, not resist offline guessing of a
    low-entropy value, so a fast HMAC is appropriate.

    Args:
        secret: The owning API key's ``webhook_secret``.
        body: The raw JSON body bytes that will actually be sent -- signing
            must happen over the exact bytes transmitted, not a re-serialized
            copy, so the receiver's own re-serialization can't disagree.

    Returns:
        A hex-encoded HMAC-SHA256 digest.
    """
    return hmac.new(secret.encode("utf-8"), body, hashlib.sha256).hexdigest()


def deliver_webhook(
    url: str, payload: dict[str, Any], secret: str, config: dict[str, Any] | None = None
) -> tuple[str, int]:
    """Attempt to deliver a signed webhook payload, with bounded retries.

    Args:
        url: The destination URL (already SSRF-validated at submission time
            via ``src.utils.ssrf.is_safe_fetch_url`` -- not re-validated
            here, since the caller is expected to have already checked it).
        payload: The JSON-serializable payload to send.
        secret: The owning key's ``webhook_secret``, used to sign the body.
        config: Optional ``{"timeout_s", "max_attempts", "retry_backoff_s"}``
            overrides (from ``configs/api_config.yaml -> webhook_delivery``).

    Returns:
        ``(status, attempts)`` where ``status`` is ``"delivered"`` or
        ``"failed"``, and ``attempts`` is how many POSTs were actually made.
    """
    config = config or {}
    timeout_s = config.get("timeout_s", _DEFAULT_TIMEOUT_S)
    max_attempts = config.get("max_attempts", _DEFAULT_MAX_ATTEMPTS)
    backoff_s = config.get("retry_backoff_s", _DEFAULT_RETRY_BACKOFF_S)

    body = json.dumps(payload).encode("utf-8")
    signature = sign_payload(secret, body)
    headers = {
        "Content-Type": "application/json",
        "X-Argus-Signature": f"sha256={signature}",
    }

    attempts = 0
    for attempt_index in range(max_attempts):
        if attempt_index > 0:
            delay = backoff_s[min(attempt_index, len(backoff_s) - 1)]
            if delay:
                time.sleep(delay)
        attempts += 1
        try:
            # Redirects are refused, not followed: a webhook target silently
            # redirecting elsewhere is exactly the open-redirect SSRF gap
            # src.utils.ssrf's docstring warns about -- refusing means the
            # one submission-time check never needs a second, per-hop check.
            resp = requests.post(
                url, data=body, headers=headers, timeout=timeout_s, allow_redirects=False
            )
            if 200 <= resp.status_code < 300:
                return "delivered", attempts
            logger.warning(
                "Webhook delivery to %s returned %d (attempt %d/%d).",
                url, resp.status_code, attempts, max_attempts,
            )
        except requests.RequestException as exc:
            logger.warning(
                "Webhook delivery to %s failed (attempt %d/%d): %s", url, attempts, max_attempts, exc
            )

    return "failed", attempts
