"""Request-level input validation (Phase 6, Task 6.1).

Cheap, synchronous, no-network-I/O checks applied to every ``/detect``/
``/explain`` request before any feature extraction happens — rejects
obviously-bad input fast (malformed URL, non-http scheme, literal
localhost/loopback hostnames) with a clear error message for a 400 response.

This is deliberately *not* the SSRF guard (:mod:`src.utils.ssrf`), which does
a DNS resolution to catch hostnames that only *resolve* to an internal IP
(e.g. a DNS-rebinding domain). That check is comparatively expensive and only
needed on the enrichment (HTML fetch) path; this module's checks are cheap
enough to run on every request regardless of the ``enrich`` flag.
"""

from __future__ import annotations

from urllib.parse import urlparse

# Literal hostnames that are always rejected regardless of the allow_localhost
# flag's setting for `enrich` fetches (this is the fast, request-level check —
# ssrf.py's DNS-based check still applies on the actual fetch path).
_LOCALHOST_HOSTNAMES: frozenset[str] = frozenset(
    {"localhost", "127.0.0.1", "0.0.0.0", "::1", "[::1]"}
)

_ALLOWED_SCHEMES: frozenset[str] = frozenset({"http", "https"})

# Reject absurdly long URLs outright — no legitimate phishing/legit URL needs
# this much, and it bounds worst-case parsing/logging cost.
_MAX_URL_LENGTH: int = 2048


def validate_url(url: object, *, allow_localhost: bool = False) -> tuple[bool, str | None]:
    """Validate a URL is well-formed and safe to hand to the feature pipeline.

    Args:
        url: The value to validate (any type — non-strings fail validation
            rather than raising, since this is meant for untrusted request
            bodies).
        allow_localhost: If ``True``, skip the localhost/loopback hostname
            check. Only intended for local development/testing — the
            production API config should never set this.

    Returns:
        ``(True, None)`` if ``url`` is valid, else ``(False, reason)`` with a
        human-readable rejection reason suitable for a 400 response body.
    """
    if not isinstance(url, str) or not url.strip():
        return False, "url must be a non-empty string"

    if len(url) > _MAX_URL_LENGTH:
        return False, f"url exceeds maximum length of {_MAX_URL_LENGTH} characters"

    try:
        parsed = urlparse(url)
    except ValueError:
        return False, "url could not be parsed"

    if parsed.scheme.lower() not in _ALLOWED_SCHEMES:
        return False, f"url scheme must be http or https, got {parsed.scheme!r}"

    if not parsed.hostname:
        return False, "url must include a hostname"

    if not allow_localhost and parsed.hostname.lower() in _LOCALHOST_HOSTNAMES:
        return False, "url must not point at localhost/loopback"

    return True, None
