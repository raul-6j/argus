"""Centralised SSRF guard (Phase 6, Task 6.2).

Used by both the live feature extractor (``src.features.pipeline``) and the
Flask API's enrichment path, so there is exactly one place that decides
whether a URL is safe to fetch. Previously this logic was duplicated inline
in ``pipeline.py``; this module is now the single source of truth.

Blocks: private, loopback, link-local, CGNAT (RFC 6598, 100.64.0.0/10 —
notably *not* covered by ``ipaddress.IPv4Address.is_private`` in the stdlib,
so it needs an explicit check), reserved, multicast, and unspecified address
ranges. This covers cloud metadata endpoints (169.254.169.254 is
link-local) and internal services (localhost, 10.0.0.0/8, etc).

Caller must re-check on every redirect hop (SSRF via open redirect) — this
module only validates one URL at a time; it does not follow redirects
itself.
"""

from __future__ import annotations

import ipaddress
import logging
import socket
from urllib.parse import urlparse

logger = logging.getLogger(__name__)

ALLOWED_SCHEMES: frozenset[str] = frozenset({"http", "https"})

# RFC 6598 — Carrier-Grade NAT (CGNAT) range. Not classified as private by
# Python's ipaddress module, so it must be checked separately.
_CGNAT_NETWORK = ipaddress.ip_network("100.64.0.0/10")


def is_safe_fetch_url(url: str) -> bool:
    """Return whether ``url`` is safe to fetch (SSRF guard).

    The URL is untrusted input in a phishing-detection system. Allows only
    http/https and refuses any host that resolves to a private, loopback,
    link-local, CGNAT, reserved, multicast, or unspecified address.

    Note: there is an unavoidable TOCTOU gap — the OS re-resolves the host
    when the connection is made, so a fast-flipping DNS record could still
    point elsewhere after this check passes. This raises the bar
    substantially but is not a complete defence; a production deployment
    should also pin the validated IP for the actual connection.

    Args:
        url: The URL to validate.

    Returns:
        ``True`` if the URL appears safe to fetch, else ``False``.
    """
    parsed = urlparse(url)
    if parsed.scheme.lower() not in ALLOWED_SCHEMES:
        return False
    host = parsed.hostname
    if not host:
        return False
    try:
        infos = socket.getaddrinfo(host, parsed.port or None, proto=socket.IPPROTO_TCP)
    except socket.gaierror:
        return False
    for info in infos:
        ip_str = info[4][0]
        try:
            ip = ipaddress.ip_address(ip_str)
        except ValueError:
            return False
        if (
            ip.is_private
            or ip.is_loopback
            or ip.is_link_local
            or ip.is_reserved
            or ip.is_multicast
            or ip.is_unspecified
            or ip in _CGNAT_NETWORK
        ):
            logger.warning("Refusing to fetch %r — resolves to blocked IP %s", url, ip)
            return False
    return True
