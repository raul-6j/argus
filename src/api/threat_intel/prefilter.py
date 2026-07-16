"""Threat-intel pre-filter orchestration (DEC-010).

Currently a single PhishTank exact-match layer, plus an opt-in hostname-only
layer for a curated set of subdomain-per-tenant hosting platforms (see
``src.api.threat_intel.phishtank.load_phishtank_hostname_index``). Structured
so a future GSB hash-prefix layer (deferred — no API key available yet, see
DEC-010) can be chained in here without changing any call site: add the GSB
check as another early-return branch in :func:`check_prefilter` ahead of the
PhishTank check (GSB's ~30-minute cache TTL from the live threat feed is
fresher than a static PhishTank snapshot), keeping ``/detect``'s call to this
function unchanged.
"""

from __future__ import annotations

from typing import Optional
from urllib.parse import urlparse

from src.data.loaders import normalize_url


def check_prefilter(
    url: str,
    phishtank_index: frozenset[str],
    phishtank_hostname_index: frozenset[str] = frozenset(),
) -> Optional[str]:
    """Check a URL against the threat-intel pre-filter.

    Args:
        url: The URL to check (as received by ``/detect``, before any other
            processing). May be a full URL or a bare hostname — the browser
            extension's S1 privacy default sends hostname-only unless the
            user opts into ``sendFullUrl``.
        phishtank_index: A normalized-URL lookup set from
            :func:`src.api.threat_intel.phishtank.load_phishtank_index`.
            Checked first; exact match (path included).
        phishtank_hostname_index: A coarser hostname-only lookup set from
            :func:`src.api.threat_intel.phishtank.load_phishtank_hostname_index`.
            Checked only if the exact-URL match misses. Defaults to empty,
            which preserves exact-URL-only matching unchanged — this
            parameter is purely additive.

    Returns:
        ``"phishtank"`` if the URL (after normalization) is a known-phishing
        PhishTank entry, or its hostname is a known-phishing hostname on a
        subdomain-per-tenant platform, else ``None``.
    """
    if normalize_url(url) in phishtank_index:
        return "phishtank"

    if phishtank_hostname_index:
        candidate = url if "://" in url else f"https://{url}"
        host = urlparse(candidate).hostname
        if host and host.lower() in phishtank_hostname_index:
            return "phishtank"

    return None
