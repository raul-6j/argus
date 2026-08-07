"""Pluggable threat-intel provider abstraction (Phase 5, F6; DEC-035).

DEC-010 originally scoped Phase 9.1 to PhishTank-only, deferring a Google
Safe Browsing (GSB) layer "structured so it can be chained into
``check_prefilter()`` later without changing ``/detect``'s call site." This
module is that chaining point: every provider (PhishTank, GSB, and any
future feed) implements the same small :class:`ThreatIntelProvider`
interface, and :func:`build_providers` assembles the ordered list
``check_prefilter`` walks. Adding a new source is "write a class, add it to
the list" — no call site anywhere in ``src/api/`` changes.

Ordering matters: providers are checked in the order returned by
:func:`build_providers`, first match wins. GSB is checked ahead of PhishTank
when enabled, since its lookup reflects Google's live-updated blocklist
(fresher than a static/periodically-refreshed PhishTank snapshot); PhishTank
is always present as the free, zero-latency, no-external-dependency fallback.
"""

from __future__ import annotations

import logging
import threading
import time
from typing import Any, Optional, Protocol, runtime_checkable

from src.data.loaders import normalize_url

logger = logging.getLogger(__name__)

# Bounds the GSB HTTP call the same way _connect_redis_or_fail/domain_intel's
# WHOIS lookups are bounded elsewhere in this project (CLAUDE.md gotcha: a
# third-party network dependency with no explicit timeout can hang every
# request indefinitely, not just fail it -- found the hard way with Redis in
# Phase 2, DEC-027). This module is on /detect's hot path, so 3s is a firm
# ceiling, not a generous one.
_GSB_TIMEOUT_S = 3.0

# Matches prefilter.py's pre-existing docstring, which already described GSB
# as having "~30-minute cache TTL from the live threat feed" before GSB was
# actually implemented -- this keeps that stated design intent, and bounds
# how often the same URL re-hits Google's API (a real cost/quota concern,
# not just a latency one).
_GSB_CACHE_TTL_S = 30 * 60

_GSB_ENDPOINT = "https://safebrowsing.googleapis.com/v4/threatMatches:find"


@runtime_checkable
class ThreatIntelProvider(Protocol):
    """A single threat-intel source :func:`check_prefilter` can consult.

    Implementations must never raise -- a provider failure degrades to "no
    match from this provider", matching every other module in this package's
    graceful-degradation convention, not a 500 for the whole request.
    """

    name: str

    def check(self, url: str) -> bool:
        """Return ``True`` if ``url`` is a known-phishing entry per this provider."""
        ...


class PhishTankProvider:
    """Wraps the existing PhishTank exact-URL + subdomain-per-tenant
    hostname indices (DEC-010/DEC-023) in the provider interface.

    Pure in-memory set lookups -- no behavior change from the pre-F6
    implementation, just re-homed behind :class:`ThreatIntelProvider` so it
    composes with other providers uniformly.
    """

    name = "phishtank"

    def __init__(
        self,
        phishtank_index: frozenset[str],
        phishtank_hostname_index: frozenset[str] = frozenset(),
    ) -> None:
        self._index = phishtank_index
        self._hostname_index = phishtank_hostname_index

    def check(self, url: str) -> bool:
        if normalize_url(url) in self._index:
            return True
        if self._hostname_index:
            from urllib.parse import urlparse

            candidate = url if "://" in url else f"https://{url}"
            host = urlparse(candidate).hostname
            if host and host.lower() in self._hostname_index:
                return True
        return False


class GoogleSafeBrowsingProvider:
    """Live Google Safe Browsing v4 ``threatMatches:find`` lookup (F6).

    Deliberately the *lookup* API (one bounded HTTP call per uncached URL),
    not the full hash-prefix Update API DEC-010's original design sketched.
    The Update API needs a locally-synced, periodically-refreshed database of
    hash prefixes plus full-hash reconciliation -- real infrastructure this
    session doesn't have time to build correctly, and getting it subtly
    wrong (stale prefixes, missed reconciliation) is worse than not having
    it. ``threatMatches:find`` is the officially-supported simple
    alternative for exactly this "check one URL" use case, at the cost of
    sending each looked-up URL to Google over the network (see the privacy
    note below) and being unusable without an API key.

    Privacy note: by the time this provider runs, the URL has already
    reached the ARGUS API server (from the extension's S1 hostname-only
    default or the caller's own choice to send a full URL) -- this doesn't
    introduce a *new* leak beyond that. It does mean Google, a third party,
    additionally sees every URL checked against this provider. That's a
    real trade-off, not a hidden one: this provider is opt-in
    (``gsb_enabled: true`` in ``threat_intel_config.yaml`` *and* a
    ``GSB_API_KEY`` environment variable both required), off by default, and
    never silently activated by the presence of one without the other.

    Fails open: any network error, timeout, non-2xx response, or malformed
    body is logged and treated as "no match" -- a Safe Browsing outage must
    degrade to "PhishTank-only, same as before F6", never block or slow
    every request past the timeout ceiling.
    """

    name = "gsb"

    def __init__(self, api_key: str, session: Optional[Any] = None) -> None:
        self._api_key = api_key
        self._session = session
        self._cache: dict[str, tuple[float, bool]] = {}
        self._cache_lock = threading.Lock()

    def _cached(self, normalized_url: str) -> Optional[bool]:
        now = time.monotonic()
        with self._cache_lock:
            entry = self._cache.get(normalized_url)
        if entry is None:
            return None
        cached_at, result = entry
        if (now - cached_at) >= _GSB_CACHE_TTL_S:
            return None
        return result

    def _store(self, normalized_url: str, result: bool) -> None:
        with self._cache_lock:
            self._cache[normalized_url] = (time.monotonic(), result)

    def check(self, url: str) -> bool:
        normalized = normalize_url(url)
        cached = self._cached(normalized)
        if cached is not None:
            return cached

        result = self._lookup(url)
        self._store(normalized, result)
        return result

    def _lookup(self, url: str) -> bool:
        try:
            import requests

            body = {
                "client": {"clientId": "argus-phishing-detector", "clientVersion": "1.0.0"},
                "threatInfo": {
                    "threatTypes": ["SOCIAL_ENGINEERING", "MALWARE"],
                    "platformTypes": ["ANY_PLATFORM"],
                    "threatEntryTypes": ["URL"],
                    "threatEntries": [{"url": url}],
                },
            }
            requester = self._session or requests
            resp = requester.post(
                _GSB_ENDPOINT,
                params={"key": self._api_key},
                json=body,
                timeout=_GSB_TIMEOUT_S,
            )
            resp.raise_for_status()
            data = resp.json()
            return bool(data.get("matches"))
        except Exception as exc:  # noqa: BLE001 - fail open, never block /detect on GSB
            logger.warning("Google Safe Browsing lookup failed for %r: %s", url, exc)
            return False


def build_providers(
    config: dict[str, Any],
    phishtank_index: frozenset[str],
    phishtank_hostname_index: frozenset[str],
    gsb_api_key: Optional[str] = None,
) -> list[ThreatIntelProvider]:
    """Assemble the ordered provider list :func:`check_prefilter` walks.

    Args:
        config: Loaded ``threat_intel_config.yaml`` contents.
        phishtank_index: From :func:`src.api.threat_intel.phishtank.load_phishtank_index`.
        phishtank_hostname_index: From
            :func:`src.api.threat_intel.phishtank.load_phishtank_hostname_index`.
        gsb_api_key: The ``GSB_API_KEY`` environment variable's value, if
            set. Both ``config["gsb_enabled"]`` and this must be truthy for
            GSB to actually be included -- neither alone is sufficient
            (see :class:`GoogleSafeBrowsingProvider`'s privacy note).

    Returns:
        Providers in check order: GSB first (if enabled and keyed), then
        PhishTank always.
    """
    providers: list[ThreatIntelProvider] = []

    if config.get("gsb_enabled", False):
        if gsb_api_key:
            providers.append(GoogleSafeBrowsingProvider(gsb_api_key))
        else:
            logger.warning(
                "threat_intel_config.yaml has gsb_enabled: true but no GSB_API_KEY "
                "environment variable is set -- Google Safe Browsing stays disabled."
            )

    providers.append(PhishTankProvider(phishtank_index, phishtank_hostname_index))
    return providers
