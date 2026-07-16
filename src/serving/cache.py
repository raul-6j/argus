"""Short-TTL verdict cache (Phase 2, G1).

Keyed on ``normalize_url(url) + enrich`` — reuses the same URL
normalization the threat-intel pre-filter already relies on
(``src.data.loaders.normalize_url``) so cache keys and prefilter lookups
stay consistent. Backed by Redis when configured (reusing the same client
G2's rate limiter connects, via ``app.extensions["argus"]["redis_client"]``)
with an in-process LRU fallback for local dev (no Redis dependency).

**The threat-intel prefilter always runs before any cache lookup** (see
``src/api/detect.py``) — a URL already known-bad short-circuits before this
cache is ever consulted, so a newly-blocklisted URL is never masked by a
stale cached "legitimate" verdict. The short default TTL (minutes, not
hours) bounds how stale a *model/fusion* verdict can get for a URL that
flips after being scanned once.
"""

from __future__ import annotations

import json
import logging
import time
from collections import OrderedDict
from typing import Any, Optional

from src.data.loaders import normalize_url

logger = logging.getLogger(__name__)

_KEY_PREFIX = "argus:verdict:"
_DEFAULT_MAX_INPROC_ENTRIES = 2000


def cache_key(url: str, enrich: bool) -> str:
    """Build the cache key for a (url, enrich) pair."""
    return f"{normalize_url(url)}:{'enrich' if enrich else 'fast'}"


class VerdictCache:
    """A short-TTL cache for fused/model verdicts.

    Never raises: a Redis backend failure logs a warning and behaves as a
    cache miss (bypass — compute live) rather than failing the request.
    """

    def __init__(self, redis_client: Optional[Any] = None, ttl_s: int = 300, max_inproc_entries: int = _DEFAULT_MAX_INPROC_ENTRIES):
        self._redis = redis_client
        self._ttl_s = ttl_s
        self._max_inproc_entries = max_inproc_entries
        self._inproc: "OrderedDict[str, tuple[dict, float]]" = OrderedDict()

    def get(self, key: str) -> Optional[dict[str, Any]]:
        """Return the cached verdict dict for ``key``, or ``None`` on a miss
        (including any backend failure)."""
        if self._redis is not None:
            try:
                raw = self._redis.get(_KEY_PREFIX + key)
                return json.loads(raw) if raw else None
            except Exception as exc:  # noqa: BLE001 - cache failure -> bypass, never fail the request
                logger.warning("VerdictCache Redis get failed for %r: %s -- bypassing cache.", key, exc)
                return None

        entry = self._inproc.get(key)
        if entry is None:
            return None
        value, expires_at = entry
        if time.time() > expires_at:
            del self._inproc[key]
            return None
        self._inproc.move_to_end(key)  # LRU touch
        return value

    def set(self, key: str, value: dict[str, Any]) -> None:
        """Store ``value`` for ``key`` with the configured TTL. Never raises."""
        if self._redis is not None:
            try:
                self._redis.setex(_KEY_PREFIX + key, self._ttl_s, json.dumps(value))
            except Exception as exc:  # noqa: BLE001
                logger.warning("VerdictCache Redis set failed for %r: %s -- skipping cache write.", key, exc)
            return

        self._inproc[key] = (value, time.time() + self._ttl_s)
        self._inproc.move_to_end(key)
        while len(self._inproc) > self._max_inproc_entries:
            self._inproc.popitem(last=False)  # evict oldest


def build_cache(config: dict[str, Any], redis_client: Optional[Any]) -> Optional[VerdictCache]:
    """Build the verdict cache from ``api_config.yaml``'s ``cache`` section.

    Returns:
        A :class:`VerdictCache`, or ``None`` if ``cache.enabled`` is falsy
        (caching is entirely skipped, not just always-miss).
    """
    cache_config = config.get("cache", {})
    if not cache_config.get("enabled", False):
        return None
    return VerdictCache(redis_client=redis_client, ttl_s=cache_config.get("ttl_s", 300))
