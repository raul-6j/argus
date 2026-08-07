"""A small thread-safe, bounded, TTL + LRU in-process cache.

Written because two long-lived caches in this project had a TTL check but no
eviction and no size cap — ``src.features.domain_intel``'s per-domain WHOIS
cache and ``GoogleSafeBrowsingProvider``'s per-URL verdict cache. Both only
*skipped* expired entries on read; nothing ever removed them, so every distinct
domain/URL a process ever scanned was retained for that process's lifetime.
For a public scanner that is exactly the workload that turns an optimisation
into an OOM (CWE-401).

``src.serving.cache.VerdictCache`` already implemented the correct bounded-LRU
pattern for the *verdict* cache; it stays where it is (it also has a Redis
backend and a public/response-shaped API). This is the same idea extracted as a
reusable primitive for the plain in-process cases.

Two-layer bound, deliberately:
    * **TTL** bounds staleness, and expired entries are actively purged on
      write rather than merely skipped on read.
    * **``max_entries``** bounds memory even in the pathological case where
      every key is distinct and none has expired yet — a TTL alone is not a
      size bound.
"""

from __future__ import annotations

import threading
import time
from collections import OrderedDict
from typing import Generic, Optional, TypeVar

V = TypeVar("V")


class TtlCache(Generic[V]):
    """A thread-safe cache with per-entry TTL and an LRU size cap.

    Thread safety is not optional here: both call sites are read and written
    concurrently from thread pools (``extract_domain_intel_batch``'s fan-out,
    and the API's enrichment/job executors).
    """

    def __init__(self, ttl_s: float, max_entries: int) -> None:
        """Build an empty cache.

        Args:
            ttl_s: How long an entry stays fresh, in seconds.
            max_entries: Hard cap on retained entries. The least-recently-used
                entry is evicted once the cap is exceeded.

        Raises:
            ValueError: If ``max_entries`` is not positive — a cache that can
                hold nothing is always a configuration mistake, and failing
                loudly here beats silently never caching.
        """
        if max_entries <= 0:
            raise ValueError(f"max_entries must be positive, got {max_entries!r}")
        self._ttl_s = ttl_s
        self._max_entries = max_entries
        self._entries: "OrderedDict[str, tuple[float, V]]" = OrderedDict()
        self._lock = threading.Lock()

    def get(self, key: str) -> Optional[V]:
        """Return the fresh value for ``key``, or ``None`` on a miss.

        A hit refreshes the entry's LRU recency. An expired entry is deleted
        here rather than left behind, so a repeatedly-requested-then-abandoned
        key does not accumulate.

        Note:
            ``None`` means "not cached". A caller storing ``Optional`` values
            cannot distinguish a cached ``None`` from a miss — store a
            sentinel instead. Both current callers store non-``None`` values
            (a dict, and a plain ``bool`` where ``False`` is a real cached
            result distinct from ``None``).
        """
        now = time.monotonic()
        with self._lock:
            entry = self._entries.get(key)
            if entry is None:
                return None
            stored_at, value = entry
            if (now - stored_at) >= self._ttl_s:
                del self._entries[key]
                return None
            self._entries.move_to_end(key)
            return value

    def set(self, key: str, value: V) -> None:
        """Store ``value`` under ``key``, evicting as needed to stay bounded."""
        now = time.monotonic()
        with self._lock:
            self._entries[key] = (now, value)
            self._entries.move_to_end(key)
            self._purge_expired(now)
            while len(self._entries) > self._max_entries:
                self._entries.popitem(last=False)  # evict least-recently-used

    def _purge_expired(self, now: float) -> None:
        """Drop every expired entry. Caller must hold ``self._lock``.

        Walks from the LRU end and stops at the first *fresh* entry. That is
        only a heuristic — recency order is not expiry order, since a cache hit
        moves an entry to the fresh end without resetting its timestamp — so
        the ``max_entries`` cap, not this, is what actually guarantees the
        bound. This just keeps the common case (keys that go quiet) from
        occupying the cap.
        """
        while self._entries:
            key, (stored_at, _value) = next(iter(self._entries.items()))
            if (now - stored_at) < self._ttl_s:
                return
            del self._entries[key]

    def clear(self) -> None:
        """Drop every entry. Used by tests; harmless in production."""
        with self._lock:
            self._entries.clear()

    def __len__(self) -> int:
        """Number of retained entries, expired-but-not-yet-purged included."""
        with self._lock:
            return len(self._entries)
