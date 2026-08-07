"""Tests for src.utils.ttl_cache — the bounded TTL/LRU in-process cache.

The size bound is the point of this module (CWE-401: the WHOIS and Google
Safe Browsing caches it replaced had a TTL but no eviction and no cap, so a
long-lived process retained every key it ever saw), so the eviction and
concurrency cases are covered as carefully as the plain hit/miss ones.
"""

from __future__ import annotations

import threading
import time

import pytest

from src.utils.ttl_cache import TtlCache


class TestBasics:
    def test_miss_returns_none(self):
        cache = TtlCache[str](ttl_s=60, max_entries=10)
        assert cache.get("absent") is None

    def test_set_then_get_round_trips(self):
        cache = TtlCache[str](ttl_s=60, max_entries=10)
        cache.set("k", "v")
        assert cache.get("k") == "v"

    def test_set_overwrites_existing_key(self):
        cache = TtlCache[str](ttl_s=60, max_entries=10)
        cache.set("k", "first")
        cache.set("k", "second")
        assert cache.get("k") == "second"
        assert len(cache) == 1

    def test_falsy_values_are_distinguishable_from_a_miss(self):
        """GoogleSafeBrowsingProvider caches plain bools — a cached ``False``
        (a real "not on the blocklist" result) must not read as a miss, or
        every negative lookup would re-hit the billable upstream API."""
        cache = TtlCache[bool](ttl_s=60, max_entries=10)
        cache.set("k", False)
        assert cache.get("k") is False
        assert cache.get("other") is None

    def test_clear_empties_the_cache(self):
        cache = TtlCache[str](ttl_s=60, max_entries=10)
        cache.set("a", "1")
        cache.set("b", "2")
        cache.clear()
        assert len(cache) == 0
        assert cache.get("a") is None

    def test_rejects_a_non_positive_max_entries(self):
        with pytest.raises(ValueError):
            TtlCache[str](ttl_s=60, max_entries=0)
        with pytest.raises(ValueError):
            TtlCache[str](ttl_s=60, max_entries=-1)


class TestExpiry:
    def test_entry_expires_after_ttl(self):
        cache = TtlCache[str](ttl_s=0.01, max_entries=10)
        cache.set("k", "v")
        time.sleep(0.02)
        assert cache.get("k") is None

    def test_expired_entry_is_deleted_not_merely_skipped(self):
        """The bug this module exists to fix: the previous implementations
        skipped stale entries on read but never removed them."""
        cache = TtlCache[str](ttl_s=0.01, max_entries=10)
        cache.set("k", "v")
        time.sleep(0.02)
        cache.get("k")
        assert len(cache) == 0

    def test_a_write_purges_expired_entries(self):
        cache = TtlCache[str](ttl_s=0.01, max_entries=10)
        cache.set("old", "v")
        time.sleep(0.02)
        cache.set("new", "v")
        assert len(cache) == 1
        assert cache.get("new") == "v"


class TestSizeBound:
    def test_never_exceeds_max_entries(self):
        cache = TtlCache[int](ttl_s=3600, max_entries=5)
        for i in range(1000):
            cache.set(f"k{i}", i)
        assert len(cache) == 5

    def test_evicts_least_recently_used(self):
        cache = TtlCache[int](ttl_s=3600, max_entries=3)
        cache.set("a", 1)
        cache.set("b", 2)
        cache.set("c", 3)
        cache.set("d", 4)  # evicts "a"

        assert cache.get("a") is None
        assert cache.get("b") == 2
        assert cache.get("c") == 3
        assert cache.get("d") == 4

    def test_a_read_refreshes_recency(self):
        cache = TtlCache[int](ttl_s=3600, max_entries=3)
        cache.set("a", 1)
        cache.set("b", 2)
        cache.set("c", 3)

        cache.get("a")  # "a" is now the most recently used; "b" the least
        cache.set("d", 4)

        assert cache.get("a") == 1
        assert cache.get("b") is None


class TestThreadSafety:
    def test_concurrent_writers_respect_the_bound(self):
        """Both call sites are written from thread pools (the domain-intel
        batch fan-out, the API's enrichment/job executors), so the bound has
        to hold under genuine concurrency, not just serial use."""
        cache = TtlCache[int](ttl_s=3600, max_entries=50)
        errors: list[BaseException] = []

        def worker(offset: int) -> None:
            try:
                for i in range(200):
                    cache.set(f"k{offset}-{i}", i)
                    cache.get(f"k{offset}-{i}")
            except BaseException as exc:  # noqa: BLE001 - re-raised in the assert below
                errors.append(exc)

        threads = [threading.Thread(target=worker, args=(n,)) for n in range(8)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()

        assert not errors
        assert len(cache) <= 50
