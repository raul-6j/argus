"""Tests for src.serving.cache (Phase 2, G1)."""

from __future__ import annotations

from unittest import mock

from src.serving.cache import VerdictCache, build_cache, cache_key


class TestCacheKey:
    def test_same_url_enrich_combo_same_key(self):
        assert cache_key("https://example.com", True) == cache_key("https://example.com", True)

    def test_different_enrich_different_key(self):
        assert cache_key("https://example.com", True) != cache_key("https://example.com", False)

    def test_normalizes_url(self):
        """Reuses normalize_url -- scheme/host case and fragment shouldn't
        defeat a cache hit."""
        assert cache_key("HTTPS://EXAMPLE.com/x#frag", False) == cache_key("https://example.com/x", False)


class TestInProcBackend:
    def test_miss_returns_none(self):
        cache = VerdictCache(redis_client=None, ttl_s=60)
        assert cache.get("nope") is None

    def test_set_then_get_roundtrips(self):
        cache = VerdictCache(redis_client=None, ttl_s=60)
        cache.set("k1", {"label": "phishing", "confidence": 0.9})
        assert cache.get("k1") == {"label": "phishing", "confidence": 0.9}

    def test_expired_entry_is_a_miss(self):
        cache = VerdictCache(redis_client=None, ttl_s=-1)  # already expired
        cache.set("k1", {"label": "phishing"})
        assert cache.get("k1") is None

    def test_lru_eviction_when_over_capacity(self):
        cache = VerdictCache(redis_client=None, ttl_s=60, max_inproc_entries=2)
        cache.set("a", {"v": 1})
        cache.set("b", {"v": 2})
        cache.set("c", {"v": 3})  # evicts "a" (oldest)
        assert cache.get("a") is None
        assert cache.get("b") == {"v": 2}
        assert cache.get("c") == {"v": 3}

    def test_get_touches_lru_order(self):
        """Accessing an entry should protect it from eviction over an
        untouched older entry."""
        cache = VerdictCache(redis_client=None, ttl_s=60, max_inproc_entries=2)
        cache.set("a", {"v": 1})
        cache.set("b", {"v": 2})
        cache.get("a")  # "a" is now most-recently-used
        cache.set("c", {"v": 3})  # should evict "b", not "a"
        assert cache.get("a") == {"v": 1}
        assert cache.get("b") is None


class TestRedisBackend:
    def test_set_then_get_roundtrips(self):
        redis_client = mock.Mock()
        store = {}
        redis_client.setex = mock.Mock(side_effect=lambda k, ttl, v: store.__setitem__(k, v))
        redis_client.get = mock.Mock(side_effect=lambda k: store.get(k))

        cache = VerdictCache(redis_client=redis_client, ttl_s=60)
        cache.set("k1", {"label": "phishing"})
        assert cache.get("k1") == {"label": "phishing"}
        redis_client.setex.assert_called_once()

    def test_get_failure_is_a_miss_not_a_crash(self):
        redis_client = mock.Mock()
        redis_client.get = mock.Mock(side_effect=RuntimeError("connection lost"))
        cache = VerdictCache(redis_client=redis_client, ttl_s=60)
        assert cache.get("k1") is None

    def test_set_failure_does_not_raise(self):
        redis_client = mock.Mock()
        redis_client.setex = mock.Mock(side_effect=RuntimeError("connection lost"))
        cache = VerdictCache(redis_client=redis_client, ttl_s=60)
        cache.set("k1", {"label": "phishing"})  # must not raise

    def test_miss_returns_none(self):
        redis_client = mock.Mock()
        redis_client.get = mock.Mock(return_value=None)
        cache = VerdictCache(redis_client=redis_client, ttl_s=60)
        assert cache.get("k1") is None


class TestBuildCache:
    def test_disabled_returns_none(self):
        assert build_cache({"cache": {"enabled": False}}, redis_client=None) is None

    def test_missing_config_key_defaults_disabled(self):
        assert build_cache({}, redis_client=None) is None

    def test_enabled_returns_cache_with_configured_ttl(self):
        cache = build_cache({"cache": {"enabled": True, "ttl_s": 42}}, redis_client=None)
        assert isinstance(cache, VerdictCache)
        assert cache._ttl_s == 42
