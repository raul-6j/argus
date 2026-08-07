"""Tests for src.api.threat_intel.providers (Phase 5, F6; DEC-035)."""

from __future__ import annotations

import time
from unittest import mock

import pytest

from src.api.threat_intel.providers import (
    GoogleSafeBrowsingProvider,
    PhishTankProvider,
    build_providers,
)
from src.data.loaders import normalize_url


class TestPhishTankProvider:
    def test_exact_match(self):
        index = frozenset({normalize_url("http://evil.example.com/login")})
        provider = PhishTankProvider(index)
        assert provider.name == "phishtank"
        assert provider.check("http://evil.example.com/login") is True

    def test_no_match(self):
        provider = PhishTankProvider(frozenset())
        assert provider.check("https://example.com") is False

    def test_hostname_index_match(self):
        provider = PhishTankProvider(frozenset(), frozenset({"attacker.wixstudio.com"}))
        assert provider.check("attacker.wixstudio.com") is True

    def test_hostname_index_empty_never_matches_via_hostname(self):
        provider = PhishTankProvider(frozenset())
        assert provider.check("attacker.wixstudio.com") is False


def _fake_response(status_code=200, json_body=None, raise_for_status_exc=None):
    resp = mock.Mock()
    resp.status_code = status_code
    resp.json.return_value = json_body or {}
    if raise_for_status_exc:
        resp.raise_for_status.side_effect = raise_for_status_exc
    else:
        resp.raise_for_status.return_value = None
    return resp


class TestGoogleSafeBrowsingProvider:
    def test_name_is_gsb(self):
        assert GoogleSafeBrowsingProvider("fake-key").name == "gsb"

    def test_match_returns_true(self):
        session = mock.Mock()
        session.post.return_value = _fake_response(json_body={"matches": [{"threat": {"url": "x"}}]})
        provider = GoogleSafeBrowsingProvider("fake-key", session=session)

        assert provider.check("http://evil.example.com/login") is True
        session.post.assert_called_once()
        _, kwargs = session.post.call_args
        assert kwargs["params"] == {"key": "fake-key"}
        assert kwargs["timeout"] == pytest.approx(3.0)

    def test_no_match_returns_false(self):
        session = mock.Mock()
        session.post.return_value = _fake_response(json_body={})
        provider = GoogleSafeBrowsingProvider("fake-key", session=session)

        assert provider.check("https://example.com") is False

    def test_network_error_fails_open(self):
        session = mock.Mock()
        session.post.side_effect = ConnectionError("boom")
        provider = GoogleSafeBrowsingProvider("fake-key", session=session)

        assert provider.check("https://example.com") is False

    def test_timeout_fails_open(self):
        session = mock.Mock()
        session.post.side_effect = TimeoutError("timed out")
        provider = GoogleSafeBrowsingProvider("fake-key", session=session)

        assert provider.check("https://example.com") is False

    def test_non_2xx_fails_open(self):
        session = mock.Mock()
        session.post.return_value = _fake_response(
            status_code=403, raise_for_status_exc=RuntimeError("403 forbidden")
        )
        provider = GoogleSafeBrowsingProvider("fake-key", session=session)

        assert provider.check("https://example.com") is False

    def test_result_is_cached_second_call_does_not_hit_network(self):
        session = mock.Mock()
        session.post.return_value = _fake_response(json_body={"matches": [{}]})
        provider = GoogleSafeBrowsingProvider("fake-key", session=session)

        assert provider.check("http://evil.example.com/login") is True
        assert provider.check("http://evil.example.com/login") is True
        session.post.assert_called_once()

    def test_cache_is_keyed_by_normalized_url(self):
        session = mock.Mock()
        session.post.return_value = _fake_response(json_body={"matches": [{}]})
        provider = GoogleSafeBrowsingProvider("fake-key", session=session)

        provider.check("http://evil.example.com/login")
        provider.check("HTTP://EVIL.EXAMPLE.COM/login#frag")
        session.post.assert_called_once()

    def test_cache_expires_after_ttl(self):
        session = mock.Mock()
        session.post.return_value = _fake_response(json_body={"matches": [{}]})
        provider = GoogleSafeBrowsingProvider("fake-key", session=session, cache_ttl_s=0.01)

        provider.check("http://evil.example.com/login")
        time.sleep(0.02)
        provider.check("http://evil.example.com/login")

        assert session.post.call_count == 2

    def test_cache_is_bounded_and_evicts_least_recently_used(self):
        """The per-URL cache must not grow without limit (CWE-401).

        Keyed per *URL* rather than per domain, so on a public scanner its key
        space is effectively unbounded — a size cap, not just a TTL, is what
        prevents a long-lived process from retaining every URL it ever checked.
        """
        session = mock.Mock()
        session.post.return_value = _fake_response(json_body={"matches": []})
        provider = GoogleSafeBrowsingProvider("fake-key", session=session, cache_max_entries=3)

        for i in range(10):
            provider.check(f"http://example.com/{i}")

        assert len(provider._cache) == 3
        # The 10 lookups were all distinct, so none was served from cache.
        assert session.post.call_count == 10
        # The most recent 3 are retained; re-checking one is a cache hit.
        provider.check("http://example.com/9")
        assert session.post.call_count == 10
        # The evicted oldest is not, and costs a fresh lookup.
        provider.check("http://example.com/0")
        assert session.post.call_count == 11


class TestBuildProviders:
    def test_gsb_disabled_yields_phishtank_only(self):
        providers = build_providers({"gsb_enabled": False}, frozenset(), frozenset(), gsb_api_key="k")
        assert [p.name for p in providers] == ["phishtank"]

    def test_gsb_enabled_without_api_key_yields_phishtank_only(self):
        providers = build_providers({"gsb_enabled": True}, frozenset(), frozenset(), gsb_api_key=None)
        assert [p.name for p in providers] == ["phishtank"]

    def test_gsb_enabled_with_api_key_is_checked_first(self):
        providers = build_providers({"gsb_enabled": True}, frozenset(), frozenset(), gsb_api_key="real-key")
        assert [p.name for p in providers] == ["gsb", "phishtank"]

    def test_missing_gsb_enabled_key_defaults_to_disabled(self):
        providers = build_providers({}, frozenset(), frozenset(), gsb_api_key="real-key")
        assert [p.name for p in providers] == ["phishtank"]
