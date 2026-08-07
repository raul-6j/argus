"""Tests for src.api.threat_intel.providers (Phase 5, F6; DEC-035)."""

from __future__ import annotations

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
        provider = GoogleSafeBrowsingProvider("fake-key", session=session)

        with mock.patch("src.api.threat_intel.providers.time.monotonic", return_value=0.0):
            provider.check("http://evil.example.com/login")
        with mock.patch("src.api.threat_intel.providers.time.monotonic", return_value=99999.0):
            provider.check("http://evil.example.com/login")

        assert session.post.call_count == 2


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
