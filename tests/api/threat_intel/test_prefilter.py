"""Tests for src.api.threat_intel.prefilter.check_prefilter (DEC-035 provider abstraction)."""

from __future__ import annotations

from src.api.threat_intel.prefilter import check_prefilter
from src.api.threat_intel.providers import PhishTankProvider
from src.data.loaders import normalize_url


def _phishtank(index, hostname_index=frozenset()):
    return [PhishTankProvider(index, hostname_index)]


def test_match_returns_phishtank():
    index = frozenset({normalize_url("http://evil.example.com/login")})
    assert check_prefilter("http://evil.example.com/login", _phishtank(index)) == "phishtank"


def test_no_match_returns_none():
    index = frozenset({normalize_url("http://evil.example.com/login")})
    assert check_prefilter("https://example.com", _phishtank(index)) is None


def test_empty_provider_list_never_matches():
    assert check_prefilter("http://evil.example.com/login", []) is None


def test_empty_index_never_matches():
    assert check_prefilter("http://evil.example.com/login", _phishtank(frozenset())) is None


def test_matching_is_normalization_aware():
    """Scheme case, host case, and fragment differences shouldn't defeat a match."""
    index = frozenset({normalize_url("http://evil.example.com/login")})
    assert check_prefilter("HTTP://EVIL.EXAMPLE.COM/login#ignored", _phishtank(index)) == "phishtank"


def test_different_path_does_not_match():
    """Exact-URL matching, not domain-level -- a different path on the same
    host must not match (avoids false positives on shared hosting)."""
    index = frozenset({normalize_url("http://evil.example.com/login")})
    assert check_prefilter("http://evil.example.com/other-page", _phishtank(index)) is None


def test_hostname_index_defaults_to_empty_and_changes_nothing():
    """Omitting the hostname index must behave identically to exact-URL-only matching."""
    index = frozenset({normalize_url("http://evil.example.com/login")})
    assert check_prefilter("http://evil.example.com/other-page", _phishtank(index)) is None
    assert check_prefilter("http://evil.example.com/login", _phishtank(index)) == "phishtank"


def test_hostname_only_request_matches_via_hostname_index():
    """S1's hostname-only default sends no path -- a subdomain-per-tenant
    platform entry should still match via the hostname index even though
    the exact-URL index (which has the recorded path) misses."""
    full_url_index = frozenset({normalize_url("https://attacker.wixstudio.com/en-us")})
    hostname_index = frozenset({"attacker.wixstudio.com"})

    assert check_prefilter("attacker.wixstudio.com", _phishtank(full_url_index)) is None
    assert (
        check_prefilter("attacker.wixstudio.com", _phishtank(full_url_index, hostname_index))
        == "phishtank"
    )


def test_different_path_on_non_platform_host_still_does_not_match_via_hostname_index():
    """A hostname not present in the (curated) hostname index must not
    match, even if hostname-index checking is enabled for other hosts --
    this preserves the shared-hosting false-positive protection."""
    full_url_index = frozenset({normalize_url("http://evil.example.com/login")})
    hostname_index = frozenset({"attacker.wixstudio.com"})

    assert (
        check_prefilter("http://evil.example.com/other-page", _phishtank(full_url_index, hostname_index))
        is None
    )


def test_full_url_request_also_benefits_from_hostname_index():
    """A full-URL request with a *different* path than the recorded entry
    still matches via the hostname index, since the whole subdomain is
    attacker-controlled on these platforms."""
    full_url_index = frozenset({normalize_url("https://attacker.wixstudio.com/en-us")})
    hostname_index = frozenset({"attacker.wixstudio.com"})

    assert (
        check_prefilter(
            "https://attacker.wixstudio.com/different-page", _phishtank(full_url_index, hostname_index)
        )
        == "phishtank"
    )


def test_provider_order_first_match_wins():
    """When multiple providers are configured, the first (list order) match
    decides the source -- later providers are not consulted."""

    class _AlwaysMatch:
        name = "gsb"

        def check(self, url: str) -> bool:
            return True

    class _NeverCalled:
        name = "should-not-be-reached"

        def check(self, url: str) -> bool:
            raise AssertionError("later provider must not be consulted after an earlier match")

    assert check_prefilter("https://example.com", [_AlwaysMatch(), _NeverCalled()]) == "gsb"


def test_second_provider_checked_when_first_misses():
    class _NeverMatch:
        name = "gsb"

        def check(self, url: str) -> bool:
            return False

    index = frozenset({normalize_url("http://evil.example.com/login")})
    providers = [_NeverMatch(), *_phishtank(index)]
    assert check_prefilter("http://evil.example.com/login", providers) == "phishtank"
