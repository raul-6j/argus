"""Tests for src.features.lexical — URL lexical feature extraction."""

from __future__ import annotations

import math
from unittest import mock

import pytest

from src.features.lexical import (
    FEATURE_KEYS,
    extract_lexical_features,
)


def test_all_feature_keys_present_for_normal_url() -> None:
    """A normal URL yields every declared feature key, none missing."""
    feats = extract_lexical_features("https://login.example.com/path?x=1")
    assert set(feats.keys()) == set(FEATURE_KEYS)


def test_normal_url() -> None:
    """Lexical features are correct for a typical HTTPS URL with a subdomain."""
    url = "https://login.example.com/secure/account"
    feats = extract_lexical_features(url)

    assert feats["url_length"] == len(url)
    assert feats["hostname_length"] == len("login.example.com")
    assert feats["path_length"] == len("/secure/account")
    assert feats["num_dots_in_url"] == url.count(".")
    assert feats["num_dots_in_hostname"] == 2
    assert feats["num_subdomains"] == 1  # "login"
    assert feats["has_ip_address"] is False
    assert feats["has_at_symbol"] is False
    assert feats["has_https"] is True
    assert feats["has_port"] is False
    assert feats["port_number"] == -1
    assert feats["tld"] == "com"
    assert feats["is_suspicious_tld"] is False
    assert feats["domain"] == "example.com"
    assert feats["has_suspicious_keywords"] is True  # login/secure/account
    assert feats["num_hyphens_in_hostname"] == 0
    assert 0.0 < feats["url_entropy"]
    assert 0.0 <= feats["digit_ratio_in_url"] <= 1.0


def test_ip_based_url() -> None:
    """An IPv4 literal hostname is detected as an IP address."""
    feats = extract_lexical_features("http://192.168.0.1/login")
    assert feats["has_ip_address"] is True
    assert feats["has_https"] is False
    # tldextract yields no registered domain / suffix for a bare IP.
    assert feats["tld"] == ""
    assert feats["num_subdomains"] == 0


def test_ipv6_based_url() -> None:
    """An IPv6 literal hostname (bracketed in the URL) is detected."""
    feats = extract_lexical_features("http://[2001:db8::1]/path")
    assert feats["has_ip_address"] is True


def test_url_with_port() -> None:
    """An explicit port is captured in has_port / port_number."""
    feats = extract_lexical_features("http://example.com:8080/path")
    assert feats["has_port"] is True
    assert feats["port_number"] == 8080


def test_url_with_at_symbol() -> None:
    """The @ symbol (credential/obfuscation marker) is detected."""
    feats = extract_lexical_features("http://user@evil.com/login")
    assert feats["has_at_symbol"] is True


def test_double_slash_redirect() -> None:
    """A // after the scheme separator is flagged as a redirect marker."""
    feats = extract_lexical_features("http://example.com/redirect//evil.com")
    assert feats["has_double_slash_redirect"] is True

    clean = extract_lexical_features("http://example.com/normal/path")
    assert clean["has_double_slash_redirect"] is False


def test_suspicious_tld() -> None:
    """A TLD on the known-bad list flips is_suspicious_tld."""
    feats = extract_lexical_features("http://free-prize.tk/claim")
    assert feats["is_suspicious_tld"] is True
    assert feats["tld"] == "tk"


def test_known_shortener_detected() -> None:
    """A domain on the known-shortener list flips has_shortening."""
    feats = extract_lexical_features("https://bit.ly/3xYzAbc")
    assert feats["has_shortening"] is True


def test_normal_domain_not_shortener() -> None:
    """An ordinary domain does not trip has_shortening."""
    feats = extract_lexical_features("https://example.com/path")
    assert feats["has_shortening"] is False


def test_hyphens_in_hostname() -> None:
    """Hyphens are counted in the hostname only, not the whole URL."""
    feats = extract_lexical_features("http://my-secure-bank.com/a-b")
    assert feats["num_hyphens_in_hostname"] == 2


def test_empty_string() -> None:
    """An empty string yields an all-None feature dict."""
    feats = extract_lexical_features("")
    assert set(feats.keys()) == set(FEATURE_KEYS)
    assert all(value is None for value in feats.values())


def test_whitespace_only_string() -> None:
    """A whitespace-only string is treated as unusable input."""
    feats = extract_lexical_features("   ")
    assert all(value is None for value in feats.values())


def test_none_input() -> None:
    """None input yields an all-None feature dict without raising."""
    feats = extract_lexical_features(None)
    assert set(feats.keys()) == set(FEATURE_KEYS)
    assert all(value is None for value in feats.values())


def test_non_string_input() -> None:
    """A non-string, non-None input is handled gracefully."""
    feats = extract_lexical_features(12345)  # type: ignore[arg-type]
    assert all(value is None for value in feats.values())


def test_unicode_url() -> None:
    """A unicode (IDN) URL is processed without raising and yields all keys."""
    url = "https://例え.テスト/ログイン"
    feats = extract_lexical_features(url)
    assert set(feats.keys()) == set(FEATURE_KEYS)
    assert feats["url_length"] == len(url)
    assert feats["has_https"] is True
    # Entropy must be a finite float for non-trivial input.
    assert isinstance(feats["url_entropy"], float)
    assert math.isfinite(feats["url_entropy"])


def test_entropy_zero_for_repeated_chars() -> None:
    """A single repeated character has zero entropy."""
    from src.features.lexical import _shannon_entropy

    assert _shannon_entropy("aaaa") == 0.0
    assert _shannon_entropy("") == 0.0


def test_digit_ratio() -> None:
    """digit_ratio_in_url is the fraction of digit characters."""
    url = "http://a1b2.com"  # 2 digits out of len(url)
    feats = extract_lexical_features(url)
    expected = sum(c.isdigit() for c in url) / len(url)
    assert feats["digit_ratio_in_url"] == pytest.approx(expected)


def test_malformed_port_returns_false_and_sentinel() -> None:
    """A non-numeric or out-of-range port yields has_port=False, port_number=-1."""
    for url in ("http://x:abc/", "http://x:99999/"):
        feats = extract_lexical_features(url)
        assert feats["has_port"] is False, url
        assert feats["port_number"] == -1, url


def test_schemeless_input_does_not_crash() -> None:
    """A schemeless URL is handled gracefully (all keys present)."""
    feats = extract_lexical_features("example.com/login")
    assert set(feats.keys()) == set(FEATURE_KEYS)
    assert feats["has_https"] is False
    assert feats["has_suspicious_keywords"] is True  # 'login'


def test_oversized_url_handled() -> None:
    """A very long URL is processed without error."""
    url = "http://example.com/" + "a" * 20000
    feats = extract_lexical_features(url)
    assert feats["url_length"] == len(url)
    assert isinstance(feats["url_entropy"], float)


def test_single_feature_failure_is_isolated() -> None:
    """Iron Law #3: one failing computation sets only its key to None.

    Forces the entropy computation to raise and asserts every other feature is
    still produced — exercising the per-field _safe resilience path.
    """

    def _boom(_text: str) -> float:
        raise ValueError("entropy boom")

    with mock.patch("src.features.lexical._shannon_entropy", side_effect=_boom):
        feats = extract_lexical_features("https://login.example.com/path")

    assert feats["url_entropy"] is None
    # Everything else survived.
    non_entropy = {k: v for k, v in feats.items() if k != "url_entropy"}
    assert all(v is not None for v in non_entropy.values())
    assert feats["has_https"] is True
    assert feats["url_length"] > 0
