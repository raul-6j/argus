"""Tests for src.utils.validators — request-level URL validation."""

from __future__ import annotations

import pytest

from src.utils.validators import validate_url


@pytest.mark.parametrize(
    "url",
    ["https://example.com", "http://example.com/path?q=1", "https://sub.example.com:8443/x"],
)
def test_valid_urls_pass(url):
    ok, reason = validate_url(url)
    assert ok is True
    assert reason is None


@pytest.mark.parametrize("bad", [None, "", "   ", 123, [], {}])
def test_non_string_or_empty_rejected(bad):
    ok, reason = validate_url(bad)
    assert ok is False
    assert reason is not None


def test_too_long_url_rejected():
    ok, reason = validate_url("https://example.com/" + "a" * 3000)
    assert ok is False
    assert "length" in reason


@pytest.mark.parametrize("url", ["ftp://example.com", "file:///etc/passwd", "javascript:alert(1)"])
def test_non_http_scheme_rejected(url):
    ok, reason = validate_url(url)
    assert ok is False
    assert "scheme" in reason


def test_missing_hostname_rejected():
    ok, reason = validate_url("http://")
    assert ok is False
    assert "hostname" in reason


@pytest.mark.parametrize("url", ["http://localhost", "http://127.0.0.1", "http://0.0.0.0", "http://[::1]"])
def test_localhost_rejected_by_default(url):
    ok, reason = validate_url(url)
    assert ok is False
    assert "localhost" in reason


@pytest.mark.parametrize("url", ["http://localhost", "http://127.0.0.1"])
def test_localhost_allowed_when_flagged(url):
    ok, reason = validate_url(url, allow_localhost=True)
    assert ok is True
    assert reason is None
