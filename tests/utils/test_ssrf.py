"""Tests for src.utils.ssrf — the centralised SSRF guard.

Moved here from tests/features/test_pipeline.py (Phase 6, Task 6.2) when the
guard was extracted out of pipeline.py into its own reusable module.
"""

from __future__ import annotations

import socket as _socket
from unittest import mock

import pytest

from src.utils.ssrf import is_safe_fetch_url

MODULE = "src.utils.ssrf"


def _addrinfo(ip: str, port: int = 80):
    """Build a getaddrinfo-shaped result for a single IP."""
    return [(2, 1, 6, "", (ip, port))]


def test_safe_url_allows_public_ip():
    """A host resolving to a public IP is allowed."""
    with mock.patch(f"{MODULE}.socket.getaddrinfo", return_value=_addrinfo("93.184.216.34")):
        assert is_safe_fetch_url("http://example.com") is True


@pytest.mark.parametrize(
    "ip",
    [
        "127.0.0.1",        # loopback (e.g. localhost:6379 redis)
        "10.0.0.5",         # private
        "192.168.1.1",      # private
        "169.254.169.254",  # link-local — cloud metadata endpoint
        "0.0.0.0",          # unspecified
        "100.64.0.1",       # CGNAT (RFC 6598) — not covered by ipaddress.is_private
        "100.100.100.1",    # CGNAT, mid-range
    ],
)
def test_safe_url_blocks_internal_ips(ip):
    """Hosts resolving to internal/metadata/CGNAT IPs are refused (SSRF)."""
    with mock.patch(f"{MODULE}.socket.getaddrinfo", return_value=_addrinfo(ip)):
        assert is_safe_fetch_url(f"http://target/{ip}") is False


@pytest.mark.parametrize("url", ["ftp://example.com/x", "file:///etc/passwd", "gopher://x"])
def test_safe_url_blocks_non_http_schemes(url):
    """Only http/https are permitted."""
    assert is_safe_fetch_url(url) is False


def test_safe_url_blocks_unresolvable_host():
    """A host that fails DNS resolution is refused."""
    with mock.patch(f"{MODULE}.socket.getaddrinfo", side_effect=_socket.gaierror):
        assert is_safe_fetch_url("http://does-not-exist.invalid") is False


def test_safe_url_blocks_missing_host():
    """A URL with no hostname (e.g. malformed) is refused."""
    assert is_safe_fetch_url("http://") is False
