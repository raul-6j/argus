"""Tests for src.features.page_artifacts — the shared single-fetch context (P1.0).

Mirrors the SSRF/redirect/size-cap test patterns already established for
src.features.pipeline._fetch_html in tests/features/test_pipeline.py, since
page_artifacts.fetch() intentionally reuses the same bounds.
"""

from __future__ import annotations

from unittest import mock

from src.features import page_artifacts

MODULE = "src.features.page_artifacts"
SSRF_MODULE = "src.utils.ssrf"


def _addrinfo(ip: str, port: int = 80):
    return [(2, 1, 6, "", (ip, port))]


class _FakeResponse:
    def __init__(self, status_code=200, headers=None, chunks=None, encoding="utf-8"):
        self.status_code = status_code
        self.headers = headers or {}
        self._chunks = chunks or []
        self.encoding = encoding
        self.closed = False

    def iter_content(self, chunk_size=8192):
        yield from self._chunks

    def raise_for_status(self):
        if self.status_code >= 400:
            raise RuntimeError(f"HTTP {self.status_code}")

    def close(self):
        self.closed = True


def test_fetch_refuses_private_without_connecting():
    with mock.patch(
        f"{SSRF_MODULE}.socket.getaddrinfo", return_value=_addrinfo("127.0.0.1")
    ), mock.patch(f"{MODULE}._fetch_once") as fetch_once:
        artifacts = page_artifacts.fetch("http://localhost:6379")
    assert artifacts.html is None
    assert artifacts.fetch_error is not None
    assert artifacts.ok is False
    fetch_once.assert_not_called()


def test_fetch_success_records_html_and_final_url():
    resp = _FakeResponse(chunks=[b"<html><title>hi", b"</title></html>"])
    with mock.patch(
        f"{SSRF_MODULE}.socket.getaddrinfo", return_value=_addrinfo("93.184.216.34")
    ), mock.patch(f"{MODULE}._fetch_once", return_value=resp):
        artifacts = page_artifacts.fetch("http://example.com")
    assert artifacts.ok is True
    assert "<title>hi</title>" in artifacts.html
    assert artifacts.final_url == "http://example.com"
    assert artifacts.status_code == 200
    assert artifacts.redirect_chain == []
    assert resp.closed is True


def test_fetch_enforces_size_cap():
    resp = _FakeResponse(chunks=[b"x" * 50])
    with mock.patch(f"{MODULE}.MAX_BODY_BYTES", 10), mock.patch(
        f"{SSRF_MODULE}.socket.getaddrinfo", return_value=_addrinfo("93.184.216.34")
    ), mock.patch(f"{MODULE}._fetch_once", return_value=resp):
        artifacts = page_artifacts.fetch("http://example.com")
    assert artifacts.html is None
    assert artifacts.ok is False
    assert "size cap" in artifacts.fetch_error


def test_fetch_blocks_redirect_to_private():
    redirect = _FakeResponse(status_code=302, headers={"Location": "http://127.0.0.1/"})
    addr = [_addrinfo("93.184.216.34"), _addrinfo("127.0.0.1")]
    with mock.patch(f"{SSRF_MODULE}.socket.getaddrinfo", side_effect=addr), mock.patch(
        f"{MODULE}._fetch_once", return_value=redirect
    ):
        artifacts = page_artifacts.fetch("http://example.com")
    assert artifacts.ok is False
    assert artifacts.redirect_chain == ["http://example.com"]


def test_fetch_follows_safe_redirect_and_records_chain():
    redirect = _FakeResponse(status_code=302, headers={"Location": "http://example.com/final"})
    final = _FakeResponse(chunks=[b"<html>ok</html>"])
    with mock.patch(
        f"{SSRF_MODULE}.socket.getaddrinfo", return_value=_addrinfo("93.184.216.34")
    ), mock.patch(f"{MODULE}._fetch_once", side_effect=[redirect, final]):
        artifacts = page_artifacts.fetch("http://example.com")
    assert artifacts.html == "<html>ok</html>"
    assert artifacts.final_url == "http://example.com/final"
    assert artifacts.redirect_chain == ["http://example.com"]


def test_fetch_too_many_redirects():
    redirect = _FakeResponse(status_code=302, headers={"Location": "http://example.com/x"})
    with mock.patch(
        f"{SSRF_MODULE}.socket.getaddrinfo", return_value=_addrinfo("93.184.216.34")
    ), mock.patch(f"{MODULE}._fetch_once", return_value=redirect):
        artifacts = page_artifacts.fetch("http://example.com")
    assert artifacts.ok is False
    assert "too many redirects" in artifacts.fetch_error


def test_fetch_redirect_with_no_location_header():
    redirect = _FakeResponse(status_code=302, headers={})
    with mock.patch(
        f"{SSRF_MODULE}.socket.getaddrinfo", return_value=_addrinfo("93.184.216.34")
    ), mock.patch(f"{MODULE}._fetch_once", return_value=redirect):
        artifacts = page_artifacts.fetch("http://example.com")
    assert artifacts.ok is False
    assert "Location" in artifacts.fetch_error


def test_fetch_http_error_status_records_failure():
    resp = _FakeResponse(status_code=500)
    with mock.patch(
        f"{SSRF_MODULE}.socket.getaddrinfo", return_value=_addrinfo("93.184.216.34")
    ), mock.patch(f"{MODULE}._fetch_once", return_value=resp):
        artifacts = page_artifacts.fetch("http://example.com")
    assert artifacts.ok is False
    assert artifacts.status_code == 500


def test_fetch_records_response_headers():
    resp = _FakeResponse(chunks=[b"ok"], headers={"Content-Type": "text/html"})
    with mock.patch(
        f"{SSRF_MODULE}.socket.getaddrinfo", return_value=_addrinfo("93.184.216.34")
    ), mock.patch(f"{MODULE}._fetch_once", return_value=resp):
        artifacts = page_artifacts.fetch("http://example.com")
    assert artifacts.response_headers.get("Content-Type") == "text/html"


def test_fetch_never_raises_on_unexpected_exception():
    with mock.patch(
        f"{SSRF_MODULE}.socket.getaddrinfo", return_value=_addrinfo("93.184.216.34")
    ), mock.patch(f"{MODULE}._fetch_once", side_effect=RuntimeError("boom")):
        artifacts = page_artifacts.fetch("http://example.com")
    assert artifacts.ok is False
    assert "boom" in artifacts.fetch_error


def test_fetch_records_fetch_time_ms():
    resp = _FakeResponse(chunks=[b"ok"])
    with mock.patch(
        f"{SSRF_MODULE}.socket.getaddrinfo", return_value=_addrinfo("93.184.216.34")
    ), mock.patch(f"{MODULE}._fetch_once", return_value=resp):
        artifacts = page_artifacts.fetch("http://example.com")
    assert isinstance(artifacts.fetch_time_ms, float)
    assert artifacts.fetch_time_ms >= 0.0


def test_page_artifacts_ok_false_when_fetch_error_set_even_with_html():
    """`.ok` requires both html present AND no fetch_error -- defensive
    invariant, exercised directly rather than only via fetch()."""
    artifacts = page_artifacts.PageArtifacts(
        requested_url="http://example.com", html="<html></html>", fetch_error="something"
    )
    assert artifacts.ok is False


def test_page_artifacts_ok_true_when_html_present_no_error():
    artifacts = page_artifacts.PageArtifacts(requested_url="http://example.com", html="<html></html>")
    assert artifacts.ok is True
