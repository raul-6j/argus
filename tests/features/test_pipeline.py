"""Tests for src.features.pipeline — the unified extraction orchestrator.

HTML fetching and domain intel are mocked; no real network access occurs.
"""

from __future__ import annotations

from pathlib import Path
from unittest import mock

import numpy as np
import pytest

from src.features import pipeline
from src.features.pipeline import extract_features

MODULE = "src.features.pipeline"
FIXTURES = Path(__file__).resolve().parents[1] / "fixtures"


@pytest.fixture(autouse=True)
def _clear_config_cache():
    """Ensure the lru_cached config loader does not leak across tests."""
    pipeline._load_feature_config.cache_clear()
    yield
    pipeline._load_feature_config.cache_clear()


# --------------------------------------------------------------------------- #
# Component selection
# --------------------------------------------------------------------------- #
def test_lexical_only_by_default():
    """With no HTML and defaults, only the lexical tier runs."""
    fv = extract_features("https://login.example.com/path")
    assert fv.components_run == ["lexical"]
    assert fv.features["url_length"] == len("https://login.example.com/path")
    # HTML/domain features absent → listed as missing.
    assert "num_forms" in fv.features_missing
    assert "domain_age_days" in fv.features_missing


def test_html_runs_when_html_provided():
    """Providing HTML triggers the HTML tier without fetching."""
    html = (FIXTURES / "legit_page.html").read_text(encoding="utf-8")
    with mock.patch(f"{MODULE}._fetch_html") as fetch:
        fv = extract_features("https://example.com", html=html)
    fetch.assert_not_called()
    assert "html" in fv.components_run
    assert fv.features["num_images"] == 2
    assert fv.features["has_favicon"] is True


def test_html_fetched_when_fetch_html_true():
    """fetch_html=True fetches the page when no HTML is supplied."""
    html = "<html><title>Fetched</title><body><p>hi</p></body></html>"
    with mock.patch(f"{MODULE}._fetch_html", return_value=html) as fetch:
        fv = extract_features("https://example.com", fetch_html=True)
    fetch.assert_called_once()
    assert "html" in fv.components_run
    assert fv.features["title_length"] == len("Fetched")


def test_provided_html_takes_precedence_over_fetch():
    """If HTML is provided, fetch_html does not trigger a fetch."""
    html = "<html><title>Provided</title></html>"
    with mock.patch(f"{MODULE}._fetch_html") as fetch:
        fv = extract_features("https://example.com", html=html, fetch_html=True)
    fetch.assert_not_called()
    assert fv.features["title_length"] == len("Provided")


def test_failed_fetch_skips_html_tier():
    """A failed fetch (None) means the HTML tier does not run."""
    with mock.patch(f"{MODULE}._fetch_html", return_value=None):
        fv = extract_features("https://example.com", fetch_html=True)
    assert "html" not in fv.components_run


def test_domain_intel_runs_when_requested():
    """include_domain=True runs the domain-intel tier with the registered domain."""
    fake = {
        "domain_age_days": 365,
        "days_until_expiry": 100,
        "registrar": "R",
        "is_recently_registered": False,
        "has_dns_a_record": True,
        "has_mx_record": True,
        "ip_address": "1.2.3.4",
        "ip_country": "US",
    }
    with mock.patch(
        f"{MODULE}.domain_intel.extract_domain_intel", return_value=fake
    ) as m:
        fv = extract_features("https://sub.example.com/x", include_domain=True)
    m.assert_called_once_with("example.com")
    assert "domain_intel" in fv.components_run
    assert fv.features["domain_age_days"] == 365


def test_domain_intel_off_by_default():
    """Domain intel does not run unless explicitly requested."""
    with mock.patch(f"{MODULE}.domain_intel.extract_domain_intel") as m:
        fv = extract_features("https://example.com")
    m.assert_not_called()
    assert "domain_intel" not in fv.components_run


def test_all_tiers_together():
    """All three tiers run and merge into one feature dict."""
    html = "<html><title>T</title><body><input type='password'></body></html>"
    fake_domain = {k: 0 for k in pipeline.domain_intel.DOMAIN_INTEL_KEYS}
    with mock.patch(
        f"{MODULE}.domain_intel.extract_domain_intel", return_value=fake_domain
    ):
        fv = extract_features(
            "https://example.com", html=html, include_domain=True
        )
    assert set(fv.components_run) == {"lexical", "html", "domain_intel"}
    assert fv.features["has_password_field"] is True
    assert fv.features["url_length"] > 0


# --------------------------------------------------------------------------- #
# Metadata
# --------------------------------------------------------------------------- #
def test_extraction_time_recorded():
    """extraction_time_ms is a non-negative float."""
    fv = extract_features("https://example.com")
    assert isinstance(fv.extraction_time_ms, float)
    assert fv.extraction_time_ms >= 0.0


def test_model_version_compatible_true_when_all_tiers_run():
    """When every contract feature is produced, the vector is model-ready."""
    html = "<html><title>t</title><body><p>x</p></body></html>"
    fake_domain = {k: 0 for k in pipeline.domain_intel.DOMAIN_INTEL_KEYS}
    with mock.patch(
        f"{MODULE}.domain_intel.extract_domain_intel", return_value=fake_domain
    ):
        fv = extract_features("https://example.com", html=html, include_domain=True)
    assert fv.model_version_compatible is True
    assert fv.model_version == "0.1.0"


def test_model_version_incompatible_when_tiers_not_run():
    """Honest flag: lexical-only leaves HTML/domain slots unproduced → False."""
    fv = extract_features("https://example.com")
    assert fv.model_version_compatible is False
    assert "num_forms" in fv.features_missing


def test_model_version_incompatible_when_config_has_unknown_feature(tmp_path):
    """A config feature the extractors cannot produce → incompatible."""
    cfg = tmp_path / "feature_config.yaml"
    cfg.write_text(
        "model_version: '9.9.9'\nfeature_order:\n  - url_length\n  - made_up_feature\n",
        encoding="utf-8",
    )
    fv = extract_features("https://example.com", config_path=str(cfg))
    assert fv.model_version_compatible is False


def test_missing_config_does_not_crash(tmp_path):
    """A missing config yields an empty contract but no crash."""
    fv = extract_features(
        "https://example.com", config_path=str(tmp_path / "nope.yaml")
    )
    assert fv.feature_order == ()
    assert fv.model_version == "unknown"
    # Lexical still ran.
    assert fv.features["url_length"] > 0


# --------------------------------------------------------------------------- #
# to_model_input
# --------------------------------------------------------------------------- #
def test_to_model_input_order_and_length():
    """The array matches feature_order length and element ordering."""
    fv = extract_features("https://example.com")
    arr = fv.to_model_input()
    assert isinstance(arr, np.ndarray)
    assert arr.shape == (len(fv.feature_order),)
    # url_length is the first feature in the contract.
    assert arr[0] == float(fv.features["url_length"])


def test_to_model_input_bool_to_float():
    """Boolean features become 1.0 / 0.0 in the array."""
    fv = extract_features("https://example.com")  # has_https True
    idx = fv.feature_order.index("has_https")
    arr = fv.to_model_input()
    assert arr[idx] == 1.0


def test_to_model_input_fills_missing_with_nan():
    """Missing features (e.g. un-run domain intel) become NaN by default."""
    fv = extract_features("https://example.com")
    idx = fv.feature_order.index("domain_age_days")
    arr = fv.to_model_input()
    assert np.isnan(arr[idx])


def test_to_model_input_custom_fill_value():
    """A custom fill_value replaces missing features."""
    fv = extract_features("https://example.com")
    idx = fv.feature_order.index("domain_age_days")
    arr = fv.to_model_input(fill_value=-1.0)
    assert arr[idx] == -1.0


def test_to_model_input_non_numeric_treated_as_missing():
    """A non-numeric value in a contract slot is filled, not crashed on."""
    fv = extract_features("https://example.com")
    # Inject a string into a numeric slot.
    fv.features["url_length"] = "not a number"
    arr = fv.to_model_input(fill_value=0.0)
    assert arr[0] == 0.0


# --------------------------------------------------------------------------- #
# Hardened fetch (_fetch_html)
#
# The SSRF guard itself (src.utils.ssrf.is_safe_fetch_url) is unit-tested in
# tests/utils/test_ssrf.py (Phase 6, Task 6.2 — extracted into its own
# reusable module). These tests only verify _fetch_html's wiring to it.
# --------------------------------------------------------------------------- #
def _addrinfo(ip: str, port: int = 80):
    """Build a getaddrinfo-shaped result for a single IP."""
    return [(2, 1, 6, "", (ip, port))]


SSRF_MODULE = "src.utils.ssrf"



class _FakeResponse:
    """Minimal stand-in for a streaming requests.Response."""

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


def test_fetch_html_refuses_private_without_connecting():
    """A private-resolving URL is refused before any GET is issued."""
    with mock.patch(
        f"{SSRF_MODULE}.socket.getaddrinfo", return_value=_addrinfo("127.0.0.1")
    ), mock.patch(f"{MODULE}._fetch_once") as fetch_once:
        result = pipeline._fetch_html("http://localhost:6379")
    assert result is None
    fetch_once.assert_not_called()


def test_fetch_html_success_streams_body():
    """A safe URL returns the decoded, streamed body."""
    resp = _FakeResponse(chunks=[b"<html><title>hi", b"</title></html>"])
    with mock.patch(
        f"{SSRF_MODULE}.socket.getaddrinfo", return_value=_addrinfo("93.184.216.34")
    ), mock.patch(f"{MODULE}._fetch_once", return_value=resp):
        out = pipeline._fetch_html("http://example.com")
    assert out is not None
    assert "<title>hi</title>" in out
    assert resp.closed is True


def test_fetch_html_enforces_size_cap():
    """A body exceeding the byte cap yields None (no memory blowup)."""
    resp = _FakeResponse(chunks=[b"x" * 50])
    with mock.patch(f"{MODULE}._MAX_HTML_BYTES", 10), mock.patch(
        f"{SSRF_MODULE}.socket.getaddrinfo", return_value=_addrinfo("93.184.216.34")
    ), mock.patch(f"{MODULE}._fetch_once", return_value=resp):
        out = pipeline._fetch_html("http://example.com")
    assert out is None


def test_fetch_html_blocks_redirect_to_private():
    """A redirect pointing at an internal IP is refused at the next hop."""
    redirect = _FakeResponse(status_code=302, headers={"Location": "http://127.0.0.1/"})
    addr = [_addrinfo("93.184.216.34"), _addrinfo("127.0.0.1")]
    with mock.patch(f"{SSRF_MODULE}.socket.getaddrinfo", side_effect=addr), mock.patch(
        f"{MODULE}._fetch_once", return_value=redirect
    ):
        out = pipeline._fetch_html("http://example.com")
    assert out is None


def test_fetch_html_follows_safe_redirect():
    """A redirect to another safe URL is followed and its body returned."""
    redirect = _FakeResponse(status_code=302, headers={"Location": "http://example.com/final"})
    final = _FakeResponse(chunks=[b"<html>ok</html>"])
    with mock.patch(
        f"{SSRF_MODULE}.socket.getaddrinfo", return_value=_addrinfo("93.184.216.34")
    ), mock.patch(f"{MODULE}._fetch_once", side_effect=[redirect, final]):
        out = pipeline._fetch_html("http://example.com")
    assert out == "<html>ok</html>"


def test_fetch_html_too_many_redirects():
    """Exceeding the redirect cap yields None."""
    redirect = _FakeResponse(status_code=302, headers={"Location": "http://example.com/x"})
    with mock.patch(
        f"{SSRF_MODULE}.socket.getaddrinfo", return_value=_addrinfo("93.184.216.34")
    ), mock.patch(f"{MODULE}._fetch_once", return_value=redirect):
        out = pipeline._fetch_html("http://example.com")
    assert out is None
