"""Tests for src.detection.signals.favicon_match (A2).

Uses synthetic in-memory images (never real network/live-site favicons) so
the reference hashes and the "page's" favicon are both computed by the same
hashing code — deterministic, offline, no dependency on real brand assets.
"""

from __future__ import annotations

import base64
import io
from unittest import mock

from src.detection.brand_reference import Brand, BrandIndex
from src.detection.hashing import average_hash, mmh3_32
from src.detection.signals import favicon_match
from src.features.page_artifacts import PageArtifacts

MODULE = "src.detection.signals.favicon_match"


def _png_bytes(color=(10, 20, 30), size=(16, 16)) -> bytes:
    from PIL import Image

    img = Image.new("RGB", size, color=color)
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    return buf.getvalue()


def _data_uri(raw: bytes) -> str:
    return f"data:image/png;base64,{base64.b64encode(raw).decode()}"


def _brand_index_for(raw_favicon: bytes, domain="brand.com", name="Brand") -> BrandIndex:
    mmh3_hash = mmh3_32(base64.b64encode(raw_favicon))
    ahash = average_hash(raw_favicon)
    brand = Brand(
        name=name,
        domains=(domain,),
        aliases=(name.lower(),),
        favicon_mmh3=(mmh3_hash,),
        logo_phash=(format(ahash, "016x"),),
    )
    return BrandIndex(brands=(brand,))


class TestExactMatch:
    def test_exact_favicon_hash_match_is_hard_override(self):
        raw = _png_bytes()
        idx = _brand_index_for(raw)
        html = f'<html><head><link rel="icon" href="{_data_uri(raw)}"></head></html>'
        artifacts = PageArtifacts(requested_url="x", html=html, final_url="https://attacker.com")

        sig = favicon_match.evaluate(artifacts, "https://attacker.com", idx)
        assert sig.triggered is True
        assert sig.is_hard_override is True
        assert sig.evidence["match_type"] == "exact_favicon_hash"
        assert sig.evidence["impersonated_brand"] == "Brand"
        assert sig.evidence["hash_distance"] == 0

    def test_matching_the_brands_own_domain_is_neutral(self):
        raw = _png_bytes()
        idx = _brand_index_for(raw, domain="brand.com")
        html = f'<html><head><link rel="icon" href="{_data_uri(raw)}"></head></html>'
        artifacts = PageArtifacts(requested_url="x", html=html, final_url="https://brand.com")

        sig = favicon_match.evaluate(artifacts, "https://brand.com", idx)
        assert sig.triggered is False


class TestSoftMatch:
    def test_similar_but_not_identical_image_is_soft_match(self):
        raw = _png_bytes(color=(10, 10, 10))
        # A visually-similar-but-not-byte-identical favicon: same solid
        # color family, different exact bytes/size -> mmh3 differs, but the
        # average-hash of a uniform image is still 0 (all pixels == mean),
        # matching the reference's all-zero hash within tolerance.
        similar_raw = _png_bytes(color=(12, 12, 12), size=(32, 32))
        idx = _brand_index_for(raw)
        html = f'<html><head><link rel="icon" href="{_data_uri(similar_raw)}"></head></html>'
        artifacts = PageArtifacts(requested_url="x", html=html, final_url="https://attacker.com")

        sig = favicon_match.evaluate(artifacts, "https://attacker.com", idx, phash_tolerance=8)
        assert sig.triggered is True
        assert sig.is_hard_override is False
        assert sig.evidence["match_type"] == "perceptual_hash"


class TestRealWorldFalsePositiveRegression:
    """Regression test for a real false positive found during Phase 1
    validation (16 Jul 2026), reproduced live with phash_tolerance=8 (the
    original default):

    * Bank of America's real, live-resolved favicon (its homepage's actual
      <link rel="icon"> points to a higher-res apple-touch-icon variant,
      hash 0xffff830081e3ffff -- distinct from the plain /favicon.ico hash
      scripts/build_brand_reference.py stored for it) landed at Hamming
      distance 8 from Apple's *stored* reference hash and was flagged
      phishing on Bank of America's own legitimate domain.
    * Wells Fargo's favicon (hash 0x0000ff7f7e540000, same value whether
      resolved live or via plain /favicon.ico) landed at distance 8 from
      USPS's stored hash and was likewise flagged phishing on its own
      domain.

    Both real collisions happen to measure exactly 8 bits -- the same value
    the original tolerance used, guaranteeing these false positives. Fixed
    by lowering the default to 3 (configs/detection_config.yaml), which has
    a 5-bit safety margin below every pairwise distance found across the 23
    populated real brand favicons as of 16 Jul 2026 (see
    docs/PHASE_1_VALIDATION_REPORT.md for the full pairwise analysis). If
    the brand reference is ever regenerated, re-run that analysis before
    trusting this margin still holds.
    """

    def _real_hash_index(self) -> BrandIndex:
        return BrandIndex(
            brands=(
                Brand(name="Apple", domains=("apple.com",), logo_phash=("ffffe3c3c3e3ffff",)),
                Brand(
                    name="Bank of America",
                    domains=("bankofamerica.com",),
                    logo_phash=("ffff830081e3ffff",),
                ),
                Brand(name="USPS", domains=("usps.com",), logo_phash=("80e0ff7f7e70c000",)),
                Brand(
                    name="Wells Fargo", domains=("wellsfargo.com",), logo_phash=("0000ff7f7e540000",)
                ),
            )
        )

    def test_default_tolerance_does_not_flag_bank_of_americas_own_favicon(self):
        idx = self._real_hash_index()
        html = '<html><head><link rel="icon" href="https://bankofamerica.com/favicon.ico"></head></html>'
        artifacts = PageArtifacts(requested_url="x", html=html, final_url="https://bankofamerica.com")
        with mock.patch(
            f"{MODULE}._fetch_favicon_bytes", return_value=b"placeholder-not-a-real-image"
        ), mock.patch(f"{MODULE}.average_hash", return_value=0xFFFF830081E3FFFF), mock.patch(
            f"{MODULE}.mmh3_32", return_value=999999  # force a miss on the exact-hash path
        ):
            sig = favicon_match.evaluate(artifacts, "https://bankofamerica.com", idx)
        assert sig.triggered is False

    def test_default_tolerance_does_not_flag_wells_fargos_own_favicon(self):
        idx = self._real_hash_index()
        html = '<html><head><link rel="icon" href="https://wellsfargo.com/favicon.ico"></head></html>'
        artifacts = PageArtifacts(requested_url="x", html=html, final_url="https://wellsfargo.com")
        with mock.patch(
            f"{MODULE}._fetch_favicon_bytes", return_value=b"placeholder-not-a-real-image"
        ), mock.patch(f"{MODULE}.average_hash", return_value=0x0000FF7F7E540000), mock.patch(
            f"{MODULE}.mmh3_32", return_value=999999
        ):
            sig = favicon_match.evaluate(artifacts, "https://wellsfargo.com", idx)
        assert sig.triggered is False

    def test_distance_8_no_longer_within_default_tolerance(self):
        """Direct unit check on the boundary itself: distance 8 (the exact
        real-world collision distance, in both observed cases) must not
        trigger at the new default."""
        from src.detection.hashing import hamming_distance

        bofa_live = 0xFFFF830081E3FFFF
        apple_stored = 0xFFFFE3C3C3E3FFFF
        wells_fargo = 0x0000FF7F7E540000
        usps_stored = 0x80E0FF7F7E70C000

        assert hamming_distance(bofa_live, apple_stored) == 8
        assert hamming_distance(wells_fargo, usps_stored) == 8
        assert favicon_match._DEFAULT_PHASH_TOLERANCE < 8


class TestNeutralCases:
    def test_no_page_artifacts_is_neutral(self):
        idx = _brand_index_for(_png_bytes())
        sig = favicon_match.evaluate(None, "https://example.com", idx)
        assert sig.triggered is False

    def test_failed_fetch_is_neutral(self):
        idx = _brand_index_for(_png_bytes())
        artifacts = PageArtifacts(requested_url="x", html=None, fetch_error="dead")
        sig = favicon_match.evaluate(artifacts, "https://example.com", idx)
        assert sig.triggered is False

    def test_empty_brand_index_is_neutral(self):
        artifacts = PageArtifacts(requested_url="x", html="<html></html>", final_url="https://example.com")
        sig = favicon_match.evaluate(artifacts, "https://example.com", BrandIndex(brands=()))
        assert sig.triggered is False

    def test_no_favicon_link_and_favicon_ico_fetch_fails_is_neutral(self):
        idx = _brand_index_for(_png_bytes())
        artifacts = PageArtifacts(
            requested_url="x", html="<html><body>no icon here</body></html>", final_url="https://example.com"
        )
        with mock.patch(f"{MODULE}._fetch_favicon_bytes", return_value=None):
            sig = favicon_match.evaluate(artifacts, "https://example.com", idx)
        assert sig.triggered is False

    def test_undecodable_favicon_bytes_is_neutral(self):
        idx = _brand_index_for(_png_bytes())
        html = f'<html><head><link rel="icon" href="{_data_uri(b"not a real image")}"></head></html>'
        artifacts = PageArtifacts(requested_url="x", html=html, final_url="https://attacker.com")
        sig = favicon_match.evaluate(artifacts, "https://attacker.com", idx)
        assert sig.triggered is False


class TestSSRF:
    """A redirect from the favicon URL must be re-validated on every hop --
    `requests`' default auto-follow-redirects behavior would otherwise
    validate only the initial URL and then silently follow a 3xx response
    to any address, including a private/internal one."""

    def _addrinfo(self, ip: str, port: int = 443):
        return [(2, 1, 6, "", (ip, port))]

    def test_redirect_to_private_ip_is_refused(self):
        idx = _brand_index_for(_png_bytes())
        html = '<html><head><link rel="icon" href="https://attacker.com/favicon.ico"></head></html>'
        artifacts = PageArtifacts(requested_url="x", html=html, final_url="https://attacker.com")

        redirect_resp = mock.Mock(status_code=302, headers={"Location": "http://169.254.169.254/latest/meta-data/"})
        addr_sequence = [self._addrinfo("93.184.216.34"), self._addrinfo("169.254.169.254")]

        with mock.patch("src.utils.ssrf.socket.getaddrinfo", side_effect=addr_sequence), mock.patch(
            "requests.get", return_value=redirect_resp
        ) as m_get:
            sig = favicon_match.evaluate(artifacts, "https://attacker.com", idx)

        assert sig.triggered is False
        # The second (internal) hop must never have been fetched.
        assert m_get.call_count == 1

    def test_redirect_passes_allow_redirects_false(self):
        """Every request.get call must disable auto-redirect-following so
        the manual per-hop SSRF check is actually the thing deciding
        whether a redirect is followed."""
        idx = _brand_index_for(_png_bytes())
        html = '<html><head><link rel="icon" href="https://attacker.com/favicon.ico"></head></html>'
        artifacts = PageArtifacts(requested_url="x", html=html, final_url="https://attacker.com")

        ok_resp = mock.Mock(status_code=200)
        ok_resp.iter_content = mock.Mock(return_value=iter([]))

        with mock.patch(
            "src.utils.ssrf.socket.getaddrinfo", return_value=self._addrinfo("93.184.216.34")
        ), mock.patch("requests.get", return_value=ok_resp) as m_get:
            favicon_match.evaluate(artifacts, "https://attacker.com", idx)

        assert m_get.call_args.kwargs.get("allow_redirects") is False

    def test_too_many_favicon_redirects_is_neutral(self):
        idx = _brand_index_for(_png_bytes())
        html = '<html><head><link rel="icon" href="https://attacker.com/favicon.ico"></head></html>'
        artifacts = PageArtifacts(requested_url="x", html=html, final_url="https://attacker.com")

        redirect_resp = mock.Mock(status_code=302, headers={"Location": "https://attacker.com/favicon.ico"})

        with mock.patch(
            "src.utils.ssrf.socket.getaddrinfo", return_value=self._addrinfo("93.184.216.34")
        ), mock.patch("requests.get", return_value=redirect_resp):
            sig = favicon_match.evaluate(artifacts, "https://attacker.com", idx)

        assert sig.triggered is False


class TestFaviconUrlResolution:
    def test_falls_back_to_favicon_ico_when_no_link_tag(self):
        idx = _brand_index_for(_png_bytes())
        artifacts = PageArtifacts(
            requested_url="x", html="<html><body>no icon link</body></html>", final_url="https://attacker.com"
        )
        with mock.patch(f"{MODULE}._fetch_favicon_bytes") as m:
            m.return_value = None
            favicon_match.evaluate(artifacts, "https://attacker.com", idx)
        called_url = m.call_args[0][0]
        assert called_url == "https://attacker.com/favicon.ico"

    def test_resolves_relative_favicon_href(self):
        idx = _brand_index_for(_png_bytes())
        html = '<html><head><link rel="shortcut icon" href="/static/fav.png"></head></html>'
        artifacts = PageArtifacts(requested_url="x", html=html, final_url="https://attacker.com/page")
        with mock.patch(f"{MODULE}._fetch_favicon_bytes") as m:
            m.return_value = None
            favicon_match.evaluate(artifacts, "https://attacker.com/page", idx)
        called_url = m.call_args[0][0]
        assert called_url == "https://attacker.com/static/fav.png"


class TestRobustness:
    def test_never_raises_on_garbage_html(self):
        idx = _brand_index_for(_png_bytes())
        artifacts = PageArtifacts(requested_url="x", html="<<<not html>>>", final_url="https://attacker.com")
        sig = favicon_match.evaluate(artifacts, "https://attacker.com", idx)
        assert sig.triggered in (True, False)  # doesn't raise
