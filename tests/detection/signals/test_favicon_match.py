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
