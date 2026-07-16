"""Tests for src.detection.signals.redirect_chain (Phase 2, A5)."""

from __future__ import annotations

from src.detection.brand_reference import Brand, BrandIndex
from src.detection.signals import redirect_chain
from src.features.page_artifacts import PageArtifacts


def _index() -> BrandIndex:
    return BrandIndex(brands=(Brand(name="PayPal", domains=("paypal.com",), aliases=("paypal",)),))


class TestNeutralCases:
    def test_no_page_artifacts_is_neutral(self):
        sig = redirect_chain.evaluate(None, "https://example.com", _index())
        assert sig.triggered is False

    def test_no_redirect_at_all_is_neutral(self):
        artifacts = PageArtifacts(requested_url="https://example.com", final_url="https://example.com", redirect_chain=[])
        sig = redirect_chain.evaluate(artifacts, "https://example.com", _index())
        assert sig.triggered is False

    def test_http_to_https_same_domain_is_neutral(self):
        """The most common legitimate redirect -- must never false-trigger."""
        artifacts = PageArtifacts(
            requested_url="http://example.com", final_url="https://example.com",
            redirect_chain=["http://example.com"],
        )
        sig = redirect_chain.evaluate(artifacts, "http://example.com", _index())
        assert sig.triggered is False

    def test_apex_to_www_same_domain_is_neutral(self):
        artifacts = PageArtifacts(
            requested_url="https://example.com", final_url="https://www.example.com",
            redirect_chain=["https://example.com"],
        )
        sig = redirect_chain.evaluate(artifacts, "https://example.com", _index())
        assert sig.triggered is False

    def test_shortener_landing_on_unrelated_legit_site_is_neutral(self):
        """A shortener redirecting to an ordinary, non-brand-impersonating
        site must not be flagged -- redirects through many domains
        (ad networks, affiliate links) are extremely common and benign."""
        artifacts = PageArtifacts(
            requested_url="https://bit.ly/abc", final_url="https://wikipedia.org",
            redirect_chain=["https://bit.ly/abc"],
        )
        sig = redirect_chain.evaluate(artifacts, "https://bit.ly/abc", _index())
        assert sig.triggered is False

    def test_no_final_url_is_neutral(self):
        artifacts = PageArtifacts(requested_url="https://bit.ly/abc", final_url=None, redirect_chain=["https://bit.ly/abc"])
        sig = redirect_chain.evaluate(artifacts, "https://bit.ly/abc", _index())
        assert sig.triggered is False


class TestLaunderingDetected:
    def test_shortener_landing_on_lookalike_domain_triggers(self):
        artifacts = PageArtifacts(
            requested_url="https://bit.ly/xyz", final_url="https://paypal-secure-login.net",
            redirect_chain=["https://bit.ly/xyz"],
        )
        sig = redirect_chain.evaluate(artifacts, "https://bit.ly/xyz", _index())
        assert sig.triggered is True
        assert sig.evidence["shortener_used"] is True
        assert sig.evidence["final_domain"] == "paypal-secure-login.net"
        assert sig.evidence["impersonated_brand"] == "PayPal"

    def test_non_shortener_cross_domain_landing_on_lookalike_also_triggers(self):
        """Laundering doesn't require a known shortener -- any cross-domain
        redirect landing on a brand look-alike is worth flagging."""
        artifacts = PageArtifacts(
            requested_url="https://adnetwork-click.example/track", final_url="https://paypal-secure-login.net",
            redirect_chain=["https://adnetwork-click.example/track"],
        )
        sig = redirect_chain.evaluate(artifacts, "https://adnetwork-click.example/track", _index())
        assert sig.triggered is True
        assert sig.evidence["shortener_used"] is False

    def test_evidence_includes_full_chain(self):
        artifacts = PageArtifacts(
            requested_url="https://bit.ly/xyz",
            final_url="https://paypal-secure-login.net",
            redirect_chain=["https://bit.ly/xyz", "https://intermediate.example"],
        )
        sig = redirect_chain.evaluate(artifacts, "https://bit.ly/xyz", _index())
        assert sig.evidence["redirect_chain"] == [
            "https://bit.ly/xyz",
            "https://intermediate.example",
            "https://paypal-secure-login.net",
        ]


class TestRobustness:
    def test_empty_brand_index_never_triggers(self):
        artifacts = PageArtifacts(
            requested_url="https://bit.ly/xyz", final_url="https://paypal-secure-login.net",
            redirect_chain=["https://bit.ly/xyz"],
        )
        sig = redirect_chain.evaluate(artifacts, "https://bit.ly/xyz", BrandIndex(brands=()))
        assert sig.triggered is False

    def test_never_raises_on_malformed_urls(self):
        artifacts = PageArtifacts(requested_url="not a url", final_url="also not a url", redirect_chain=["not a url"])
        sig = redirect_chain.evaluate(artifacts, "not a url", _index())
        assert sig.triggered is False
