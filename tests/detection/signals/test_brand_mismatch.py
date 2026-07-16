"""Tests for src.detection.signals.brand_mismatch (A1).

DEC-A: this is a deterministic heuristic engine, not a trained model --
these tests exercise the rule logic directly against crafted HTML fixtures.
"""

from __future__ import annotations

from src.detection.brand_reference import Brand, BrandIndex
from src.detection.signals import brand_mismatch
from src.detection.types import RiskSignal
from src.features.page_artifacts import PageArtifacts


def _index() -> BrandIndex:
    return BrandIndex(brands=(Brand(name="PayPal", domains=("paypal.com",), aliases=("paypal",)),))


def _artifacts(html: str, final_url="https://attacker.example.com") -> PageArtifacts:
    return PageArtifacts(requested_url=final_url, html=html, final_url=final_url)


class TestNoTrigger:
    def test_legit_own_domain_never_flagged(self):
        html = "<html><head><title>PayPal Login</title></head><body><input type=password></body></html>"
        artifacts = _artifacts(html, final_url="https://paypal.com")
        sig = brand_mismatch.evaluate(artifacts, "https://paypal.com", _index())
        assert sig.triggered is False

    def test_bare_brand_mention_without_corroboration_not_flagged(self):
        """A merchant page mentioning 'We accept PayPal' with no password
        field and no favicon corroboration must NOT be flagged -- avoids
        false positives on ordinary brand mentions."""
        html = "<html><head><title>Acme Shop - We accept PayPal</title></head><body>Buy stuff</body></html>"
        artifacts = _artifacts(html)
        sig = brand_mismatch.evaluate(artifacts, "https://attacker.example.com", _index())
        assert sig.triggered is False

    def test_no_brand_mentioned_not_flagged(self):
        html = "<html><head><title>My Personal Blog</title></head><body>Hello</body></html>"
        artifacts = _artifacts(html)
        sig = brand_mismatch.evaluate(artifacts, "https://attacker.example.com", _index())
        assert sig.triggered is False

    def test_no_html_is_neutral(self):
        artifacts = PageArtifacts(requested_url="x", html=None)
        sig = brand_mismatch.evaluate(artifacts, "https://attacker.example.com", _index())
        assert sig.triggered is False

    def test_empty_brand_index_is_neutral(self):
        html = "<html><head><title>PayPal Login</title></head><body><input type=password></body></html>"
        artifacts = _artifacts(html)
        sig = brand_mismatch.evaluate(artifacts, "https://attacker.example.com", BrandIndex(brands=()))
        assert sig.triggered is False


class TestTriggersWithCorroboration:
    def test_credential_context_corroborates_and_triggers(self):
        html = "<html><head><title>PayPal - Log In to Your Account</title></head><body><input type=password></body></html>"
        artifacts = _artifacts(html)
        sig = brand_mismatch.evaluate(artifacts, "https://attacker.example.com", _index())
        assert sig.triggered is True
        assert sig.evidence["page_brand"] == "PayPal"
        assert "credential_context" in sig.evidence["axes_triggered"]

    def test_favicon_signal_corroborates_and_triggers_without_password_field(self):
        html = "<html><head><title>PayPal</title></head><body>no password field here</body></html>"
        artifacts = _artifacts(html)
        favicon_sig = RiskSignal(
            name="favicon_match", triggered=True, score=0.97, direction="phishing",
            is_hard_override=True, evidence={"impersonated_brand": "PayPal"},
        )
        sig = brand_mismatch.evaluate(artifacts, "https://attacker.example.com", _index(), favicon_sig)
        assert sig.triggered is True
        assert "favicon_signal" in sig.evidence["axes_triggered"]

    def test_favicon_signal_for_different_brand_does_not_corroborate(self):
        html = "<html><head><title>PayPal</title></head><body>text</body></html>"
        artifacts = _artifacts(html)
        favicon_sig = RiskSignal(
            name="favicon_match", triggered=True, score=0.97, direction="phishing",
            is_hard_override=True, evidence={"impersonated_brand": "SomeOtherBrand"},
        )
        sig = brand_mismatch.evaluate(artifacts, "https://attacker.example.com", _index(), favicon_sig)
        assert sig.triggered is False  # no credential context, no matching favicon corroboration

    def test_offsite_form_adds_to_score_but_needs_primary_corroboration(self):
        html = "<html><head><title>PayPal - Login</title></head><body><input type=password></body></html>"
        artifacts = _artifacts(html)
        sig = brand_mismatch.evaluate(
            artifacts, "https://attacker.example.com", _index(),
            html_features={"form_action_is_external": True},
        )
        assert sig.triggered is True
        assert "offsite_form" in sig.evidence["axes_triggered"]
        assert "credential_context" in sig.evidence["axes_triggered"]

    def test_score_increases_with_more_corroborating_axes(self):
        html_min = "<html><head><title>PayPal</title></head><body><input type=password></body></html>"
        html_more = html_min
        artifacts_min = _artifacts(html_min)
        sig_min = brand_mismatch.evaluate(artifacts_min, "https://attacker.example.com", _index())

        favicon_sig = RiskSignal(
            name="favicon_match", triggered=True, score=0.97, direction="phishing",
            is_hard_override=True, evidence={"impersonated_brand": "PayPal"},
        )
        artifacts_more = _artifacts(html_more)
        sig_more = brand_mismatch.evaluate(
            artifacts_more, "https://attacker.example.com", _index(), favicon_sig,
            html_features={"form_action_is_external": True},
        )
        assert sig_more.score > sig_min.score


class TestBrandTokenExtraction:
    def test_matches_og_site_name(self):
        html = (
            '<html><head><meta property="og:site_name" content="PayPal">'
            "</head><body><input type=password></body></html>"
        )
        artifacts = _artifacts(html)
        sig = brand_mismatch.evaluate(artifacts, "https://attacker.example.com", _index())
        assert sig.triggered is True

    def test_alias_match_via_title(self):
        html = "<html><head><title>Sign in - paypal account</title></head><body><input type=password></body></html>"
        artifacts = _artifacts(html)
        sig = brand_mismatch.evaluate(artifacts, "https://attacker.example.com", _index())
        assert sig.triggered is True


class TestRobustness:
    def test_never_raises_on_garbage_html(self):
        artifacts = _artifacts("<<<not html>>>")
        sig = brand_mismatch.evaluate(artifacts, "https://attacker.example.com", _index())
        assert sig.triggered is False

    def test_score_capped_at_one(self):
        html = "<html><head><title>PayPal - Login</title></head><body><input type=password></body></html>"
        artifacts = _artifacts(html)
        favicon_sig = RiskSignal(
            name="favicon_match", triggered=True, score=0.97, direction="phishing",
            is_hard_override=True, evidence={"impersonated_brand": "PayPal"},
        )
        sig = brand_mismatch.evaluate(
            artifacts, "https://attacker.example.com", _index(), favicon_sig,
            html_features={"form_action_is_external": True, "form_submits_to_email": True},
        )
        assert sig.score <= 1.0
