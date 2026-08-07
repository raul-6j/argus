"""Tests for src.detection.signals.semantic_content (Phase 6, F17)."""

from __future__ import annotations

from src.detection.signals import semantic_content
from src.detection.types import RiskSignal
from src.features.page_artifacts import PageArtifacts


def _artifacts(html: str) -> PageArtifacts:
    return PageArtifacts(requested_url="https://example.com", html=html, final_url="https://example.com")


def _signal(name: str, triggered: bool) -> RiskSignal:
    return RiskSignal(
        name=name, triggered=triggered, score=0.7 if triggered else 0.0,
        direction="phishing" if triggered else "neutral",
    )


class TestNeutralCases:
    def test_no_page_artifacts_is_neutral(self):
        sig = semantic_content.evaluate(None, [])
        assert sig.triggered is False

    def test_no_html_is_neutral(self):
        sig = semantic_content.evaluate(PageArtifacts(requested_url="x", html=None), [])
        assert sig.triggered is False

    def test_no_matched_category_is_neutral(self):
        html = "<html><body><p>Welcome to our shop. Browse our products.</p></body></html>"
        sig = semantic_content.evaluate(_artifacts(html), [_signal("brand_mismatch", True)])
        assert sig.triggered is False

    def test_matched_category_without_corroboration_is_neutral(self):
        """The core false-positive guard: pretext wording alone (no other
        triggered signal, no recently-registered domain) must never trigger
        -- real marketing/billing copy uses urgency language too."""
        html = "<html><body><p>Your account will be suspended. Act now.</p></body></html>"
        sig = semantic_content.evaluate(_artifacts(html), [])
        assert sig.triggered is False

    def test_matched_category_with_untriggered_corroborators_is_neutral(self):
        html = "<html><body><p>Security alert: suspicious login attempt detected.</p></body></html>"
        sig = semantic_content.evaluate(
            _artifacts(html),
            [_signal("brand_mismatch", False), _signal("credential_context", False)],
            html_features={},
        )
        assert sig.triggered is False

    def test_non_corroborating_signal_name_does_not_count(self):
        html = "<html><body><p>Security alert: suspicious login attempt detected.</p></body></html>"
        sig = semantic_content.evaluate(_artifacts(html), [_signal("cert_intel", True)])
        assert sig.triggered is False

    def test_script_and_style_content_is_excluded(self):
        html = (
            "<html><head><style>.alert{color:red}</style></head>"
            "<body><script>var securityAlert = 'account will be suspended act now';</script>"
            "<p>Welcome to our shop.</p></body></html>"
        )
        sig = semantic_content.evaluate(_artifacts(html), [_signal("brand_mismatch", True)])
        assert sig.triggered is False


class TestTriggeredCases:
    def test_urgency_threat_with_brand_mismatch_corroboration(self):
        html = "<html><body><p>Your account will be suspended. Act now.</p></body></html>"
        sig = semantic_content.evaluate(_artifacts(html), [_signal("brand_mismatch", True)])
        assert sig.triggered is True
        assert "urgency_threat" in sig.evidence["matched_categories"]
        assert "brand_mismatch" in sig.evidence["corroborating_signals"]

    def test_fake_security_alert_with_credential_context_corroboration(self):
        html = "<html><body><p>Security Alert: we detected a suspicious login attempt.</p></body></html>"
        sig = semantic_content.evaluate(_artifacts(html), [_signal("credential_context", True)])
        assert sig.triggered is True
        assert "fake_security_alert" in sig.evidence["matched_categories"]

    def test_prize_lottery_category_matches(self):
        html = "<html><body><p>Congratulations, you are our lucky winner! Claim your prize now.</p></body></html>"
        sig = semantic_content.evaluate(_artifacts(html), [_signal("brand_mismatch", True)])
        assert sig.triggered is True
        assert "prize_lottery" in sig.evidence["matched_categories"]

    def test_tech_support_scam_category_matches(self):
        html = "<html><body><p>Your computer has been infected. Call the number below immediately.</p></body></html>"
        sig = semantic_content.evaluate(_artifacts(html), [_signal("credential_context", True)])
        assert sig.triggered is True
        assert "tech_support_scam" in sig.evidence["matched_categories"]

    def test_payment_invoice_pressure_category_matches(self):
        html = "<html><body><p>Your payment could not be processed. Update your billing information.</p></body></html>"
        sig = semantic_content.evaluate(_artifacts(html), [_signal("brand_mismatch", True)])
        assert sig.triggered is True
        assert "payment_invoice_pressure" in sig.evidence["matched_categories"]

    def test_account_verification_pressure_category_matches(self):
        html = "<html><body><p>Please confirm your identity and verify your account.</p></body></html>"
        sig = semantic_content.evaluate(_artifacts(html), [_signal("credential_context", True)])
        assert sig.triggered is True
        assert "account_verification_pressure" in sig.evidence["matched_categories"]

    def test_recently_registered_domain_corroborates_without_other_signal(self):
        html = "<html><body><p>Your account will be suspended. Act now.</p></body></html>"
        sig = semantic_content.evaluate(
            _artifacts(html), [], html_features={"is_recently_registered": True}
        )
        assert sig.triggered is True
        assert sig.evidence["recently_registered_domain"] is True

    def test_multiple_categories_combine_score(self):
        html = (
            "<html><body><p>Security Alert: your account will be suspended, act now. "
            "Please confirm your identity to continue.</p></body></html>"
        )
        sig = semantic_content.evaluate(_artifacts(html), [_signal("brand_mismatch", True)])
        assert sig.triggered is True
        assert len(sig.evidence["matched_categories"]) >= 2
        assert sig.score > 0.3

    def test_score_never_exceeds_one(self):
        html = (
            "<html><body><p>Security Alert! Your account will be suspended, act now. "
            "Congratulations, you are our lucky winner, claim your prize. "
            "Your computer has been infected, call the number below immediately. "
            "Your payment could not be processed, update your billing information. "
            "Please confirm your identity and verify your account.</p></body></html>"
        )
        sig = semantic_content.evaluate(
            _artifacts(html), [_signal("brand_mismatch", True)], html_features={"is_recently_registered": True}
        )
        assert sig.triggered is True
        assert sig.score <= 1.0

    def test_direction_is_always_phishing_when_triggered(self):
        html = "<html><body><p>Your account will be suspended. Act now.</p></body></html>"
        sig = semantic_content.evaluate(_artifacts(html), [_signal("brand_mismatch", True)])
        assert sig.direction == "phishing"

    def test_never_marked_as_hard_override(self):
        html = "<html><body><p>Your account will be suspended. Act now.</p></body></html>"
        sig = semantic_content.evaluate(_artifacts(html), [_signal("brand_mismatch", True)])
        assert sig.is_hard_override is False


class TestRobustness:
    def test_malformed_html_does_not_crash(self):
        sig = semantic_content.evaluate(_artifacts("<html><body><p>Act now"), [])
        assert sig.triggered in (True, False)

    def test_none_html_features_does_not_crash(self):
        html = "<html><body><p>Your account will be suspended. Act now.</p></body></html>"
        sig = semantic_content.evaluate(_artifacts(html), [], html_features=None)
        assert sig.triggered is False

    def test_result_has_latency_recorded(self):
        sig = semantic_content.evaluate(_artifacts("<html></html>"), [])
        assert sig.latency_ms >= 0.0

    def test_very_long_page_text_does_not_crash(self):
        html = "<html><body><p>" + ("filler content. " * 5000) + "Act now, account suspended.</p></body></html>"
        sig = semantic_content.evaluate(_artifacts(html), [_signal("brand_mismatch", True)])
        assert sig.triggered in (True, False)
