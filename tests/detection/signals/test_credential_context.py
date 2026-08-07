"""Tests for src.detection.signals.credential_context (Phase 3, F4)."""

from __future__ import annotations

from src.detection.signals import credential_context
from src.features.page_artifacts import PageArtifacts


def _artifacts(html: str) -> PageArtifacts:
    return PageArtifacts(requested_url="https://example.com", html=html, final_url="https://example.com")


class TestNeutralCases:
    def test_no_page_artifacts_is_neutral(self):
        sig = credential_context.evaluate(None)
        assert sig.triggered is False

    def test_no_html_is_neutral(self):
        sig = credential_context.evaluate(PageArtifacts(requested_url="x", html=None))
        assert sig.triggered is False

    def test_no_sensitive_fields_is_neutral(self):
        html = "<html><body><input type=text name=search></body></html>"
        sig = credential_context.evaluate(_artifacts(html))
        assert sig.triggered is False

    def test_bare_password_field_alone_is_not_enough(self):
        """The naive rule this signal must explicitly avoid: a real login
        page also has just a password field, with no corroboration."""
        html = "<html><body><form><input type=password></form></body></html>"
        sig = credential_context.evaluate(_artifacts(html), html_features={})
        assert sig.triggered is False

    def test_bare_credit_card_field_alone_is_not_enough(self):
        html = "<html><body><input type=text autocomplete=cc-number></body></html>"
        sig = credential_context.evaluate(_artifacts(html), html_features={})
        assert sig.triggered is False


class TestTriggeredCases:
    def test_password_field_plus_cross_origin_post_triggers(self):
        html = "<html><body><form><input type=password></form></body></html>"
        sig = credential_context.evaluate(
            _artifacts(html), html_features={"form_action_is_external": True}
        )
        assert sig.triggered is True
        assert "password_field" in sig.evidence["sensitive_fields"]
        assert sig.evidence["cross_origin_post"] is True

    def test_password_field_plus_recently_registered_triggers(self):
        html = "<html><body><input type=password></body></html>"
        sig = credential_context.evaluate(
            _artifacts(html), html_features={"is_recently_registered": True}
        )
        assert sig.triggered is True
        assert sig.evidence["recently_registered_domain"] is True

    def test_otp_field_detected_via_autocomplete(self):
        html = '<html><body><input type=text autocomplete="one-time-code"></body></html>'
        sig = credential_context.evaluate(
            _artifacts(html), html_features={"form_submits_to_email": True}
        )
        assert sig.triggered is True
        assert "otp_field" in sig.evidence["sensitive_fields"]

    def test_otp_field_detected_via_name_keyword(self):
        html = '<html><body><input type=text name="verification_code"></body></html>'
        sig = credential_context.evaluate(
            _artifacts(html), html_features={"form_action_is_external": True}
        )
        assert sig.triggered is True
        assert "otp_field" in sig.evidence["sensitive_fields"]

    def test_credit_card_field_plus_cross_origin_triggers(self):
        html = '<html><body><input type=text name="card_number"></body></html>'
        sig = credential_context.evaluate(
            _artifacts(html), html_features={"form_action_is_external": True}
        )
        assert sig.triggered is True
        assert "credit_card_field" in sig.evidence["sensitive_fields"]

    def test_crypto_seed_phrase_field_triggers_alone(self):
        """The one self-sufficient axis -- narrow (an actual input field
        asking for it), and legitimate use is vanishingly rare."""
        html = '<html><body><textarea name="wallet_recovery_phrase"></textarea></body></html>'
        sig = credential_context.evaluate(_artifacts(html), html_features={})
        assert sig.triggered is True
        assert "crypto_seed_phrase" in sig.evidence["sensitive_fields"]
        assert sig.evidence["cross_origin_post"] is False
        assert sig.evidence["recently_registered_domain"] is False

    def test_crypto_seed_phrase_via_input_placeholder(self):
        html = '<html><body><input type=text placeholder="Enter your seed phrase"></body></html>'
        sig = credential_context.evaluate(_artifacts(html), html_features={})
        assert sig.triggered is True

    def test_multiple_sensitive_fields_combine_score(self):
        html = (
            "<html><body><form><input type=password>"
            '<input type=text name="card_number"></form></body></html>'
        )
        sig = credential_context.evaluate(
            _artifacts(html), html_features={"form_action_is_external": True}
        )
        assert sig.triggered is True
        assert set(sig.evidence["sensitive_fields"]) == {"password_field", "credit_card_field"}
        assert sig.score > 0.5

    def test_score_never_exceeds_one(self):
        html = (
            "<html><body><form><input type=password>"
            '<input type=text autocomplete="one-time-code">'
            '<input type=text name="card_number">'
            '<textarea name="seed_phrase"></textarea></form></body></html>'
        )
        sig = credential_context.evaluate(
            _artifacts(html),
            html_features={"form_action_is_external": True, "is_recently_registered": True},
        )
        assert sig.triggered is True
        assert sig.score <= 1.0


class TestRobustness:
    def test_malformed_html_does_not_crash(self):
        sig = credential_context.evaluate(_artifacts("<html><body><input type=passw"))
        assert sig.triggered in (True, False)

    def test_none_html_features_does_not_crash(self):
        html = "<html><body><input type=password></body></html>"
        sig = credential_context.evaluate(_artifacts(html), html_features=None)
        assert sig.triggered is False  # no corroboration available -> neutral

    def test_result_has_latency_recorded(self):
        sig = credential_context.evaluate(_artifacts("<html></html>"))
        assert sig.latency_ms >= 0.0

    def test_field_values_never_appear_in_evidence(self):
        """Iron Law #1 spirit: only field TYPES/attributes are inspected,
        never actual submitted values (there are none to submit here, but
        the evidence dict must never echo raw attribute text that could
        carry a real secret)."""
        html = '<html><body><input type=password value="hunter2"></body></html>'
        sig = credential_context.evaluate(
            _artifacts(html), html_features={"form_action_is_external": True}
        )
        assert "hunter2" not in str(sig.evidence)
