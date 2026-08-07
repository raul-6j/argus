"""Tests for src.detection.signals.platform_risk (Phase 3, F3)."""

from __future__ import annotations

from src.detection.signals import platform_risk
from src.detection.types import RiskSignal

_PLATFORMS = frozenset({"wixstudio.com", "vercel.app", "github.io"})


def _signal(name: str, triggered: bool) -> RiskSignal:
    return RiskSignal(name=name, triggered=triggered, score=0.7 if triggered else 0.0, direction="phishing" if triggered else "neutral")


class TestNeutralCases:
    def test_empty_platform_list_is_neutral(self):
        sig = platform_risk.evaluate("https://attacker.wixstudio.com", frozenset(), [_signal("brand_mismatch", True)])
        assert sig.triggered is False

    def test_non_platform_hostname_is_neutral(self):
        sig = platform_risk.evaluate("https://randomsite.com", _PLATFORMS, [_signal("brand_mismatch", True)])
        assert sig.triggered is False

    def test_platform_hostname_without_corroboration_is_neutral(self):
        """The core false-positive guard: a real, benign site hosted on a
        free platform must never trigger on its own."""
        sig = platform_risk.evaluate("https://real-small-business.wixstudio.com", _PLATFORMS, [])
        assert sig.triggered is False

    def test_platform_hostname_with_untriggered_corroborators_is_neutral(self):
        sig = platform_risk.evaluate(
            "https://real-small-business.wixstudio.com",
            _PLATFORMS,
            [_signal("brand_mismatch", False), _signal("credential_context", False)],
        )
        assert sig.triggered is False

    def test_non_corroborating_signal_name_does_not_count(self):
        """Only brand_mismatch/credential_context corroborate -- an
        unrelated triggered signal (e.g. cert_intel) must not count."""
        sig = platform_risk.evaluate(
            "https://attacker.wixstudio.com", _PLATFORMS, [_signal("cert_intel", True)]
        )
        assert sig.triggered is False


class TestTriggeredCases:
    def test_apex_hostname_match_with_brand_mismatch_corroboration(self):
        sig = platform_risk.evaluate(
            "https://wixstudio.com", _PLATFORMS, [_signal("brand_mismatch", True)]
        )
        assert sig.triggered is True
        assert sig.evidence["platform"] == "wixstudio.com"

    def test_subdomain_match_with_credential_context_corroboration(self):
        sig = platform_risk.evaluate(
            "https://phisher123.vercel.app",
            _PLATFORMS,
            [_signal("credential_context", True)],
        )
        assert sig.triggered is True
        assert sig.evidence["platform"] == "vercel.app"
        assert "credential_context" in sig.evidence["corroborating_signals"]

    def test_both_corroborators_triggered_lists_both(self):
        sig = platform_risk.evaluate(
            "https://phisher.github.io",
            _PLATFORMS,
            [_signal("brand_mismatch", True), _signal("credential_context", True)],
        )
        assert sig.triggered is True
        assert set(sig.evidence["corroborating_signals"]) == {"brand_mismatch", "credential_context"}

    def test_direction_is_always_phishing_when_triggered(self):
        sig = platform_risk.evaluate(
            "https://attacker.wixstudio.com", _PLATFORMS, [_signal("brand_mismatch", True)]
        )
        assert sig.direction == "phishing"

    def test_never_marked_as_hard_override(self):
        """platform_risk must never be eligible for a fusion hard override
        -- it is corroborating evidence by design, not a decisive signal."""
        sig = platform_risk.evaluate(
            "https://attacker.wixstudio.com", _PLATFORMS, [_signal("brand_mismatch", True)]
        )
        assert sig.is_hard_override is False


class TestRobustness:
    def test_unparseable_url_does_not_crash(self):
        sig = platform_risk.evaluate("not a url", _PLATFORMS, [_signal("brand_mismatch", True)])
        assert sig.triggered is False

    def test_empty_url_does_not_crash(self):
        sig = platform_risk.evaluate("", _PLATFORMS, [_signal("brand_mismatch", True)])
        assert sig.triggered is False

    def test_result_has_latency_recorded(self):
        sig = platform_risk.evaluate("https://example.com", _PLATFORMS, [])
        assert sig.latency_ms >= 0.0

    def test_matching_is_case_insensitive_on_hostname(self):
        sig = platform_risk.evaluate(
            "https://Attacker.WixStudio.com", _PLATFORMS, [_signal("brand_mismatch", True)]
        )
        assert sig.triggered is True
