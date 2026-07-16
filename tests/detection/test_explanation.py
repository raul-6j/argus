"""Tests for src.detection.explanation (B2, plain-language renderer)."""

from __future__ import annotations

from src.detection.explanation import explain_plain
from src.detection.types import RiskSignal


def _signal(name, triggered, evidence=None):
    return RiskSignal(name=name, triggered=triggered, score=0.7, direction="phishing", evidence=evidence or {})


class TestLegitimateNoSignals:
    def test_legitimate_with_no_signals_gets_reassuring_sentence(self):
        sentence = explain_plain(None, [], "legitimate")
        assert "No phishing indicators" in sentence

    def test_legitimate_with_empty_shap_gets_reassuring_sentence(self):
        sentence = explain_plain([], None, "legitimate")
        assert "No phishing indicators" in sentence


class TestSignalPhrases:
    def test_typosquat_signal_renders_impersonated_brand(self):
        sig = _signal("typosquat", True, {"impersonated_brand": "PayPal"})
        sentence = explain_plain(None, [sig], "phishing")
        assert "PayPal" in sentence
        assert "look-alike" in sentence or "misspelled" in sentence

    def test_favicon_match_signal_renders(self):
        sig = _signal("favicon_match", True, {"impersonated_brand": "Google"})
        sentence = explain_plain(None, [sig], "phishing")
        assert "Google" in sentence
        assert "icon" in sentence

    def test_brand_mismatch_signal_renders_both_brands(self):
        sig = _signal("brand_mismatch", True, {"page_brand": "PayPal", "domain_brand": "evil.com"})
        sentence = explain_plain(None, [sig], "phishing")
        assert "PayPal" in sentence
        assert "evil.com" in sentence

    def test_untriggered_signal_not_mentioned(self):
        sig = RiskSignal(name="typosquat", triggered=False, score=0.0, direction="neutral")
        sentence = explain_plain(None, [sig], "legitimate")
        assert "No phishing indicators" in sentence

    def test_signal_with_missing_evidence_key_falls_back_gracefully(self):
        sig = _signal("typosquat", True, {})  # no 'impersonated_brand' key
        sentence = explain_plain(None, [sig], "phishing")
        assert isinstance(sentence, str)
        assert sentence != ""

    def test_accepts_dict_shaped_signals_too(self):
        """.to_dict()'d signals must render identically to RiskSignal objects."""
        sig_dict = {
            "name": "typosquat",
            "triggered": True,
            "score": 0.65,
            "direction": "phishing",
            "evidence": {"impersonated_brand": "PayPal"},
        }
        sentence = explain_plain(None, [sig_dict], "phishing")
        assert "PayPal" in sentence


class TestShapPhrases:
    def test_positive_shap_feature_included(self):
        shap = [{"feature": "domain_age_cat", "shap_value": 0.4, "feature_value": -1}]
        sentence = explain_plain(shap, [], "phishing")
        assert "registered very recently" in sentence

    def test_negative_shap_value_not_included_as_a_phishing_reason(self):
        shap = [{"feature": "domain_age_cat", "shap_value": -0.4, "feature_value": 1}]
        sentence = explain_plain(shap, [], "phishing")
        assert "registered very recently" not in sentence

    def test_unknown_feature_name_ignored(self):
        shap = [{"feature": "some_unmapped_feature", "shap_value": 0.9, "feature_value": 1}]
        sentence = explain_plain(shap, [], "phishing")
        assert isinstance(sentence, str)


class TestCombinedAndDedup:
    def test_signals_and_shap_combine_up_to_max_reasons(self):
        sig = _signal("typosquat", True, {"impersonated_brand": "PayPal"})
        shap = [
            {"feature": "domain_age_cat", "shap_value": 0.5, "feature_value": -1},
            {"feature": "has_at_symbol", "shap_value": 0.4, "feature_value": -1},
            {"feature": "has_popup", "shap_value": 0.3, "feature_value": -1},
        ]
        sentence = explain_plain(shap, [sig], "phishing")
        # Capped at 3 reasons -> at most 2 "and"s in the joined clause.
        assert sentence.count(", and ") <= 2

    def test_duplicate_reasons_are_deduplicated(self):
        sig1 = _signal("typosquat", True, {"impersonated_brand": "PayPal"})
        sig2 = _signal("typosquat", True, {"impersonated_brand": "PayPal"})
        sentence = explain_plain(None, [sig1, sig2], "phishing")
        # Only one occurrence of the (identical) reason despite two signals.
        assert sentence.count("PayPal") == 1


class TestFallbackAndRobustness:
    def test_phishing_with_no_reasons_gets_generic_sentence(self):
        sentence = explain_plain(None, [], "phishing")
        assert "model's analysis" in sentence

    def test_never_raises_on_malformed_shap_input(self):
        sentence = explain_plain("not a list", [], "phishing")
        assert isinstance(sentence, str)

    def test_never_raises_on_malformed_signal_input(self):
        sentence = explain_plain(None, ["not a signal object"], "phishing")
        assert isinstance(sentence, str)

    def test_never_raises_on_none_inputs(self):
        sentence = explain_plain(None, None, "phishing")
        assert isinstance(sentence, str)
