"""Tests for src.detection.fusion (verdict-fusion rule, DEC-A)."""

from __future__ import annotations

from src.detection.fusion import fuse
from src.detection.types import RiskSignal

_CONFIG = {
    "fusion_threshold": 0.30,
    "signal_weights": {"model": 1.0, "typosquat": 0.6, "favicon_match": 0.9, "brand_mismatch": 0.8},
    "hard_override_signals": ["favicon_match"],
}


def _signal(name, triggered, score, direction="phishing", is_hard_override=False):
    return RiskSignal(name=name, triggered=triggered, score=score, direction=direction, is_hard_override=is_hard_override)


class TestNoSignalsReproducesModelOnly:
    def test_empty_signals_high_proba_is_phishing(self):
        v = fuse(0.8, [], _CONFIG)
        assert v.label == "phishing"
        assert v.risk_score == 0.8
        assert v.decisive_source == "model"

    def test_empty_signals_low_proba_is_legitimate(self):
        v = fuse(0.1, [], _CONFIG)
        assert v.label == "legitimate"
        assert v.risk_score == 0.1
        assert v.decisive_source == "model"

    def test_all_neutral_signals_reproduces_model_only(self):
        signals = [_signal("typosquat", False, 0.0, direction="neutral")]
        v = fuse(0.5, signals, _CONFIG)
        assert v.risk_score == 0.5
        assert v.decisive_source == "model"

    def test_exactly_at_threshold_is_phishing(self):
        v = fuse(0.30, [], _CONFIG)
        assert v.label == "phishing"

    def test_just_below_threshold_is_legitimate(self):
        v = fuse(0.2999, [], _CONFIG)
        assert v.label == "legitimate"


class TestHardOverride:
    def test_hard_override_forces_phishing_regardless_of_low_model_proba(self):
        signals = [_signal("favicon_match", True, 0.97, is_hard_override=True)]
        v = fuse(0.01, signals, _CONFIG)
        assert v.label == "phishing"
        assert v.decisive_source == "favicon_match"
        assert v.confidence >= 0.95

    def test_hard_override_flag_alone_insufficient_without_config_gate(self):
        """is_hard_override=True but the signal isn't in
        hard_override_signals -- falls through to the weighted path."""
        config = dict(_CONFIG, hard_override_signals=[])
        signals = [_signal("favicon_match", True, 0.97, is_hard_override=True)]
        v = fuse(0.01, signals, config)
        assert v.decisive_source != "favicon_match"

    def test_soft_favicon_match_never_hard_overrides(self):
        """A triggered favicon_match signal that is NOT marked
        is_hard_override (a soft perceptual-hash match) must never force the
        verdict, even though the name is in hard_override_signals."""
        signals = [_signal("favicon_match", True, 0.6, is_hard_override=False)]
        v = fuse(0.01, signals, _CONFIG)
        assert v.decisive_source != "favicon_match"
        assert v.label == "legitimate"  # weak weighted contribution, low model proba

    def test_untriggered_hard_override_signal_ignored(self):
        signals = [_signal("favicon_match", False, 0.0, direction="neutral", is_hard_override=True)]
        v = fuse(0.01, signals, _CONFIG)
        assert v.decisive_source == "model"


class TestWeightedCombination:
    def test_triggered_phishing_signal_raises_risk_score(self):
        signals = [_signal("typosquat", True, 0.65)]
        v = fuse(0.1, signals, _CONFIG)
        # weighted_sum = 1.0*0.1 + 0.6*0.65 = 0.49; total_weight = 1.6
        expected = (1.0 * 0.1 + 0.6 * 0.65) / 1.6
        assert abs(v.risk_score - expected) < 1e-9
        assert v.decisive_source == "fusion"

    def test_triggered_legitimate_signal_lowers_risk_score(self):
        signals = [_signal("typosquat", True, 0.65, direction="legitimate")]
        v = fuse(0.5, signals, _CONFIG)
        expected = (1.0 * 0.5 - 0.6 * 0.65) / 1.6
        expected = max(0.0, min(1.0, expected))
        assert abs(v.risk_score - expected) < 1e-9

    def test_risk_score_clamped_to_zero_and_one(self):
        signals = [_signal("typosquat", True, 1.0, direction="legitimate")]
        v = fuse(0.0, signals, _CONFIG)
        assert v.risk_score == 0.0

    def test_untriggered_signal_contributes_nothing(self):
        signals = [_signal("typosquat", False, 0.0, direction="neutral")]
        v = fuse(0.4, signals, _CONFIG)
        assert v.risk_score == 0.4

    def test_zero_weight_signal_contributes_nothing(self):
        config = dict(_CONFIG, signal_weights={"model": 1.0})  # typosquat weight absent -> 0
        signals = [_signal("typosquat", True, 0.9)]
        v = fuse(0.4, signals, config)
        assert v.risk_score == 0.4

    def test_multiple_triggered_signals_combine(self):
        signals = [
            _signal("typosquat", True, 0.65),
            _signal("brand_mismatch", True, 0.8),
        ]
        v = fuse(0.1, signals, _CONFIG)
        expected = (1.0 * 0.1 + 0.6 * 0.65 + 0.8 * 0.8) / (1.0 + 0.6 + 0.8)
        assert abs(v.risk_score - expected) < 1e-9

    def test_confidence_reflects_the_winning_side(self):
        v_phish = fuse(0.9, [], _CONFIG)
        assert v_phish.confidence == v_phish.risk_score
        v_legit = fuse(0.1, [], _CONFIG)
        assert v_legit.confidence == 1 - v_legit.risk_score


class TestSignalIsolation:
    def test_signals_list_preserved_in_verdict_regardless_of_trigger(self):
        signals = [
            _signal("typosquat", False, 0.0, direction="neutral"),
            _signal("favicon_match", True, 0.97, is_hard_override=True),
        ]
        v = fuse(0.5, signals, _CONFIG)
        assert v.signals == signals

    def test_model_proba_always_recorded_even_on_hard_override(self):
        signals = [_signal("favicon_match", True, 0.97, is_hard_override=True)]
        v = fuse(0.05, signals, _CONFIG)
        assert v.model_proba == 0.05
