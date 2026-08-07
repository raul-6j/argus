"""Tests for src.detection.fusion (verdict-fusion rule, DEC-A; noisy-OR DEC-039)."""

from __future__ import annotations

import itertools
import random

import pytest

from src.detection.fusion import fuse
from src.detection.types import RiskSignal

_CONFIG = {
    "fusion_threshold": 0.30,
    "signal_weights": {"model": 1.0, "typosquat": 0.6, "favicon_match": 0.9, "brand_mismatch": 0.8},
    "hard_override_signals": ["favicon_match"],
}

# The real shipped weights, so the monotonicity guarantee is demonstrated
# against the actual production configuration and not just a test fixture.
_PROD_WEIGHTS = {
    "model": 1.0,
    "typosquat": 0.6,
    "favicon_match": 0.9,
    "brand_mismatch": 0.8,
    "cert_intel": 0.4,
    "redirect_chain": 0.7,
    "credential_context": 0.55,
    "platform_risk": 0.5,
    "semantic_content": 0.45,
}
_PROD_CONFIG = {
    "fusion_threshold": 0.30,
    "signal_weights": _PROD_WEIGHTS,
    "hard_override_signals": ["favicon_match"],
}


def _signal(name, triggered, score, direction="phishing", is_hard_override=False):
    return RiskSignal(name=name, triggered=triggered, score=score, direction=direction, is_hard_override=is_hard_override)


def _untriggered(name):
    """An evaluated-but-not-fired signal (the only legal 'neutral' shape)."""
    return _signal(name, False, 0.0, direction="neutral")


class TestNoSignalsReproducesModelOnly:
    def test_empty_signals_high_proba_is_phishing(self):
        v = fuse(0.8, [], _CONFIG)
        assert v.label == "phishing"
        assert v.risk_score == pytest.approx(0.8)
        assert v.decisive_source == "model"

    def test_empty_signals_low_proba_is_legitimate(self):
        v = fuse(0.1, [], _CONFIG)
        assert v.label == "legitimate"
        assert v.risk_score == pytest.approx(0.1)
        assert v.decisive_source == "model"

    def test_all_neutral_signals_reproduces_model_only(self):
        v = fuse(0.5, [_untriggered("typosquat")], _CONFIG)
        assert v.risk_score == pytest.approx(0.5)
        assert v.decisive_source == "model"

    def test_exactly_at_threshold_is_phishing(self):
        v = fuse(0.30, [], _CONFIG)
        assert v.label == "phishing"

    def test_just_below_threshold_is_legitimate(self):
        v = fuse(0.2999, [], _CONFIG)
        assert v.label == "legitimate"

    @pytest.mark.parametrize("proba", [0.0, 0.05, 0.3, 0.5, 0.75, 1.0])
    def test_model_only_equivalence_holds_across_the_range(self, proba):
        """DEC-A's invariant: with model weight 1.0 and nothing triggered,
        fusion is an identity on model_proba (empty noisy-OR products)."""
        assert fuse(proba, [], _CONFIG).risk_score == pytest.approx(proba)


class TestHardOverride:
    def test_hard_override_forces_phishing_regardless_of_low_model_proba(self):
        signals = [_signal("favicon_match", True, 0.97, is_hard_override=True)]
        v = fuse(0.01, signals, _CONFIG)
        assert v.label == "phishing"
        assert v.decisive_source == "favicon_match"
        assert v.confidence >= 0.95

    def test_hard_override_flag_alone_insufficient_without_config_gate(self):
        """is_hard_override=True but the signal isn't in
        hard_override_signals -- falls through to the noisy-OR path."""
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

    def test_untriggered_hard_override_signal_ignored(self):
        signals = [_signal("favicon_match", False, 0.0, direction="neutral", is_hard_override=True)]
        v = fuse(0.01, signals, _CONFIG)
        assert v.decisive_source == "model"


class TestNoisyOrCombination:
    def test_triggered_phishing_signal_raises_risk_score(self):
        signals = [_signal("typosquat", True, 0.65)]
        v = fuse(0.1, signals, _CONFIG)
        # risk = 1 - (1 - 1.0*0.1) * (1 - 0.6*0.65) = 1 - 0.9*0.61
        expected = 1 - (1 - 0.1) * (1 - 0.6 * 0.65)
        assert v.risk_score == pytest.approx(expected)
        assert v.risk_score > 0.1
        assert v.decisive_source == "fusion"

    def test_triggered_legitimate_signal_lowers_risk_score(self):
        signals = [_signal("typosquat", True, 0.65, direction="legitimate")]
        v = fuse(0.5, signals, _CONFIG)
        # Dissenting evidence discounts multiplicatively: 0.5 * (1 - 0.6*0.65)
        expected = 0.5 * (1 - 0.6 * 0.65)
        assert v.risk_score == pytest.approx(expected)
        assert v.risk_score < 0.5

    def test_risk_score_clamped_to_zero_and_one(self):
        signals = [_signal("typosquat", True, 1.0, direction="legitimate")]
        v = fuse(0.0, signals, _CONFIG)
        assert v.risk_score == 0.0

    def test_untriggered_signal_contributes_nothing(self):
        v = fuse(0.4, [_untriggered("typosquat")], _CONFIG)
        assert v.risk_score == pytest.approx(0.4)

    def test_zero_weight_signal_contributes_nothing(self):
        config = dict(_CONFIG, signal_weights={"model": 1.0})  # typosquat weight absent -> 0
        signals = [_signal("typosquat", True, 0.9)]
        v = fuse(0.4, signals, config)
        assert v.risk_score == pytest.approx(0.4)

    def test_multiple_triggered_signals_combine(self):
        signals = [
            _signal("typosquat", True, 0.65),
            _signal("brand_mismatch", True, 0.8),
        ]
        v = fuse(0.1, signals, _CONFIG)
        expected = 1 - (1 - 0.1) * (1 - 0.6 * 0.65) * (1 - 0.8 * 0.8)
        assert v.risk_score == pytest.approx(expected)

    def test_confidence_reflects_the_winning_side(self):
        v_phish = fuse(0.9, [], _CONFIG)
        assert v_phish.confidence == pytest.approx(v_phish.risk_score)
        v_legit = fuse(0.1, [], _CONFIG)
        assert v_legit.confidence == pytest.approx(1 - v_legit.risk_score)

    def test_saturates_below_one_never_reaching_certainty(self):
        """Noisy-OR approaches but never reaches 1.0 for sub-1.0 evidence."""
        signals = [
            _signal("typosquat", True, 0.99),
            _signal("brand_mismatch", True, 0.99),
        ]
        v = fuse(0.95, signals, _CONFIG)
        assert 0.99 < v.risk_score < 1.0

    def test_out_of_range_weight_is_clamped_not_inverted(self):
        """A misconfigured weight > 1.0 must not flip the (1 - w*s) factor
        negative and start *reducing* risk."""
        config = dict(_CONFIG, signal_weights={"model": 1.0, "typosquat": 5.0})
        v = fuse(0.5, [_signal("typosquat", True, 0.9)], config)
        assert 0.0 <= v.risk_score <= 1.0
        assert v.risk_score >= 0.5


class TestMonotonicity:
    """The DEC-039 guarantee: agreeing evidence never lowers confidence.

    This is the class that pins the audit finding H-1. Every test here fails
    against the pre-DEC-039 weighted mean.
    """

    def test_audit_h1_scenario_no_longer_regresses(self):
        """The exact scenario from docs/AUDIT_2026-08.md H-1.

        Old (weighted mean): 0.900 -> 0.757 -> 0.689 -- evidence of phishing
        made ARGUS *less* sure. New: monotonically non-decreasing.
        """
        base = fuse(0.90, [], _PROD_CONFIG).risk_score
        one = fuse(0.90, [_signal("cert_intel", True, 0.4)], _PROD_CONFIG).risk_score
        two = fuse(
            0.90,
            [_signal("cert_intel", True, 0.4), _signal("typosquat", True, 0.5)],
            _PROD_CONFIG,
        ).risk_score

        assert base == pytest.approx(0.90)
        assert one >= base
        assert two >= one
        # And specifically NOT the old numbers.
        assert one > 0.757
        assert two > 0.689

    def test_adding_agreeing_signals_one_at_a_time_never_decreases(self):
        """Fold in every production signal cumulatively; the score must be
        non-decreasing at every single step."""
        names = [n for n in _PROD_WEIGHTS if n != "model"]
        accumulated: list[RiskSignal] = []
        previous = fuse(0.5, [], _PROD_CONFIG).risk_score

        for name in names:
            # A deliberately *low* score -- the exact case the weighted mean
            # got wrong, since it sat well below the running risk score.
            accumulated.append(_signal(name, True, 0.3))
            current = fuse(0.5, accumulated, _PROD_CONFIG).risk_score
            assert current >= previous, f"adding {name!r} lowered risk {previous} -> {current}"
            previous = current

    @pytest.mark.parametrize("model_proba", [0.0, 0.1, 0.3, 0.5, 0.75, 0.9, 0.99])
    @pytest.mark.parametrize("signal_score", [0.05, 0.2, 0.4, 0.6, 0.9])
    def test_one_agreeing_signal_never_lowers_risk_across_the_grid(self, model_proba, signal_score):
        """Exhaustive grid over model probability x signal strength."""
        without = fuse(model_proba, [], _PROD_CONFIG).risk_score
        with_signal = fuse(
            model_proba, [_signal("cert_intel", True, signal_score)], _PROD_CONFIG
        ).risk_score
        assert with_signal >= without

    def test_every_signal_subset_dominates_each_of_its_own_subsets(self):
        """Strongest form of the guarantee: for every subset of signals,
        adding any further agreeing signal never reduces the score."""
        names = ["cert_intel", "typosquat", "platform_risk", "semantic_content"]
        scores = {"cert_intel": 0.4, "typosquat": 0.5, "platform_risk": 0.35, "semantic_content": 0.3}

        for size in range(len(names)):
            for subset in itertools.combinations(names, size):
                base_signals = [_signal(n, True, scores[n]) for n in subset]
                base = fuse(0.6, base_signals, _PROD_CONFIG).risk_score
                for extra in names:
                    if extra in subset:
                        continue
                    grown = fuse(
                        0.6, [*base_signals, _signal(extra, True, scores[extra])], _PROD_CONFIG
                    ).risk_score
                    assert grown >= base, f"{subset} + {extra}: {base} -> {grown}"

    def test_randomised_monotonicity_sweep(self):
        """Randomised sweep (random_state=42, Iron Law #6) over model
        probabilities and agreeing-signal sets."""
        rng = random.Random(42)
        names = [n for n in _PROD_WEIGHTS if n != "model"]

        for _ in range(500):
            model_proba = rng.random()
            chosen = rng.sample(names, rng.randint(1, len(names)))
            signals = [_signal(n, True, rng.random()) for n in chosen]

            previous = fuse(model_proba, [], _PROD_CONFIG).risk_score
            for i in range(1, len(signals) + 1):
                current = fuse(model_proba, signals[:i], _PROD_CONFIG).risk_score
                assert current >= previous - 1e-12
                assert 0.0 <= current <= 1.0
                previous = current

    def test_order_of_signals_does_not_change_the_score(self):
        """Noisy-OR is commutative -- evaluation order must not matter."""
        signals = [
            _signal("cert_intel", True, 0.4),
            _signal("typosquat", True, 0.65),
            _signal("brand_mismatch", True, 0.5),
        ]
        scores = {
            fuse(0.4, list(perm), _PROD_CONFIG).risk_score
            for perm in itertools.permutations(signals)
        }
        assert max(scores) - min(scores) < 1e-12

    def test_label_never_flips_from_phishing_to_legitimate_on_agreeing_evidence(self):
        """The verdict-level consequence: corroboration cannot exonerate."""
        names = [n for n in _PROD_WEIGHTS if n != "model"]
        accumulated: list[RiskSignal] = []
        for name in names:
            accumulated.append(_signal(name, True, 0.35))
            assert fuse(0.31, accumulated, _PROD_CONFIG).label == "phishing"

    def test_stronger_agreeing_signal_scores_at_least_as_high(self):
        """Monotone in the signal's own score, not just in signal count."""
        previous = 0.0
        for score in [0.0, 0.1, 0.25, 0.5, 0.75, 0.9, 1.0]:
            current = fuse(0.4, [_signal("typosquat", True, score)], _PROD_CONFIG).risk_score
            assert current >= previous
            previous = current

    def test_dissenting_evidence_still_lowers_risk(self):
        """The asymmetry is deliberate: only *agreeing* evidence is barred
        from lowering the score."""
        without = fuse(0.8, [], _CONFIG).risk_score
        with_legit = fuse(
            0.8, [_signal("typosquat", True, 0.6, direction="legitimate")], _CONFIG
        ).risk_score
        assert with_legit < without


class TestSignalIsolation:
    def test_signals_list_preserved_in_verdict_regardless_of_trigger(self):
        signals = [
            _untriggered("typosquat"),
            _signal("favicon_match", True, 0.97, is_hard_override=True),
        ]
        v = fuse(0.5, signals, _CONFIG)
        assert v.signals == signals

    def test_model_proba_always_recorded_even_on_hard_override(self):
        signals = [_signal("favicon_match", True, 0.97, is_hard_override=True)]
        v = fuse(0.05, signals, _CONFIG)
        assert v.model_proba == 0.05
