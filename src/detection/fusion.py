"""Verdict-fusion rule (Phase 1, DEC-A; combiner replaced in DEC-039).

Combines the ML model's phishing probability with every evaluated
:class:`~src.detection.types.RiskSignal` into one
:class:`~src.detection.types.FusedVerdict`, via an explicit, fully
config-driven rule (``configs/detection_config.yaml``) rather than a second
trained model:

    1. **Hard overrides** — a *triggered*, *hard-override* signal (e.g. an
       exact favicon-hash match) whose name is also listed in
       ``config["hard_override_signals"]`` forces ``label="phishing"``
       outright, regardless of the model or any other signal. Reserved for
       near-zero-false-positive signals only.
    2. **Noisy-OR accumulation** — otherwise, the model and every
       *triggered* signal are combined as independent pieces of evidence,
       then thresholded at ``config["fusion_threshold"]``.

Why noisy-OR and not a weighted mean
------------------------------------
Until DEC-039 step 2 was a weighted *mean*::

    risk = (w_model * p + SUM_i w_i * s_i) / (w_model + SUM_i w_i)

A mean satisfies the *internality* axiom — its result is always bounded by
the smallest and largest of its inputs — which makes it the wrong operator
for accumulating evidence. Writing ``R`` for the score before a signal ``k``
is folded in and ``W`` for the weight accumulated so far::

    R_new - R_old = w_k * (s_k - R_old) / (W + w_k)

The sign of that change is the sign of ``s_k - R_old``. So *any* triggered
signal scoring below the running score dragged the score **down**, even when
it pointed at phishing: model 0.90 plus an agreeing ``cert_intel`` 0.4 gave
0.757, and a second agreeing signal gave 0.680. More evidence that a site
was phishing made ARGUS less sure that it was.

Noisy-OR is monotone by construction instead. Each source contributes an
independent "this alone would explain a phishing verdict" probability
``w_i * s_i``, and the combined risk is the probability that *at least one*
of them fires::

    escalated = 1 - (1 - w_model * p) * PROD_phishing (1 - w_i * s_i)
    risk      = escalated * PROD_legitimate (1 - w_j * s_j)

Because every factor ``(1 - w * s)`` lies in ``[0, 1]``, extending the
product can only shrink it, so ``escalated`` can only rise: adding agreeing
phishing evidence never lowers the risk score. Dissenting
``direction="legitimate"`` evidence still lowers it, via a separate
multiplicative discount — the asymmetry is deliberate, since corroboration
and contradiction are genuinely different operations.

The weights keep exactly the meaning they had in ``detection_config.yaml``
(*how far one signal alone is allowed to move a verdict*), so the existing
tuned values carry over unchanged; they are now interpreted as per-signal
reliabilities and are clamped to ``[0, 1]``, which every shipped value
already satisfies.

Backward compatibility: with no triggered signals the products are empty
(``= 1``) and the rule collapses to ``risk = w_model * p``, i.e. exactly
``model_proba`` at the shipped ``model: 1.0`` weight. A disabled or
all-neutral run therefore still reproduces the pre-Phase-1 model-only
decision when ``fusion_threshold`` equals the model's own calibrated
threshold (the default in ``detection_config.yaml``).

Known limitation: noisy-OR assumes the sources are conditionally
independent, and ARGUS's signals are not fully independent (``redirect_chain``
only ever fires when a typosquat check already fired on the final landing
URL). Correlated signals are therefore counted twice, which inflates risk
rather than deflating it. That is a calibration question, tuned through the
per-signal weights in ``detection_config.yaml``, not a monotonicity bug —
and it is the safer failure direction for the operator that was previously
losing recall outright.
"""

from __future__ import annotations

import logging
from typing import Any

from src.detection.types import FusedVerdict, RiskSignal

logger = logging.getLogger(__name__)

# Matches configs/model_config.yaml's calibrated threshold (DEC-017) — used
# only if detection_config.yaml doesn't specify its own fusion_threshold.
DEFAULT_FUSION_THRESHOLD = 0.30


def _clamp01(value: float) -> float:
    """Clamp a float into ``[0.0, 1.0]``."""
    return max(0.0, min(1.0, value))


def fuse(model_proba: float, signals: list[RiskSignal], config: dict[str, Any]) -> FusedVerdict:
    """Combine the model's probability with a list of evaluated signals.

    Uses a monotone noisy-OR accumulation (see the module docstring): adding
    a triggered ``direction="phishing"`` signal can never lower the returned
    ``risk_score``.

    Args:
        model_proba: The ML model's phishing-class probability, ``0.0``-``1.0``.
        signals: Every signal that was evaluated (triggered or not).
        config: The loaded ``detection_config.yaml`` contents — reads
            ``fusion_threshold``, ``signal_weights`` (``{"model": ..., "<signal
            name>": ...}``), and ``hard_override_signals``.

    Returns:
        A :class:`FusedVerdict`.
    """
    hard_override_names = set(config.get("hard_override_signals", []))
    weights = config.get("signal_weights", {})
    model_weight = _clamp01(float(weights.get("model", 1.0)))
    threshold = float(config.get("fusion_threshold", DEFAULT_FUSION_THRESHOLD))

    for signal in signals:
        if signal.triggered and signal.is_hard_override and signal.name in hard_override_names:
            confidence = max(signal.score, 0.95)
            logger.info(
                "Fusion hard override: signal=%r evidence=%s", signal.name, signal.evidence
            )
            return FusedVerdict(
                label="phishing",
                confidence=confidence,
                risk_score=confidence,
                model_proba=model_proba,
                signals=signals,
                decisive_source=signal.name,
            )

    # P(no source has fired yet), seeded with the model's own evidence. Each
    # agreeing signal multiplies this by its own (1 - w*s) <= 1, so it only
    # ever shrinks -- which is precisely why the escalated risk below only
    # ever grows as agreeing evidence accumulates.
    none_fired = 1.0 - _clamp01(model_weight * _clamp01(model_proba))

    # Independent multiplicative discount for dissenting evidence. No shipped
    # signal emits direction="legitimate" today (every signal is
    # "phishing" when triggered and "neutral" when not), but the contract
    # allows it and the type system carries it, so it is handled explicitly.
    exoneration = 1.0

    for signal in signals:
        if not signal.triggered:
            continue
        weight = _clamp01(float(weights.get(signal.name, 0.0)))
        if weight <= 0:
            continue
        contribution = _clamp01(weight * _clamp01(signal.score))
        if signal.direction == "phishing":
            none_fired *= 1.0 - contribution
        elif signal.direction == "legitimate":
            exoneration *= 1.0 - contribution
        # A triggered signal is never "neutral" -- enforced at construction
        # time by RiskSignal.__post_init__, so there is no third branch here.

    risk_score = _clamp01((1.0 - none_fired) * exoneration)

    is_phishing = risk_score >= threshold
    label = "phishing" if is_phishing else "legitimate"
    any_triggered = any(s.triggered for s in signals)
    decisive_source = "fusion" if any_triggered else "model"

    return FusedVerdict(
        label=label,
        confidence=risk_score if is_phishing else 1 - risk_score,
        risk_score=risk_score,
        model_proba=model_proba,
        signals=signals,
        decisive_source=decisive_source,
    )
