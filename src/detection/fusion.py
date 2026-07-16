"""Verdict-fusion rule (Phase 1, DEC-A).

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
    2. **Weighted combination** — otherwise, a weighted sum of the model's
       contribution plus every *triggered* signal's contribution,
       normalized by the total weight that actually contributed, then
       thresholded at ``config["fusion_threshold"]``.

When no signal triggers at all, the weighted sum reduces to exactly
``model_proba`` (the model's own weight is the only term), so a disabled or
all-neutral run reproduces the pre-Phase-1 model-only decision when
``fusion_threshold`` is kept equal to the model's own calibrated threshold
(the default in ``detection_config.yaml``).
"""

from __future__ import annotations

import logging
from typing import Any

from src.detection.types import FusedVerdict, RiskSignal

logger = logging.getLogger(__name__)

# Matches configs/model_config.yaml's calibrated threshold (DEC-017) — used
# only if detection_config.yaml doesn't specify its own fusion_threshold.
DEFAULT_FUSION_THRESHOLD = 0.30


def fuse(model_proba: float, signals: list[RiskSignal], config: dict[str, Any]) -> FusedVerdict:
    """Combine the model's probability with a list of evaluated signals.

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
    model_weight = float(weights.get("model", 1.0))
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

    weighted_sum = model_weight * model_proba
    total_weight = model_weight

    for signal in signals:
        if not signal.triggered:
            continue
        weight = float(weights.get(signal.name, 0.0))
        if weight <= 0:
            continue
        total_weight += weight
        if signal.direction == "phishing":
            weighted_sum += weight * signal.score
        elif signal.direction == "legitimate":
            weighted_sum -= weight * signal.score
        # direction == "neutral" contributes nothing, but its weight has
        # already been added to total_weight above -- deliberately not the
        # case, since a triggered signal is never "neutral" by convention
        # (triggered implies phishing or legitimate); kept as a documented
        # invariant rather than an extra branch.

    risk_score = weighted_sum / total_weight if total_weight > 0 else model_proba
    risk_score = max(0.0, min(1.0, risk_score))

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
