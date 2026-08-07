"""Shared dataclasses for the Phase-1 detection/fusion layer (DEC-A).

Kept in their own module (rather than inside ``fusion.py`` or a signal
module) so every signal, the fusion layer, and the API wiring can import
them without a circular dependency.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Optional

# Default risk-band boundaries (Phase 3, F5), used when
# detection_config.yaml's own ``risk_bands`` list is absent -- calibrated
# against data/processed/val.parquet, not invented (see
# scripts/calibrate_risk_bands.py and reports/risk_band_calibration.json).
# The "suspicious" floor intentionally equals fusion.DEFAULT_FUSION_THRESHOLD
# (0.30, DEC-017) so a verdict's risk_band and its binary label never
# disagree: label == "phishing" iff band is suspicious/high/critical.
DEFAULT_RISK_BANDS: tuple[tuple[str, float], ...] = (
    ("low", 0.0),
    ("caution", 0.15),
    ("suspicious", 0.30),
    ("high", 0.50),
    ("critical", 0.75),
)


def risk_band_for_score(
    risk_score: float, bands: Optional[list[dict[str, Any]]] = None
) -> str:
    """Map a ``risk_score`` (0.0-1.0) to a named risk band.

    Args:
        risk_score: The fused (or model-only) phishing-likelihood score.
        bands: ``detection_config.yaml``'s ``risk_bands`` list
            (``[{"name": ..., "floor": ...}, ...]``, ascending floors), or
            ``None``/empty to use :data:`DEFAULT_RISK_BANDS`.

    Returns:
        The name of the highest band whose floor is ``<= risk_score``
        (``"low"`` if ``risk_score`` is below every floor, defensively).
    """
    ordered = (
        [(b["name"], float(b["floor"])) for b in bands] if bands else list(DEFAULT_RISK_BANDS)
    )
    if not ordered:
        ordered = list(DEFAULT_RISK_BANDS)

    band_name = ordered[0][0]
    for name, floor in ordered:
        if risk_score >= floor:
            band_name = name
        else:
            break
    return band_name


@dataclass
class RiskSignal:
    """One detection signal's verdict for a single URL/page.

    Attributes:
        name: Signal identifier (``"typosquat"``, ``"favicon_match"``,
            ``"brand_mismatch"``).
        triggered: Whether the signal fired.
        score: Signal-local phishing likelihood, ``0.0``-``1.0``. Meaningless
            when ``triggered`` is ``False`` (always ``0.0``).
        direction: ``"phishing"``, ``"legitimate"``, or ``"neutral"``.
        evidence: Signal-specific supporting detail (e.g.
            ``{"impersonated_brand": "PayPal", "distance": 1}``), rendered
            to the API response and consumed by the plain-language explainer.
        is_hard_override: Whether this specific trigger is precise enough to
            force a verdict on its own (e.g. an *exact* favicon-hash match —
            never a fuzzy/heuristic match). Decided by the signal itself,
            gated a second time by ``detection_config.yaml``'s
            ``hard_override_signals`` list in :func:`src.detection.fusion.fuse`.
        latency_ms: Wall-clock time this signal took to evaluate.
        weight: Populated for introspection/debugging only; the actual
            fusion weight is read fresh from config by
            :func:`src.detection.fusion.fuse`.
    """

    name: str
    triggered: bool
    score: float
    direction: str
    evidence: dict[str, Any] = field(default_factory=dict)
    is_hard_override: bool = False
    latency_ms: float = 0.0
    weight: float = 0.0

    def to_dict(self) -> dict[str, Any]:
        """Shape matching each ``signals[]`` entry in the public API contract
        (see ``docs/API.md``)."""
        return {
            "name": self.name,
            "triggered": self.triggered,
            "score": round(self.score, 4),
            "direction": self.direction,
            "evidence": self.evidence,
        }


@dataclass
class FusedVerdict:
    """The combined output of the ML model + every :class:`RiskSignal`.

    Attributes:
        label: ``"phishing"`` or ``"legitimate"``.
        confidence: Confidence in ``label``, ``0.0``-``1.0``.
        risk_score: The fused phishing-likelihood score, ``0.0``-``1.0``
            (equals ``model_proba`` when no signal contributes).
        model_proba: The ML model's raw phishing-class probability, kept
            for transparency/debugging even when a signal overrides it.
        signals: Every signal that was evaluated (triggered or not).
        decisive_source: What actually drove the label — ``"model"`` (no
            signal contributed), ``"fusion"`` (a weighted combination), or a
            signal name (a hard override).
    """

    label: str
    confidence: float
    risk_score: float
    model_proba: float
    signals: list[RiskSignal]
    decisive_source: str
