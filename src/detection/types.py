"""Shared dataclasses for the Phase-1 detection/fusion layer (DEC-A).

Kept in their own module (rather than inside ``fusion.py`` or a signal
module) so every signal, the fusion layer, and the API wiring can import
them without a circular dependency.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


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
        """Shape matching ``RiskSignalSchema`` (the public API contract)."""
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
