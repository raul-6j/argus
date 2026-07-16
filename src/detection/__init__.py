"""ARGUS detection / verdict-fusion layer (Phase 1, DEC-A).

Combines the trained ML model's phishing probability with deterministic,
explainable brand-intelligence signals (typosquat/homograph, favicon/logo
match, brand-vs-domain mismatch) via :mod:`src.detection.fusion`. The
18-feature ML model itself is never retrained or modified by this package —
there is no labeled page-content training corpus, so brand/page signals
live here as a separate, additive layer fused with the model's probability
at request time, keeping the model's own honestly-evaluated F1 untouched
(see ``docs/DECISIONS.md`` DEC-A).

Entry point: :func:`run_detection`, called from ``src/api/detect.py`` on the
enriched (``enrich=true``) path only — page-dependent signals need the
fetched page, and the fast/hostname-only path stays byte-for-byte unchanged
from before this package existed.
"""

from __future__ import annotations

import logging
from typing import Any, Optional

from src.detection import fusion
from src.detection.brand_reference import BrandIndex
from src.detection.signals import brand_mismatch, favicon_match, typosquat
from src.detection.types import FusedVerdict, RiskSignal
from src.features.page_artifacts import PageArtifacts

logger = logging.getLogger(__name__)


def _run_signal_safely(name: str, fn) -> RiskSignal:
    """Run one signal function, catching anything it raises.

    Every signal module already guards its own body (Iron Law #3), but this
    is defense-in-depth at the orchestration level: a bug in one signal must
    never sink the overall fused verdict.
    """
    try:
        return fn()
    except Exception as exc:  # noqa: BLE001 - a signal must never crash detection
        logger.warning("Detection signal %r raised, treating as neutral: %s", name, exc)
        return RiskSignal(name=name, triggered=False, score=0.0, direction="neutral", evidence={})


def run_detection(
    url: str,
    *,
    model_proba: float,
    page_artifacts: Optional[PageArtifacts],
    html_features: Optional[dict[str, Any]],
    brand_index: BrandIndex,
    config: dict[str, Any],
) -> FusedVerdict:
    """Run every detection signal and fuse them with the model's probability.

    Args:
        url: The URL being evaluated (hostname-only or full, as received).
        model_proba: The ML model's phishing-class probability for ``url``.
        page_artifacts: The shared single-fetch context from
            :mod:`src.features.page_artifacts` (``None`` or ``not .ok``
            means page-dependent signals — favicon match, brand mismatch —
            become neutral automatically; typosquat still runs, since it is
            hostname-only).
        html_features: The live-extractor's Tier-4 HTML feature dict (used
            by the brand-mismatch signal for offsite-form corroboration),
            or ``None``.
        brand_index: The loaded brand reference (an empty index makes every
            brand-dependent signal a safe no-op).
        config: The loaded ``detection_config.yaml`` contents.

    Returns:
        A :class:`~src.detection.types.FusedVerdict` combining the model and
        every signal's contribution.
    """
    if not config.get("enabled", False):
        # Not normally reached (callers gate on `enabled` before calling
        # this at all), but defensive: reproduce the model-only decision
        # exactly, with no signals.
        threshold = float(config.get("fusion_threshold", fusion.DEFAULT_FUSION_THRESHOLD))
        is_phishing = model_proba >= threshold
        return FusedVerdict(
            label="phishing" if is_phishing else "legitimate",
            confidence=model_proba if is_phishing else 1 - model_proba,
            risk_score=model_proba,
            model_proba=model_proba,
            signals=[],
            decisive_source="model",
        )

    signal_params = config.get("signal_params", {})
    signals: list[RiskSignal] = []

    # A3 — pure lexical (hostname only); safe to run regardless of whether
    # the page fetch succeeded.
    typo_params = signal_params.get("typosquat", {})
    signals.append(
        _run_signal_safely(
            "typosquat",
            lambda: typosquat.evaluate(
                url, brand_index, max_edit_distance=typo_params.get("max_edit_distance", 2)
            ),
        )
    )

    favicon_signal: Optional[RiskSignal] = None
    if page_artifacts is not None and page_artifacts.ok:
        favicon_params = signal_params.get("favicon_match", {})
        favicon_signal = _run_signal_safely(
            "favicon_match",
            lambda: favicon_match.evaluate(
                page_artifacts,
                url,
                brand_index,
                phash_tolerance=favicon_params.get("phash_tolerance", 8),
            ),
        )
        signals.append(favicon_signal)

        signals.append(
            _run_signal_safely(
                "brand_mismatch",
                lambda: brand_mismatch.evaluate(
                    page_artifacts, url, brand_index, favicon_signal, html_features
                ),
            )
        )

    return fusion.fuse(model_proba, signals, config)
