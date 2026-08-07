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
from src.detection.signals import (
    brand_mismatch,
    cert_intel,
    credential_context,
    favicon_match,
    platform_risk,
    redirect_chain,
    semantic_content,
    typosquat,
)
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

    # Every page-dependent signal lives in this one block. `corroborators`
    # is computed partway through it (rather than the block being split in
    # two around that computation, as it was originally) because the
    # signals after it are the ones that consume it — the ordering of
    # appends, and so of the `signals` list in the API response, is
    # unchanged.
    corroborators: list[RiskSignal] = []
    if page_artifacts is not None and page_artifacts.ok:
        favicon_params = signal_params.get("favicon_match", {})
        favicon_signal = _run_signal_safely(
            "favicon_match",
            lambda: favicon_match.evaluate(
                page_artifacts,
                url,
                brand_index,
                # Single source of truth: fall back to the signal module's
                # own default rather than duplicating the magic number here
                # -- a stale hardcoded copy of this value is exactly what
                # caused the real-brand false positives found and fixed
                # during Phase 1 validation (DEC-026).
                phash_tolerance=favicon_params.get(
                    "phash_tolerance", favicon_match._DEFAULT_PHASH_TOLERANCE
                ),
            ),
        )
        signals.append(favicon_signal)

        brand_mismatch_signal = _run_signal_safely(
            "brand_mismatch",
            lambda: brand_mismatch.evaluate(
                page_artifacts, url, brand_index, favicon_signal, html_features
            ),
        )
        signals.append(brand_mismatch_signal)

        # F4 (Phase 3) — credential-harvesting taxonomy. Independent of
        # brand_index (works even when the brand reference is empty), so it
        # runs on any successfully-fetched page regardless of brand match.
        credential_context_signal = _run_signal_safely(
            "credential_context",
            lambda: credential_context.evaluate(page_artifacts, html_features),
        )
        signals.append(credential_context_signal)

        # An already-triggered brand-identity signal corroborates each of
        # the three signals below (semantic_content, cert_intel per DEC-034,
        # and platform_risk after this block).
        corroborators = [
            s for s in (brand_mismatch_signal, credential_context_signal) if s is not None
        ]

        # F17 (Phase 6) — social-engineering content taxonomy. A pure
        # corroborator (see semantic_content.py's module docstring): it can
        # only ever trigger alongside an already-triggered brand_mismatch/
        # credential_context, or a recently-registered domain, so it never
        # independently contributes fusion weight to a verdict nothing else
        # already flagged.
        signals.append(
            _run_signal_safely(
                "semantic_content",
                lambda: semantic_content.evaluate(page_artifacts, corroborators, html_features),
            )
        )

        # A4 (Phase 2) — reuses the TLS cert already captured by the shared
        # fetch; no extra connection. A5 (Phase 2) — reuses the redirect
        # chain already captured by the same fetch; no extra fetch either.
        signals.append(
            _run_signal_safely(
                "cert_intel",
                lambda: cert_intel.evaluate(
                    page_artifacts, url, brand_index, html_features, corroborators
                ),
            )
        )
        redirect_params = signal_params.get("redirect_chain", {})
        signals.append(
            _run_signal_safely(
                "redirect_chain",
                lambda: redirect_chain.evaluate(
                    page_artifacts,
                    url,
                    brand_index,
                    max_edit_distance=redirect_params.get("max_edit_distance", 2),
                ),
            )
        )

    # F3 (Phase 3) — free/shared-hosting-platform risk awareness. Runs
    # regardless of page-fetch success (it's hostname-only), but only ever
    # triggers when it can corroborate an already-triggered brand_mismatch
    # or credential_context signal -- both of which require a successful
    # fetch, so in practice this is a safe no-op whenever the fetch failed.
    tenant_hosting_platforms = frozenset(
        p.lower() for p in config.get("tenant_hosting_platforms", [])
    )
    signals.append(
        _run_signal_safely(
            "platform_risk",
            lambda: platform_risk.evaluate(url, tenant_hosting_platforms, corroborators),
        )
    )

    return fusion.fuse(model_proba, signals, config)
