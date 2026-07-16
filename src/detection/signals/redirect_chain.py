"""Redirect-chain / shortener-unwrapping signal (Phase 2, A5).

Reuses ``PageArtifacts.redirect_chain``/``final_url`` already captured by
the Phase-1 shared fetch (``src.features.page_artifacts.fetch``, P1.0) —
every hop was already SSRF-validated during that fetch, so this signal
makes **no new network request** and exposing the chain as evidence is
safe.

Design goal: legitimate redirects (``http``→``https``, apex→``www``, ad/
marketing click-trackers landing on a real site) must never false-trigger
— redirecting through multiple domains is extremely common and not itself
suspicious. This signal only fires when the redirect **lands somewhere
that independently looks like a brand impersonation** (re-running the A3
typosquat/homograph check against the *final* URL, not the requested one)
— i.e. it catches "a shortened/redirected link launders a phishing
destination," not "this URL used a redirect."
"""

from __future__ import annotations

import logging
import time
from typing import TYPE_CHECKING, Optional

from src.detection.signals import typosquat
from src.detection.types import RiskSignal
from src.features.lexical import _load_known_shorteners
from src.utils.domains import registered_domain

if TYPE_CHECKING:
    from src.detection.brand_reference import BrandIndex
    from src.features.page_artifacts import PageArtifacts

logger = logging.getLogger(__name__)

_SIGNAL_NAME = "redirect_chain"


def _elapsed(start: float) -> float:
    return round((time.perf_counter() - start) * 1000, 3)


def _neutral(start: float) -> RiskSignal:
    return RiskSignal(
        name=_SIGNAL_NAME, triggered=False, score=0.0, direction="neutral",
        evidence={}, latency_ms=_elapsed(start),
    )


def evaluate(
    page_artifacts: Optional["PageArtifacts"],
    visited_url: str,
    brand_index: "BrandIndex",
    max_edit_distance: int = 2,
) -> RiskSignal:
    """Evaluate a page's redirect chain for laundered brand impersonation.

    Args:
        page_artifacts: The shared fetch context. Returns neutral if
            ``None``, the fetch didn't succeed, or no redirect occurred.
        visited_url: The URL originally requested (before any redirect).
        brand_index: The loaded brand reference, forwarded to a fresh A3
            typosquat evaluation against the *final* landing URL.
        max_edit_distance: Forwarded to the typosquat re-evaluation.

    Returns:
        A :class:`RiskSignal`; never raises.
    """
    start = time.perf_counter()
    try:
        if page_artifacts is None or not page_artifacts.redirect_chain:
            return _neutral(start)

        final_url = page_artifacts.final_url
        if not final_url:
            return _neutral(start)

        requested_domain = registered_domain(visited_url) or registered_domain(
            page_artifacts.requested_url
        )
        final_domain = registered_domain(final_url)
        if not final_domain or final_domain == requested_domain:
            # Same registered domain throughout (http->https, apex->www,
            # or the chain looped back) -- not a laundering case.
            return _neutral(start)

        known_shorteners = _load_known_shorteners()
        shortener_used = bool(requested_domain) and requested_domain in known_shorteners

        # Re-run A3 against the FINAL landing URL, not the requested one --
        # this is the actual page the user ends up on.
        final_signal = typosquat.evaluate(final_url, brand_index, max_edit_distance=max_edit_distance)
        if not final_signal.triggered:
            # Cross-domain redirect, but the landing site doesn't look like
            # a brand impersonation -- the extremely common, benign case
            # (ad networks, affiliate links, OAuth callbacks, etc).
            return _neutral(start)

        evidence = dict(final_signal.evidence)
        evidence["redirect_chain"] = list(page_artifacts.redirect_chain) + [final_url]
        evidence["requested_domain"] = requested_domain or "unknown"
        evidence["final_domain"] = final_domain
        evidence["shortener_used"] = shortener_used

        return RiskSignal(
            name=_SIGNAL_NAME, triggered=True, score=final_signal.score,
            direction="phishing", evidence=evidence, latency_ms=_elapsed(start),
        )
    except Exception as exc:  # noqa: BLE001 - Iron Law #3
        logger.warning("redirect_chain signal failed for %r: %s", visited_url, exc)
        return _neutral(start)
