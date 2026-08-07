"""Free/shared-hosting-platform risk-awareness signal (Phase 3, F3).

Targets DEC-018's documented real-world generalisation gap directly: the
trained model's features measure the *registered domain's* legitimacy
(WHOIS age, DNS health, HTTPS, favicon-of-domain), but modern phishing
increasingly lives at a path/subdomain on an otherwise-legitimate,
freshly-provisioned free-hosting platform (Wix, Vercel, GitHub Pages,
shorteners, ...) -- a domain-level signal that is old/healthy/HTTPS *by
construction*, regardless of what the specific tenant's page actually
contains.

This signal does not judge the page on its own -- doing so would flag every
legitimate site on these platforms too, an enormous false-positive source.
Instead it is a **pure corroborator**: it only triggers when the visited
hostname sits on a known tenant-hosting platform *and* an independent,
already-evaluated page-content signal (``brand_mismatch`` or
``credential_context``) has already fired for the same request. In that
case, the platform match is genuine additional evidence that the domain's
own reputation is not a meaningful signal here -- reframing exactly the
case the model gets wrong -- but never sole justification on its own.

Hostname matching mirrors ``src/api/threat_intel/phishtank.py::
load_phishtank_hostname_index``'s convention exactly (bare hostname,
``host == platform or host.endswith(f".{platform}")``) rather than
registered-domain matching, since several of these platforms
(``github.io``, ``vercel.app``, ``netlify.app``, ...) are themselves public
suffixes -- a tldextract "registered domain" of ``foo.github.io`` is
``foo.github.io`` itself, not ``github.io``.
"""

from __future__ import annotations

import logging
import time
from typing import Optional
from urllib.parse import urlparse

from src.detection.types import RiskSignal

logger = logging.getLogger(__name__)

_SIGNAL_NAME = "platform_risk"
_SCORE = 0.6

# Signals whose trigger corroborates a platform-risk match. Kept in one
# place so a future new page-content signal only needs to be added here to
# participate.
_CORROBORATING_SIGNAL_NAMES: frozenset[str] = frozenset({"brand_mismatch", "credential_context"})


def _elapsed(start: float) -> float:
    return round((time.perf_counter() - start) * 1000, 3)


def _neutral(start: float) -> RiskSignal:
    return RiskSignal(
        name=_SIGNAL_NAME, triggered=False, score=0.0, direction="neutral",
        evidence={}, latency_ms=_elapsed(start),
    )


def _hostname_of(url: str) -> str:
    try:
        return (urlparse(url).hostname or "").lower()
    except Exception:  # noqa: BLE001
        return ""


def _matches_platform(hostname: str, platforms: frozenset[str]) -> Optional[str]:
    for platform in platforms:
        if hostname == platform or hostname.endswith(f".{platform}"):
            return platform
    return None


def evaluate(
    visited_url: str,
    tenant_hosting_platforms: frozenset[str],
    corroborating_signals: list[RiskSignal],
) -> RiskSignal:
    """Evaluate whether a platform-hosted page's risk is corroborated by
    another already-triggered page-content signal.

    Args:
        visited_url: The URL actually being evaluated.
        tenant_hosting_platforms: Lowercase apex domains where each tenant
            gets a dedicated subdomain (``detection_config.yaml``'s
            ``tenant_hosting_platforms``). An empty set makes this signal a
            safe no-op.
        corroborating_signals: Every other signal already evaluated for
            this request (``run_detection`` passes ``brand_mismatch`` and
            ``credential_context``'s results here, in that order) -- this
            signal never re-derives page content itself.

    Returns:
        A :class:`RiskSignal`; never raises.
    """
    start = time.perf_counter()
    try:
        if not tenant_hosting_platforms:
            return _neutral(start)

        hostname = _hostname_of(visited_url)
        if not hostname:
            return _neutral(start)

        matched_platform = _matches_platform(hostname, tenant_hosting_platforms)
        if matched_platform is None:
            return _neutral(start)

        corroborators = [
            s
            for s in corroborating_signals
            if s.triggered and s.name in _CORROBORATING_SIGNAL_NAMES
        ]
        if not corroborators:
            # Platform-hosted, but nothing about the page itself looked
            # suspicious -- the overwhelmingly common, benign case (a real
            # small business's real Wix site, etc). Must not trigger alone.
            return _neutral(start)

        return RiskSignal(
            name=_SIGNAL_NAME, triggered=True, score=_SCORE, direction="phishing",
            evidence={
                "platform": matched_platform,
                "hostname": hostname,
                "corroborating_signals": [s.name for s in corroborators],
            },
            latency_ms=_elapsed(start),
        )
    except Exception as exc:  # noqa: BLE001 - Iron Law #3
        logger.warning("platform_risk signal failed for %r: %s", visited_url, exc)
        return _neutral(start)
