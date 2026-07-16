"""Brand-vs-domain mismatch engine (Phase 1, A1).

**DEC-A:** this is a deterministic, configurable *heuristic/rule* engine —
NOT a retrained ML model. There is no labeled page-content training corpus
(UCI/Kaggle have no brand-mismatch columns), so this signal lives entirely
in the fusion layer, outside the trained 18-feature model (see
``docs/DECISIONS.md`` DEC-A). A supervised page-content brand model is
explicitly out of scope for Phase 1.

Extracts the brand the *page* claims to be (title / ``og:site_name`` / other
meta tags) and compares it against the brand that actually owns the
*domain*. A mismatch alone is deliberately **not** enough to trigger — a
merchant page that mentions "We accept PayPal" or a news article about
PayPal would otherwise false-positive. Triggering requires at least one
corroborating axis: a credential-harvesting context (a password field on the
page) or an independent favicon-match hit for the same brand. This mirrors
the plan's explicit requirement: "require credential/login context, not mere
mention."
"""

from __future__ import annotations

import logging
import re
import time
from typing import TYPE_CHECKING, Any, Optional

from bs4 import BeautifulSoup

from src.detection.types import RiskSignal
from src.utils.domains import registered_domain

if TYPE_CHECKING:
    from src.detection.brand_reference import Brand, BrandIndex
    from src.features.page_artifacts import PageArtifacts

logger = logging.getLogger(__name__)

_SIGNAL_NAME = "brand_mismatch"

# Weight of each contributing axis toward the final score. A module
# constant (not detection_config.yaml) since these are structural to this
# signal's own internal scoring, distinct from the cross-signal fusion
# weights the fusion layer reads from config.
_AXIS_WEIGHTS: dict[str, float] = {
    "page_brand_domain_mismatch": 0.45,
    "credential_context": 0.25,
    "favicon_signal": 0.20,
    "offsite_form": 0.10,
}

_META_BRAND_PROPERTIES = ("og:site_name", "application-name", "twitter:site")
# Precompiled once at import time -- this signal runs on the hot enriched
# request path, and the pattern set is fixed, so there is no reason to
# recompile the same 3 small regexes on every evaluate() call.
_META_BRAND_PATTERNS = [re.compile(f"^{re.escape(p)}$", re.IGNORECASE) for p in _META_BRAND_PROPERTIES]


def _extract_page_brand_tokens(html: str) -> set[str]:
    """Pull candidate brand-name text from the title and brand-ish meta tags."""
    tokens: set[str] = set()
    try:
        soup = BeautifulSoup(html, "lxml")
    except Exception as exc:  # noqa: BLE001
        logger.warning("brand_mismatch: HTML parse failed: %s", exc)
        return tokens

    if soup.title and soup.title.get_text(strip=True):
        tokens.add(soup.title.get_text(strip=True).lower())

    for pattern in _META_BRAND_PATTERNS:
        tag = soup.find("meta", attrs={"property": pattern}) or soup.find(
            "meta", attrs={"name": pattern}
        )
        if tag is not None:
            content = tag.get("content")
            if content:
                tokens.add(str(content).strip().lower())

    return tokens


def _has_credential_context(html: str) -> bool:
    try:
        soup = BeautifulSoup(html, "lxml")
    except Exception:  # noqa: BLE001
        return False
    for inp in soup.find_all("input"):
        if str(inp.get("type", "")).strip().lower() == "password":
            return True
    return False


def _brand_mentioned(tokens: set[str], brand: "Brand") -> bool:
    needles = {brand.name.lower(), *brand.aliases}
    for token in tokens:
        for needle in needles:
            if needle and needle in token:
                return True
    return False


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
    favicon_signal: Optional[RiskSignal] = None,
    html_features: Optional[dict[str, Any]] = None,
) -> RiskSignal:
    """Evaluate whether the page claims a brand identity its domain doesn't own.

    Args:
        page_artifacts: The shared fetch context. Returns neutral if
            ``None`` or no HTML was retrieved.
        visited_url: The URL actually being evaluated.
        brand_index: The loaded brand reference.
        favicon_signal: The already-evaluated favicon-match signal (A2), if
            any — used as a corroborating axis.
        html_features: The live-extractor's Tier-4 HTML feature dict, used
            for the offsite-form corroborating axis
            (``form_action_is_external`` / ``form_submits_to_email``).

    Returns:
        A :class:`RiskSignal`; never raises.
    """
    start = time.perf_counter()
    try:
        if page_artifacts is None or not page_artifacts.html or not brand_index.brands:
            return _neutral(start)

        visited_domain = registered_domain(visited_url) or registered_domain(
            page_artifacts.final_url or ""
        )
        page_tokens = _extract_page_brand_tokens(page_artifacts.html)
        if not page_tokens:
            return _neutral(start)

        has_credential_context = _has_credential_context(page_artifacts.html)
        offsite_form = False
        if html_features is not None:
            offsite_form = bool(html_features.get("form_action_is_external")) or bool(
                html_features.get("form_submits_to_email")
            )

        for brand in brand_index.brands:
            if visited_domain and visited_domain in brand.domains:
                continue  # legitimate site — the page IS allowed to claim this brand
            if not _brand_mentioned(page_tokens, brand):
                continue

            axes_triggered = ["page_brand_domain_mismatch"]
            score = _AXIS_WEIGHTS["page_brand_domain_mismatch"]

            favicon_corroborates = (
                favicon_signal is not None
                and favicon_signal.triggered
                and favicon_signal.evidence.get("impersonated_brand") == brand.name
            )

            if has_credential_context:
                axes_triggered.append("credential_context")
                score += _AXIS_WEIGHTS["credential_context"]
            if favicon_corroborates:
                axes_triggered.append("favicon_signal")
                score += _AXIS_WEIGHTS["favicon_signal"]
            if offsite_form:
                axes_triggered.append("offsite_form")
                score += _AXIS_WEIGHTS["offsite_form"]

            # A bare brand mention with no corroborating context is too weak
            # to flag (avoids false positives on merchant/news pages that
            # merely mention a brand).
            if not has_credential_context and not favicon_corroborates:
                continue

            return RiskSignal(
                name=_SIGNAL_NAME, triggered=True, score=round(min(score, 1.0), 4),
                direction="phishing",
                evidence={
                    "page_brand": brand.name,
                    "domain_brand": visited_domain or "unknown",
                    "axes_triggered": axes_triggered,
                },
                latency_ms=_elapsed(start),
            )

        return _neutral(start)
    except Exception as exc:  # noqa: BLE001 - Iron Law #3
        logger.warning("brand_mismatch signal failed for %r: %s", visited_url, exc)
        return _neutral(start)
