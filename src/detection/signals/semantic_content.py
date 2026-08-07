"""Semantic / social-engineering content-taxonomy signal (Phase 6, F17).

Targets the same content-level gap F2-F4 targeted (DEC-018): a page's
*wording* -- the pretext it uses to pressure a visitor -- carries no weight
in the trained model's domain-level feature contract at all, and isn't
covered by any existing signal either (``credential_context`` classifies
*what field* a page asks for, never *what it says* to talk a visitor into
filling it in). This signal closes that specific gap: a deterministic,
explainable lexicon/taxonomy classifier over the page's visible text,
matching the exact architectural choice already made for
``credential_context``/``platform_risk`` -- there is no labeled
phishing-page-text corpus in this project (``src/detection/__init__.py``'s
own module docstring), so a trained text classifier is not attempted here;
a rule-based taxonomy is the honest, reproducible alternative available
today.

Six social-engineering categories, drawn from well-documented phishing
pretexts (urgency/threat, fake security alerts, prize/lottery scams,
tech-support scams, payment/invoice pressure, account-verification
pressure). Matching page text against this lexicon is deliberately treated
as *weak* evidence on its own -- legitimate marketing and billing copy uses
urgency language too ("Sale ends today!", "Update your payment method") --
so, exactly like ``platform_risk``, **this signal never triggers alone**.
It is a pure corroborator: it only fires when the page's wording matches the
taxonomy *and* an independent, already-evaluated signal
(``brand_mismatch`` or ``credential_context``) has already triggered, or the
domain was recently registered. DEC-031 documented that fusion had no
headroom for a moderately-weighted signal to tip a borderline verdict alone
(``cert_intel`` was the practical offender, fixed at its own source by
DEC-034); this signal is designed so it structurally cannot do that either:
it cannot contribute fusion weight to a verdict where nothing else has
already fired.
"""

from __future__ import annotations

import logging
import re
import time
from typing import Any, Optional

from bs4 import BeautifulSoup

from src.detection.types import RiskSignal

logger = logging.getLogger(__name__)

_SIGNAL_NAME = "semantic_content"

# Cap on how much visible text is scanned -- bounds regex cost on
# pathologically large pages, matching the spirit of page_artifacts.py's own
# MAX_BODY_BYTES cap. Social-engineering pretext language is front-loaded
# (headline/lede of the page), so truncation does not meaningfully reduce
# detection power.
_MAX_TEXT_CHARS = 20_000

# Weight of each matched taxonomy category toward this signal's own score --
# a module constant (structural to this signal's internal scoring), distinct
# from the cross-signal fusion weights read from detection_config.yaml.
_CATEGORY_WEIGHTS: dict[str, float] = {
    "urgency_threat": 0.30,
    "fake_security_alert": 0.30,
    "tech_support_scam": 0.30,
    "account_verification_pressure": 0.25,
    "payment_invoice_pressure": 0.25,
    "prize_lottery": 0.20,
}

# Signals whose trigger corroborates a taxonomy match -- same convention as
# platform_risk.py's _CORROBORATING_SIGNAL_NAMES, kept in one place so a
# future new page-content signal only needs to be added here to participate.
_CORROBORATING_SIGNAL_NAMES: frozenset[str] = frozenset({"brand_mismatch", "credential_context"})

_CATEGORY_PATTERNS: dict[str, re.Pattern[str]] = {
    "urgency_threat": re.compile(
        r"\bact(ion)?\s+(now|immediately|required)\b|"
        r"\baccount\s+(will\s+be|has\s+been)\s+(suspended|locked|limited|restricted|"
        r"disabled|closed|terminated)\b|"
        r"\bimmediate\s+action\s+required\b|"
        r"\bunusual\s+activity\s+detected\b|"
        r"\bverify\s+(immediately|now|within\s+\d+\s+hours?)\b|"
        r"\bwithin\s+24\s+hours\b",
        re.IGNORECASE,
    ),
    "fake_security_alert": re.compile(
        r"\bsecurity\s+alert\b|"
        r"\bsuspicious\s+(login|sign-?in)\s+attempt\b|"
        r"\bunauthoriz(ed|ation)\s+(access|login|sign-?in)\s+attempt\b|"
        r"\baccount\s+(has\s+been\s+)?compromised\b",
        re.IGNORECASE,
    ),
    "prize_lottery": re.compile(
        r"\byou(r|'ve|\s+have)?\s+(have\s+)?won\b|"
        r"\bclaim\s+your\s+(prize|reward|gift)\b|"
        r"\bcongratulations,?\s+you\b|"
        r"\blucky\s+winner\b",
        re.IGNORECASE,
    ),
    "tech_support_scam": re.compile(
        r"\bcall\s+(the\s+number\s+)?(below|now|immediately)\b|"
        r"\bcomputer\s+(has\s+been\s+)?infected\b|"
        r"\bdo\s+not\s+(restart|shut\s*down|turn\s*off)\s+your\s+computer\b|"
        r"\btechnical\s+support\s+(team|department)\b",
        re.IGNORECASE,
    ),
    "payment_invoice_pressure": re.compile(
        r"\binvoice\s+attached\b|"
        r"\boutstanding\s+(payment|balance)\b|"
        r"\bpayment\s+(could\s+not\s+be|failed\s+to\s+be)\s+processed\b|"
        r"\bupdate\s+your\s+(billing|payment)\s+(information|details|method)\b",
        re.IGNORECASE,
    ),
    "account_verification_pressure": re.compile(
        r"\bconfirm\s+your\s+identity\b|"
        r"\bverify\s+your\s+account\b|"
        r"\bre-?enter\s+your\s+password\b|"
        r"\baccount\s+access\s+will\s+be\s+restricted\b",
        re.IGNORECASE,
    ),
}


def _elapsed(start: float) -> float:
    return round((time.perf_counter() - start) * 1000, 3)


def _neutral(start: float) -> RiskSignal:
    return RiskSignal(
        name=_SIGNAL_NAME, triggered=False, score=0.0, direction="neutral",
        evidence={}, latency_ms=_elapsed(start),
    )


def _visible_text(soup: BeautifulSoup) -> str:
    """Concatenate the page's visible text, stripping script/style content
    so JS/CSS source text can never masquerade as page wording."""
    for tag in soup(["script", "style", "noscript"]):
        tag.decompose()
    return soup.get_text(separator=" ", strip=True)[:_MAX_TEXT_CHARS]


def _classify_text(text: str) -> set[str]:
    """Return the set of social-engineering taxonomy categories matched in
    ``text``."""
    return {
        category
        for category, pattern in _CATEGORY_PATTERNS.items()
        if pattern.search(text)
    }


def evaluate(
    page_artifacts: Optional[Any],
    corroborating_signals: list[RiskSignal],
    html_features: Optional[dict[str, Any]] = None,
) -> RiskSignal:
    """Evaluate a page's visible text against a social-engineering taxonomy.

    Args:
        page_artifacts: The shared fetch context. Returns neutral if
            ``None`` or no HTML was retrieved.
        corroborating_signals: Every other signal already evaluated for this
            request (``run_detection`` passes ``brand_mismatch`` and
            ``credential_context``'s results here, same convention as
            ``platform_risk.evaluate``) -- this signal never re-derives page
            content itself, and never triggers unless one of these already
            has.
        html_features: The live-extractor's feature dict -- used for the
            ``recently_registered_domain`` corroboration axis
            (``is_recently_registered``, from ``domain_intel.py``), same
            convention as ``credential_context.evaluate``.

    Returns:
        A :class:`RiskSignal`; never raises.
    """
    start = time.perf_counter()
    try:
        if page_artifacts is None or not getattr(page_artifacts, "html", None):
            return _neutral(start)

        try:
            soup = BeautifulSoup(page_artifacts.html, "lxml")
        except Exception as exc:  # noqa: BLE001
            logger.warning("semantic_content: HTML parse failed: %s", exc)
            return _neutral(start)

        matched_categories = _classify_text(_visible_text(soup))
        if not matched_categories:
            return _neutral(start)

        corroborators = [
            s
            for s in corroborating_signals
            if s.triggered and s.name in _CORROBORATING_SIGNAL_NAMES
        ]
        recently_registered = bool(
            html_features.get("is_recently_registered") if html_features else False
        )
        if not corroborators and not recently_registered:
            # Pretext language alone is exactly the weak evidence this
            # signal must not act on -- real marketing/billing copy uses
            # urgency language too. Must not trigger without independent
            # corroboration (mirrors platform_risk.py's identical rule).
            return _neutral(start)

        score = sum(_CATEGORY_WEIGHTS[c] for c in matched_categories)

        return RiskSignal(
            name=_SIGNAL_NAME, triggered=True, score=round(min(score, 1.0), 4),
            direction="phishing",
            evidence={
                "matched_categories": sorted(matched_categories),
                "corroborating_signals": [s.name for s in corroborators],
                "recently_registered_domain": recently_registered,
            },
            latency_ms=_elapsed(start),
        )
    except Exception as exc:  # noqa: BLE001 - Iron Law #3
        logger.warning("semantic_content signal failed: %s", exc)
        return _neutral(start)
