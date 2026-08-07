"""Credential-harvesting taxonomy signal (Phase 3, F4).

Goes beyond the existing ``has_password_field`` boolean (used only as one
corroborating axis inside ``brand_mismatch.py``) to classify *what kind* of
sensitive input a page is collecting, and whether the surrounding context
makes that collection suspicious. Deliberately **not** the naive rule
warned against in the Phase 3 plan ("classifying every page with a password
field as phishing") -- a bare sensitive field is never enough on its own
(a real bank's real login page has a password field too). Triggering
requires a sensitive-field axis **plus** a corroborating axis: the form
posts cross-origin (reusing ``html_content.py``'s already-computed
``form_action_is_external``/``form_submits_to_email``), or the domain was
recently registered (reusing ``domain_intel.py``'s
``is_recently_registered``, present in ``html_features`` whenever the
enriched request also ran the domain-intel tier).

One deliberate exception: a **crypto wallet seed/recovery-phrase** input
field can trigger on its own axis, with no corroboration required. This is
narrow by construction (it only fires on an actual input/textarea field
whose own attributes ask for a seed phrase -- not on page text that merely
*mentions* one, which would false-positive on security-education content)
and the legitimate case is vanishingly rare: wallet software's own
documented best practice is that a seed phrase should **never** be typed
into a web page at all, so a page with such a field is overwhelmingly
either a wallet-drainer phishing kit or the wallet's own onboarding flow
(same-origin, not this signal's target).

Only inspects page *structure* (input attributes, form actions) -- never
reads or logs actual field *values* (Iron Law #1's spirit: nothing here can
leak a real user's password/card/seed phrase, because none is ever
submitted through this static-analysis path).
"""

from __future__ import annotations

import logging
import re
import time
from typing import TYPE_CHECKING, Any, Optional

from bs4 import BeautifulSoup

from src.detection.types import RiskSignal

if TYPE_CHECKING:
    from src.features.page_artifacts import PageArtifacts

logger = logging.getLogger(__name__)

_SIGNAL_NAME = "credential_context"

# Weight of each contributing axis toward the final score -- a module
# constant (structural to this signal's own internal scoring), distinct
# from the cross-signal fusion weights read from detection_config.yaml.
_AXIS_WEIGHTS: dict[str, float] = {
    "password_field": 0.25,
    "otp_field": 0.30,
    "credit_card_field": 0.35,
    "crypto_seed_phrase": 0.60,
    "cross_origin_post": 0.35,
    "recently_registered_domain": 0.30,
}

_WORD_SEP = r"[\s_-]?"

# Note: no \b anchors around the joined multi-word alternatives below --
# form-field name/id attributes commonly join words with underscores
# ("card_number", "wallet_recovery_phrase"), and underscore counts as a
# \w character, so a leading \b would fail to match right after a
# preceding word ("wallet_recovery" has no word/non-word transition before
# "recovery"). These are distinctive enough multi-word phrases that a
# plain substring search carries negligible false-positive risk on a short
# field-attribute descriptor string.
_OTP_PATTERN = re.compile(
    rf"\botp\b|\b2fa\b|one{_WORD_SEP}time{_WORD_SEP}code|verification{_WORD_SEP}code|"
    rf"auth(entication)?{_WORD_SEP}code",
    re.IGNORECASE,
)
_CREDIT_CARD_PATTERN = re.compile(
    rf"card{_WORD_SEP}number|cc{_WORD_SEP}number|\bccnum\b|\bcvv\b|\bcvc\b|"
    rf"card{_WORD_SEP}expiry|exp{_WORD_SEP}date",
    re.IGNORECASE,
)
_SEED_PHRASE_PATTERN = re.compile(
    rf"seed{_WORD_SEP}phrase|recovery{_WORD_SEP}phrase|secret{_WORD_SEP}phrase|"
    rf"\bmnemonic\b|backup{_WORD_SEP}phrase|wallet{_WORD_SEP}phrase",
    re.IGNORECASE,
)

_SENSITIVE_AXES: tuple[str, ...] = (
    "password_field",
    "otp_field",
    "credit_card_field",
    "crypto_seed_phrase",
)
# Axes that are strong enough evidence to trigger with no corroboration at
# all -- see the module docstring's reasoning for crypto_seed_phrase.
_SELF_SUFFICIENT_AXES: frozenset[str] = frozenset({"crypto_seed_phrase"})


def _elapsed(start: float) -> float:
    return round((time.perf_counter() - start) * 1000, 3)


def _neutral(start: float) -> RiskSignal:
    return RiskSignal(
        name=_SIGNAL_NAME, triggered=False, score=0.0, direction="neutral",
        evidence={}, latency_ms=_elapsed(start),
    )


def _field_descriptor(tag: Any) -> str:
    """Concatenate an input/textarea's own attributes/label text (never its
    *value*) into one lowercase string to pattern-match against."""
    parts = [
        str(tag.get("name", "")),
        str(tag.get("id", "")),
        str(tag.get("placeholder", "")),
        str(tag.get("aria-label", "")),
        str(tag.get("autocomplete", "")),
    ]
    return " ".join(parts).lower()


def _classify_fields(soup: BeautifulSoup) -> set[str]:
    """Return the set of sensitive-field axes present on the page."""
    axes: set[str] = set()

    for inp in soup.find_all("input"):
        field_type = str(inp.get("type", "")).strip().lower()
        descriptor = _field_descriptor(inp)
        autocomplete = str(inp.get("autocomplete", "")).strip().lower()

        if field_type == "password":
            axes.add("password_field")
        if autocomplete == "one-time-code" or _OTP_PATTERN.search(descriptor):
            axes.add("otp_field")
        if autocomplete in ("cc-number", "cc-exp", "cc-csc") or _CREDIT_CARD_PATTERN.search(
            descriptor
        ):
            axes.add("credit_card_field")
        if _SEED_PHRASE_PATTERN.search(descriptor):
            axes.add("crypto_seed_phrase")

    for textarea in soup.find_all("textarea"):
        if _SEED_PHRASE_PATTERN.search(_field_descriptor(textarea)):
            axes.add("crypto_seed_phrase")

    return axes


def evaluate(
    page_artifacts: Optional["PageArtifacts"],
    html_features: Optional[dict[str, Any]] = None,
) -> RiskSignal:
    """Evaluate a page's sensitive-input fields and posting context.

    Args:
        page_artifacts: The shared fetch context. Returns neutral if
            ``None`` or no HTML was retrieved.
        html_features: The live-extractor's feature dict -- used for the
            ``cross_origin_post`` axis (``form_action_is_external``/
            ``form_submits_to_email``, from ``html_content.py``) and the
            ``recently_registered_domain`` axis (``is_recently_registered``,
            from ``domain_intel.py``, present only when the domain-intel
            tier ran).

    Returns:
        A :class:`RiskSignal`; never raises.
    """
    start = time.perf_counter()
    try:
        if page_artifacts is None or not page_artifacts.html:
            return _neutral(start)

        try:
            soup = BeautifulSoup(page_artifacts.html, "lxml")
        except Exception as exc:  # noqa: BLE001
            logger.warning("credential_context: HTML parse failed: %s", exc)
            return _neutral(start)

        sensitive_axes = _classify_fields(soup)
        if not sensitive_axes:
            return _neutral(start)

        cross_origin_post = False
        recently_registered = False
        if html_features is not None:
            cross_origin_post = bool(html_features.get("form_action_is_external")) or bool(
                html_features.get("form_submits_to_email")
            )
            recently_registered = bool(html_features.get("is_recently_registered"))

        axes_triggered: list[str] = sorted(sensitive_axes)
        has_self_sufficient = bool(sensitive_axes & _SELF_SUFFICIENT_AXES)
        has_corroboration = cross_origin_post or recently_registered

        if not has_self_sufficient and not has_corroboration:
            # A sensitive field alone (e.g. just a password field) is
            # exactly the naive rule this signal must avoid -- a real
            # login page looks identical on this axis alone.
            return _neutral(start)

        score = sum(_AXIS_WEIGHTS[axis] for axis in sensitive_axes)
        if cross_origin_post:
            axes_triggered.append("cross_origin_post")
            score += _AXIS_WEIGHTS["cross_origin_post"]
        if recently_registered:
            axes_triggered.append("recently_registered_domain")
            score += _AXIS_WEIGHTS["recently_registered_domain"]

        return RiskSignal(
            name=_SIGNAL_NAME, triggered=True, score=round(min(score, 1.0), 4),
            direction="phishing",
            evidence={
                "sensitive_fields": sorted(sensitive_axes),
                "axes_triggered": axes_triggered,
                "cross_origin_post": cross_origin_post,
                "recently_registered_domain": recently_registered,
            },
            latency_ms=_elapsed(start),
        )
    except Exception as exc:  # noqa: BLE001 - Iron Law #3
        logger.warning("credential_context signal failed: %s", exc)
        return _neutral(start)
