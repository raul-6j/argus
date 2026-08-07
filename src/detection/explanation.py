"""Plain-language verdict explanations (Phase 1, B2).

Renders a single human-readable sentence from SHAP top-5 feature
attributions plus triggered detection signals. Deterministic template
renderer — no LLM call — so it's free, instant, and has no external
dependency; a future localization/LLM-upgraded version can replace the
phrase tables below without changing :func:`explain_plain`'s signature.
"""

from __future__ import annotations

import logging
from typing import Any, Optional, Union

from src.detection.types import RiskSignal

logger = logging.getLogger(__name__)

# Human phrases for each detection signal, keyed by signal name. ``{...}``
# placeholders are filled from that signal's `evidence` dict (see
# RiskSignal.to_dict / detection signal modules).
_SIGNAL_PHRASES: dict[str, str] = {
    "favicon_match": "its icon matches {impersonated_brand}'s, but the site is hosted on a different domain",
    "typosquat": "its domain looks like a misspelled or look-alike version of {impersonated_brand}",
    "brand_mismatch": "the page claims to be {page_brand} but is hosted on {domain_brand}",
    "credential_context": "it asks for sensitive information and submits it in a suspicious way",
    "platform_risk": "it is hosted on a free/shared platform ({platform}), which hides "
                     "the usual domain-reputation signals",
    "semantic_content": "its wording uses social-engineering pressure tactics (e.g. urgency, "
                        "fake security alerts, or account-verification threats)",
}

# Human phrases for a handful of the most explainable SHAP features (the
# 18-feature training contract — src.models.contract.FEATURE_ORDER). Only
# fired when that feature pushed toward phishing (positive SHAP value).
_SHAP_PHRASES: dict[str, str] = {
    "domain_age_cat": "the domain was registered very recently",
    "domain_reg_length": "the domain's registration is unusually short-lived",
    "has_dns_record": "the domain has no resolvable DNS record",
    "has_ip_address": "the address is a raw IP rather than a domain name",
    "has_at_symbol": "the URL contains an '@' symbol, often used to obscure the real destination",
    "server_form_handler": "the login form submits to a different, external site",
    "has_popup": "the page opens suspicious pop-up windows",
    "right_click_disabled": "the page disables right-click, a common evasion tactic",
    "has_favicon": "the page has no favicon",
    "https_in_domain": "the page is not served over a trusted HTTPS connection",
    "submits_to_email": "the form submits data directly to an email address",
    "has_onmouseover": "the page changes the status bar on hover, a common evasion tactic",
    "has_shortening": "the URL uses a link-shortening service",
    "has_prefix_suffix": "the domain uses a hyphen, often used to imitate a real brand name",
}

_MAX_REASONS = 3


def _signal_triggered(signal: Union[RiskSignal, dict[str, Any]]) -> bool:
    if isinstance(signal, dict):
        return bool(signal.get("triggered"))
    return bool(getattr(signal, "triggered", False))


def _signal_name(signal: Union[RiskSignal, dict[str, Any]]) -> Optional[str]:
    if isinstance(signal, dict):
        return signal.get("name")
    return getattr(signal, "name", None)


def _signal_evidence(signal: Union[RiskSignal, dict[str, Any]]) -> dict[str, Any]:
    if isinstance(signal, dict):
        return signal.get("evidence") or {}
    return getattr(signal, "evidence", None) or {}


def _any_triggered(signals: Optional[list]) -> bool:
    return any(_signal_triggered(s) for s in (signals or []))


def _generic_sentence(verdict: str) -> str:
    if verdict == "phishing":
        return "Flagged as phishing based on the model's analysis of this page's characteristics."
    return "No strong phishing indicators found."


def explain_plain(
    shap_top5: Optional[list[dict[str, Any]]],
    signals: Optional[list[Union[RiskSignal, dict[str, Any]]]],
    verdict: str,
) -> str:
    """Compose a single human-readable sentence from SHAP + triggered signals.

    Never raises (Iron Law #3) — any rendering problem falls back to a
    generic, still-honest sentence.

    Args:
        shap_top5: ``/explain``'s ``top5_features`` list (or ``None``).
        signals: The fused verdict's signals — either
            :class:`~src.detection.types.RiskSignal` objects or their
            ``.to_dict()`` form (or ``None``/``[]``).
        verdict: ``"phishing"`` or ``"legitimate"``.

    Returns:
        A single explanatory sentence.
    """
    try:
        if verdict == "legitimate" and not _any_triggered(signals):
            return (
                "No phishing indicators found — this page's features are "
                "consistent with a legitimate site."
            )

        reasons: list[str] = []

        for signal in signals or []:
            if not _signal_triggered(signal):
                continue
            name = _signal_name(signal)
            if name not in _SIGNAL_PHRASES:
                continue
            evidence = _signal_evidence(signal)
            try:
                reasons.append(_SIGNAL_PHRASES[name].format(**evidence))
            except (KeyError, IndexError):
                reasons.append(_SIGNAL_PHRASES[name])

        for item in (shap_top5 or [])[:5]:
            feature = item.get("feature") if isinstance(item, dict) else None
            shap_value = item.get("shap_value") if isinstance(item, dict) else None
            if feature in _SHAP_PHRASES and isinstance(shap_value, (int, float)) and shap_value > 0:
                reasons.append(_SHAP_PHRASES[feature])

        if not reasons:
            return _generic_sentence(verdict)

        seen: set[str] = set()
        unique_reasons: list[str] = []
        for reason in reasons:
            if reason not in seen:
                seen.add(reason)
                unique_reasons.append(reason)
        unique_reasons = unique_reasons[:_MAX_REASONS]

        verb = (
            "Flagged as phishing because"
            if verdict == "phishing"
            else "Marked as legitimate, though note that"
        )
        return f"{verb} {', and '.join(unique_reasons)}."
    except Exception as exc:  # noqa: BLE001 - Iron Law #3
        logger.warning("explain_plain rendering failed: %s", exc)
        return _generic_sentence(verdict)
