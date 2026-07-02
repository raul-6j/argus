"""Live-extractor -> training-contract adapter (DEC-015, DEC-016).

``src/features/pipeline.py`` produces a live URL's raw signals (Tier 1
lexical, Tier 4 HTML, Tier 2/3 domain intelligence). The trained model
consumes a different, UCI-scaled 18-feature contract
(:data:`src.models.contract.FEATURE_ORDER`). This module bridges the two —
see the feature-space-schism note in project memory for why they're
different in the first place.

Every one of the 18 trained features now has a genuine live derivation
(direct, or bucketed onto UCI's ``-1/0/1`` scale using the same
published/empirically-verified thresholds as
``src.data.preprocessor.bucket_kaggle_scale`` — DEC-014). DEC-015 originally
built this adapter over a 22-feature contract with 4 stubbed dead signals
(``web_traffic``, ``page_rank``, ``google_indexed``, ``in_statistical_report``
— Alexa/Google PageRank-era signals, dead in 2026, or requiring an
unavailable third-party blocklist API); feature-importance analysis
(``docs/EXPERIMENTS.md`` Run 1) showed the trained model relying heavily on
exactly those stubbed features, meaning its benchmark accuracy did not
reflect real deployed accuracy. DEC-016 dropped them from the training
contract entirely rather than keep stubbing them — same reasoning as
DEC-013's original 8 dropped features. ``ModelInput.approximated`` is still
populated (and should stay empty in the normal case) if any live tier fails
to run and a feature falls back to its missing-input default.
"""

from __future__ import annotations

import logging
from typing import Any, Callable, Optional

from src.models.contract import FEATURE_ORDER, ModelInput

logger = logging.getLogger(__name__)


def _bool_to_scale(value: Optional[bool], *, true_is_phishing: bool) -> int:
    """Map a boolean signal onto UCI's binary -1/1 convention.

    ``None`` (extraction failed / signal unavailable) maps to -1, the
    phishing-indicating value, per DEC-007's "assume threat when uncertain"
    principle.
    """
    if value is None:
        return -1
    if value:
        return -1 if true_is_phishing else 1
    return 1 if true_is_phishing else -1


def _bucket_reg_length(features: dict[str, Any]) -> int:
    """Same rule as ``preprocessor._bucket_registration_length`` (DEC-014).

    Approximated as domain_age_days + days_until_expiry (creation-to-expiry
    span), since the live extractor has no direct "registration length" field.
    """
    age = features.get("domain_age_days")
    expiry = features.get("days_until_expiry")
    if age is None or expiry is None:
        return -1
    total_days = age + expiry
    return -1 if total_days <= 365 else 1


def _bucket_domain_age(features: dict[str, Any]) -> int:
    """Same rule as ``preprocessor._bucket_domain_age`` (DEC-014)."""
    age = features.get("domain_age_days")
    if age is None or age < 180:
        return -1
    return 1


def _bucket_subdomain_level(features: dict[str, Any]) -> int:
    """0-1 subdomain levels -> legit(1); 2 -> suspicious(0); >=3 -> phishing(-1).

    Approximation: lexical.num_subdomains counts tldextract subdomain parts
    (e.g. "www.example.com" -> 1), so a single common "www" level is treated
    as still-legit rather than suspicious — unlike a strict dot-count rule.
    """
    count = features.get("num_subdomains")
    if count is None:
        return -1
    if count <= 1:
        return 1
    if count == 2:
        return 0
    return -1


def _bucket_has_prefix_suffix(features: dict[str, Any]) -> int:
    """UCI rule: any '-' in hostname -> phishing(-1); none -> legit(1)."""
    count = features.get("num_hyphens_in_hostname")
    return _bool_to_scale(None if count is None else count > 0, true_is_phishing=True)


def _bucket_links_in_tags(features: dict[str, Any]) -> int:
    """Same tercile thresholds as ``preprocessor._bucket_links_in_tags`` (DEC-014),
    adapted to the extractor's 0.0-1.0 ratio scale rather than Kaggle's 0-100.
    """
    ratio = features.get("internal_tag_link_ratio")
    if ratio is None or ratio < 0.333:
        return -1
    if ratio <= 0.667:
        return 0
    return 1


def _bucket_server_form_handler(features: dict[str, Any]) -> int:
    """UCI rule: blank/about:blank action -> -1; external domain -> 0; else 1."""
    is_blank = features.get("form_action_is_empty_or_blank")
    is_external = features.get("form_action_is_external")
    if is_blank is None and is_external is None:
        return -1
    if is_blank:
        return -1
    if is_external:
        return 0
    return 1


# Table of (contract feature name -> deriving function). Each function reads
# whatever raw keys it needs from the live features dict and returns one of
# {-1, 0, 1}. `simple_keys` lists the raw input key(s) each depends on, used
# only to report which contract features were approximated due to missing
# live input (does not affect the computed value itself).
_DERIVATIONS: dict[str, tuple[Callable[[dict[str, Any]], int], tuple[str, ...]]] = {
    "has_ip_address": (
        lambda f: _bool_to_scale(f.get("has_ip_address"), true_is_phishing=True),
        ("has_ip_address",),
    ),
    "has_shortening": (
        lambda f: _bool_to_scale(f.get("has_shortening"), true_is_phishing=True),
        ("has_shortening",),
    ),
    "has_at_symbol": (
        lambda f: _bool_to_scale(f.get("has_at_symbol"), true_is_phishing=True),
        ("has_at_symbol",),
    ),
    "has_prefix_suffix": (_bucket_has_prefix_suffix, ("num_hyphens_in_hostname",)),
    "subdomain_level": (_bucket_subdomain_level, ("num_subdomains",)),
    "domain_reg_length": (_bucket_reg_length, ("domain_age_days", "days_until_expiry")),
    "has_favicon": (
        lambda f: _bool_to_scale(f.get("has_favicon"), true_is_phishing=False),
        ("has_favicon",),
    ),
    "has_port": (
        lambda f: _bool_to_scale(f.get("has_port"), true_is_phishing=True),
        ("has_port",),
    ),
    "https_in_domain": (
        lambda f: _bool_to_scale(f.get("has_https"), true_is_phishing=False),
        ("has_https",),
    ),
    "links_in_tags": (_bucket_links_in_tags, ("internal_tag_link_ratio",)),
    "server_form_handler": (
        _bucket_server_form_handler,
        ("form_action_is_empty_or_blank", "form_action_is_external"),
    ),
    "submits_to_email": (
        lambda f: _bool_to_scale(f.get("form_submits_to_email"), true_is_phishing=True),
        ("form_submits_to_email",),
    ),
    "has_onmouseover": (
        lambda f: _bool_to_scale(f.get("has_onmouseover"), true_is_phishing=True),
        ("has_onmouseover",),
    ),
    "right_click_disabled": (
        lambda f: _bool_to_scale(
            f.get("has_right_click_disabled"), true_is_phishing=True
        ),
        ("has_right_click_disabled",),
    ),
    "has_popup": (
        lambda f: _bool_to_scale(f.get("has_suspicious_popup"), true_is_phishing=True),
        ("has_suspicious_popup",),
    ),
    "has_iframe": (
        lambda f: _bool_to_scale(f.get("has_iframe"), true_is_phishing=True),
        ("has_iframe",),
    ),
    "domain_age_cat": (_bucket_domain_age, ("domain_age_days",)),
    "has_dns_record": (
        lambda f: _bool_to_scale(f.get("has_dns_a_record"), true_is_phishing=False),
        ("has_dns_a_record",),
    ),
}


def adapt_to_training_contract(features: dict[str, Any]) -> ModelInput:
    """Map a live :class:`~src.features.pipeline.FeatureVector` feature dict
    onto the model's 18-feature training contract.

    Args:
        features: The ``.features`` dict from a live-extracted
            ``FeatureVector`` (union of lexical + HTML + domain-intel keys;
            any subset may be missing/``None`` if a tier didn't run).

    Returns:
        A :class:`ModelInput` with all 18 :data:`FEATURE_ORDER` features
        populated. ``approximated`` lists any features that fell back to
        their missing-input default because a live tier didn't run (e.g.
        HTML/domain-intel weren't fetched) — normally empty when all tiers
        ran, since every contract feature now has a genuine live derivation
        (DEC-016).

    Raises:
        KeyError: If a contract feature has no registered derivation —
            signals the adapter is out of sync with ``data_config.yaml``.
    """
    values: dict[str, int] = {}
    approximated: list[str] = []

    for name in FEATURE_ORDER:
        if name not in _DERIVATIONS:
            raise KeyError(
                f"feature_adapter has no derivation for contract feature {name!r} — "
                "adapter is out of sync with data_config.yaml feature_columns"
            )
        derive_fn, input_keys = _DERIVATIONS[name]
        values[name] = derive_fn(features)
        if not input_keys or any(features.get(key) is None for key in input_keys):
            approximated.append(name)

    if approximated:
        logger.info(
            "feature_adapter: %d/%d contract features approximated (no live "
            "signal, or fell back to a default due to missing input): %s",
            len(approximated),
            len(FEATURE_ORDER),
            approximated,
        )

    return ModelInput(values=values, approximated=approximated)
