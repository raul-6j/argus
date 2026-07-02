"""Tests for src.models.feature_adapter — live extractor -> training contract."""

from __future__ import annotations

from src.models.contract import FEATURE_ORDER, VALID_FEATURE_VALUES
from src.models.feature_adapter import _STUB_VALUES, adapt_to_training_contract

# A feature dict shaped like a fully-populated, legitimate-looking live
# extraction (all three tiers ran, nothing suspicious tripped).
_LEGIT_FEATURES = {
    "has_ip_address": False,
    "has_shortening": False,
    "has_at_symbol": False,
    "num_hyphens_in_hostname": 0,
    "num_subdomains": 1,
    "has_favicon": True,
    "has_port": False,
    "has_https": True,
    "internal_tag_link_ratio": 1.0,
    "form_action_is_empty_or_blank": False,
    "form_action_is_external": False,
    "form_submits_to_email": False,
    "has_onmouseover": False,
    "has_right_click_disabled": False,
    "has_suspicious_popup": False,
    "has_iframe": False,
    "domain_age_days": 3000,
    "days_until_expiry": 400,
    "has_dns_a_record": True,
}

# A feature dict shaped like a phishing-style page tripping every signal.
_PHISHING_FEATURES = {
    "has_ip_address": True,
    "has_shortening": True,
    "has_at_symbol": True,
    "num_hyphens_in_hostname": 3,
    "num_subdomains": 4,
    "has_favicon": False,
    "has_port": True,
    "has_https": False,
    "internal_tag_link_ratio": 0.0,
    "form_action_is_empty_or_blank": False,
    "form_action_is_external": True,
    "form_submits_to_email": True,
    "has_onmouseover": True,
    "has_right_click_disabled": True,
    "has_suspicious_popup": True,
    "has_iframe": True,
    "domain_age_days": 10,
    "days_until_expiry": 20,
    "has_dns_a_record": False,
}


def test_output_covers_exactly_the_contract():
    result = adapt_to_training_contract(_LEGIT_FEATURES)
    assert set(result.values.keys()) == set(FEATURE_ORDER)


def test_all_values_are_uci_scale():
    for features in (_LEGIT_FEATURES, _PHISHING_FEATURES, {}):
        result = adapt_to_training_contract(features)
        assert all(v in VALID_FEATURE_VALUES for v in result.values.values())


def test_dead_signals_always_approximated():
    """The 4 features with no live equivalent are always flagged."""
    result = adapt_to_training_contract(_LEGIT_FEATURES)
    for name in _STUB_VALUES:
        assert name in result.approximated
        assert result.values[name] == _STUB_VALUES[name]


def test_legit_like_input_skews_legit():
    result = adapt_to_training_contract(_LEGIT_FEATURES)
    # Every feature with a direct live signal in _LEGIT_FEATURES should read
    # legit (1) or suspicious (0), never phishing (-1) — excluding the 4
    # always-stubbed dead signals which don't depend on the input at all.
    for name in FEATURE_ORDER:
        if name in _STUB_VALUES:
            continue
        assert result.values[name] in (0, 1), f"{name} unexpectedly phishing-leaning"


def test_phishing_like_input_skews_phishing():
    result = adapt_to_training_contract(_PHISHING_FEATURES)
    for name in FEATURE_ORDER:
        if name in _STUB_VALUES:
            continue
        assert result.values[name] in (-1, 0), f"{name} unexpectedly legit-leaning"


def test_empty_input_is_conservative():
    """No live signal at all -> every feature defaults to phishing(-1) or the
    training-set mode stub, never a legit-leaning guess (DEC-007)."""
    result = adapt_to_training_contract({})
    assert set(result.approximated) == set(FEATURE_ORDER)
    for name in FEATURE_ORDER:
        if name in _STUB_VALUES:
            assert result.values[name] == _STUB_VALUES[name]
        else:
            assert result.values[name] == -1, f"{name} was not conservative on missing input"


def test_domain_reg_length_derived_from_age_plus_expiry():
    long_lived = dict(_LEGIT_FEATURES, domain_age_days=3000, days_until_expiry=400)
    short_lived = dict(_LEGIT_FEATURES, domain_age_days=10, days_until_expiry=20)
    assert adapt_to_training_contract(long_lived).values["domain_reg_length"] == 1
    assert adapt_to_training_contract(short_lived).values["domain_reg_length"] == -1


def test_server_form_handler_ternary():
    blank = dict(_LEGIT_FEATURES, form_action_is_empty_or_blank=True, form_action_is_external=False)
    external = dict(_LEGIT_FEATURES, form_action_is_empty_or_blank=False, form_action_is_external=True)
    same_domain = dict(_LEGIT_FEATURES, form_action_is_empty_or_blank=False, form_action_is_external=False)
    assert adapt_to_training_contract(blank).values["server_form_handler"] == -1
    assert adapt_to_training_contract(external).values["server_form_handler"] == 0
    assert adapt_to_training_contract(same_domain).values["server_form_handler"] == 1


def test_www_subdomain_still_reads_legit():
    """A single 'www' subdomain level should not be treated as suspicious."""
    features = dict(_LEGIT_FEATURES, num_subdomains=1)
    assert adapt_to_training_contract(features).values["subdomain_level"] == 1
