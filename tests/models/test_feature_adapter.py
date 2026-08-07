"""Tests for src.models.feature_adapter — live extractor -> training contract."""

from __future__ import annotations

import math
from pathlib import Path

import pytest

from src.models.contract import FEATURE_ORDER, VALID_FEATURE_VALUES, is_missing
from src.models.feature_adapter import (
    LIVE_FEATURE_ORDER,
    adapt_live,
    adapt_to_training_contract,
    describe,
)

_PROJECT_ROOT = Path(__file__).resolve().parents[2]

# A feature dict shaped like a fully-populated, legitimate-looking live
# extraction (all three tiers ran, nothing suspicious tripped).
_LEGIT_FEATURES = {
    "has_ip_address": False,
    "has_shortening": False,
    "has_at_symbol": False,
    "num_hyphens_in_hostname": 0,
    "num_subdomains": 1,
    "domain": "example.com",
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
    "domain": "https-paypal-verify.tk",
    "has_favicon": False,
    "has_port": True,
    "port_number": 8080,
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


def test_measured_values_are_uci_scale():
    """Every *measured* value is on the trained alphabet; unmeasured ones are NaN."""
    for features in (_LEGIT_FEATURES, _PHISHING_FEATURES, {}):
        result = adapt_to_training_contract(features)
        for name, value in result.values.items():
            assert is_missing(value) or int(value) in VALID_FEATURE_VALUES, name


def test_nothing_is_unavailable_when_all_tiers_ran():
    """A fully-populated input measures every contract feature."""
    result = adapt_to_training_contract(_LEGIT_FEATURES)
    assert result.unavailable == []
    assert result.measured == list(FEATURE_ORDER)


def test_approximated_now_means_proxy_not_missing():
    """DEC-040: `approximated` flags reduced-fidelity proxies, a permanent
    property of the derivation, and no longer doubles as a missing-data flag —
    that is what `unavailable` is for."""
    result = adapt_to_training_contract(_LEGIT_FEATURES)
    assert set(result.approximated) == {
        "domain_reg_length",
        "has_favicon",
        "https_in_domain",
    }


def test_legit_like_input_skews_legit():
    result = adapt_to_training_contract(_LEGIT_FEATURES)
    for name in FEATURE_ORDER:
        assert result.values[name] in (0, 1), f"{name} unexpectedly phishing-leaning"


def test_phishing_like_input_skews_phishing():
    result = adapt_to_training_contract(_PHISHING_FEATURES)
    for name in FEATURE_ORDER:
        assert result.values[name] in (-1, 0), f"{name} unexpectedly legit-leaning"


def test_missing_input_is_nan_never_phishing():
    """DEC-040, the core regression test: with no live signal at all, every
    feature must be explicitly unmeasurable — NOT silently encoded as -1,
    which is the trained 'phishing' value and was the old behaviour."""
    result = adapt_to_training_contract({})
    assert set(result.unavailable) == set(FEATURE_ORDER)
    assert result.measured == []
    for name in FEATURE_ORDER:
        assert is_missing(result.values[name]), f"{name} was not marked unmeasurable"
        assert result.values[name] != -1, f"{name} fabricated a phishing default"


def test_lexical_only_path_still_measures_lexical_features():
    """The fast path has no page and no WHOIS, but must not lose the signals it
    genuinely does have."""
    lexical_only = {
        "has_ip_address": False,
        "has_shortening": False,
        "has_at_symbol": False,
        "num_hyphens_in_hostname": 0,
        "num_subdomains": 1,
        "domain": "example.com",
        "has_port": False,
        "has_https": True,
    }
    result = adapt_to_training_contract(lexical_only)
    measured = set(result.measured)
    assert measured == {
        "has_ip_address",
        "has_shortening",
        "has_at_symbol",
        "has_prefix_suffix",
        "subdomain_level",
        "has_port",
        "https_in_domain",
    }
    # Everything a page/WHOIS fetch would have supplied is unmeasurable, not -1.
    assert set(result.unavailable) == set(FEATURE_ORDER) - measured


def test_distinct_urls_produce_distinct_vectors():
    """The bug DEC-040 fixes: unrelated legitimate inputs used to collapse onto
    one byte-identical vector because the unmeasurable majority was constant."""
    a = adapt_to_training_contract({"num_hyphens_in_hostname": 0, "has_https": True})
    b = adapt_to_training_contract({"num_hyphens_in_hostname": 4, "has_https": False})
    assert a.to_vector() != b.to_vector()


def test_hyphen_count_is_graded_not_all_or_nothing():
    """A single hyphen (`my-bank.co.uk`) must not score like four."""
    one = dict(_LEGIT_FEATURES, num_hyphens_in_hostname=1)
    many = dict(_LEGIT_FEATURES, num_hyphens_in_hostname=4)
    assert adapt_to_training_contract(_LEGIT_FEATURES).values["has_prefix_suffix"] == 1
    assert adapt_to_training_contract(one).values["has_prefix_suffix"] == 0
    assert adapt_to_training_contract(many).values["has_prefix_suffix"] == -1


def test_port_is_graded_by_number():
    standard = dict(_LEGIT_FEATURES, has_port=True, port_number=443)
    odd = dict(_LEGIT_FEATURES, has_port=True, port_number=8080)
    assert adapt_to_training_contract(_LEGIT_FEATURES).values["has_port"] == 1
    assert adapt_to_training_contract(standard).values["has_port"] == 0
    assert adapt_to_training_contract(odd).values["has_port"] == -1


def test_https_in_domain_keeps_the_scheme_reading_deliberately():
    """DEC-040: UCI's HTTPS_token means 'https' embedded in the hostname, but
    substituting that faithful reading measurably *cost* live ROC-AUC (the
    token is near-absent in real traffic, so the column goes constant). The
    scheme keeps the slot; the mismatch is recorded, not silently tolerated."""
    plain_http = dict(_LEGIT_FEATURES, has_https=False)
    tls = dict(_LEGIT_FEATURES, has_https=True)
    assert adapt_to_training_contract(plain_http).values["https_in_domain"] == -1
    assert adapt_to_training_contract(tls).values["https_in_domain"] == 1
    assert "https_in_domain" in adapt_to_training_contract(tls).approximated


def test_both_https_readings_travel_on_the_continuous_track():
    """Neither quantity is discarded — the retrain can give each a column."""
    live = adapt_live(dict(_LEGIT_FEATURES, has_https=True, domain="https-example.tk"))
    assert live.values["uses_https"] == 1.0
    assert live.values["https_token_in_domain"] == 1.0
    assert adapt_live(_LEGIT_FEATURES).values["https_token_in_domain"] == 0.0


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


# --------------------------------------------------------------------------
# Continuous track
# --------------------------------------------------------------------------


def test_continuous_track_preserves_full_precision():
    """The measurements the contract squashes must survive unsquashed."""
    live = adapt_live(_LEGIT_FEATURES)
    assert live.values["domain_age_days"] == 3000.0
    assert live.values["registration_span_days"] == 3400.0
    assert live.values["subdomain_count"] == 1.0
    assert live.values["internal_tag_link_ratio"] == 1.0
    # ...while the contract projection of the same row is a single trit.
    assert live.contract.values["domain_age_cat"] == 1


def test_continuous_track_distinguishes_rows_the_contract_cannot():
    """Two domains the contract scores identically differ continuously."""
    young = dict(_LEGIT_FEATURES, domain_age_days=200)
    ancient = dict(_LEGIT_FEATURES, domain_age_days=9000)
    assert (
        adapt_to_training_contract(young).values["domain_age_cat"]
        == adapt_to_training_contract(ancient).values["domain_age_cat"]
    )
    assert adapt_live(young).values["domain_age_days"] != adapt_live(ancient).values["domain_age_days"]


def test_continuous_track_carries_signals_the_contract_has_no_slot_for():
    live = adapt_live(dict(_PHISHING_FEATURES, url_entropy=4.2, has_password_field=True))
    assert live.values["url_entropy"] == 4.2
    assert live.values["has_password_field"] == 1.0
    assert live.values["is_suspicious_tld"] is None  # absent from this input


def test_live_vector_order_and_missing_encoding():
    live = adapt_live({})
    vector = live.to_live_vector(LIVE_FEATURE_ORDER)
    assert len(vector) == len(LIVE_FEATURE_ORDER)
    assert all(math.isnan(v) for v in vector)


def test_live_feature_order_has_no_duplicates():
    assert len(set(LIVE_FEATURE_ORDER)) == len(LIVE_FEATURE_ORDER)


def test_live_feature_order_is_strictly_richer_than_the_contract():
    assert len(LIVE_FEATURE_ORDER) > len(FEATURE_ORDER)


def test_missing_components_are_reported():
    assert adapt_live({}).components_missing == ("html", "domain_intel")
    assert adapt_live(_LEGIT_FEATURES).components_missing == ()


def test_describe_covers_every_contract_feature():
    rows = describe()
    assert [r["contract_feature"] for r in rows] == list(FEATURE_ORDER)


# --------------------------------------------------------------------------
# Guards against the adapter drifting from what the model was trained on
# --------------------------------------------------------------------------


def test_alphabets_match_training_data():
    """The `0` band may only be emitted for columns the model has seen it in.

    Re-derives each column's observed alphabet from the processed training
    frames so a retrain that changes them fails here rather than silently
    shipping out-of-distribution input.
    """
    pd = pytest.importorskip("pandas")
    paths = [
        _PROJECT_ROOT / "data" / "processed" / f"{split}.parquet"
        for split in ("train", "val")
    ]
    if not all(p.is_file() for p in paths):
        pytest.skip("processed training data not present")

    from src.models.feature_adapter import _BINARY_COLUMNS

    frame = pd.concat([pd.read_parquet(p) for p in paths])
    binary = {name for name in FEATURE_ORDER if 0 not in set(frame[name].unique())}
    assert binary == set(_BINARY_COLUMNS)


def test_nan_survives_the_serving_pipeline():
    """NaN must reach the fitted imputer intact rather than blowing up.

    This is what makes 'missing' representable at all — if the pipeline
    rejected NaN the whole redesign would be unshippable.
    """
    joblib = pytest.importorskip("joblib")
    model_path = _PROJECT_ROOT / "models" / "production" / "model.joblib"
    if not model_path.is_file():
        pytest.skip("no trained model present")

    pipeline = joblib.load(model_path)
    vector = adapt_to_training_contract({}).to_vector()
    assert all(math.isnan(v) for v in vector)
    proba = pipeline.predict_proba([vector])[0][1]
    assert 0.0 <= proba <= 1.0
