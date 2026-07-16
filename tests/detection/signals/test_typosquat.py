"""Tests for src.detection.signals.typosquat (A3)."""

from __future__ import annotations

from src.detection.brand_reference import Brand, BrandIndex
from src.detection.signals import typosquat


def _index() -> BrandIndex:
    return BrandIndex(
        brands=(
            Brand(name="PayPal", domains=("paypal.com",), aliases=("paypal", "pay pal")),
            Brand(name="Hp", domains=("hp.com",), aliases=("hp",)),  # short-name guard case
        )
    )


class TestAllowlist:
    def test_brands_own_domain_is_neutral(self):
        sig = typosquat.evaluate("https://paypal.com/login", _index())
        assert sig.triggered is False

    def test_brands_own_subdomain_is_neutral(self):
        sig = typosquat.evaluate("https://login.paypal.com/x", _index())
        assert sig.triggered is False

    def test_unrelated_domain_is_neutral(self):
        sig = typosquat.evaluate("https://example.com", _index())
        assert sig.triggered is False


class TestEditDistance:
    def test_one_char_substitution_triggers(self):
        sig = typosquat.evaluate("https://paypaI.com", _index(), max_edit_distance=2)
        assert sig.triggered is True
        assert sig.evidence["impersonated_brand"] == "PayPal"

    def test_beyond_max_distance_does_not_trigger(self):
        sig = typosquat.evaluate("https://xxxxxxxxx.com", _index(), max_edit_distance=1)
        assert sig.triggered is False


class TestTldSwap:
    def test_same_root_different_tld_triggers(self):
        sig = typosquat.evaluate("https://paypal.tk", _index())
        assert sig.triggered is True
        assert sig.evidence["technique"] == "tld_swap"


class TestBrandInSubdomain:
    def test_brand_as_subdomain_of_unrelated_domain_triggers(self):
        sig = typosquat.evaluate("https://paypal.attacker.com", _index())
        assert sig.triggered is True
        assert sig.evidence["technique"] == "brand_in_subdomain"
        assert sig.evidence["impersonated_brand"] == "PayPal"


class TestCombosquat:
    def test_brand_alias_substring_triggers(self):
        sig = typosquat.evaluate("https://paypal-secure-login.net", _index())
        assert sig.triggered is True
        assert sig.evidence["technique"] == "combosquat"

    def test_exact_alias_alone_does_not_trigger_combosquat(self):
        """paypal.com itself is allowlisted (own domain), not a combosquat case."""
        sig = typosquat.evaluate("https://paypal.com", _index())
        assert sig.triggered is False


class TestGuards:
    def test_short_brand_name_is_skipped(self):
        """'Hp' is below the minimum brand-name length guard -- must never
        cause false positives on unrelated 2-letter-adjacent domains."""
        sig = typosquat.evaluate("https://hpx.com", _index())
        assert sig.triggered is False

    def test_empty_brand_index_is_neutral(self):
        sig = typosquat.evaluate("https://paypal-secure.com", BrandIndex(brands=()))
        assert sig.triggered is False

    def test_unparseable_url_never_raises(self):
        sig = typosquat.evaluate("not a url at all", _index())
        assert sig.triggered is False


class TestRobustness:
    def test_never_raises_on_bare_hostname(self):
        sig = typosquat.evaluate("paypal-secure.net", _index())
        assert sig.triggered is True

    def test_result_has_latency_recorded(self):
        sig = typosquat.evaluate("https://example.com", _index())
        assert sig.latency_ms >= 0.0

    def test_neutral_signal_has_no_evidence(self):
        sig = typosquat.evaluate("https://example.com", _index())
        assert sig.evidence == {}
        assert sig.direction == "neutral"
