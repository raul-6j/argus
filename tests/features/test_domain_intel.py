"""Tests for src.features.domain_intel — WHOIS/DNS extraction.

All network access is mocked. No test performs a real WHOIS or DNS lookup.
"""

from __future__ import annotations

from datetime import datetime, timedelta
from types import SimpleNamespace
from unittest import mock

import dns.resolver
import pytest

from src.features import domain_intel
from src.features.domain_intel import (
    DOMAIN_INTEL_KEYS,
    extract_domain_intel,
    extract_domain_intel_batch,
)

MODULE = "src.features.domain_intel"


# --------------------------------------------------------------------------- #
# Fakes / helpers
# --------------------------------------------------------------------------- #
def _fake_whois_record(creation, expiration, registrar):
    """Build an object that mimics a python-whois result."""
    return SimpleNamespace(
        creation_date=creation,
        expiration_date=expiration,
        registrar=registrar,
    )


class _FakeRdata:
    """Stand-in for a dnspython A-record rdata item."""

    def __init__(self, address: str) -> None:
        self.address = address


class _FakeAnswer:
    """Stand-in for a dnspython Answer (iterable of rdata)."""

    def __init__(self, items) -> None:
        self._items = list(items)

    def __iter__(self):
        return iter(self._items)

    def __len__(self) -> int:
        return len(self._items)


def _patch_dns(a_records=None, mx_records=None, a_exc=None, mx_exc=None):
    """Return a side_effect fn for dns.resolver.resolve covering A and MX."""

    def _side_effect(domain, rdtype, *args, **kwargs):
        if rdtype == "A":
            if a_exc is not None:
                raise a_exc
            if a_records is None:
                raise dns.resolver.NXDOMAIN()
            return _FakeAnswer([_FakeRdata(ip) for ip in a_records])
        if rdtype == "MX":
            if mx_exc is not None:
                raise mx_exc
            if mx_records is None:
                raise dns.resolver.NoAnswer()
            return _FakeAnswer(mx_records)
        raise AssertionError(f"unexpected rdtype {rdtype}")

    return _side_effect


# --------------------------------------------------------------------------- #
# Happy path
# --------------------------------------------------------------------------- #
def test_full_extraction_happy_path():
    """WHOIS + DNS both succeed; all features populated correctly."""
    created = datetime.utcnow() - timedelta(days=400)
    expires = datetime.utcnow() + timedelta(days=200)
    record = _fake_whois_record(created, expires, "  NameCheap,  Inc.  ")

    with mock.patch(f"{MODULE}.whois.whois", return_value=record), mock.patch(
        f"{MODULE}.dns.resolver.resolve",
        side_effect=_patch_dns(a_records=["93.184.216.34"], mx_records=["mx1"]),
    ):
        feats = extract_domain_intel("example.com")

    assert set(feats.keys()) == set(DOMAIN_INTEL_KEYS)
    assert feats["domain_age_days"] == 400
    assert feats["days_until_expiry"] in (199, 200)  # rounding tolerance
    assert feats["registrar"] == "NameCheap, Inc."
    assert feats["is_recently_registered"] is False
    assert feats["has_dns_a_record"] is True
    assert feats["has_mx_record"] is True
    assert feats["ip_address"] == "93.184.216.34"
    assert feats["ip_country"] == "unknown"  # no GeoIP provider wired


def test_recently_registered_domain():
    """A domain created within 30 days flips is_recently_registered."""
    created = datetime.utcnow() - timedelta(days=5)
    record = _fake_whois_record(created, None, "Registrar")

    with mock.patch(f"{MODULE}.whois.whois", return_value=record), mock.patch(
        f"{MODULE}.dns.resolver.resolve",
        side_effect=_patch_dns(a_records=["1.2.3.4"], mx_records=["mx"]),
    ):
        feats = extract_domain_intel("new-domain.com")

    assert feats["domain_age_days"] == 5
    assert feats["is_recently_registered"] is True


def test_creation_date_as_list_takes_earliest():
    """When WHOIS returns a list of creation dates, the earliest is used."""
    dates = [
        datetime.utcnow() - timedelta(days=100),
        datetime.utcnow() - timedelta(days=300),
    ]
    record = _fake_whois_record(dates, None, "R")

    with mock.patch(f"{MODULE}.whois.whois", return_value=record), mock.patch(
        f"{MODULE}.dns.resolver.resolve",
        side_effect=_patch_dns(a_records=["1.2.3.4"]),
    ):
        feats = extract_domain_intel("example.com")

    assert feats["domain_age_days"] == 300


def test_creation_date_as_string_is_parsed():
    """A string creation date is parsed rather than ignored."""
    created_str = (datetime.utcnow() - timedelta(days=50)).strftime("%Y-%m-%d %H:%M:%S")
    record = _fake_whois_record(created_str, None, "R")

    with mock.patch(f"{MODULE}.whois.whois", return_value=record), mock.patch(
        f"{MODULE}.dns.resolver.resolve",
        side_effect=_patch_dns(a_records=["1.2.3.4"]),
    ):
        feats = extract_domain_intel("example.com")

    assert feats["domain_age_days"] in (49, 50)


# --------------------------------------------------------------------------- #
# Failure / degradation modes
# --------------------------------------------------------------------------- #
def test_whois_failure_degrades_but_dns_survives():
    """A WHOIS exception yields WHOIS sentinels but keeps DNS results."""
    with mock.patch(
        f"{MODULE}.whois.whois", side_effect=RuntimeError("whois boom")
    ), mock.patch(
        f"{MODULE}.dns.resolver.resolve",
        side_effect=_patch_dns(a_records=["8.8.8.8"], mx_records=["mx"]),
    ):
        feats = extract_domain_intel("example.com")

    assert feats["domain_age_days"] == -1
    assert feats["days_until_expiry"] == -1
    assert feats["registrar"] is None
    assert feats["is_recently_registered"] is False
    # DNS still worked.
    assert feats["has_dns_a_record"] is True
    assert feats["ip_address"] == "8.8.8.8"


def test_whois_timeout_uses_sentinels():
    """A WHOIS lookup exceeding the timeout degrades gracefully."""

    def _slow(_domain):
        import time

        time.sleep(5)
        return _fake_whois_record(datetime.utcnow(), None, "R")

    with mock.patch(f"{MODULE}.LOOKUP_TIMEOUT", 0.1), mock.patch(
        f"{MODULE}.whois.whois", side_effect=_slow
    ), mock.patch(
        f"{MODULE}.dns.resolver.resolve",
        side_effect=_patch_dns(a_records=["1.2.3.4"]),
    ):
        feats = extract_domain_intel("slow.com")

    assert feats["domain_age_days"] == -1
    assert feats["has_dns_a_record"] is True  # DNS unaffected


def test_nxdomain_means_no_a_record():
    """NXDOMAIN on the A lookup sets has_dns_a_record False, ip None."""
    record = _fake_whois_record(datetime.utcnow() - timedelta(days=10), None, "R")

    with mock.patch(f"{MODULE}.whois.whois", return_value=record), mock.patch(
        f"{MODULE}.dns.resolver.resolve",
        side_effect=_patch_dns(a_records=None, mx_records=None),
    ):
        feats = extract_domain_intel("nonexistent.invalid")

    assert feats["has_dns_a_record"] is False
    assert feats["ip_address"] is None
    assert feats["has_mx_record"] is False


def test_dns_timeout_sets_false():
    """A DNS Timeout exception is caught and treated as no record."""
    record = _fake_whois_record(datetime.utcnow() - timedelta(days=10), None, "R")

    with mock.patch(f"{MODULE}.whois.whois", return_value=record), mock.patch(
        f"{MODULE}.dns.resolver.resolve",
        side_effect=_patch_dns(a_exc=dns.resolver.LifetimeTimeout(), mx_exc=dns.resolver.LifetimeTimeout()),
    ):
        feats = extract_domain_intel("example.com")

    assert feats["has_dns_a_record"] is False
    assert feats["has_mx_record"] is False
    assert feats["ip_address"] is None


def test_whois_returns_none():
    """A None WHOIS record (domain not found) yields sentinels, no crash."""
    with mock.patch(f"{MODULE}.whois.whois", return_value=None), mock.patch(
        f"{MODULE}.dns.resolver.resolve",
        side_effect=_patch_dns(a_records=["1.2.3.4"]),
    ):
        feats = extract_domain_intel("example.com")

    assert feats["domain_age_days"] == -1
    assert feats["registrar"] is None


# --------------------------------------------------------------------------- #
# Input validation
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize("bad", [None, "", "   ", 12345, []])
def test_unusable_input_returns_all_none(bad):
    """Non-string / empty input yields an all-None dict without lookups."""
    with mock.patch(f"{MODULE}.whois.whois") as mwhois, mock.patch(
        f"{MODULE}.dns.resolver.resolve"
    ) as mdns:
        feats = extract_domain_intel(bad)

    assert set(feats.keys()) == set(DOMAIN_INTEL_KEYS)
    assert all(v is None for v in feats.values())
    mwhois.assert_not_called()
    mdns.assert_not_called()


def test_ip_country_uses_provider_when_mocked():
    """When a GeoIP provider is available (mocked), its result is used."""
    record = _fake_whois_record(datetime.utcnow() - timedelta(days=10), None, "R")

    with mock.patch(f"{MODULE}.whois.whois", return_value=record), mock.patch(
        f"{MODULE}.dns.resolver.resolve",
        side_effect=_patch_dns(a_records=["1.2.3.4"]),
    ), mock.patch(f"{MODULE}._lookup_ip_country", return_value="US"):
        feats = extract_domain_intel("example.com")

    assert feats["ip_country"] == "US"


# --------------------------------------------------------------------------- #
# Batch concurrency
# --------------------------------------------------------------------------- #
def test_batch_extraction_returns_all_domains():
    """The batch helper returns a result for every input domain."""
    record = _fake_whois_record(datetime.utcnow() - timedelta(days=10), None, "R")

    with mock.patch(f"{MODULE}.whois.whois", return_value=record), mock.patch(
        f"{MODULE}.dns.resolver.resolve",
        side_effect=_patch_dns(a_records=["1.2.3.4"], mx_records=["mx"]),
    ):
        results = extract_domain_intel_batch(
            ["a.com", "b.com", "c.com"], max_workers=3
        )

    assert set(results.keys()) == {"a.com", "b.com", "c.com"}
    for feats in results.values():
        assert feats["has_dns_a_record"] is True
        assert feats["domain_age_days"] == 10


def test_batch_empty_input():
    """An empty iterable yields an empty result mapping."""
    assert extract_domain_intel_batch([]) == {}


def test_batch_isolates_per_domain_failure():
    """One domain raising does not break results for the others."""
    record = _fake_whois_record(datetime.utcnow() - timedelta(days=10), None, "R")

    def _whois_side_effect(domain):
        if domain == "bad.com":
            raise RuntimeError("kaboom")
        return record

    with mock.patch(
        f"{MODULE}.whois.whois", side_effect=_whois_side_effect
    ), mock.patch(
        f"{MODULE}.dns.resolver.resolve",
        side_effect=_patch_dns(a_records=["1.2.3.4"]),
    ):
        results = extract_domain_intel_batch(["good.com", "bad.com"])

    # good.com fully extracted; bad.com degraded (WHOIS sentinel) but present.
    assert results["good.com"]["domain_age_days"] == 10
    assert results["bad.com"]["domain_age_days"] == -1
    assert "bad.com" in results
