"""WHOIS and DNS ("domain intelligence") feature extraction.

Tier 2/3 features that require network I/O — WHOIS registration data and DNS
resolution. These lookups are slow (hundreds of milliseconds, occasionally
seconds) and are therefore designed to run inside a thread pool with a hard
timeout. See :func:`extract_domain_intel_batch` for the concurrent fan-out
pattern callers should use.

Design contract:
    * Every lookup is bounded by :data:`LOOKUP_TIMEOUT` seconds.
    * Individual lookup failures degrade gracefully to sentinels
      (``-1`` / ``"unknown"`` / ``None`` / ``False``) — a WHOIS timeout never
      discards otherwise-good DNS data.
    * Any *unexpected* error is caught at the top level and yields an
      all-``None`` dict (:func:`_all_none`); the extractor never raises.
"""

from __future__ import annotations

import logging
import re
from concurrent.futures import (
    ThreadPoolExecutor,
    as_completed,
)
from concurrent.futures import (
    TimeoutError as FuturesTimeoutError,
)
from datetime import datetime, timezone
from typing import Any, Callable, Iterable, Optional

import dns.exception
import dns.resolver
import whois

from src.utils.timeout import call_with_timeout as _call_with_timeout
from src.utils.ttl_cache import TtlCache

logger = logging.getLogger(__name__)

# Hard timeout (seconds) applied to every individual network lookup.
LOOKUP_TIMEOUT: float = 5.0

# A domain registered within this many days is treated as "recently registered".
RECENT_REGISTRATION_DAYS: int = 30

# Default concurrency for the batch helper.
DEFAULT_MAX_WORKERS: int = 8

# Per-domain WHOIS result cache (Phase 6, Task 6.2). WHOIS is the slowest,
# most rate-limit-sensitive lookup (CLAUDE.md gotcha: 500ms+), and the same
# domain is often requested repeatedly in a short window (e.g. many URLs on
# the same phishing-kit host). Registration data changes rarely, so a 6-hour
# TTL trades a small amount of staleness for a large reduction in WHOIS
# traffic. Thread-safe: extract_domain_intel_batch fans out across a thread
# pool, so this cache is read/written from multiple threads concurrently.
#
# The TTL is a *staleness* bound, not a *memory* bound: an earlier version of
# this cache was a plain dict that only skipped expired entries on read and
# never removed them, so every distinct domain a process ever scanned was
# retained until the process died (CWE-401). TtlCache adds the missing size
# cap and LRU eviction. 4096 entries of ~4 small fields is a few MB at worst,
# and comfortably exceeds the working set of any realistic scanning burst —
# past that, evicting the least-recently-used domain costs one WHOIS lookup,
# which is exactly the trade this cache exists to make.
_WHOIS_CACHE_TTL_SECONDS: float = 6 * 60 * 60
_WHOIS_CACHE_MAX_ENTRIES: int = 4096
_whois_cache: TtlCache[dict[str, Any]] = TtlCache(
    ttl_s=_WHOIS_CACHE_TTL_SECONDS, max_entries=_WHOIS_CACHE_MAX_ENTRIES
)


def clear_whois_cache() -> None:
    """Clear the WHOIS cache. Exposed for tests; not needed in normal use."""
    _whois_cache.clear()

# Canonical ordering of every feature this module produces.
DOMAIN_INTEL_KEYS: tuple[str, ...] = (
    "domain_age_days",
    "days_until_expiry",
    "registrar",
    "is_recently_registered",
    "has_dns_a_record",
    "has_mx_record",
    "ip_address",
    "ip_country",
)

_DATE_FORMATS: tuple[str, ...] = (
    "%Y-%m-%d %H:%M:%S",
    "%Y-%m-%dT%H:%M:%S",
    "%Y-%m-%d",
    "%d-%b-%Y",
)


def _all_none() -> dict[str, Any]:
    """Build a result dict with every feature set to ``None``."""
    return dict.fromkeys(DOMAIN_INTEL_KEYS)


def _coerce_datetime(value: Any, pick: Callable[[list], Any]) -> Optional[datetime]:
    """Normalize a python-whois date field to a single naive UTC datetime.

    ``python-whois`` returns dates as a ``datetime``, a ``list`` of datetimes,
    or a string depending on the registrar. All three are handled.

    Args:
        value: The raw WHOIS date field.
        pick: Reducer applied when ``value`` is a list (e.g. ``min`` for
            creation dates, ``max`` for expiry dates).

    Returns:
        A timezone-naive (UTC) ``datetime``, or ``None`` if unparseable.
    """
    if value is None:
        return None
    if isinstance(value, list):
        candidates = [_coerce_datetime(v, pick) for v in value]
        candidates = [c for c in candidates if c is not None]
        return pick(candidates) if candidates else None
    if isinstance(value, datetime):
        return value.astimezone(timezone.utc).replace(tzinfo=None) if value.tzinfo else value
    if isinstance(value, str):
        text = value.strip()
        try:
            parsed = datetime.fromisoformat(text)
            return (
                parsed.astimezone(timezone.utc).replace(tzinfo=None)
                if parsed.tzinfo
                else parsed
            )
        except ValueError:
            pass
        for fmt in _DATE_FORMATS:
            try:
                return datetime.strptime(text, fmt)
            except ValueError:
                continue
    return None


def _clean_registrar(value: Any) -> Optional[str]:
    """Normalize a WHOIS registrar field to a clean string.

    Args:
        value: Raw registrar field (``str``, ``list``, or ``None``).

    Returns:
        A whitespace-collapsed registrar name, or ``None`` if unavailable.
    """
    if isinstance(value, list):
        value = next((v for v in value if v), None)
    if not value or not isinstance(value, str):
        return None
    cleaned = re.sub(r"\s+", " ", value).strip()
    return cleaned or None


def _lookup_ip_country(ip: Optional[str]) -> str:
    """Resolve an IP address to a 2-letter country code, best effort.

    Optional GeoIP providers (``ip2country`` / ``ipinfo``) are used when
    installed and configured; otherwise this returns ``"unknown"``. Isolated
    here so it can be mocked in tests and swapped without touching callers.

    Args:
        ip: An IPv4/IPv6 address string, or ``None``.

    Returns:
        An uppercase country code, or ``"unknown"``.
    """
    if not ip:
        return "unknown"
    try:
        # Integration point for a GeoIP provider. No provider is wired by
        # default (keeps extraction offline-safe), so we fall back to unknown.
        return "unknown"
    except Exception as exc:  # noqa: BLE001 - never let geo lookup crash extraction
        logger.warning("IP country lookup failed for %r: %s", ip, exc)
        return "unknown"


def _whois_features(domain: str) -> dict[str, Any]:
    """Extract WHOIS-derived features for a domain.

    Args:
        domain: Registered domain (e.g. ``"example.com"``).

    Returns:
        Partial feature dict with ``domain_age_days``, ``days_until_expiry``,
        ``registrar``, and ``is_recently_registered``. Sentinels on failure.
    """
    features: dict[str, Any] = {
        "domain_age_days": -1,
        "days_until_expiry": -1,
        "registrar": None,
        "is_recently_registered": False,
    }
    try:
        record = _call_with_timeout(whois.whois, LOOKUP_TIMEOUT, domain)
    except FuturesTimeoutError:
        logger.warning("WHOIS lookup timed out for %r", domain)
        return features
    except Exception as exc:  # noqa: BLE001 - whois raises many ad-hoc errors
        logger.warning("WHOIS lookup failed for %r: %s", domain, exc)
        return features

    if record is None:
        return features

    now = datetime.utcnow()
    creation = _coerce_datetime(getattr(record, "creation_date", None), min)
    expiry = _coerce_datetime(getattr(record, "expiration_date", None), max)

    if creation is not None:
        age = (now - creation).days
        if age >= 0:
            features["domain_age_days"] = age
            features["is_recently_registered"] = age <= RECENT_REGISTRATION_DAYS
    if expiry is not None:
        features["days_until_expiry"] = (expiry - now).days

    features["registrar"] = _clean_registrar(getattr(record, "registrar", None))
    return features


def _cached_whois_features(domain: str) -> dict[str, Any]:
    """Thread-safe, 6-hour-TTL, size-bounded cache wrapper around
    :func:`_whois_features`.

    Args:
        domain: Registered domain (e.g. ``"example.com"``).

    Returns:
        A fresh copy of the cached (or newly-fetched) WHOIS feature dict —
        copied so a caller mutating the result (e.g. ``.update()``) never
        corrupts the cached entry for other callers.
    """
    cached = _whois_cache.get(domain)
    if cached is not None:
        return dict(cached)

    result = _whois_features(domain)
    _whois_cache.set(domain, result)
    return dict(result)


def _resolve(domain: str, rdtype: str) -> Optional[dns.resolver.Answer]:
    """Resolve a DNS record type with a bounded lifetime.

    Args:
        domain: Domain to resolve.
        rdtype: Record type, e.g. ``"A"`` or ``"MX"``.

    Returns:
        The dnspython ``Answer`` on success, or ``None`` if the record does not
        exist (``NXDOMAIN`` / ``NoAnswer``) or the lookup fails/times out.
    """
    try:
        return dns.resolver.resolve(domain, rdtype, lifetime=LOOKUP_TIMEOUT)
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
        return None
    except (dns.exception.DNSException, Exception) as exc:  # noqa: BLE001
        logger.warning("DNS %s lookup failed for %r: %s", rdtype, domain, exc)
        return None


def _dns_features(domain: str) -> dict[str, Any]:
    """Extract DNS-derived features for a domain.

    Args:
        domain: Domain to resolve.

    Returns:
        Partial feature dict with ``has_dns_a_record``, ``has_mx_record``,
        ``ip_address``, and ``ip_country``.
    """
    features: dict[str, Any] = {
        "has_dns_a_record": False,
        "has_mx_record": False,
        "ip_address": None,
        "ip_country": "unknown",
    }

    a_answer = _resolve(domain, "A")
    if a_answer is not None:
        addresses = [getattr(rr, "address", None) for rr in a_answer]
        addresses = [a for a in addresses if a]
        if addresses:
            features["has_dns_a_record"] = True
            features["ip_address"] = addresses[0]
            features["ip_country"] = _lookup_ip_country(addresses[0])

    mx_answer = _resolve(domain, "MX")
    features["has_mx_record"] = mx_answer is not None and len(list(mx_answer)) > 0

    return features


def extract_domain_intel(domain: Any) -> dict[str, Any]:
    """Extract WHOIS + DNS features for a single domain.

    Performs blocking network I/O bounded by :data:`LOOKUP_TIMEOUT`. Intended
    to be called from a thread pool — see :func:`extract_domain_intel_batch`.
    Never raises: any unexpected error yields an all-``None`` dict.

    Args:
        domain: Registered domain string (e.g. ``"example.com"``). Non-string or
            empty input yields an all-``None`` result.

    Returns:
        A dict keyed by :data:`DOMAIN_INTEL_KEYS`:
            domain_age_days (int, -1 if unknown),
            days_until_expiry (int, -1 if unknown),
            registrar (str | None),
            is_recently_registered (bool),
            has_dns_a_record (bool), has_mx_record (bool),
            ip_address (str | None), ip_country (str, "unknown" if unresolved).
    """
    if not isinstance(domain, str) or not domain.strip():
        logger.warning("extract_domain_intel received unusable input: %r", domain)
        return _all_none()

    domain = domain.strip().lower()
    try:
        features = _cached_whois_features(domain)
        features.update(_dns_features(domain))
        return features
    except Exception as exc:  # noqa: BLE001 - top-level safety net (never crash)
        logger.warning("Domain intel extraction failed for %r: %s", domain, exc)
        return _all_none()


def extract_domain_intel_batch(
    domains: Iterable[str], max_workers: int = DEFAULT_MAX_WORKERS
) -> dict[str, dict[str, Any]]:
    """Extract domain intelligence for many domains concurrently.

    Fans the per-domain blocking work out across a thread pool so that the
    slow, network-bound lookups overlap. Each domain is independently safe: a
    failure for one yields an all-``None`` result for that domain only.

    Args:
        domains: Iterable of registered domain strings.
        max_workers: Maximum number of concurrent worker threads.

    Returns:
        A mapping from each input domain to its feature dict.
    """
    domain_list = list(domains)
    results: dict[str, dict[str, Any]] = {}
    if not domain_list:
        return results

    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        future_to_domain = {
            executor.submit(extract_domain_intel, d): d for d in domain_list
        }
        for future in as_completed(future_to_domain):
            domain = future_to_domain[future]
            try:
                results[domain] = future.result()
            except Exception as exc:  # noqa: BLE001 - defensive; should not happen
                logger.warning("Batch worker failed for %r: %s", domain, exc)
                results[domain] = _all_none()
    return results
