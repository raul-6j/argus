"""URL lexical feature extraction.

Tier 1 features computed from the URL string alone — no HTTP requests, no DNS,
no WHOIS. Every feature is computed defensively: any failure yields ``None`` for
that field (and a logged warning) rather than raising, so a single malformed
component never crashes extraction for the whole URL.

Example:
    >>> from src.features.lexical import extract_lexical_features
    >>> feats = extract_lexical_features("https://login.example.com/path")
    >>> feats["has_https"]
    True
"""

from __future__ import annotations

import ipaddress
import logging
import math
import re
from collections import Counter
from functools import lru_cache
from pathlib import Path
from typing import Any, Callable, Optional, Pattern
from urllib.parse import urlparse

import yaml

from src.utils.domains import get_extractor, registered_domain_of

logger = logging.getLogger(__name__)

# Built-in defaults. The authoritative lists live in feature_config.yaml (so
# each experiment can cite them); these are the fallback when config is absent.
DEFAULT_SUSPICIOUS_TLDS: frozenset[str] = frozenset(
    {"tk", "ml", "ga", "cf", "gq", "xyz", "top", "club", "work", "click"}
)
DEFAULT_SUSPICIOUS_KEYWORDS: tuple[str, ...] = (
    "login",
    "verify",
    "secure",
    "update",
    "account",
)
# Known URL-shortener domains — needed for has_shortening (DEC-015: this
# signal has no live-extractor equivalent yet; UCI's own Shortining_Service
# feature is a similar hardcoded-list check against the raw URL).
DEFAULT_KNOWN_SHORTENERS: frozenset[str] = frozenset(
    {
        "bit.ly", "tinyurl.com", "goo.gl", "t.co", "ow.ly", "is.gd", "buff.ly",
        "adf.ly", "bl.ink", "lnkd.in", "rebrand.ly", "shorturl.at", "cutt.ly",
        "tiny.cc", "s.id", "v.gd", "rb.gy", "shrtco.de", "chilp.it", "qr.ae",
    }
)

_CONFIG_PATH = Path(__file__).resolve().parents[2] / "configs" / "feature_config.yaml"


@lru_cache(maxsize=1)
def _load_suspicious_lists() -> tuple[frozenset[str], Pattern[str]]:
    """Load suspicious TLDs/keywords from config, falling back to defaults.

    Returns:
        A tuple of ``(suspicious_tlds, compiled_keyword_regex)``.
    """
    tlds = DEFAULT_SUSPICIOUS_TLDS
    keywords = DEFAULT_SUSPICIOUS_KEYWORDS
    try:
        with _CONFIG_PATH.open("r", encoding="utf-8") as fh:
            data = yaml.safe_load(fh)
        if isinstance(data, dict):
            cfg_tlds = data.get("suspicious_tlds")
            cfg_keywords = data.get("suspicious_keywords")
            if cfg_tlds:
                tlds = frozenset(str(t).lower() for t in cfg_tlds)
            if cfg_keywords:
                keywords = tuple(str(k) for k in cfg_keywords)
    except Exception as exc:  # noqa: BLE001 - config is optional; defaults suffice
        logger.warning("Falling back to default suspicious lists: %s", exc)
    regex = re.compile("|".join(re.escape(k) for k in keywords))
    return tlds, regex


@lru_cache(maxsize=1)
def _load_known_shorteners() -> frozenset[str]:
    """Load known URL-shortener domains from config, falling back to defaults.

    Returns:
        A frozenset of lowercase shortener domains (e.g. ``"bit.ly"``).
    """
    shorteners = DEFAULT_KNOWN_SHORTENERS
    try:
        with _CONFIG_PATH.open("r", encoding="utf-8") as fh:
            data = yaml.safe_load(fh)
        if isinstance(data, dict):
            cfg_shorteners = data.get("known_shorteners")
            if cfg_shorteners:
                shorteners = frozenset(str(s).lower() for s in cfg_shorteners)
    except Exception as exc:  # noqa: BLE001 - config is optional; defaults suffice
        logger.warning("Falling back to default known-shorteners list: %s", exc)
    return shorteners

# Canonical ordering of every feature this module produces. Used to build a
# fully-``None`` result when the input itself is unusable.
FEATURE_KEYS: tuple[str, ...] = (
    "url_length",
    "hostname_length",
    "path_length",
    "num_dots_in_url",
    "num_dots_in_hostname",
    "num_subdomains",
    "has_ip_address",
    "has_at_symbol",
    "has_double_slash_redirect",
    "has_https",
    "has_port",
    "port_number",
    "tld",
    "is_suspicious_tld",
    "domain",
    "has_suspicious_keywords",
    "num_hyphens_in_hostname",
    "url_entropy",
    "digit_ratio_in_url",
    "has_shortening",
)


def _safe(feature_name: str, func: Callable[[], Any]) -> Optional[Any]:
    """Run a feature computation, returning ``None`` on any failure.

    Args:
        feature_name: Name of the feature, used in the warning log.
        func: Zero-argument callable that computes the feature value.

    Returns:
        The computed value, or ``None`` if ``func`` raised.
    """
    try:
        return func()
    except Exception as exc:  # noqa: BLE001 - defensive by design (Iron Law #3)
        logger.warning("Lexical feature %r failed: %s", feature_name, exc)
        return None


def _shannon_entropy(text: str) -> float:
    """Compute the Shannon entropy (base 2) of a string.

    Args:
        text: Input string.

    Returns:
        Entropy in bits per character; ``0.0`` for an empty string.
    """
    if not text:
        return 0.0
    counts = Counter(text)
    length = len(text)
    return -sum(
        (count / length) * math.log2(count / length) for count in counts.values()
    )


def _is_ip_address(hostname: Optional[str]) -> bool:
    """Return whether a hostname is a literal IPv4 or IPv6 address.

    Args:
        hostname: Hostname extracted from the URL (may be ``None``).

    Returns:
        ``True`` if ``hostname`` parses as an IP address, else ``False``.
    """
    if not hostname:
        return False
    try:
        ipaddress.ip_address(hostname)
        return True
    except ValueError:
        return False


def _empty_features() -> dict[str, Any]:
    """Build a result dict with every feature set to ``None``."""
    return {key: None for key in FEATURE_KEYS}


def extract_lexical_features(url: Any) -> dict[str, Any]:
    """Extract Tier 1 lexical features from a URL string.

    No network I/O is performed. Each feature is computed independently and
    defensively: a failure in one field sets only that field to ``None``.
    If ``url`` itself is not a usable string, every feature is ``None``.

    Args:
        url: The URL to analyse. Expected to be a non-empty ``str``; any other
            value (including ``None``) yields an all-``None`` result.

    Returns:
        A dict mapping each feature name in :data:`FEATURE_KEYS` to its value
        (or ``None`` on failure). Keys:
            url_length (int), hostname_length (int), path_length (int),
            num_dots_in_url (int), num_dots_in_hostname (int),
            num_subdomains (int), has_ip_address (bool), has_at_symbol (bool),
            has_double_slash_redirect (bool), has_https (bool), has_port (bool),
            port_number (int, -1 if absent), tld (str), is_suspicious_tld (bool),
            domain (str), has_suspicious_keywords (bool),
            num_hyphens_in_hostname (int), url_entropy (float),
            digit_ratio_in_url (float), has_shortening (bool).
    """
    if not isinstance(url, str) or not url.strip():
        logger.warning("extract_lexical_features received unusable input: %r", url)
        return _empty_features()

    # Parse once; downstream lambdas tolerate parse failures via _safe.
    parsed = _safe("urlparse", lambda: urlparse(url))
    ext = _safe("tldextract", lambda: get_extractor()(url))
    # .hostname can raise on some malformed netlocs; keep it guarded too.
    hostname = _safe("hostname", lambda: parsed.hostname if parsed is not None else None)
    lower_url = url.lower()
    suspicious_tlds, keyword_re = _load_suspicious_lists()
    known_shorteners = _load_known_shorteners()

    def _has_shortening() -> bool:
        registered = registered_domain_of(ext) if ext is not None else ""
        return bool(registered) and registered.lower() in known_shorteners

    def _safe_port() -> Optional[int]:
        # parsed.port raises ValueError on a malformed port (e.g. :abc, :99999).
        if parsed is None:
            return None
        try:
            return parsed.port
        except ValueError:
            return None

    def _port_number() -> int:
        port = _safe_port()
        return port if port is not None else -1

    def _has_double_slash_redirect() -> bool:
        # A "//" appearing after the scheme separator signals an open redirect.
        sep = url.find("://")
        start = sep + 3 if sep != -1 else 0
        return "//" in url[start:]

    def _num_subdomains() -> int:
        subdomain = ext.subdomain if ext is not None else ""
        return len(subdomain.split(".")) if subdomain else 0

    return {
        "url_length": _safe("url_length", lambda: len(url)),
        "hostname_length": _safe(
            "hostname_length", lambda: len(hostname) if hostname else 0
        ),
        "path_length": _safe(
            "path_length", lambda: len(parsed.path) if parsed is not None else 0
        ),
        "num_dots_in_url": _safe("num_dots_in_url", lambda: url.count(".")),
        "num_dots_in_hostname": _safe(
            "num_dots_in_hostname", lambda: hostname.count(".") if hostname else 0
        ),
        "num_subdomains": _safe("num_subdomains", _num_subdomains),
        "has_ip_address": _safe("has_ip_address", lambda: _is_ip_address(hostname)),
        "has_at_symbol": _safe("has_at_symbol", lambda: "@" in url),
        "has_double_slash_redirect": _safe(
            "has_double_slash_redirect", _has_double_slash_redirect
        ),
        "has_https": _safe(
            "has_https",
            lambda: (parsed.scheme.lower() == "https") if parsed is not None else False,
        ),
        "has_port": _safe("has_port", lambda: _safe_port() is not None),
        "port_number": _safe("port_number", _port_number),
        "tld": _safe("tld", lambda: ext.suffix if ext is not None else ""),
        "is_suspicious_tld": _safe(
            "is_suspicious_tld",
            lambda: (ext.suffix.lower() in suspicious_tlds) if ext is not None else False,
        ),
        "domain": _safe(
            "domain", lambda: registered_domain_of(ext) if ext is not None else ""
        ),
        "has_suspicious_keywords": _safe(
            "has_suspicious_keywords", lambda: keyword_re.search(lower_url) is not None
        ),
        "num_hyphens_in_hostname": _safe(
            "num_hyphens_in_hostname", lambda: hostname.count("-") if hostname else 0
        ),
        "url_entropy": _safe("url_entropy", lambda: _shannon_entropy(url)),
        "digit_ratio_in_url": _safe(
            "digit_ratio_in_url",
            lambda: sum(c.isdigit() for c in url) / len(url) if url else 0.0,
        ),
        "has_shortening": _safe("has_shortening", _has_shortening),
    }
