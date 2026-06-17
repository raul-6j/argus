"""Unified feature-extraction orchestrator.

Combines the three feature tiers into a single call:

    * Tier 1 — lexical (``src.features.lexical``): always run, synchronous, fast.
    * Tier 4 — HTML/content (``src.features.html_content``): run when HTML is
      provided or when ``fetch_html=True``.
    * Tier 2/3 — domain intelligence (``src.features.domain_intel``): run only
      when ``include_domain=True`` (off by default — it performs slow network
      I/O).

The result is a :class:`FeatureVector` carrying the flat feature dict plus
extraction metadata, and a :meth:`FeatureVector.to_model_input` method that
materializes a numpy array in the exact order the trained model expects (read
from ``configs/feature_config.yaml``).
"""

from __future__ import annotations

import ipaddress
import logging
import socket
import time
from concurrent.futures import TimeoutError as FuturesTimeoutError
from dataclasses import dataclass, field
from functools import lru_cache
from pathlib import Path
from typing import Any, Optional
from urllib.parse import urljoin, urlparse

import numpy as np
import yaml

from src.features import domain_intel, html_content, lexical
from src.utils.domains import registered_domain as _registered_domain
from src.utils.timeout import call_with_timeout

logger = logging.getLogger(__name__)

# Default location of the feature contract config.
_DEFAULT_CONFIG_PATH = (
    Path(__file__).resolve().parents[2] / "configs" / "feature_config.yaml"
)

# Optional HTML fetch limits (CLAUDE.md gotcha: always bound slow I/O).
_FETCH_TIMEOUT: float = 5.0
_FETCH_HEADERS = {"User-Agent": "ARGUS-FeatureBot/0.1 (+phishing-detection)"}
# Cap the response body to avoid memory exhaustion from a hostile page.
_MAX_HTML_BYTES: int = 5 * 1024 * 1024  # 5 MiB
# Redirects are followed manually so each hop can be SSRF-validated.
_MAX_REDIRECTS: int = 3
_ALLOWED_SCHEMES = frozenset({"http", "https"})

# Every feature key the extractors are capable of producing.
_KNOWN_FEATURE_KEYS: frozenset[str] = frozenset(
    set(lexical.FEATURE_KEYS)
    | set(html_content.FEATURE_KEYS)
    | set(domain_intel.DOMAIN_INTEL_KEYS)
)


@lru_cache(maxsize=8)
def _load_feature_config(config_path: str) -> tuple[tuple[str, ...], str]:
    """Load and cache the (feature_order, model_version) contract.

    Args:
        config_path: Absolute path to the feature config YAML.

    Returns:
        A tuple ``(feature_order, model_version)``.

    Raises:
        FileNotFoundError: If the config file does not exist.
        KeyError: If the config lacks a ``feature_order`` list.
    """
    path = Path(config_path)
    if not path.is_file():
        raise FileNotFoundError(f"Feature config not found: {path}")
    with path.open("r", encoding="utf-8") as fh:
        data = yaml.safe_load(fh)
    if not isinstance(data, dict):
        raise KeyError(f"Feature config is not a mapping: {path}")
    if "feature_order" not in data or not data["feature_order"]:
        raise KeyError(f"'feature_order' missing or empty in {path}")
    feature_order = tuple(str(name) for name in data["feature_order"])
    model_version = str(data.get("model_version", "unknown"))
    return feature_order, model_version


@dataclass
class FeatureVector:
    """A unified feature vector with extraction metadata.

    Attributes:
        url: The URL the features were extracted from.
        features: Flat mapping of feature name -> value (may contain ``None``).
        feature_order: The model's expected feature ordering (from config).
        model_version: The feature-contract version from config.
        extraction_time_ms: Wall-clock extraction time in milliseconds.
        features_missing: Names of contract features that are absent or ``None``.
        model_version_compatible: Whether this vector is model-ready — i.e.
            every feature in the contract was actually *produced* (present and
            non-``None``). ``False`` means the vector has gaps (a tier was not
            run, a feature failed, or the config asks for something the
            extractors cannot make) and needs imputation before ``predict``.
        components_run: Which tiers actually ran (``"lexical"``, ``"html"``,
            ``"domain_intel"``).
    """

    url: str
    features: dict[str, Any]
    feature_order: tuple[str, ...]
    model_version: str
    extraction_time_ms: float
    features_missing: list[str] = field(default_factory=list)
    model_version_compatible: bool = True
    components_run: list[str] = field(default_factory=list)

    def to_model_input(self, fill_value: float = np.nan) -> np.ndarray:
        """Materialize features as a numeric array in model feature order.

        Booleans are cast to ``0.0``/``1.0``; missing or non-numeric values are
        replaced with ``fill_value``. String categoricals are not part of the
        contract and, if encountered, are treated as missing (logged).

        Args:
            fill_value: Value substituted for missing/non-numeric features.

        Returns:
            A 1-D ``float`` numpy array of length ``len(self.feature_order)``.
        """
        values: list[float] = []
        for name in self.feature_order:
            raw = self.features.get(name)
            if isinstance(raw, bool):
                values.append(1.0 if raw else 0.0)
            elif isinstance(raw, (int, float)) and not isinstance(raw, bool):
                values.append(float(raw))
            else:
                if raw is not None:
                    logger.warning(
                        "Feature %r has non-numeric value %r; using fill_value",
                        name,
                        raw,
                    )
                values.append(fill_value)
        return np.array(values, dtype=float)


def _is_safe_fetch_url(url: str) -> bool:
    """Return whether ``url`` is safe to fetch (SSRF guard).

    The URL is untrusted input in a phishing-detection API. We allow only
    http/https and refuse any host that resolves to a private, loopback,
    link-local, reserved, multicast, or unspecified address — which blocks
    cloud metadata endpoints (169.254.169.254) and internal services
    (localhost, 10.0.0.0/8, etc).

    Note: there is an unavoidable TOCTOU gap — the OS re-resolves the host when
    the connection is made, so a fast-flipping DNS record could still point
    elsewhere. This check raises the bar substantially but is not a complete
    defence; a production deployment should also pin the validated IP.

    Args:
        url: The URL to validate.

    Returns:
        ``True`` if the URL appears safe to fetch, else ``False``.
    """
    parsed = urlparse(url)
    if parsed.scheme.lower() not in _ALLOWED_SCHEMES:
        return False
    host = parsed.hostname
    if not host:
        return False
    try:
        infos = socket.getaddrinfo(host, parsed.port or None, proto=socket.IPPROTO_TCP)
    except socket.gaierror:
        return False
    for info in infos:
        ip_str = info[4][0]
        try:
            ip = ipaddress.ip_address(ip_str)
        except ValueError:
            return False
        if (
            ip.is_private
            or ip.is_loopback
            or ip.is_link_local
            or ip.is_reserved
            or ip.is_multicast
            or ip.is_unspecified
        ):
            logger.warning("Refusing to fetch %r — resolves to blocked IP %s", url, ip)
            return False
    return True


def _read_capped_body(response: Any) -> Optional[str]:
    """Read a streamed response body up to :data:`_MAX_HTML_BYTES`.

    Args:
        response: A streaming ``requests`` response (``stream=True``).

    Returns:
        The decoded body, or ``None`` if it exceeds the size cap.
    """
    total = 0
    chunks: list[bytes] = []
    for chunk in response.iter_content(chunk_size=8192):
        if not chunk:
            continue
        total += len(chunk)
        if total > _MAX_HTML_BYTES:
            logger.warning("Response body exceeded %d bytes; aborting", _MAX_HTML_BYTES)
            return None
        chunks.append(chunk)
    encoding = response.encoding or "utf-8"
    return b"".join(chunks).decode(encoding, errors="replace")


def _fetch_once(url: str) -> Any:
    """Issue a single non-redirecting streamed GET. Returns the response."""
    import requests

    return requests.get(
        url,
        timeout=_FETCH_TIMEOUT,
        headers=_FETCH_HEADERS,
        allow_redirects=False,
        stream=True,
    )


def _fetch_html(url: str) -> Optional[str]:
    """Fetch page HTML safely, returning ``None`` on any failure.

    Hardened against SSRF (each URL/redirect hop is validated before connecting)
    and against memory exhaustion (body is streamed with a size cap). The whole
    operation is bounded by :data:`_FETCH_TIMEOUT` via a worker thread so a hung
    socket cannot block the caller.

    Args:
        url: The (untrusted) URL to fetch.

    Returns:
        The response body as text, or ``None`` if the fetch failed or was
        refused.
    """
    current = url
    try:
        for _ in range(_MAX_REDIRECTS + 1):
            if not _is_safe_fetch_url(current):
                logger.warning("HTML fetch refused for unsafe URL: %r", current)
                return None
            response = call_with_timeout(_fetch_once, _FETCH_TIMEOUT, current)
            try:
                if response.status_code in (301, 302, 303, 307, 308):
                    location = response.headers.get("Location")
                    if not location:
                        return None
                    current = urljoin(current, location)
                    continue
                response.raise_for_status()
                return _read_capped_body(response)
            finally:
                response.close()
        logger.warning("Too many redirects fetching %r", url)
        return None
    except FuturesTimeoutError:
        logger.warning("HTML fetch timed out for %r", url)
        return None
    except Exception as exc:  # noqa: BLE001 - dead URLs are expected, never crash
        logger.warning("HTML fetch failed for %r: %s", url, exc)
        return None


def extract_features(
    url: Any,
    html: Optional[str] = None,
    fetch_html: bool = False,
    include_domain: bool = False,
    config_path: Optional[str] = None,
) -> FeatureVector:
    """Run the feature-extraction pipeline for a single URL.

    Args:
        url: The URL to analyse.
        html: Pre-fetched page HTML. When provided, HTML features are extracted
            from it and no fetch occurs (avoids double-fetching).
        fetch_html: If ``True`` and ``html`` is not provided, fetch the page.
        include_domain: If ``True``, run the slow WHOIS/DNS domain-intel tier.
            Defaults to ``False`` for speed.
        config_path: Override path to the feature config. Defaults to
            ``configs/feature_config.yaml``.

    Returns:
        A populated :class:`FeatureVector`.
    """
    start = time.perf_counter()
    cfg_path = str(config_path) if config_path else str(_DEFAULT_CONFIG_PATH)

    try:
        feature_order, model_version = _load_feature_config(cfg_path)
    except Exception as exc:  # noqa: BLE001 - config problems must not crash callers
        logger.warning("Failed to load feature config %r: %s", cfg_path, exc)
        feature_order, model_version = (), "unknown"

    url_str = url if isinstance(url, str) else ""
    features: dict[str, Any] = {}
    components_run: list[str] = []

    # Tier 1 — lexical: always.
    features.update(lexical.extract_lexical_features(url))
    components_run.append("lexical")

    # Tier 4 — HTML/content: if HTML supplied, or fetch requested.
    page_html = html
    if page_html is None and fetch_html and url_str:
        page_html = _fetch_html(url_str)
    if page_html is not None:
        features.update(
            html_content.extract_html_features(page_html, base_url=url_str or None)
        )
        components_run.append("html")

    # Tier 2/3 — domain intelligence: opt-in. Reuse the registered domain the
    # lexical tier already computed instead of re-parsing.
    if include_domain and url_str:
        domain = features.get("domain") or _registered_domain(url_str) or url_str
        features.update(domain_intel.extract_domain_intel(domain))
        components_run.append("domain_intel")

    # Metadata. Surface config drift (contract asks for an unproducible feature).
    unknown_features = [n for n in feature_order if n not in _KNOWN_FEATURE_KEYS]
    if unknown_features:
        logger.warning(
            "Feature contract references unknown features: %s", unknown_features
        )

    features_missing = [
        name
        for name in feature_order
        if name not in features or features.get(name) is None
    ]
    # Honest flag: the vector is model-ready only if every contract feature was
    # actually produced (no NaN slots). Un-run tiers therefore mark it False.
    model_version_compatible = len(features_missing) == 0
    extraction_time_ms = round((time.perf_counter() - start) * 1000, 3)

    return FeatureVector(
        url=url_str,
        features=features,
        feature_order=feature_order,
        model_version=model_version,
        extraction_time_ms=extraction_time_ms,
        features_missing=features_missing,
        model_version_compatible=model_version_compatible,
        components_run=components_run,
    )
