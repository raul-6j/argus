"""Favicon / logo perceptual-hash brand-impersonation signal (Phase 1, A2).

Resolves the visited page's favicon, hashes it two ways, and compares
against the brand reference's known-legitimate hashes:

    * An **exact** MurmurHash3 match (the "Shodan favicon hash" convention)
      to a brand whose real domain differs from the visited domain is a
      near-zero-false-positive signal — attackers copy the real icon
      byte-for-byte far more often than they bother re-encoding it — and is
      marked ``is_hard_override=True`` so the fusion layer can treat it as
      decisive on its own (subject to ``detection_config.yaml``'s
      ``hard_override_signals`` gate).
    * A **soft** perceptual-hash (average-hash) match within a configurable
      Hamming-distance tolerance is a weaker, non-override signal — the icon
      merely *looks* similar (e.g. recompressed/resized), which is weaker
      evidence and never forces the verdict on its own.

Reuses the SSRF guard for the favicon fetch itself (a second, small,
independently-validated request — see docs/DECISIONS.md DEC-025).
"""

from __future__ import annotations

import base64
import logging
import time
from typing import TYPE_CHECKING, Optional
from urllib.parse import urljoin, urlparse

from bs4 import BeautifulSoup

from src.detection.hashing import average_hash, hamming_distance, mmh3_32
from src.detection.types import RiskSignal
from src.utils.domains import registered_domain
from src.utils.ssrf import is_safe_fetch_url
from src.utils.timeout import call_with_timeout

if TYPE_CHECKING:
    from src.detection.brand_reference import BrandIndex
    from src.features.page_artifacts import PageArtifacts

logger = logging.getLogger(__name__)

_SIGNAL_NAME = "favicon_match"
_FAVICON_FETCH_TIMEOUT: float = 3.0
_MAX_FAVICON_BYTES: int = 512 * 1024  # 512 KiB — favicons are always tiny
_DEFAULT_PHASH_TOLERANCE = 8  # Hamming distance out of 64 bits (~12.5%)
_EXACT_MATCH_SCORE = 0.97


def _resolve_favicon_url(html: Optional[str], page_url: str) -> Optional[str]:
    """Find the favicon URL from ``<link rel~=icon>``, falling back to ``/favicon.ico``."""
    if html:
        try:
            soup = BeautifulSoup(html, "lxml")
            for link in soup.find_all("link"):
                rel = link.get("rel")
                rel_str = " ".join(rel) if isinstance(rel, list) else str(rel or "")
                if "icon" in rel_str.lower():
                    href = link.get("href")
                    if href:
                        return urljoin(page_url, str(href).strip())
        except Exception as exc:  # noqa: BLE001 - malformed markup -> fall back
            logger.warning("Favicon <link> parse failed: %s", exc)

    try:
        parsed = urlparse(page_url)
        if parsed.scheme and parsed.netloc:
            return f"{parsed.scheme}://{parsed.netloc}/favicon.ico"
    except Exception:  # noqa: BLE001
        pass
    return None


def _decode_data_uri(favicon_url: str) -> Optional[bytes]:
    try:
        header, b64data = favicon_url.split(",", 1)
        if ";base64" not in header:
            return None
        return base64.b64decode(b64data)
    except Exception as exc:  # noqa: BLE001
        logger.warning("Failed to decode data-URI favicon: %s", exc)
        return None


def _fetch_favicon_bytes(favicon_url: str) -> Optional[bytes]:
    """Fetch favicon bytes, SSRF-guarded and size-capped. Never raises."""
    if favicon_url.lower().startswith("data:"):
        return _decode_data_uri(favicon_url)

    if not is_safe_fetch_url(favicon_url):
        logger.warning("Favicon fetch refused for unsafe URL: %r", favicon_url)
        return None

    try:
        import requests

        def _get():
            return requests.get(favicon_url, timeout=_FAVICON_FETCH_TIMEOUT, stream=True)

        response = call_with_timeout(_get, _FAVICON_FETCH_TIMEOUT)
        try:
            if response.status_code != 200:
                return None
            total = 0
            chunks: list[bytes] = []
            for chunk in response.iter_content(chunk_size=4096):
                if not chunk:
                    continue
                total += len(chunk)
                if total > _MAX_FAVICON_BYTES:
                    logger.warning("Favicon exceeded %d bytes; aborting", _MAX_FAVICON_BYTES)
                    return None
                chunks.append(chunk)
            return b"".join(chunks)
        finally:
            response.close()
    except Exception as exc:  # noqa: BLE001 - Iron Law #3
        logger.warning("Favicon fetch failed for %r: %s", favicon_url, exc)
        return None


def _elapsed(start: float) -> float:
    return round((time.perf_counter() - start) * 1000, 3)


def _neutral(start: float) -> RiskSignal:
    return RiskSignal(
        name=_SIGNAL_NAME, triggered=False, score=0.0, direction="neutral",
        evidence={}, latency_ms=_elapsed(start),
    )


def evaluate(
    page_artifacts: Optional["PageArtifacts"],
    visited_url: str,
    brand_index: "BrandIndex",
    phash_tolerance: int = _DEFAULT_PHASH_TOLERANCE,
) -> RiskSignal:
    """Evaluate a fetched page's favicon against the brand reference.

    Args:
        page_artifacts: The shared fetch context. Returns neutral if
            ``None`` or the fetch didn't succeed.
        visited_url: The URL actually being evaluated (used to derive the
            visited registered domain, to suppress matches on a brand's own
            real site).
        brand_index: The loaded brand reference.
        phash_tolerance: Maximum Hamming distance (out of 64 bits) for a
            soft perceptual-hash match.

    Returns:
        A :class:`RiskSignal`; never raises.
    """
    start = time.perf_counter()
    try:
        if page_artifacts is None or not page_artifacts.ok or not brand_index.brands:
            return _neutral(start)

        visited_domain = registered_domain(visited_url) or registered_domain(
            page_artifacts.final_url or ""
        )
        page_url = page_artifacts.final_url or visited_url
        favicon_url = _resolve_favicon_url(page_artifacts.html, page_url)
        if not favicon_url:
            return _neutral(start)

        favicon_bytes = _fetch_favicon_bytes(favicon_url)
        if not favicon_bytes:
            return _neutral(start)

        # 1) Exact MurmurHash3 match -- hard-override candidate.
        mmh3_hash = mmh3_32(base64.b64encode(favicon_bytes))
        matched_brand = brand_index.brand_for_favicon_hash(mmh3_hash)
        if matched_brand is not None:
            if visited_domain and visited_domain in matched_brand.domains:
                return _neutral(start)  # it IS the brand's own real site
            return RiskSignal(
                name=_SIGNAL_NAME, triggered=True, score=_EXACT_MATCH_SCORE,
                direction="phishing", is_hard_override=True,
                evidence={
                    "impersonated_brand": matched_brand.name,
                    "brand_domain": matched_brand.domains[0] if matched_brand.domains else "",
                    "match_type": "exact_favicon_hash",
                    "hash_distance": 0,
                },
                latency_ms=_elapsed(start),
            )

        # 2) Soft perceptual-hash (average-hash) match -- weaker evidence.
        page_hash = average_hash(favicon_bytes)
        if page_hash is None:
            return _neutral(start)

        best_brand = None
        best_distance: Optional[int] = None
        for brand in brand_index.brands:
            if visited_domain and visited_domain in brand.domains:
                continue
            for hex_hash in brand.logo_phash:
                try:
                    ref_hash = int(hex_hash, 16)
                except ValueError:
                    continue
                distance = hamming_distance(page_hash, ref_hash)
                if best_distance is None or distance < best_distance:
                    best_distance = distance
                    best_brand = brand

        if best_brand is not None and best_distance is not None and best_distance <= phash_tolerance:
            frac = 1 - (best_distance / max(phash_tolerance, 1))
            score = round(max(0.4, min(0.9, 0.5 + 0.4 * frac)), 4)
            return RiskSignal(
                name=_SIGNAL_NAME, triggered=True, score=score, direction="phishing",
                is_hard_override=False,
                evidence={
                    "impersonated_brand": best_brand.name,
                    "brand_domain": best_brand.domains[0] if best_brand.domains else "",
                    "match_type": "perceptual_hash",
                    "hash_distance": best_distance,
                },
                latency_ms=_elapsed(start),
            )

        return _neutral(start)
    except Exception as exc:  # noqa: BLE001 - Iron Law #3
        logger.warning("favicon_match signal failed for %r: %s", visited_url, exc)
        return _neutral(start)
