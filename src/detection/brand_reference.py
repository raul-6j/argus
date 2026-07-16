"""Brand reference index — loader for ``data/reference/brands.json`` (DEC-C).

A small, git-tracked, reviewable asset of well-known brands (domains,
name/alias tokens, and — once populated by ``scripts/build_brand_reference.py``
with network access — known-legitimate favicon/logo hashes). Used by every
Phase-1 detection signal (typosquat, favicon match, brand mismatch) as the
"what is a real brand, and where does it actually live" reference.

Tranco is used only as an optional seed of legitimate-brand domains when
building this asset — never as ML training/validation data (that would
contradict the project's dataset decision; see ``docs/DECISIONS.md``).
"""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

logger = logging.getLogger(__name__)

_PROJECT_ROOT = Path(__file__).resolve().parents[2]
_DEFAULT_BRANDS_PATH = _PROJECT_ROOT / "data" / "reference" / "brands.json"


@dataclass(frozen=True)
class Brand:
    """One reference brand.

    Attributes:
        name: Display name (e.g. ``"PayPal"``).
        domains: The brand's own legitimate registered domain(s), lowercase
            (e.g. ``("paypal.com",)``) — also used as an allowlist so a
            signal never flags the brand's own real site.
        aliases: Additional lowercase name tokens to match against page text
            (e.g. ``("paypal", "pay pal")``).
        favicon_mmh3: Known-legitimate favicon MurmurHash3 hashes for this
            brand (populated offline; may be empty until
            ``scripts/build_brand_reference.py`` has been run with network
            access).
        logo_phash: Known-legitimate favicon/logo average-hashes, as lowercase
            hex strings (same populate-offline caveat as ``favicon_mmh3``).
    """

    name: str
    domains: tuple[str, ...]
    aliases: tuple[str, ...] = ()
    favicon_mmh3: tuple[int, ...] = ()
    logo_phash: tuple[str, ...] = ()


@dataclass
class BrandIndex:
    """In-memory index over every :class:`Brand`, built once at startup."""

    brands: tuple[Brand, ...] = ()
    _domain_lookup: dict[str, Brand] = field(default_factory=dict, init=False, repr=False)
    _favicon_lookup: dict[int, Brand] = field(default_factory=dict, init=False, repr=False)

    def __post_init__(self) -> None:
        self._domain_lookup = {d: b for b in self.brands for d in b.domains}
        self._favicon_lookup = {h: b for b in self.brands for h in b.favicon_mmh3}

    def brand_for_domain(self, domain: str) -> Optional[Brand]:
        """Return the :class:`Brand` that owns ``domain``, or ``None``."""
        return self._domain_lookup.get(domain.lower()) if domain else None

    def brand_for_favicon_hash(self, mmh3_hash: int) -> Optional[Brand]:
        """Return the :class:`Brand` whose known favicon hash matches, or ``None``."""
        return self._favicon_lookup.get(mmh3_hash)


def _empty_index() -> BrandIndex:
    return BrandIndex(brands=())


def load_brand_index(path: Optional[Path] = None) -> BrandIndex:
    """Load the brand reference asset into an in-memory :class:`BrandIndex`.

    Never raises — a missing/malformed file degrades to an empty index
    (every brand-dependent signal becomes a safe no-op), matching the
    graceful-degradation convention used by the threat-intel pre-filter
    loader (``src.api.threat_intel.phishtank``).

    Args:
        path: Path to ``brands.json``. Defaults to
            ``data/reference/brands.json`` under the project root.

    Returns:
        A populated (or, on failure, empty) :class:`BrandIndex`.
    """
    p = path or _DEFAULT_BRANDS_PATH
    if not p.is_file():
        logger.warning("Brand reference not found at %s — brand signals disabled.", p)
        return _empty_index()

    try:
        data = json.loads(p.read_text(encoding="utf-8"))
        raw_brands = data.get("brands", [])
        if not isinstance(raw_brands, list):
            raise ValueError("'brands' must be a list")

        brands: list[Brand] = []
        for entry in raw_brands:
            name = str(entry["name"])
            domains = tuple(str(d).lower() for d in entry.get("domains", []) if d)
            if not domains:
                logger.warning("Brand entry %r has no domains — skipped.", name)
                continue
            aliases = tuple(str(a).lower() for a in entry.get("aliases", []) if a)
            favicon_hashes = tuple(
                int(h) for h in entry.get("favicon_mmh3", []) if h is not None
            )
            logo_hashes = tuple(str(h).lower() for h in entry.get("logo_phash", []) if h)
            brands.append(
                Brand(
                    name=name,
                    domains=domains,
                    aliases=aliases,
                    favicon_mmh3=favicon_hashes,
                    logo_phash=logo_hashes,
                )
            )

        index = BrandIndex(brands=tuple(brands))
        logger.info("Brand reference index loaded: %d brands from %s", len(brands), p)
        return index
    except Exception as exc:  # noqa: BLE001 - a broken asset must never crash app startup
        logger.warning("Failed to load brand reference %s: %s — brand signals disabled.", p, exc)
        return _empty_index()
