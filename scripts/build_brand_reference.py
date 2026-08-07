#!/usr/bin/env python
"""Build/refresh the brand reference asset's favicon hashes (Phase 1, DEC-C).

``data/reference/brands.json`` ships with real ``name``/``domains``/
``aliases`` but empty ``favicon_mmh3``/``logo_phash`` lists — this
repository's build environment has no network access to fetch favicons from
live brand sites. Run this script wherever network access *is* available to
populate those hashes; the typosquat (A3) and brand-mismatch (A1) signals
already work fully on the shipped seed data (they only need domains/
aliases), but the favicon-match (A2) signal's exact-hash hard-override path
has nothing to match against until this has been run at least once.

Idempotent and safe to re-run on a schedule: a brand whose favicon can't be
fetched this run keeps its previously-populated hashes rather than being
wiped to empty.

Tranco is not used here — this script only re-fetches favicons for the
brands/domains already listed in ``brands.json``. Adding *new* brands (e.g.
sourced from Tranco's top domains) is a manual edit to the seed file, kept
separate from hash population so a reviewer can see exactly what domains
were added, independent of hash churn.

Usage:
    python scripts/build_brand_reference.py [--brands-path data/reference/brands.json]
"""

from __future__ import annotations

import argparse
import base64
import json
import logging
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from src.detection.hashing import average_hash, mmh3_32
from src.utils.ssrf import is_safe_fetch_url

logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")
logger = logging.getLogger("build_brand_reference")

_PROJECT_ROOT = Path(__file__).resolve().parents[1]
_DEFAULT_PATH = _PROJECT_ROOT / "data" / "reference" / "brands.json"
_FETCH_TIMEOUT: float = 5.0
_MAX_FAVICON_BYTES: int = 512 * 1024


def _fetch_favicon(domain: str) -> Optional[bytes]:
    url = f"https://{domain}/favicon.ico"
    if not is_safe_fetch_url(url):
        logger.warning("Refusing unsafe favicon URL for %s", domain)
        return None
    try:
        import requests

        resp = requests.get(url, timeout=_FETCH_TIMEOUT, stream=True)
        if resp.status_code != 200:
            return None
        total = 0
        chunks: list[bytes] = []
        for chunk in resp.iter_content(chunk_size=4096):
            if not chunk:
                continue
            total += len(chunk)
            if total > _MAX_FAVICON_BYTES:
                return None
            chunks.append(chunk)
        return b"".join(chunks)
    except Exception as exc:  # noqa: BLE001 - one brand's failure never aborts the run
        logger.warning("Favicon fetch failed for %s: %s", domain, exc)
        return None


def build(brands_path: Path) -> None:
    """Populate ``favicon_mmh3``/``logo_phash`` for every brand in ``brands_path``."""
    data = json.loads(brands_path.read_text(encoding="utf-8"))
    updated = 0
    for brand in data.get("brands", []):
        domains = brand.get("domains", [])
        if not domains:
            continue

        favicon_hashes: list[int] = []
        logo_hashes: list[str] = []
        for domain in domains:
            raw = _fetch_favicon(domain)
            if raw is None:
                continue
            favicon_hashes.append(mmh3_32(base64.b64encode(raw)))
            ahash = average_hash(raw)
            if ahash is not None:
                logo_hashes.append(format(ahash, "016x"))

        if favicon_hashes:
            brand["favicon_mmh3"] = sorted(set(favicon_hashes))
            brand["logo_phash"] = sorted(set(logo_hashes))
            updated += 1
            logger.info("Updated %s: %d favicon hash(es)", brand.get("name"), len(favicon_hashes))
        else:
            logger.warning("No favicon retrieved for %s — keeping existing hashes", brand.get("name"))

    data["generated_at"] = datetime.now(timezone.utc).isoformat()
    brands_path.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")
    logger.info(
        "Brand reference updated: %d/%d brands refreshed -> %s",
        updated,
        len(data.get("brands", [])),
        brands_path,
    )


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--brands-path", type=Path, default=_DEFAULT_PATH)
    args = parser.parse_args()
    build(args.brands_path)


if __name__ == "__main__":
    main()
