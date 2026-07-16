#!/usr/bin/env python
"""Refresh threat-intel feed snapshots (Phase 1, D1).

Downloads every feed configured in ``configs/threat_intel_config.yaml ->
feeds``, normalizes each to the same ``(url, verified, online)`` schema the
existing PhishTank pre-filter loaders already expect
(``src.api.threat_intel.phishtank``), deduplicates across feeds by
normalized URL, and writes a dated snapshot CSV plus an
``active_snapshot.txt`` pointer into ``feeds_dir``. The running API picks up
the new snapshot on its *next* start (see
``src/api/app.py::_resolve_threat_feed_snapshot``) — this script does not
hot-reload a live process.

A single feed failing (network error, schema drift) never aborts the
refresh; it's logged and skipped, and every other feed still contributes.
The active-snapshot pointer is only updated if at least one feed succeeded,
so a fully offline run leaves the previous snapshot in place rather than
wiping it.

Usage:
    python scripts/refresh_threat_feeds.py [--config configs/threat_intel_config.yaml]
"""

from __future__ import annotations

import argparse
import csv
import io
import logging
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import yaml  # noqa: E402

from src.data.loaders import normalize_url  # noqa: E402

logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")
logger = logging.getLogger("refresh_threat_feeds")

_PROJECT_ROOT = Path(__file__).resolve().parents[1]
_DEFAULT_CONFIG_PATH = _PROJECT_ROOT / "configs" / "threat_intel_config.yaml"
_FETCH_TIMEOUT: float = 15.0
_CSV_FIELDNAMES = ["url", "verified", "online"]


def _normalize_phishtank_text(raw: bytes) -> list[dict[str, str]]:
    """PhishTank's ``online-valid.csv`` already has ``verified``/``online`` columns."""
    text = raw.decode("utf-8", errors="replace")
    reader = csv.DictReader(io.StringIO(text))
    rows = []
    for row in reader:
        url = (row.get("url") or "").strip()
        if not url:
            continue
        rows.append(
            {
                "url": url,
                "verified": (row.get("verified") or "yes").strip().lower(),
                "online": (row.get("online") or "yes").strip().lower(),
            }
        )
    return rows


def _normalize_openphish_text(raw: bytes) -> list[dict[str, str]]:
    """OpenPhish's free feed is a plain-text list of currently-active phishing URLs."""
    text = raw.decode("utf-8", errors="replace")
    rows = []
    for line in text.splitlines():
        url = line.strip()
        if not url or url.startswith("#"):
            continue
        rows.append({"url": url, "verified": "yes", "online": "yes"})
    return rows


def _normalize_urlhaus_text(raw: bytes) -> list[dict[str, str]]:
    """URLhaus's ``csv_recent`` feed: id,dateadded,url,url_status,threat,tags,... (CSV, `#`-commented header)."""
    text = raw.decode("utf-8", errors="replace")
    lines = [ln for ln in text.splitlines() if ln and not ln.startswith("#")]
    reader = csv.reader(lines)
    rows = []
    for fields in reader:
        if len(fields) < 4:
            continue
        url = fields[2].strip().strip('"')
        status = fields[3].strip().strip('"').lower()
        if not url:
            continue
        rows.append({"url": url, "verified": "yes", "online": "yes" if status == "online" else "no"})
    return rows


_NORMALIZERS = {
    "phishtank": _normalize_phishtank_text,
    "openphish": _normalize_openphish_text,
    "urlhaus": _normalize_urlhaus_text,
}


def _download(url: str) -> Optional[bytes]:
    try:
        import requests

        resp = requests.get(url, timeout=_FETCH_TIMEOUT)
        resp.raise_for_status()
        return resp.content
    except Exception as exc:  # noqa: BLE001 - one feed's network failure never aborts the run
        logger.warning("Feed download failed for %s: %s", url, exc)
        return None


def refresh(config_path: Path = _DEFAULT_CONFIG_PATH) -> Optional[Path]:
    """Download, normalize, dedupe, and snapshot every configured feed.

    Args:
        config_path: Path to ``threat_intel_config.yaml``.

    Returns:
        The path to the newly-written snapshot, or ``None`` if every feed
        failed (in which case no files are changed).
    """
    if not config_path.is_file():
        logger.error("Config not found: %s", config_path)
        return None

    config = yaml.safe_load(config_path.read_text(encoding="utf-8")) or {}
    feeds = config.get("feeds", [])
    if not feeds:
        logger.warning("No feeds configured in %s — nothing to refresh.", config_path)
        return None

    feeds_dir = _PROJECT_ROOT / config.get("feeds_dir", "data/raw/feeds")
    feeds_dir.mkdir(parents=True, exist_ok=True)

    all_rows: dict[str, dict[str, str]] = {}
    any_success = False

    for feed in feeds:
        name = feed.get("name")
        feed_url = feed.get("url")
        normalizer_name = feed.get("parser", name)
        normalizer = _NORMALIZERS.get(normalizer_name)
        if not feed_url or normalizer is None:
            logger.warning("Skipping feed %r: missing url or unknown parser %r", name, normalizer_name)
            continue

        raw = _download(feed_url)
        if raw is None:
            continue
        try:
            rows = normalizer(raw)
        except Exception as exc:  # noqa: BLE001 - one feed's schema drift never aborts the run
            logger.warning("Failed to parse feed %r: %s", name, exc)
            continue

        for row in rows:
            all_rows[normalize_url(row["url"])] = row  # later feeds win on exact-URL collision
        logger.info("Feed %r: %d entries parsed", name, len(rows))
        any_success = True

    if not any_success:
        logger.error("All feeds failed — active snapshot left unchanged.")
        return None

    date_str = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    snapshot_path = feeds_dir / f"threat_feed_{date_str}.csv"
    with snapshot_path.open("w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=_CSV_FIELDNAMES)
        writer.writeheader()
        for row in all_rows.values():
            writer.writerow(row)
    logger.info("Wrote %d deduped entries to %s", len(all_rows), snapshot_path)

    # Atomic-ish pointer swap: write to a temp file, then rename over the
    # real pointer, so a crash mid-write never leaves a half-written pointer.
    # Store a project-relative path when possible (keeps the pointer
    # portable across checkouts); fall back to an absolute path for a
    # feeds_dir configured outside the project root (e.g. in tests) --
    # src.api.app._resolve_threat_feed_snapshot's `PROJECT_ROOT / relative`
    # read-back resolves an absolute string to itself either way.
    try:
        pointer_target = str(snapshot_path.relative_to(_PROJECT_ROOT))
    except ValueError:
        pointer_target = str(snapshot_path)
    pointer_path = feeds_dir / "active_snapshot.txt"
    tmp_pointer = pointer_path.with_suffix(".tmp")
    tmp_pointer.write_text(pointer_target, encoding="utf-8")
    tmp_pointer.replace(pointer_path)
    logger.info("Active snapshot pointer updated -> %s", snapshot_path)

    return snapshot_path


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", type=Path, default=_DEFAULT_CONFIG_PATH)
    args = parser.parse_args()
    result = refresh(args.config)
    sys.exit(0 if result is not None else 1)


if __name__ == "__main__":
    main()
