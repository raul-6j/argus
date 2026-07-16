"""PhishTank snapshot loading for the threat-intel pre-filter (DEC-010).

Deliberately independent of :func:`src.data.loaders.load_phishtank` (the
training-data loader): that function only filters on ``verified`` and is
used to build phishing *training examples*, where a since-taken-down URL is
still a structurally valid example. A pre-filter that short-circuits
``/detect`` straight to ``label=phishing`` with no model check has a much
higher bar — an ``online=no`` entry may mean the domain/path has since been
reclaimed or repurposed by a legitimate party, and blindly matching it would
be a false positive with nothing downstream to catch it. So this module also
filters on ``online == "yes"``.
"""

from __future__ import annotations

import logging
from pathlib import Path
from urllib.parse import urlparse

import pandas as pd

from src.data.loaders import normalize_url

logger = logging.getLogger(__name__)

_REQUIRED_COLS: frozenset[str] = frozenset({"url", "verified"})


def _load_verified_online_urls(csv_path: Path) -> list[str] | None:
    """Shared CSV-read + verified/online filter for both indices below.

    Never raises — a missing/malformed snapshot yields ``None`` so callers
    can degrade independently (each returns an empty index) rather than
    crashing API startup, matching the graceful-degradation convention used
    elsewhere in ``src.api.app``.
    """
    if not csv_path.is_file():
        logger.warning(
            "PhishTank snapshot not found at %s — threat-intel pre-filter will match nothing.",
            csv_path,
        )
        return None

    try:
        df = pd.read_csv(csv_path)
        df.columns = [c.strip() for c in df.columns]

        missing = _REQUIRED_COLS - set(df.columns)
        if missing:
            logger.warning(
                "PhishTank snapshot %s missing required columns %s — pre-filter disabled.",
                csv_path,
                sorted(missing),
            )
            return None

        df = df[df["verified"].str.strip().str.lower() == "yes"]

        if "online" in df.columns:
            n_before = len(df)
            df = df[df["online"].str.strip().str.lower() == "yes"]
            logger.info(
                "PhishTank pre-filter: dropped %d offline entries.", n_before - len(df)
            )
        else:
            logger.warning(
                "PhishTank snapshot %s has no 'online' column — including all "
                "verified entries regardless of online status.",
                csv_path,
            )

        return list(df["url"].dropna())
    except Exception as exc:  # noqa: BLE001 - a broken snapshot must never crash app startup
        logger.warning("Failed to load PhishTank snapshot %s: %s — pre-filter disabled.", csv_path, exc)
        return None


def load_phishtank_index(csv_path: Path) -> frozenset[str]:
    """Load a PhishTank snapshot into a normalized-URL lookup set.

    Never raises — a missing/malformed snapshot degrades to an empty index
    (pre-filter effectively disabled for PhishTank) rather than crashing API
    startup, matching the graceful-degradation convention used elsewhere in
    ``src.api.app`` (e.g. the SHAP explainer background sample).

    Args:
        csv_path: Path to the PhishTank CSV snapshot.

    Returns:
        A frozenset of URLs normalized via
        :func:`src.data.loaders.normalize_url`, filtered to entries that are
        both ``verified == "yes"`` and (when the column is present)
        ``online == "yes"``.
    """
    urls = _load_verified_online_urls(csv_path)
    if urls is None:
        return frozenset()

    index = frozenset(normalize_url(u) for u in urls)
    logger.info("PhishTank pre-filter index loaded: %d URLs from %s", len(index), csv_path)
    return index


def load_phishtank_hostname_index(
    csv_path: Path, subdomain_per_tenant_platforms: frozenset[str]
) -> frozenset[str]:
    """Build a coarser, hostname-only index for a curated set of platforms.

    ``load_phishtank_index`` matches the full URL (path included) by design,
    to avoid flagging unrelated content on a shared, path-differentiated host
    (see ``tests/api/threat_intel/test_prefilter.py::test_different_path_does_not_match``).
    But some hosting platforms hand each tenant a *dedicated subdomain*
    instead (e.g. ``sitename.wixstudio.com``, ``user.github.io``) — there,
    the bare hostname is already as specific as the full URL, so a request
    that only carries the hostname (e.g. the browser extension's S1
    hostname-only privacy default) can still be matched safely.

    This is deliberately opt-in and conservative: a hostname is only added to
    the index when it ends in one of ``subdomain_per_tenant_platforms``
    (configured in ``configs/threat_intel_config.yaml``). Any host not on
    that list is skipped entirely, leaving the exact-URL-only behavior of
    :func:`load_phishtank_index` as the sole match path — the safe default
    from DEC-010 is unchanged unless a platform is explicitly opted in here.

    Args:
        csv_path: Path to the PhishTank CSV snapshot.
        subdomain_per_tenant_platforms: Lowercase apex domains (e.g.
            ``{"wixstudio.com", "github.io"}``) where each tenant gets a
            dedicated subdomain. Empty set (the default if the config key is
            absent) always yields an empty index.

    Returns:
        A frozenset of lowercase hostnames eligible for hostname-only
        matching.
    """
    urls = _load_verified_online_urls(csv_path)
    if urls is None or not subdomain_per_tenant_platforms:
        return frozenset()

    hostnames: set[str] = set()
    for raw_url in urls:
        candidate = raw_url if "://" in raw_url else f"https://{raw_url}"
        host = urlparse(candidate).hostname
        if not host:
            continue
        host = host.lower()
        if any(
            host == platform or host.endswith(f".{platform}")
            for platform in subdomain_per_tenant_platforms
        ):
            hostnames.add(host)

    logger.info(
        "PhishTank hostname pre-filter index loaded: %d hostnames from %s",
        len(hostnames),
        csv_path,
    )
    return frozenset(hostnames)
