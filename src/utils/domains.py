"""Shared tldextract configuration and domain helpers.

Centralizes the single ``TLDExtract`` instance used across feature extractors so
that:

    * the cache dir is set once, and
    * extraction is **offline** — ``suffix_list_urls=()`` forces tldextract to
      use only its bundled public-suffix snapshot, never an HTTP fetch on a cold
      cache. This keeps the lexical tier's "no network I/O" guarantee honest.

It also smooths over the tldextract API change: ``registered_domain`` is
deprecated in favour of ``top_domain_under_public_suffix`` in newer releases.
:func:`registered_domain_of` prefers the new name and falls back to the old one,
so the same code works on the pinned 5.1.2 and on later versions without
emitting deprecation warnings.
"""

from __future__ import annotations

import os
from typing import Any

import tldextract

# B108 is suppressed on the line below. A fixed /tmp path is only a hardening
# concern on a shared, multi-user host, where another user could pre-create the
# path as a symlink. It is a *fallback*: TLDEXTRACT_CACHE overrides it, the
# Dockerfile sets it explicitly, and the container runs as a single non-root
# user. The contents are a public-suffix-list snapshot -- not secret, and not
# trusted input (suffix_list_urls=() below means it is never re-fetched).
_CACHE_DIR = os.environ.get("TLDEXTRACT_CACHE", "/tmp/tldextract_cache")  # nosec B108

# suffix_list_urls=() -> snapshot only, no network fetch ever.
_EXTRACTOR = tldextract.TLDExtract(cache_dir=_CACHE_DIR, suffix_list_urls=())


def get_extractor() -> tldextract.TLDExtract:
    """Return the shared, offline-configured tldextract instance."""
    return _EXTRACTOR


def registered_domain_of(ext: Any) -> str:
    """Return the registered domain from a tldextract result.

    Prefers ``top_domain_under_public_suffix`` (newer tldextract) and falls back
    to ``registered_domain`` (pinned 5.1.2) to avoid deprecation warnings.

    Args:
        ext: The object returned by calling a ``TLDExtract`` instance.

    Returns:
        The registered domain (e.g. ``"example.com"``), or ``""``.
    """
    value = getattr(ext, "top_domain_under_public_suffix", None)
    if value is None:
        value = ext.registered_domain
    return value or ""


def registered_domain(url: str) -> str:
    """Return the registered domain of a URL, or ``""`` if undeterminable.

    Args:
        url: An absolute URL.

    Returns:
        The registered domain (e.g. ``"example.com"``), or ``""`` on failure.
    """
    try:
        return registered_domain_of(_EXTRACTOR(url))
    except Exception:  # noqa: BLE001
        return ""
