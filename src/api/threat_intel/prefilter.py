"""Threat-intel pre-filter orchestration (DEC-010; provider abstraction, DEC-035).

Walks an ordered list of :class:`~src.api.threat_intel.providers.ThreatIntelProvider`
instances (built by :func:`~src.api.threat_intel.providers.build_providers`)
and returns the first one that matches. Previously this module hardcoded
PhishTank's two frozensets directly; DEC-035 (F6) moved that logic into
:class:`~src.api.threat_intel.providers.PhishTankProvider` so a second
provider (Google Safe Browsing, also DEC-035) — or any future feed — plugs
in without this function changing again.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Optional, Sequence

if TYPE_CHECKING:
    from src.api.threat_intel.providers import ThreatIntelProvider


def check_prefilter(url: str, providers: Sequence["ThreatIntelProvider"]) -> Optional[str]:
    """Check a URL against every configured threat-intel provider, in order.

    Args:
        url: The URL to check (as received by ``/detect``, before any other
            processing). May be a full URL or a bare hostname — the browser
            extension's S1 privacy default sends hostname-only unless the
            user opts into ``sendFullUrl``.
        providers: Ordered providers to consult (see
            :func:`src.api.threat_intel.providers.build_providers`). The
            first provider whose ``check(url)`` returns ``True`` wins;
            later providers are not consulted.

    Returns:
        The matching provider's ``name`` (e.g. ``"phishtank"``, ``"gsb"``),
        or ``None`` if no provider matched (including when ``providers`` is
        empty, which safely reproduces "pre-filter disabled").
    """
    for provider in providers:
        if provider.check(url):
            return provider.name
    return None
