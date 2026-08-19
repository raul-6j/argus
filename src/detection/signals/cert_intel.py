"""TLS certificate intelligence signal (Phase 2, A4).

Consumes ``PageArtifacts.tls_cert`` — captured for free during the shared
page fetch (P1.0/A4, ``src.features.page_artifacts.fetch``) by reading the
peer certificate off the connection ``requests`` already opened, so this
signal makes **no extra network connection**.

"Has HTTPS" stopped being a useful phishing signal years ago — free,
instant-issuance CAs (Let's Encrypt, ZeroSSL) mean every phishing kit ships
with valid TLS. What's still discriminating is **how recently** the
certificate was issued *relative to the domain itself*: a domain registered
an hour ago for a phishing campaign has a cert issued within the same
window, while a legitimate site's cert is very rarely younger than the site
itself. Age alone is a weak signal (many legitimate sites also rotate certs
frequently) — this module treats a very fresh, free-CA-issued cert as a
*contributing* signal, never a hard override, exactly per the plan ("age is
a contributing signal, never a sole override").

DEC-031 found this module wasn't actually living up to its own docstring:
the "fresh cert" axes triggered on cert freshness alone, with no check of
the domain's own registration age — so routine CDN/edge cert rotation on
long-established, real domains (PayPal, Google, Apple, Bank of America,
Yahoo, Steam all reproduced this live) was enough to flag them, since a
single moderately-weighted signal (weight 0.4, below every other signal's
weight) could tip a borderline-legitimate model verdict with nothing else
corroborating it. Fixed (DEC-034): the two freshness axes
(``fresh_and_free_ca``, ``fresh_cert_only``) now also require the domain
itself to look genuinely new — either the shared feature pipeline's own
WHOIS-derived ``is_recently_registered`` (``src.features.domain_intel``,
reused here rather than making a second WHOIS call), or an already-triggered
brand-identity signal (``brand_mismatch``/``credential_context``) passed in
as a corroborator. ``hostname_mismatch`` is unaffected — an actual
CN/SAN-vs-visited-hostname mismatch is strong, specific evidence regardless
of domain age.
"""

from __future__ import annotations

import logging
import time
from datetime import datetime, timezone
from typing import TYPE_CHECKING, Any, Optional

from src.detection.types import RiskSignal
from src.utils.domains import registered_domain

if TYPE_CHECKING:
    from src.detection.brand_reference import BrandIndex
    from src.features.page_artifacts import PageArtifacts

logger = logging.getLogger(__name__)

_SIGNAL_NAME = "cert_intel"

# ssl.getpeercert()'s notBefore/notAfter format, e.g. "May 31 21:39:12 2026 GMT".
_CERT_DATE_FORMAT = "%b %d %H:%M:%S %Y %Z"

_FRESH_CERT_DAYS = 7

# CAs offering free, instant (often fully automated, no identity vetting)
# issuance -- heavily used by both legitimate sites AND phishing kits, so
# this is informational/contributing evidence, never scored alone.
_FREE_INSTANT_CAS: tuple[str, ...] = ("let's encrypt", "zerossl", "buypass")

_AXIS_WEIGHTS: dict[str, float] = {
    "fresh_and_free_ca": 0.55,
    "fresh_cert_only": 0.35,
    "hostname_mismatch": 0.6,
}


def _elapsed(start: float) -> float:
    return round((time.perf_counter() - start) * 1000, 3)


def _neutral(start: float) -> RiskSignal:
    return RiskSignal(
        name=_SIGNAL_NAME, triggered=False, score=0.0, direction="neutral",
        evidence={}, latency_ms=_elapsed(start),
    )


def _parse_cert_date(value: Optional[str]) -> Optional[datetime]:
    if not value:
        return None
    try:
        return datetime.strptime(value, _CERT_DATE_FORMAT).replace(tzinfo=timezone.utc)
    except ValueError:
        return None


def _issuer_org(cert: dict[str, Any]) -> str:
    issuer = cert.get("issuer") or ()
    for rdn in issuer:
        for key, value in rdn:
            if key == "organizationName":
                return str(value)
    return ""


def _hostname_covered(hostname: str, cert: dict[str, Any]) -> bool:
    """Whether ``hostname`` matches the cert's CN or any SAN entry
    (exact match or one level of wildcard) -- a coarse, best-effort check;
    real verification already happened during the TLS handshake itself."""
    if not hostname:
        return True  # nothing to check against -> don't flag
    hostname = hostname.lower()
    candidates: set[str] = set(cert.get("san") or [])
    subject = cert.get("subject") or ()
    for rdn in subject:
        for key, value in rdn:
            if key == "commonName":
                candidates.add(str(value).lower())
    for candidate in candidates:
        candidate = candidate.lower()
        if candidate == hostname:
            return True
        if candidate.startswith("*.") and hostname.endswith(candidate[1:]):
            return True
    return False


def evaluate(
    page_artifacts: Optional["PageArtifacts"],
    visited_url: str,
    brand_index: "BrandIndex",
    html_features: Optional[dict[str, Any]] = None,
    corroborators: Optional[list[RiskSignal]] = None,
) -> RiskSignal:
    """Evaluate the TLS certificate captured for the visited page.

    Args:
        page_artifacts: The shared fetch context. Returns neutral if
            ``None`` or no certificate was captured (HTTP page, extraction
            failed, etc).
        visited_url: The URL actually being evaluated.
        brand_index: Unused directly (kept for signature parity with the
            other signals / future brand-in-SAN analysis).
        html_features: The live-extractor's feature dict, used only for its
            WHOIS-derived ``is_recently_registered`` key (from
            ``src.features.domain_intel``, already computed once for the
            whole request — this signal makes no extra WHOIS call). ``None``
            or a missing key is treated as "not recently registered".
        corroborators: Other already-evaluated signals (in practice
            ``brand_mismatch``/``credential_context``). If any of these is
            ``triggered``, that stands in for domain-age corroboration too
            (DEC-034) — see module docstring.

    Returns:
        A :class:`RiskSignal`; never raises.
    """
    del brand_index  # reserved for a future brand-in-SAN heuristic
    start = time.perf_counter()
    try:
        if page_artifacts is None or not page_artifacts.tls_cert:
            return _neutral(start)

        cert = page_artifacts.tls_cert
        not_before = _parse_cert_date(cert.get("not_before"))
        issuer_org = _issuer_org(cert)
        is_free_ca = any(ca in issuer_org.lower() for ca in _FREE_INSTANT_CAS)

        cert_age_days: Optional[int] = None
        is_fresh = False
        if not_before is not None:
            cert_age_days = (datetime.now(timezone.utc) - not_before).days
            is_fresh = cert_age_days < _FRESH_CERT_DAYS

        # The cert was captured on the FINAL hop of the redirect chain (see
        # PageArtifacts.fetch: tls_cert is set from the response that also
        # sets final_url), so it must be checked against the hostname the
        # TLS handshake actually ran against (SNI) -- not the originally
        # -requested `visited_url`. Those two differ whenever a redirect
        # crosses hosts, e.g. https://mail.google.com/... unauthenticated ->
        # 302 -> https://accounts.google.com/ServiceLogin: the peer cert is
        # genuinely scoped to accounts.google.com only (SAN does not include
        # mail.google.com), so comparing it against the pre-redirect
        # hostname produced a spurious hostname_mismatch on a legitimate
        # same-provider redirect. Every other page-dependent signal already
        # falls back to final_url for the same reason (favicon_match,
        # brand_mismatch, redirect_chain); cert_intel is the one signal
        # where the final hop is authoritative, not just a fallback, since
        # the cert was quite literally never issued for the pre-redirect host.
        effective_url = page_artifacts.final_url or visited_url
        hostname = registered_domain(effective_url) or ""
        parsed_host = ""
        try:
            from urllib.parse import urlparse

            parsed_host = (urlparse(effective_url).hostname or "").lower()
        except Exception:  # noqa: BLE001
            pass
        effective_hostname = parsed_host or hostname
        covered = _hostname_covered(effective_hostname, cert)
        logger.debug(
            "cert_intel hostname check: visited=%r final=%r effective_hostname=%r "
            "san=%r covered=%s",
            visited_url, page_artifacts.final_url, effective_hostname,
            cert.get("san"), covered,
        )

        is_recently_registered = bool((html_features or {}).get("is_recently_registered"))
        has_corroborating_signal = any(s.triggered for s in (corroborators or []))
        domain_age_corroborated = is_recently_registered or has_corroborating_signal

        axes_triggered: list[str] = []
        score = 0.0

        if not covered:
            axes_triggered.append("hostname_mismatch")
            score += _AXIS_WEIGHTS["hostname_mismatch"]
        elif is_fresh and is_free_ca and domain_age_corroborated:
            axes_triggered.append("fresh_and_free_ca")
            score += _AXIS_WEIGHTS["fresh_and_free_ca"]
        elif is_fresh and domain_age_corroborated:
            axes_triggered.append("fresh_cert_only")
            score += _AXIS_WEIGHTS["fresh_cert_only"]

        if not axes_triggered:
            return _neutral(start)

        return RiskSignal(
            name=_SIGNAL_NAME, triggered=True, score=round(min(score, 1.0), 4),
            direction="phishing",
            evidence={
                "cert_age_days": cert_age_days,
                "issuer_org": issuer_org or "unknown",
                "is_free_ca": is_free_ca,
                "hostname_covered": covered,
                "effective_hostname": effective_hostname,
                "axes_triggered": axes_triggered,
                "domain_recently_registered": is_recently_registered,
                "corroborated_by_other_signal": has_corroborating_signal,
            },
            latency_ms=_elapsed(start),
        )
    except Exception as exc:  # noqa: BLE001 - Iron Law #3
        logger.warning("cert_intel signal failed for %r: %s", visited_url, exc)
        return _neutral(start)
