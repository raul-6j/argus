"""Shared single-fetch page context for detection signals (Phase 1, P1.0).

Several Phase-1 detection signals (favicon matching, brand-vs-domain
mismatch) need artifacts from the *same* fetched page — the raw HTML, the
post-redirect final URL, and the redirect chain. This module fetches once
and returns all of it, so an enriched ``/detect``/``/explain`` call does not
turn into several outbound fetches of the same untrusted page: the caller
fetches via :func:`fetch`, then passes ``.html`` straight into
:func:`src.features.pipeline.extract_features` (which already accepts a
pre-fetched ``html=`` argument and skips its own fetch), and passes the
whole :class:`PageArtifacts` object into the detection signals.

Deliberately independent of ``src.features.pipeline``'s existing
``_fetch_html`` (left untouched, with its own tests, per the project's
"avoid unnecessary refactoring" convention) — this module mirrors the same
SSRF/timeout/size-cap bounds but additionally records the redirect chain,
final URL, status code, and response headers that ``_fetch_html`` discards.
"""

from __future__ import annotations

import logging
import time
from concurrent.futures import TimeoutError as FuturesTimeoutError
from dataclasses import dataclass, field
from typing import Any, Optional
from urllib.parse import urljoin

from src.utils.ssrf import is_safe_fetch_url
from src.utils.timeout import call_with_timeout

logger = logging.getLogger(__name__)

FETCH_TIMEOUT: float = 5.0
FETCH_HEADERS: dict[str, str] = {"User-Agent": "ARGUS-FeatureBot/0.1 (+phishing-detection)"}
MAX_BODY_BYTES: int = 5 * 1024 * 1024  # 5 MiB, matches pipeline.py's cap
MAX_REDIRECTS: int = 3


@dataclass
class PageArtifacts:
    """Everything captured from one SSRF-guarded fetch of a page.

    Attributes:
        requested_url: The URL that was asked for.
        final_url: The URL actually served content (after following any
            redirects), or ``None`` if the fetch never succeeded.
        redirect_chain: Every hop visited before ``final_url``, in order.
        status_code: The final response's HTTP status code, or ``None``.
        html: The decoded response body, or ``None`` on any failure.
        response_headers: The final response's headers.
        tls_cert: Reserved for Phase 2 (A4, certificate intelligence) — not
            populated in Phase 1.
        fetch_error: A short, human-readable reason the fetch did not fully
            succeed, or ``None`` if it did.
        fetch_time_ms: Wall-clock time the fetch took.
    """

    requested_url: str
    final_url: Optional[str] = None
    redirect_chain: list[str] = field(default_factory=list)
    status_code: Optional[int] = None
    html: Optional[str] = None
    response_headers: dict[str, str] = field(default_factory=dict)
    tls_cert: Optional[dict[str, Any]] = None
    fetch_error: Optional[str] = None
    fetch_time_ms: float = 0.0

    @property
    def ok(self) -> bool:
        """Whether HTML was actually retrieved."""
        return self.html is not None and self.fetch_error is None


def _read_capped_body(response: Any) -> Optional[str]:
    """Read a streamed response body up to :data:`MAX_BODY_BYTES`."""
    total = 0
    chunks: list[bytes] = []
    for chunk in response.iter_content(chunk_size=8192):
        if not chunk:
            continue
        total += len(chunk)
        if total > MAX_BODY_BYTES:
            logger.warning("Response body exceeded %d bytes; aborting", MAX_BODY_BYTES)
            return None
        chunks.append(chunk)
    encoding = response.encoding or "utf-8"
    return b"".join(chunks).decode(encoding, errors="replace")


def _extract_tls_cert(response: Any) -> Optional[dict[str, Any]]:
    """Pull the peer TLS certificate off an already-open ``requests``
    connection (Phase 2, A4) — no second connection/handshake needed.

    ``requests`` doesn't expose the peer certificate through its public
    API, but the underlying ``urllib3`` connection's raw ``ssl.SSLSocket``
    is reachable via ``response.raw.connection.sock`` while the connection
    is still open (i.e. before the caller closes ``response``). This is a
    best-effort extraction — a non-HTTPS response, an already-closed
    connection, or a urllib3 internal-attribute change all degrade to
    ``None`` rather than raising (Iron Law #3).

    Args:
        response: An open ``requests`` streaming response.

    Returns:
        ``{"subject": ..., "issuer": ..., "not_before": ..., "not_after":
        ..., "san": [...]}`` (raw ``ssl.getpeercert()`` shape, lightly
        flattened), or ``None`` if unavailable.
    """
    try:
        sock = response.raw.connection.sock
        cert = sock.getpeercert()
        if not cert:
            return None
        return {
            "subject": cert.get("subject"),
            "issuer": cert.get("issuer"),
            "not_before": cert.get("notBefore"),
            "not_after": cert.get("notAfter"),
            "san": [v for k, v in cert.get("subjectAltName", ()) if k == "DNS"],
        }
    except Exception as exc:  # noqa: BLE001 - best-effort only
        logger.debug("TLS cert extraction unavailable: %s", exc)
        return None


def _fetch_once(url: str) -> Any:
    """Issue a single non-redirecting streamed GET. Returns the response."""
    import requests

    return requests.get(
        url,
        timeout=FETCH_TIMEOUT,
        headers=FETCH_HEADERS,
        allow_redirects=False,
        stream=True,
    )


def fetch(url: str) -> PageArtifacts:
    """Fetch a page once, recording the redirect chain, final URL, and body.

    Never raises (Iron Law #3) — any failure is recorded in
    ``artifacts.fetch_error`` with ``html`` left ``None``. Each hop is
    independently SSRF-validated before connecting (SSRF via open
    redirect), exactly like ``src.features.pipeline._fetch_html``.

    Args:
        url: The (untrusted) URL to fetch.

    Returns:
        A populated :class:`PageArtifacts`.
    """
    start = time.perf_counter()
    artifacts = PageArtifacts(requested_url=url)
    current = url
    try:
        for _ in range(MAX_REDIRECTS + 1):
            if not is_safe_fetch_url(current):
                artifacts.fetch_error = f"refused unsafe URL: {current}"
                logger.warning("PageArtifacts fetch refused for unsafe URL: %r", current)
                return artifacts

            response = call_with_timeout(_fetch_once, FETCH_TIMEOUT, current)
            try:
                artifacts.status_code = response.status_code
                if response.status_code in (301, 302, 303, 307, 308):
                    location = response.headers.get("Location")
                    if not location:
                        artifacts.fetch_error = "redirect with no Location header"
                        return artifacts
                    artifacts.redirect_chain.append(current)
                    current = urljoin(current, location)
                    continue

                response.raise_for_status()
                artifacts.final_url = current
                artifacts.response_headers = dict(response.headers)
                artifacts.tls_cert = _extract_tls_cert(response)
                artifacts.html = _read_capped_body(response)
                if artifacts.html is None:
                    artifacts.fetch_error = "response body exceeded size cap"
                return artifacts
            finally:
                response.close()

        artifacts.fetch_error = "too many redirects"
        return artifacts
    except FuturesTimeoutError:
        artifacts.fetch_error = "fetch timed out"
        logger.warning("PageArtifacts fetch timed out for %r", url)
        return artifacts
    except Exception as exc:  # noqa: BLE001 - dead URLs are expected, never crash
        artifacts.fetch_error = str(exc)
        logger.warning("PageArtifacts fetch failed for %r: %s", url, exc)
        return artifacts
    finally:
        artifacts.fetch_time_ms = round((time.perf_counter() - start) * 1000, 3)
