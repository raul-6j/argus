"""ARGUS developer API — thin Python client (Phase 2, C3).

A minimal wrapper over ``/v1/*``. No dependencies beyond ``requests``
(already a project dependency). Not published as a package; copy this
file into your project, or vendor it as-is.

Usage:
    from argus_client import ArgusClient

    client = ArgusClient(api_key="argus_...", base_url="https://argus.example.com")
    result = client.scan("https://example.com")
    print(result["label"], result["confidence"])

    results = client.scan_batch(["https://a.com", "https://b.com"])
    explanation = client.explain("https://example.com")
"""

from __future__ import annotations

from typing import Any, Optional

import requests

_DEFAULT_TIMEOUT_S = 30.0


class ArgusApiError(Exception):
    """Raised for any non-2xx response from the ARGUS API."""

    def __init__(self, status_code: int, message: str):
        super().__init__(f"ARGUS API error {status_code}: {message}")
        self.status_code = status_code
        self.message = message


class ArgusClient:
    """A thin, synchronous client for ARGUS's ``/v1/*`` developer API."""

    def __init__(self, api_key: str, base_url: str = "https://api.argus.example.com", timeout: float = _DEFAULT_TIMEOUT_S):
        """
        Args:
            api_key: Your ARGUS API key (``argus_...``), minted via
                ``POST /auth/api-keys`` while logged in.
            base_url: The ARGUS API's base URL, no trailing slash.
            timeout: Per-request timeout in seconds.
        """
        self._api_key = api_key
        self._base_url = base_url.rstrip("/")
        self._timeout = timeout

    def _request(self, method: str, path: str, **kwargs: Any) -> dict[str, Any]:
        response = requests.request(
            method,
            f"{self._base_url}{path}",
            headers={"Authorization": f"Bearer {self._api_key}", "Content-Type": "application/json"},
            timeout=self._timeout,
            **kwargs,
        )
        body = response.json() if response.content else {}
        if not response.ok:
            raise ArgusApiError(response.status_code, body.get("error", "unknown error"))
        return body

    def scan(self, url: str, enrich: bool = False) -> dict[str, Any]:
        """Scan a single URL. Set ``enrich=True`` to run the full detection
        fusion layer (brand/favicon/cert/redirect signals) -- slower, but
        much more likely to catch a brand-impersonation phishing page."""
        return self._request("POST", "/v1/scan", json={"url": url, "enrich": enrich})

    def scan_batch(self, urls: list[str], enrich: bool = False) -> list[dict[str, Any]]:
        """Scan up to 50 URLs in one call. Each URL counts individually
        against your per-key rate limit. A malformed URL in the batch
        yields a per-item ``{"url": ..., "error": ...}`` entry rather than
        failing the whole request."""
        body = self._request("POST", "/v1/scan/batch", json={"urls": urls, "enrich": enrich})
        return body["results"]

    def explain(self, url: str) -> dict[str, Any]:
        """Full explanation for a URL: SHAP top-5 features, triggered
        detection signals, and a plain-language summary sentence."""
        return self._request("POST", "/v1/explain", json={"url": url})

    def health(self) -> dict[str, Any]:
        """Public liveness/version probe. Does not require an API key."""
        response = requests.get(f"{self._base_url}/v1/health", timeout=self._timeout)
        return response.json()
