"""API key generation and verification (Phase 2, C3).

Key format: ``argus_<43 url-safe base64 chars>`` (32 random bytes). The
raw key is shown to the caller exactly once (at mint time) and never
stored — only its SHA-256 hash (reusing
``src.api.auth.utils.hash_token``, the same function already used for
refresh tokens) is persisted, mirroring the project's established
hashed-token-at-rest convention.
"""

from __future__ import annotations

import secrets

from src.api.auth.utils import hash_token

_KEY_PREFIX = "argus_"
_KEY_RANDOM_BYTES = 32
_DISPLAY_PREFIX_CHARS = 10  # "argus_" + 4 chars of the random portion


def generate_api_key() -> tuple[str, str, str]:
    """Generate a new raw API key.

    Returns:
        A tuple ``(raw_key, key_hash, key_prefix)``:
            * ``raw_key`` — shown to the caller once, never stored.
            * ``key_hash`` — SHA-256 hex digest, stored in ``ApiKey.key_hash``.
            * ``key_prefix`` — non-secret display prefix (e.g.
              ``"argus_9fJ2"``), stored in ``ApiKey.key_prefix`` for the
              caller to recognize their key in a list without the raw
              value ever being retrievable again.
    """
    raw_key = _KEY_PREFIX + secrets.token_urlsafe(_KEY_RANDOM_BYTES)
    return raw_key, hash_token(raw_key), raw_key[:_DISPLAY_PREFIX_CHARS]


def hash_api_key(raw_key: str) -> str:
    """Hash a presented raw API key for lookup (same hash as at mint time)."""
    return hash_token(raw_key)


def extract_bearer_key(authorization_header: str | None) -> str | None:
    """Extract the raw key from an ``Authorization: Bearer <key>`` header.

    Args:
        authorization_header: The raw ``Authorization`` header value, or
            ``None`` if absent.

    Returns:
        The raw key string, or ``None`` if the header is missing or
        malformed.
    """
    if not authorization_header:
        return None
    parts = authorization_header.split(" ", 1)
    if len(parts) != 2 or parts[0].lower() != "bearer":
        return None
    key = parts[1].strip()
    return key or None
