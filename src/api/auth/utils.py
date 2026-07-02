"""Auth crypto/token helpers (Phase 8, Task 8.1).

Every security-sensitive primitive lives here so routes.py stays readable
and there's exactly one place to audit for each requirement:
    * S6 — SECRET_KEY fail-closed: :func:`get_secret_key`
    * Argon2id password hashing: :func:`hash_password` / :func:`verify_password`
    * 15-min HS256 access tokens: :func:`generate_access_token` / :func:`decode_access_token`
    * Opaque, hashed-at-rest refresh tokens: :func:`generate_refresh_token` / :func:`hash_token`
    * OTP generation/hashing (S4/S5 support): :func:`generate_otp` / :func:`hash_otp`
"""

from __future__ import annotations

import hashlib
import hmac
import os
import secrets
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any, Optional

import jwt
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError

ACCESS_TOKEN_EXPIRY_MINUTES = 15
REFRESH_TOKEN_EXPIRY_DAYS = 30
OTP_EXPIRY_MINUTES = 10
OTP_MAX_ATTEMPTS = 5
OTP_LOCKOUT_MINUTES = 15
JWT_ALGORITHM = "HS256"

_password_hasher = PasswordHasher()


def get_secret_key() -> str:
    """Read SECRET_KEY from the environment, failing closed if unset (S6).

    Returns:
        The configured secret key.

    Raises:
        RuntimeError: If the ``SECRET_KEY`` environment variable is not set.
            The app must refuse to start rather than fall back to a default —
            a hardcoded/default secret would let anyone forge access tokens.
    """
    secret_key = os.environ.get("SECRET_KEY")
    if not secret_key:
        raise RuntimeError("SECRET_KEY env var not set — refusing to start")
    return secret_key


def hash_password(password: str) -> str:
    """Hash a password with Argon2id.

    Args:
        password: The plaintext password.

    Returns:
        The Argon2id hash string (includes algorithm params + salt).
    """
    return _password_hasher.hash(password)


def verify_password(password_hash: str, password: str) -> bool:
    """Verify a plaintext password against an Argon2id hash.

    Args:
        password_hash: The stored hash.
        password: The plaintext password to check.

    Returns:
        ``True`` if it matches, ``False`` otherwise (never raises on mismatch).
    """
    try:
        return _password_hasher.verify(password_hash, password)
    except VerifyMismatchError:
        return False
    except Exception:  # noqa: BLE001 - malformed hash, wrong version, etc. -> just "no match"
        return False


def dummy_password_hash() -> str:
    """A fixed, valid Argon2id hash with no real password behind it.

    Used to run a full Argon2 verify (and pay its full time cost) when a
    login is attempted against a non-existent email, so response timing
    doesn't reveal whether the account exists.
    """
    return "$argon2id$v=19$m=65536,t=3,p=4$c29tZXNhbHQxMjM0NTY$Tnnq0AflBnKQ6QK6uNoHKQ"


def generate_access_token(user_id: int, secret_key: str) -> str:
    """Issue a short-lived JWT access token.

    Args:
        user_id: The authenticated user's ID.
        secret_key: The app's SECRET_KEY (see :func:`get_secret_key`).

    Returns:
        A signed JWT, expiring in :data:`ACCESS_TOKEN_EXPIRY_MINUTES`. Includes
        a random ``jti`` so two tokens issued for the same user within the
        same second (``iat`` has 1-second resolution) are still distinct
        strings, not just distinct in theory.
    """
    now = datetime.now(timezone.utc)
    payload = {
        "sub": str(user_id),
        "jti": secrets.token_hex(8),
        "iat": now,
        "exp": now + timedelta(minutes=ACCESS_TOKEN_EXPIRY_MINUTES),
    }
    return jwt.encode(payload, secret_key, algorithm=JWT_ALGORITHM)


def decode_access_token(token: str, secret_key: str) -> dict[str, Any]:
    """Decode and verify an access token.

    Args:
        token: The JWT to decode.
        secret_key: The app's SECRET_KEY.

    Returns:
        The decoded payload (contains ``sub`` = user ID as a string).

    Raises:
        jwt.PyJWTError: If the token is invalid, expired, or malformed.
    """
    return jwt.decode(token, secret_key, algorithms=[JWT_ALGORITHM])


def generate_refresh_token() -> str:
    """Generate a new opaque refresh token (not a JWT — random bytes only).

    Returns:
        A URL-safe random token. The caller stores only its hash (see
        :func:`hash_token`) and returns this raw value to the client once.
    """
    return secrets.token_urlsafe(32)


def hash_token(raw_token: str) -> str:
    """Hash an opaque token for at-rest storage/lookup.

    Args:
        raw_token: The raw token value.

    Returns:
        A SHA-256 hex digest. Refresh tokens are high-entropy random values
        (not low-entropy secrets like passwords), so a fast hash is
        appropriate here — the security property needed is "DB leak alone
        doesn't yield a usable token," not resistance to offline guessing.
    """
    return hashlib.sha256(raw_token.encode("utf-8")).hexdigest()


def new_token_family_id() -> str:
    """Generate a new refresh-token rotation family ID."""
    return uuid.uuid4().hex


def generate_otp() -> str:
    """Generate a 6-digit OTP code.

    Returns:
        A 6-character numeric string, e.g. ``"042817"`` (zero-padded).
    """
    return f"{secrets.randbelow(1_000_000):06d}"


def hash_otp(code: str, secret_key: str) -> str:
    """Hash an OTP code, keyed by SECRET_KEY.

    Args:
        code: The plaintext 6-digit OTP.
        secret_key: The app's SECRET_KEY, used as an HMAC key so a DB leak
            alone isn't sufficient to brute-force stored OTP hashes (the
            keyspace is small — 6 digits — so hash *strength* isn't the real
            defense; rate-limiting/lockout, S4, is. This is defense in depth.).

    Returns:
        An HMAC-SHA256 hex digest.
    """
    return hmac.new(secret_key.encode("utf-8"), code.encode("utf-8"), hashlib.sha256).hexdigest()


def as_aware_utc(value: Optional[datetime]) -> Optional[datetime]:
    """Normalize a datetime read back from the DB to timezone-aware UTC.

    SQLite does not actually preserve timezone info through a round-trip
    even for columns declared ``DateTime(timezone=True)`` — values come back
    naive. Every datetime written here is UTC by construction (see
    ``_utcnow()`` in models.py), so a naive value read back is always UTC;
    this just makes that explicit before comparing against
    ``datetime.now(timezone.utc)``, which would otherwise raise
    ``TypeError: can't compare offset-naive and offset-aware datetimes``.

    Args:
        value: A datetime that may or may not carry tzinfo, or ``None``.

    Returns:
        The same instant with UTC tzinfo attached, or ``None`` if ``value`` is ``None``.
    """
    if value is None:
        return None
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value
