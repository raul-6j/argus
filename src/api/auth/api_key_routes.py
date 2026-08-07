"""``/auth/api-keys`` blueprint (Phase 2, C3) — developer API key management.

A separate blueprint from ``src.api.auth.routes`` (kept decoupled from the
larger Phase 8 auth/OTP/token-rotation file per "avoid unnecessary
refactoring") but mounted at the same ``/auth`` prefix and reusing the same
``@require_auth`` JWT decorator — key management is a user-account concern,
authenticated the same way ``/vault`` is.

Every route is scoped to ``g.user_id`` (the JWT-verified caller), never a
client-supplied id, mirroring the vault's IDOR-safe scoping.
"""

from __future__ import annotations

import secrets
import time

from flask import Blueprint, g, jsonify

from src.api.auth.middleware import require_auth
from src.api.public.keys import generate_api_key
from src.api.public.models import ApiKey
from src.api.route_utils import db_session, error, latency_ms

auth_api_keys_bp = Blueprint("auth_api_keys", __name__, url_prefix="/auth")


@auth_api_keys_bp.post("/api-keys")
@require_auth
def create_api_key():
    """Mint a new API key for the logged-in user. The raw key -- and its
    ``webhook_secret`` (F19), used to sign async-scan-job webhook payloads --
    are shown exactly once here; neither is ever retrievable again after
    this response."""
    start = time.perf_counter()
    raw_key, key_hash, key_prefix = generate_api_key()
    webhook_secret = secrets.token_urlsafe(32)

    session = db_session()
    try:
        api_key = ApiKey(
            key_hash=key_hash,
            key_prefix=key_prefix,
            owner_user_id=g.user_id,
            tier="free",
            webhook_secret=webhook_secret,
        )
        session.add(api_key)
        session.commit()
        created_at = api_key.created_at
    finally:
        session.close()

    return (
        jsonify(
            api_key=raw_key,
            key_prefix=key_prefix,
            tier="free",
            webhook_secret=webhook_secret,
            created_at=created_at.isoformat(),
            latency_ms=latency_ms(start),
        ),
        201,
    )


@auth_api_keys_bp.get("/api-keys")
@require_auth
def list_api_keys():
    """List the caller's own keys — metadata only, never the raw value."""
    start = time.perf_counter()
    session = db_session()
    try:
        keys = session.query(ApiKey).filter_by(owner_user_id=g.user_id).all()
        payload = [
            {
                "key_prefix": k.key_prefix,
                "tier": k.tier,
                "revoked": k.revoked,
                "created_at": k.created_at.isoformat(),
                "last_used_at": k.last_used_at.isoformat() if k.last_used_at else None,
            }
            for k in keys
        ]
    finally:
        session.close()

    return jsonify(keys=payload, latency_ms=latency_ms(start))


@auth_api_keys_bp.delete("/api-keys/<key_prefix>")
@require_auth
def revoke_api_key(key_prefix: str):
    """Revoke one of the caller's own keys.

    404 (not 403) for a key that exists but belongs to someone else --
    the same "don't confirm existence to a non-owner" pattern used
    throughout the auth module, and prevents key-prefix enumeration from
    distinguishing "not yours" from "doesn't exist."
    """
    start = time.perf_counter()
    session = db_session()
    try:
        api_key = (
            session.query(ApiKey)
            .filter_by(key_prefix=key_prefix, owner_user_id=g.user_id)
            .one_or_none()
        )
        if api_key is None:
            return error("API key not found", 404)

        api_key.revoked = True
        session.commit()
    finally:
        session.close()

    return jsonify(revoked=True, latency_ms=latency_ms(start))
