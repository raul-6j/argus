"""``/vault`` routes (Phase 8, Task 8.3) — zero-knowledge, server-authoritative versioning.

The server never decrypts ``ciphertext`` — it's an opaque blob to us (S10).
The only thing the server reasons about is ``version``, used purely for
optimistic-concurrency conflict detection between concurrent writes from
multiple devices.
"""

from __future__ import annotations

from flask import Blueprint, g, jsonify, request
from marshmallow import Schema, ValidationError, fields, validate

from src.api.auth.middleware import require_auth
from src.api.route_utils import db_session, error
from src.api.vault.models import VaultEntry

vault_bp = Blueprint("vault", __name__, url_prefix="/vault")

# Per-user cap on the stored blob. The app-wide MAX_CONTENT_LENGTH already
# bounds a single *request*, but not what accumulates in the database: without
# this, one authenticated user could keep writing near-max-size blobs and grow
# the vault table without limit (CWE-770). This is the tighter of the two
# bounds and it is the one that protects storage.
#
# 256 KiB of base64 is ~192 KiB of plaintext credentials -- far beyond any
# realistic password vault, so it is a safety ceiling rather than a functional
# limit. Enforced in the schema so an over-size write is a clean 400 naming
# the offending field, not a database error.
MAX_CIPHERTEXT_CHARS = 256 * 1024


class VaultPutSchema(Schema):
    ciphertext = fields.Str(
        required=True, validate=validate.Length(max=MAX_CIPHERTEXT_CHARS)
    )
    version = fields.Int(required=True)


@vault_bp.get("")
@require_auth
def get_vault():
    """Fetch the caller's vault blob + version. Empty vault -> version 0."""
    session = db_session()
    try:
        entry = session.get(VaultEntry, g.user_id)
        if entry is None:
            return jsonify(ciphertext=None, version=0), 200
        return jsonify(ciphertext=entry.ciphertext, version=entry.version), 200
    finally:
        session.close()


@vault_bp.put("")
@require_auth
def put_vault():
    """Write the caller's vault blob, subject to optimistic-concurrency control.

    Request: ``{"ciphertext": "<opaque blob>", "version": <int>}``
    ``version`` must equal the server's current version for this user (0 if
    no vault exists yet) — mismatch means another device wrote first, and
    the client must fetch, merge/resolve, and retry.
    """
    body = request.get_json(silent=True) or {}
    try:
        data = VaultPutSchema().load(body)
    except ValidationError as exc:
        return error(f"invalid request: {exc.messages}", 400)

    session = db_session()
    try:
        entry = session.get(VaultEntry, g.user_id)
        current_version = entry.version if entry is not None else 0

        if data["version"] != current_version:
            return error(
                "conflict: vault was updated elsewhere",
                409,
                current_version=current_version,
                current_ciphertext=entry.ciphertext if entry is not None else None,
            )

        if entry is None:
            entry = VaultEntry(user_id=g.user_id, ciphertext=data["ciphertext"], version=1)
            session.add(entry)
        else:
            entry.ciphertext = data["ciphertext"]
            entry.version = current_version + 1

        session.commit()
        return jsonify(version=entry.version), 200
    finally:
        session.close()
