"""``/auth/*`` routes (Phase 8, Tasks 8.1 + 8.2).

signup -> verify-otp -> login -> refresh -> logout. Security requirements
implemented here, cross-referenced to the Interim Report's numbering:

    S2  Logout revokes the refresh token.
    S3  Refresh-token reuse (a used/revoked token presented again) revokes
        the entire rotation family — a strong signal of token theft.
    S4  OTP verification: max 5 attempts, then a 15-minute lockout.
    S5  The OTP *value* is never logged — only the event.
    S6  Enforced upstream, in utils.get_secret_key() / app.py at startup.
    Enumeration resistance: signup and login return the same generic
        response/timing regardless of whether the email exists.
"""

from __future__ import annotations

import logging
from datetime import datetime, timedelta, timezone

from flask import Blueprint, current_app, jsonify, request
from marshmallow import Schema, ValidationError, fields, validate
from sqlalchemy import select

from src.api.auth.models import Otp, RefreshToken, User
from src.api.auth.utils import (
    OTP_EXPIRY_MINUTES,
    OTP_LOCKOUT_MINUTES,
    OTP_MAX_ATTEMPTS,
    REFRESH_TOKEN_EXPIRY_DAYS,
    as_aware_utc,
    dummy_password_hash,
    generate_access_token,
    generate_otp,
    generate_refresh_token,
    hash_otp,
    hash_password,
    hash_token,
    new_token_family_id,
    verify_password,
)
from src.api.route_utils import db_session, error

logger = logging.getLogger(__name__)

auth_bp = Blueprint("auth", __name__, url_prefix="/auth")

_GENERIC_SIGNUP_MESSAGE = "If that email can be registered, a verification code has been sent."
_GENERIC_LOGIN_ERROR = "Invalid email or password."
_GENERIC_OTP_ERROR = "Invalid or expired verification code."


class SignupSchema(Schema):
    email = fields.Email(required=True)
    password = fields.Str(required=True, validate=validate.Length(min=8))


class VerifyOtpSchema(Schema):
    email = fields.Email(required=True)
    otp = fields.Str(required=True, validate=validate.Length(equal=6))


class LoginSchema(Schema):
    email = fields.Email(required=True)
    password = fields.Str(required=True)


class RefreshSchema(Schema):
    refresh_token = fields.Str(required=True)


class LogoutSchema(Schema):
    refresh_token = fields.Str(required=True)


def _secret_key() -> str:
    return current_app.extensions["argus_auth"]["secret_key"]


def _issue_token_pair(session, user: User, family_id: str) -> dict:
    """Issue a fresh access + refresh token pair for a user.

    Args:
        session: An open SQLAlchemy session (caller commits).
        user: The user to issue tokens for.
        family_id: The rotation family this refresh token belongs to — a
            fresh UUID for a new login, or the prior token's family_id when
            rotating during /refresh.

    Returns:
        ``{"access_token": ..., "refresh_token": ..., "expires_in": 900}``
    """
    access_token = generate_access_token(user.id, _secret_key())
    raw_refresh = generate_refresh_token()
    now = datetime.now(timezone.utc)
    session.add(
        RefreshToken(
            user_id=user.id,
            token_hash=hash_token(raw_refresh),
            family_id=family_id,
            expires_at=now + timedelta(days=REFRESH_TOKEN_EXPIRY_DAYS),
        )
    )
    return {
        "access_token": access_token,
        "refresh_token": raw_refresh,
        "expires_in": 900,
    }


@auth_bp.post("/signup")
def signup():
    body = request.get_json(silent=True) or {}
    try:
        data = SignupSchema().load(body)
    except ValidationError as exc:
        return error(f"invalid request: {exc.messages}", 400)

    session = db_session()
    try:
        existing = session.scalar(select(User).where(User.email == data["email"]))

        if existing is not None and existing.email_verified:
            # Account already exists and is verified: do NOT overwrite its
            # password or reissue an OTP (that would be an account-takeover
            # vector). Respond identically to the success path regardless.
            logger.info("Signup attempted for an already-verified account")
            return jsonify(message=_GENERIC_SIGNUP_MESSAGE), 200

        if existing is not None and not existing.email_verified:
            # Abandoned signup — allow a fresh OTP without disturbing state
            # beyond the password (a resend-style retry) -- UNLESS the
            # account is currently serving an S4 lockout from an earlier
            # code. verify_otp() only ever checks the newest non-consumed
            # row, so minting a fresh, unlocked row here would silently
            # reset the lockout counter and defeat S4 entirely (see
            # DEC-024): an attacker could burn 5 guesses, resend signup for
            # a clean row, and repeat indefinitely.
            existing.password_hash = hash_password(data["password"])
            user = existing

            now = datetime.now(timezone.utc)
            active_otp = session.scalar(
                select(Otp)
                .where(Otp.user_id == user.id, Otp.consumed.is_(False))
                .order_by(Otp.created_at.desc())
            )
            if (
                active_otp is not None
                and active_otp.locked_until is not None
                and as_aware_utc(active_otp.locked_until) > now
            ):
                session.commit()
                logger.info(
                    "Signup resend blocked for user_id=%s: OTP lockout still active", user.id
                )
                return jsonify(message=_GENERIC_SIGNUP_MESSAGE), 200
        else:
            user = User(email=data["email"], password_hash=hash_password(data["password"]))
            session.add(user)
            session.flush()  # populate user.id

        otp_code = generate_otp()
        session.add(
            Otp(
                user_id=user.id,
                code_hash=hash_otp(otp_code, _secret_key()),
                expires_at=datetime.now(timezone.utc) + timedelta(minutes=OTP_EXPIRY_MINUTES),
            )
        )
        session.commit()

        # S5: log the event, never the OTP value.
        logger.info("OTP issued for user_id=%s", user.id)
        # Dev-mode-only: no email backend is configured, so there is no way
        # to deliver the OTP out of band. Returning it in the response is
        # explicitly a development convenience, gated off by default — see
        # app.py's `AUTH_DEV_RETURN_OTP` config flag and DEC-021.
        response = {"message": _GENERIC_SIGNUP_MESSAGE}
        if current_app.config.get("AUTH_DEV_RETURN_OTP"):
            response["dev_otp"] = otp_code
        return jsonify(**response), 200
    finally:
        session.close()


@auth_bp.post("/verify-otp")
def verify_otp():
    body = request.get_json(silent=True) or {}
    try:
        data = VerifyOtpSchema().load(body)
    except ValidationError as exc:
        return error(f"invalid request: {exc.messages}", 400)

    session = db_session()
    try:
        user = session.scalar(select(User).where(User.email == data["email"]))
        if user is None:
            logger.info("OTP verification attempted for unknown email")
            return error(_GENERIC_OTP_ERROR, 400)

        otp = session.scalar(
            select(Otp)
            .where(Otp.user_id == user.id, Otp.consumed.is_(False))
            .order_by(Otp.created_at.desc())
        )
        now = datetime.now(timezone.utc)

        if otp is None or as_aware_utc(otp.expires_at) < now:
            logger.info("OTP verification failed for user_id=%s: no active code", user.id)
            return error(_GENERIC_OTP_ERROR, 400)

        if otp.locked_until is not None and as_aware_utc(otp.locked_until) > now:
            logger.info("OTP verification blocked for user_id=%s: locked out", user.id)
            return error(_GENERIC_OTP_ERROR, 429)

        if otp.code_hash != hash_otp(data["otp"], _secret_key()):
            otp.attempts += 1
            if otp.attempts >= OTP_MAX_ATTEMPTS:
                otp.locked_until = now + timedelta(minutes=OTP_LOCKOUT_MINUTES)
                logger.info(
                    "OTP verification failed for user_id=%s: attempt %d/%d, now locked out",
                    user.id, otp.attempts, OTP_MAX_ATTEMPTS,
                )
            else:
                logger.info(
                    "OTP verification failed for user_id=%s: attempt %d/%d",
                    user.id, otp.attempts, OTP_MAX_ATTEMPTS,
                )
            session.commit()
            return error(_GENERIC_OTP_ERROR, 400)

        otp.consumed = True
        user.email_verified = True
        session.commit()
        logger.info("OTP verification succeeded for user_id=%s", user.id)
        return jsonify(message="Email verified. You can now log in."), 200
    finally:
        session.close()


@auth_bp.post("/login")
def login():
    body = request.get_json(silent=True) or {}
    try:
        data = LoginSchema().load(body)
    except ValidationError as exc:
        return error(f"invalid request: {exc.messages}", 400)

    session = db_session()
    try:
        user = session.scalar(select(User).where(User.email == data["email"]))

        if user is None:
            # Run a real Argon2 verify against a dummy hash so response
            # timing doesn't reveal whether the account exists.
            verify_password(dummy_password_hash(), data["password"])
            return error(_GENERIC_LOGIN_ERROR, 401)

        if not verify_password(user.password_hash, data["password"]):
            return error(_GENERIC_LOGIN_ERROR, 401)

        if not user.email_verified:
            return error(_GENERIC_LOGIN_ERROR, 401)

        tokens = _issue_token_pair(session, user, new_token_family_id())
        session.commit()
        logger.info("Login succeeded for user_id=%s", user.id)
        return jsonify(**tokens), 200
    finally:
        session.close()


@auth_bp.post("/refresh")
def refresh():
    body = request.get_json(silent=True) or {}
    try:
        data = RefreshSchema().load(body)
    except ValidationError as exc:
        return error(f"invalid request: {exc.messages}", 400)

    session = db_session()
    try:
        token_hash = hash_token(data["refresh_token"])
        token_row = session.scalar(select(RefreshToken).where(RefreshToken.token_hash == token_hash))

        if token_row is None:
            return error("invalid refresh token", 401)

        now = datetime.now(timezone.utc)
        expires_at = as_aware_utc(token_row.expires_at)

        if token_row.is_used or token_row.is_revoked:
            # S3: reuse of an already-rotated (or revoked) token is a strong
            # signal of theft -- revoke the entire family, not just this token.
            family_tokens = session.scalars(
                select(RefreshToken).where(RefreshToken.family_id == token_row.family_id)
            ).all()
            for t in family_tokens:
                t.is_revoked = True
            session.commit()
            logger.warning(
                "Refresh token reuse detected for user_id=%s — revoked family %s",
                token_row.user_id, token_row.family_id,
            )
            return error("refresh token reuse detected — all sessions revoked", 401)

        if expires_at < now:
            return error("refresh token expired", 401)

        user = session.get(User, token_row.user_id)
        if user is None:
            return error("invalid refresh token", 401)

        token_row.is_used = True
        tokens = _issue_token_pair(session, user, token_row.family_id)
        session.commit()
        return jsonify(**tokens), 200
    finally:
        session.close()


@auth_bp.post("/logout")
def logout():
    body = request.get_json(silent=True) or {}
    try:
        data = LogoutSchema().load(body)
    except ValidationError as exc:
        return error(f"invalid request: {exc.messages}", 400)

    session = db_session()
    try:
        token_hash = hash_token(data["refresh_token"])
        token_row = session.scalar(select(RefreshToken).where(RefreshToken.token_hash == token_hash))
        # S2: revoke on logout. Idempotent — logging out an already-revoked
        # or unknown token still returns success (nothing to leak here; the
        # caller already possesses the token).
        if token_row is not None:
            token_row.is_revoked = True
            session.commit()
        return jsonify(message="Logged out."), 200
    finally:
        session.close()
