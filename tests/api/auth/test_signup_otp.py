"""Tests for POST /auth/signup and POST /auth/verify-otp (Task 8.1 + 8.2)."""

from __future__ import annotations

import logging

from src.api.auth.utils import OTP_MAX_ATTEMPTS


def _signup(client, email="alice@example.com", password="correct-horse-1"):
    return client.post("/auth/signup", json={"email": email, "password": password})


def test_signup_returns_generic_message(client):
    resp = _signup(client)
    assert resp.status_code == 200
    assert "message" in resp.get_json()


def test_signup_dev_otp_present_when_flagged(client):
    """Test app config sets auth_dev_return_otp=True (see conftest.py)."""
    resp = _signup(client)
    assert "dev_otp" in resp.get_json()
    assert len(resp.get_json()["dev_otp"]) == 6


def test_signup_invalid_email_400(client):
    resp = client.post("/auth/signup", json={"email": "not-an-email", "password": "longenough1"})
    assert resp.status_code == 400


def test_signup_short_password_400(client):
    resp = client.post("/auth/signup", json={"email": "a@b.com", "password": "short"})
    assert resp.status_code == 400


def test_signup_duplicate_verified_account_no_enumeration(client):
    """Signing up twice with the same (now-verified) email gives the same
    generic response both times -- no signal about account existence."""
    _signup(client, email="bob@example.com")
    otp = _signup(client, email="bob@example.com").get_json()["dev_otp"]
    client.post("/auth/verify-otp", json={"email": "bob@example.com", "otp": otp})

    resp = _signup(client, email="bob@example.com")
    assert resp.status_code == 200
    assert resp.get_json()["message"] == "If that email can be registered, a verification code has been sent."
    # No dev_otp for an already-verified account -- signup did not reissue one.
    assert "dev_otp" not in resp.get_json()


def test_verify_otp_correct_code_verifies_email(client, db_session):
    from sqlalchemy import select

    from src.api.auth.models import User

    otp = _signup(client, email="carol@example.com").get_json()["dev_otp"]
    resp = client.post("/auth/verify-otp", json={"email": "carol@example.com", "otp": otp})
    assert resp.status_code == 200

    user = db_session.scalar(select(User).where(User.email == "carol@example.com"))
    assert user.email_verified is True


def test_verify_otp_wrong_code_rejected(client):
    _signup(client, email="dave@example.com")
    resp = client.post("/auth/verify-otp", json={"email": "dave@example.com", "otp": "000000"})
    assert resp.status_code == 400


def test_verify_otp_unknown_email_generic_error(client):
    """S: no enumeration -- same error shape as a wrong code for a real user."""
    resp = client.post("/auth/verify-otp", json={"email": "nobody@example.com", "otp": "123456"})
    assert resp.status_code == 400
    assert resp.get_json()["error"] == "Invalid or expired verification code."


def test_otp_lockout_after_max_attempts(client):
    """S4: after OTP_MAX_ATTEMPTS (5) wrong attempts, further attempts are
    locked out (429) even with the correct code."""
    otp = _signup(client, email="erin@example.com").get_json()["dev_otp"]

    for _ in range(OTP_MAX_ATTEMPTS):
        resp = client.post("/auth/verify-otp", json={"email": "erin@example.com", "otp": "000000"})
        assert resp.status_code == 400

    # Locked out now -- even the correct code is rejected.
    resp = client.post("/auth/verify-otp", json={"email": "erin@example.com", "otp": otp})
    assert resp.status_code == 429


def test_signup_resend_blocked_during_active_lockout(client):
    """Regression test for the S4 bypass found during live testing: resending
    signup while locked out must NOT mint a fresh, unlocked OTP row -- that
    would silently reset the lockout counter and defeat S4 entirely."""
    otp1 = _signup(client, email="grace@example.com").get_json()["dev_otp"]

    for _ in range(OTP_MAX_ATTEMPTS):
        resp = client.post("/auth/verify-otp", json={"email": "grace@example.com", "otp": "000000"})
        assert resp.status_code == 400

    # Confirm locked out -- even the correct code for OTP #1 is rejected.
    resp = client.post("/auth/verify-otp", json={"email": "grace@example.com", "otp": otp1})
    assert resp.status_code == 429

    # THE BUG: resend signup mid-lockout used to mint a fresh, unlocked OTP.
    resend = _signup(client, email="grace@example.com")
    assert resend.status_code == 200
    assert resend.get_json()["message"] == "If that email can be registered, a verification code has been sent."
    # No new OTP was issued -- the lockout is still in force, nothing to return.
    assert "dev_otp" not in resend.get_json()

    # The account must still be locked out -- a wrong guess gets the generic
    # error (not a fresh "attempt 1/5"), and the ORIGINAL correct code is
    # still rejected too, proving no new row was created.
    resp = client.post("/auth/verify-otp", json={"email": "grace@example.com", "otp": "111111"})
    assert resp.status_code == 429
    resp = client.post("/auth/verify-otp", json={"email": "grace@example.com", "otp": otp1})
    assert resp.status_code == 429


def test_signup_resend_allowed_after_lockout_expires(client, db_session):
    """Once the lockout window has actually passed, a resend should issue a
    normal fresh OTP again -- the fix must not block resends forever."""
    from datetime import datetime, timedelta, timezone

    from sqlalchemy import select

    from src.api.auth.models import Otp, User

    _signup(client, email="heidi@example.com")
    for _ in range(OTP_MAX_ATTEMPTS):
        client.post("/auth/verify-otp", json={"email": "heidi@example.com", "otp": "000000"})

    # Simulate the lockout window having already passed.
    user = db_session.scalar(select(User).where(User.email == "heidi@example.com"))
    otp_row = db_session.scalar(select(Otp).where(Otp.user_id == user.id))
    otp_row.locked_until = datetime.now(timezone.utc) - timedelta(minutes=1)
    db_session.commit()

    resend = _signup(client, email="heidi@example.com")
    assert resend.status_code == 200
    assert "dev_otp" in resend.get_json()

    new_otp = resend.get_json()["dev_otp"]
    resp = client.post("/auth/verify-otp", json={"email": "heidi@example.com", "otp": new_otp})
    assert resp.status_code == 200


def test_otp_value_never_logged(client, caplog):
    """S5: grepping captured log output for the OTP value must find nothing."""
    with caplog.at_level(logging.DEBUG):
        otp = _signup(client, email="frank@example.com").get_json()["dev_otp"]
        client.post("/auth/verify-otp", json={"email": "frank@example.com", "otp": "000000"})
        client.post("/auth/verify-otp", json={"email": "frank@example.com", "otp": otp})

    log_text = "\n".join(record.getMessage() for record in caplog.records)
    assert otp not in log_text
