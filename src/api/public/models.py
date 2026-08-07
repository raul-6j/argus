"""API key table (Phase 2, C3) — developer-API authentication.

Mirrors ``src.api.auth.models.RefreshToken``'s security posture: only a
SHA-256 hash of the key is ever stored (``key_hash``), never the raw value
— a database leak alone never yields a usable key. ``key_prefix`` is the
non-secret, human-visible portion shown in key-management UIs (e.g.
``argus_9fJ2...``) so a user can tell their keys apart without the raw
value ever being retrievable again after the mint response.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Optional

from sqlalchemy import Boolean, DateTime, ForeignKey, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from src.api.db import Base


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


class ApiKey(Base):
    __tablename__ = "api_keys"

    id: Mapped[int] = mapped_column(primary_key=True)
    key_hash: Mapped[str] = mapped_column(String, unique=True, nullable=False, index=True)
    key_prefix: Mapped[str] = mapped_column(String, nullable=False)
    owner_user_id: Mapped[int] = mapped_column(ForeignKey("users.id"), nullable=False, index=True)
    tier: Mapped[str] = mapped_column(String, default="free", nullable=False)
    revoked: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow, nullable=False)
    last_used_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    # F19: HMAC key used to sign every webhook payload delivered for this
    # key's async scan jobs. One stable secret per key (not per-job), shown
    # once in the mint response exactly like the raw key above -- a receiver
    # verifies every delivery the same way without re-fetching anything.
    webhook_secret: Mapped[Optional[str]] = mapped_column(String, nullable=True)


class ScanJob(Base):
    """Async scan job (F19) — tracks a ``POST /v1/scan/async`` request from
    submission through completion, and optional webhook delivery.

    Deliberately its own table rather than reusing ``Scan``/``UserScan``
    (``src.api.scan.models``): those model *completed, persisted reports* for
    the public web app; this models a *job's lifecycle* for a developer-API
    caller, scoped to the owning API key (not a user), including states
    (``queued``/``running``) that have no result yet.
    """

    __tablename__ = "scan_jobs"

    id: Mapped[int] = mapped_column(primary_key=True)
    job_id: Mapped[str] = mapped_column(String, unique=True, nullable=False, index=True)
    owner_api_key_id: Mapped[int] = mapped_column(ForeignKey("api_keys.id"), nullable=False, index=True)
    url: Mapped[str] = mapped_column(Text, nullable=False)
    enrich: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    status: Mapped[str] = mapped_column(String, default="queued", nullable=False)
    result_json: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    error: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    webhook_url: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    webhook_status: Mapped[Optional[str]] = mapped_column(String, nullable=True)
    webhook_attempts: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=_utcnow, nullable=False, index=True
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=_utcnow, onupdate=_utcnow, nullable=False
    )
    completed_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
