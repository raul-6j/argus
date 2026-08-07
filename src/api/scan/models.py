"""Scan table (Phase 2, C1) — public, shareable scan reports.

Stores only what a shareable permalink needs to render: the submitted URL,
the fused verdict, and the serialized signal evidence. No requester
identity (IP, session, account) is stored — the read endpoint is public by
design (the submitter chooses to share the link), so nothing here should
be sensitive beyond what the submitter already put in the URL itself.
``scan_id`` is an opaque, randomly-generated token (never a sequential
integer) specifically so a report can't be enumerated by guessing
neighboring ids.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Optional

from sqlalchemy import DateTime, Float, ForeignKey, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from src.api.db import Base


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


class Scan(Base):
    __tablename__ = "scans"

    id: Mapped[int] = mapped_column(primary_key=True)
    scan_id: Mapped[str] = mapped_column(String, unique=True, nullable=False, index=True)
    url: Mapped[str] = mapped_column(Text, nullable=False)
    label: Mapped[str] = mapped_column(String, nullable=False)
    confidence: Mapped[float] = mapped_column(Float, nullable=False)
    risk_score: Mapped[float] = mapped_column(Float, nullable=False)
    signals_json: Mapped[str] = mapped_column(Text, nullable=False)  # JSON-encoded signals[]
    plain_explanation: Mapped[str] = mapped_column(Text, nullable=False)
    source: Mapped[str] = mapped_column(String, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow, nullable=False)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, index=True)


class UserScan(Base):
    """A signed-in user's own scan history (Phase 4, F11).

    Deliberately a separate table from ``Scan``, not an added column on it:
    ``Scan`` is the anonymous, no-requester-identity, 7-day-TTL permalink
    store from DEC-027, and stays that way for every caller regardless of
    whether they happen to be logged in. This table is the opposite shape on
    purpose — owner-linked, no TTL, self-contained (its own copy of the
    signals/explanation) so it outlives the anonymous row it may reference.
    """

    __tablename__ = "user_scans"

    id: Mapped[int] = mapped_column(primary_key=True)
    owner_user_id: Mapped[int] = mapped_column(ForeignKey("users.id"), nullable=False, index=True)
    scan_id: Mapped[Optional[str]] = mapped_column(String, nullable=True)  # best-effort link to Scan.scan_id
    url: Mapped[str] = mapped_column(Text, nullable=False)
    label: Mapped[str] = mapped_column(String, nullable=False)
    confidence: Mapped[float] = mapped_column(Float, nullable=False)
    risk_score: Mapped[float] = mapped_column(Float, nullable=False)
    risk_band: Mapped[str] = mapped_column(String, nullable=False)
    signals_json: Mapped[str] = mapped_column(Text, nullable=False)  # JSON-encoded signals[]
    plain_explanation: Mapped[str] = mapped_column(Text, nullable=False)
    source: Mapped[str] = mapped_column(String, nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=_utcnow, nullable=False, index=True
    )
