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

from sqlalchemy import DateTime, Float, String, Text
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
