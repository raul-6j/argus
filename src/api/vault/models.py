"""Vault table (Phase 8, Task 8.3) — zero-knowledge storage.

``ciphertext`` is an opaque blob (base64, AES-GCM-encrypted client-side).
The server never decrypts it, never derives the key, and has no way to
recover plaintext from what's stored here (S10). ``version`` is the only
field the server reasons about — a simple integer used purely to detect
concurrent-write conflicts (see ``routes.py``'s optimistic-concurrency PUT).
"""

from __future__ import annotations

from datetime import datetime, timezone

from sqlalchemy import DateTime, ForeignKey, Integer, Text
from sqlalchemy.orm import Mapped, mapped_column

from src.api.db import Base


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


class VaultEntry(Base):
    __tablename__ = "vault_entries"

    # One vault blob per user -- user_id is both PK and FK.
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id"), primary_key=True)
    ciphertext: Mapped[str] = mapped_column(Text, nullable=False)
    version: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=_utcnow, onupdate=_utcnow, nullable=False
    )
