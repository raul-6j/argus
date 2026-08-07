"""EvalRun table (Phase 3, F10) — persisted real-world evaluation runs.

Backs the continuous drift-monitoring harness (``scripts/eval_drift.py``):
each scheduled run of ``scripts/measure_realworld_recall.py`` against a
fresh, independent phishing feed is persisted here so recall, false-positive
rate, and prediction-confidence can be tracked **over time** rather than as
a single point-in-time snapshot — turning DEC-018's documented real-world
generalisation gap into a measured, trending quantity instead of a one-off
number that can go stale unnoticed.

Shares the same ``Base``/engine/session-factory as every other table
(``scans``, ``api_keys``, ``users``, ...) — an offline script writing here
uses exactly the same ``src.api.db`` helpers ``create_app()`` uses, no new
infrastructure. This is intentionally a durable, queryable SQL table rather
than another JSON file in ``reports/`` (the convention every other one-shot
evaluation script already follows): unlike those, this data is meant to be
compared *across* runs, which a flat set of timestamped JSON files makes
tedious — a table one script can query for "all runs, ordered by time" is
the more honest fit for what a drift harness actually needs. Not wired into
any live API endpoint (a ``GET /eval-runs`` read endpoint would be a small,
natural follow-up if a live dashboard is ever wanted — flagged, not
built, since it wasn't asked for and adding it speculatively would be scope
creep beyond what a drift *harness* needs).
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Optional

from sqlalchemy import DateTime, Float, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from src.api.db import Base


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


class EvalRun(Base):
    """One scheduled real-world evaluation run.

    ``recall_by_hosting_category_json`` and ``recall_by_signal_json`` are
    JSON-encoded dicts (mirrors ``Scan.signals_json``'s existing
    JSON-in-Text convention) rather than normalized child tables — the
    breakdown's keys are open-ended (a hosting platform or signal name),
    and nothing here needs to query *into* those breakdowns with SQL, only
    read them back out whole for charting/reporting.
    """

    __tablename__ = "eval_runs"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    run_id: Mapped[str] = mapped_column(String, unique=True, nullable=False, index=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=_utcnow, nullable=False, index=True
    )
    eval_feed: Mapped[str] = mapped_column(Text, nullable=False)

    total_sampled: Mapped[int] = mapped_column(Integer, nullable=False)
    reachable: Mapped[int] = mapped_column(Integer, nullable=False)
    reachability_rate: Mapped[float] = mapped_column(Float, nullable=False)

    model_only_recall: Mapped[Optional[float]] = mapped_column(Float, nullable=True)
    fused_recall: Mapped[Optional[float]] = mapped_column(Float, nullable=True)
    recall_delta: Mapped[Optional[float]] = mapped_column(Float, nullable=True)

    control_set_size: Mapped[int] = mapped_column(Integer, nullable=False)
    model_only_fp_rate: Mapped[Optional[float]] = mapped_column(Float, nullable=True)
    fused_fp_rate: Mapped[Optional[float]] = mapped_column(Float, nullable=True)

    # JSON-encoded {category: {"n": int, "model_only_recall": float|None,
    # "fused_recall": float|None}}. "hosting category" is derived, not
    # fabricated ground truth: tenant-hosting-platform vs. standalone
    # domain, the exact axis DEC-018 identified as the model's blind spot.
    recall_by_hosting_category_json: Mapped[str] = mapped_column(Text, nullable=False, default="{}")

    # JSON-encoded {signal_name: {"n": int, "model_only_recall": float|None,
    # "fused_recall": float|None}}, keyed by which detection signal(s) fired
    # for a given URL (a URL can appear under multiple signals, or "none").
    # This is a signal-derived proxy for "attack category", not verified
    # ground-truth labeling -- no such labels exist in the source feeds.
    recall_by_signal_json: Mapped[str] = mapped_column(Text, nullable=False, default="{}")

    mean_model_confidence: Mapped[Optional[float]] = mapped_column(Float, nullable=True)
    confidence_std: Mapped[Optional[float]] = mapped_column(Float, nullable=True)

    # The full report dict from measure_realworld_recall.run(), JSON-encoded
    # verbatim -- forward-compatible with any future report keys without a
    # schema migration for every addition.
    report_json: Mapped[str] = mapped_column(Text, nullable=False)
