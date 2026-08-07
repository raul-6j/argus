"""Tests for scripts/plot_drift.py (Phase 3, F10)."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

from scripts import plot_drift as p
from src.api.db import create_db_engine, create_session_factory, init_db
from src.api.evalruns.models import EvalRun


def _db_url(tmp_path) -> str:
    return f"sqlite:///{tmp_path / 'test.db'}"


def _seed_runs(db_url: str, n: int) -> None:
    engine = create_db_engine(db_url)
    init_db(engine)
    session = create_session_factory(engine)()
    try:
        base = datetime(2026, 1, 1, tzinfo=timezone.utc)
        for i in range(n):
            session.add(
                EvalRun(
                    run_id=f"run-{i}",
                    created_at=base + timedelta(days=i),
                    eval_feed="feed.csv",
                    total_sampled=10,
                    reachable=8,
                    reachability_rate=0.8,
                    model_only_recall=0.1 + i * 0.01,
                    fused_recall=0.2 + i * 0.01,
                    recall_delta=0.1,
                    control_set_size=5,
                    model_only_fp_rate=0.0,
                    fused_fp_rate=0.0,
                    recall_by_hosting_category_json="{}",
                    recall_by_signal_json="{}",
                    mean_model_confidence=0.3 + i * 0.01,
                    confidence_std=0.05,
                    report_json="{}",
                )
            )
        session.commit()
    finally:
        session.close()


class TestLoadRuns:
    def test_empty_database_yields_empty_list(self, tmp_path):
        db_url = _db_url(tmp_path)
        engine = create_db_engine(db_url)
        init_db(engine)
        assert p.load_runs(db_url) == []

    def test_missing_table_does_not_raise(self, tmp_path):
        """A totally fresh sqlite file (never had init_db run) must degrade
        to an empty list, not crash the harness."""
        db_url = _db_url(tmp_path)
        assert p.load_runs(db_url) == []

    def test_returns_runs_oldest_first(self, tmp_path):
        db_url = _db_url(tmp_path)
        _seed_runs(db_url, 3)
        runs = p.load_runs(db_url)
        assert [r.run_id for r in runs] == ["run-0", "run-1", "run-2"]

    def test_limit_keeps_most_recent_but_still_ascending(self, tmp_path):
        db_url = _db_url(tmp_path)
        _seed_runs(db_url, 5)
        runs = p.load_runs(db_url, limit=2)
        assert [r.run_id for r in runs] == ["run-3", "run-4"]


class TestGenerateCharts:
    def test_fewer_than_two_runs_writes_nothing(self, tmp_path):
        db_url = _db_url(tmp_path)
        _seed_runs(db_url, 1)
        runs = p.load_runs(db_url)
        written = p.generate_charts(runs, tmp_path / "charts")
        assert written == []
        assert not (tmp_path / "charts").exists()

    def test_two_or_more_runs_writes_three_charts(self, tmp_path):
        db_url = _db_url(tmp_path)
        _seed_runs(db_url, 4)
        runs = p.load_runs(db_url)
        out_dir = tmp_path / "charts"
        written = p.generate_charts(runs, out_dir)
        assert len(written) == 3
        for path in written:
            assert path.is_file()
            assert path.stat().st_size > 0
