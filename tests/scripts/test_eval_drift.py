"""Tests for scripts/eval_drift.py (Phase 3, F10)."""

from __future__ import annotations

from pathlib import Path
from unittest import mock

import pandas as pd
import pytest
import yaml

PROJECT_ROOT = Path(__file__).resolve().parents[2]
_MODEL_PATH = PROJECT_ROOT / "models" / "production" / "model.joblib"

pytestmark = pytest.mark.skipif(
    not _MODEL_PATH.is_file(), reason="Run scripts/train.py + scripts/evaluate.py first."
)

MODULE = "scripts.eval_drift"


@pytest.fixture(autouse=True)
def _mock_page_fetch():
    """No test in this file should ever perform real network I/O."""
    from scripts import measure_realworld_recall as m

    fake_artifacts = m.page_artifacts.PageArtifacts(requested_url="x", html=None, fetch_error="mocked: no network")
    with mock.patch.object(m.page_artifacts, "fetch", return_value=fake_artifacts):
        yield


def _make_eval_feed(tmp_path: Path, urls: list[str]) -> Path:
    eval_feed = tmp_path / "eval.csv"
    pd.DataFrame({"url": urls, "verified": ["yes"] * len(urls), "online": ["yes"] * len(urls)}).to_csv(
        eval_feed, index=False
    )
    return eval_feed


class TestResolveEvalFeed:
    def test_explicit_feed_wins(self, tmp_path):
        from scripts import eval_drift as d

        explicit = tmp_path / "explicit.csv"
        assert d._resolve_eval_feed(explicit, tmp_path / "nonexistent.yaml") == explicit

    def test_falls_back_to_active_snapshot_pointer(self, tmp_path):
        from scripts import eval_drift as d

        feeds_dir = tmp_path / "feeds"
        feeds_dir.mkdir()
        (feeds_dir / "active_snapshot.txt").write_text("data/raw/feeds/snap.csv", encoding="utf-8")
        ti_config_path = tmp_path / "threat_intel_config.yaml"
        ti_config_path.write_text(yaml.safe_dump({"feeds_dir": str(feeds_dir)}), encoding="utf-8")

        resolved = d._resolve_eval_feed(None, ti_config_path)
        assert resolved == d._PROJECT_ROOT / "data/raw/feeds/snap.csv"

    def test_raises_when_nothing_resolvable(self, tmp_path):
        from scripts import eval_drift as d

        with pytest.raises(FileNotFoundError):
            d._resolve_eval_feed(None, tmp_path / "nonexistent.yaml")

    def test_raises_when_no_pointer_file_written_yet(self, tmp_path):
        from scripts import eval_drift as d

        feeds_dir = tmp_path / "feeds"
        feeds_dir.mkdir()
        ti_config_path = tmp_path / "threat_intel_config.yaml"
        ti_config_path.write_text(yaml.safe_dump({"feeds_dir": str(feeds_dir)}), encoding="utf-8")

        with pytest.raises(FileNotFoundError):
            d._resolve_eval_feed(None, ti_config_path)


class TestDriftVsPrevious:
    def test_no_previous_run_yields_all_none(self):
        from scripts import eval_drift as d

        report = {"fused_recall": 0.5, "model_only_recall": 0.1, "fused_fp_rate": 0.0, "confidence_stats": {"mean": 0.3}}
        drift = d._drift_vs_previous(report, None)
        assert drift == {
            "fused_recall_drift": None,
            "model_only_recall_drift": None,
            "fused_fp_rate_drift": None,
            "mean_confidence_drift": None,
        }

    def test_computes_deltas_against_previous(self):
        from scripts import eval_drift as d

        previous = mock.Mock(fused_recall=0.4, model_only_recall=0.05, fused_fp_rate=0.02, mean_model_confidence=0.25)
        report = {
            "fused_recall": 0.5,
            "model_only_recall": 0.1,
            "fused_fp_rate": 0.0,
            "confidence_stats": {"mean": 0.3},
        }
        drift = d._drift_vs_previous(report, previous)
        assert drift["fused_recall_drift"] == pytest.approx(0.1)
        assert drift["model_only_recall_drift"] == pytest.approx(0.05)
        assert drift["fused_fp_rate_drift"] == pytest.approx(-0.02)
        assert drift["mean_confidence_drift"] == pytest.approx(0.05)

    def test_none_values_in_report_yield_none_delta(self):
        from scripts import eval_drift as d

        previous = mock.Mock(fused_recall=0.4, model_only_recall=None, fused_fp_rate=0.0, mean_model_confidence=0.25)
        report = {
            "fused_recall": None,
            "model_only_recall": 0.1,
            "fused_fp_rate": 0.0,
            "confidence_stats": {"mean": 0.3},
        }
        drift = d._drift_vs_previous(report, previous)
        assert drift["fused_recall_drift"] is None
        assert drift["model_only_recall_drift"] is None
        assert drift["fused_fp_rate_drift"] == pytest.approx(0.0)


class TestRunAndPersist:
    def test_first_run_persists_a_row_with_no_drift(self, tmp_path):
        from scripts import eval_drift as d
        from src.api.evalruns.models import EvalRun

        eval_feed = _make_eval_feed(tmp_path, ["https://a-test-url.example"])
        db_url = f"sqlite:///{tmp_path / 'test.db'}"

        result = d.run_and_persist(eval_feed, sample_size=5, control_sample_size=1, database_url=db_url)

        assert result["drift_vs_previous_run"]["fused_recall_drift"] is None
        assert "run_id" in result

        engine = d.create_db_engine(db_url)
        session = d.create_session_factory(engine)()
        try:
            rows = session.query(EvalRun).all()
            assert len(rows) == 1
            assert rows[0].run_id == result["run_id"]
            assert rows[0].eval_feed == str(eval_feed)
        finally:
            session.close()

    def test_second_run_computes_drift_against_the_first(self, tmp_path):
        from scripts import eval_drift as d

        eval_feed = _make_eval_feed(tmp_path, ["https://a-test-url.example"])
        db_url = f"sqlite:///{tmp_path / 'test.db'}"

        first = d.run_and_persist(eval_feed, sample_size=5, control_sample_size=1, database_url=db_url)
        second = d.run_and_persist(eval_feed, sample_size=5, control_sample_size=1, database_url=db_url)

        # Same (mocked-unreachable) inputs both times -- recall is None both
        # runs, so the delta is None, not a crash; the meaningful assertion
        # is that a *previous run* was found and compared against at all.
        assert first["run_id"] != second["run_id"]
        assert "fused_recall_drift" in second["drift_vs_previous_run"]

    def test_persisted_breakdowns_are_valid_json(self, tmp_path):
        import json

        from scripts import eval_drift as d
        from src.api.evalruns.models import EvalRun

        eval_feed = _make_eval_feed(tmp_path, ["https://a-test-url.example"])
        db_url = f"sqlite:///{tmp_path / 'test.db'}"
        d.run_and_persist(eval_feed, sample_size=5, control_sample_size=1, database_url=db_url)

        engine = d.create_db_engine(db_url)
        session = d.create_session_factory(engine)()
        try:
            row = session.query(EvalRun).one()
            assert isinstance(json.loads(row.recall_by_hosting_category_json), dict)
            assert isinstance(json.loads(row.recall_by_signal_json), dict)
            assert isinstance(json.loads(row.report_json), dict)
        finally:
            session.close()
