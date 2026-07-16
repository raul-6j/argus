"""Tests for scripts/measure_realworld_recall.py (Phase 1, D2).

Uses the real trained model (skipped if unavailable, matching the project's
existing conftest.py convention) but mocks every network fetch -- no live
phishing URLs are ever actually contacted in this test.
"""

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

MODULE = "scripts.measure_realworld_recall"


@pytest.fixture(autouse=True)
def _mock_page_fetch():
    """No test in this file should ever perform real network I/O."""
    from scripts import measure_realworld_recall as m

    fake_artifacts = m.page_artifacts.PageArtifacts(requested_url="x", html=None, fetch_error="mocked: no network")
    with mock.patch.object(m.page_artifacts, "fetch", return_value=fake_artifacts):
        yield


class TestCircularityGuard:
    def test_prefilter_urls_excluded_from_sample(self, tmp_path):
        from scripts import measure_realworld_recall as m

        ti_config_path = tmp_path / "threat_intel_config.yaml"
        snapshot_path = tmp_path / "prefilter_snapshot.csv"
        pd.DataFrame({"url": ["https://excluded-example.com"], "verified": ["yes"], "online": ["yes"]}).to_csv(
            snapshot_path, index=False
        )
        ti_config_path.write_text(
            yaml.safe_dump({"enabled": True, "phishtank_snapshot_path": str(snapshot_path)}), encoding="utf-8"
        )
        excluded = m._load_active_prefilter_urls(ti_config_path)
        assert len(excluded) == 1

    def test_disabled_prefilter_yields_no_exclusions(self, tmp_path):
        from scripts import measure_realworld_recall as m

        ti_config_path = tmp_path / "threat_intel_config.yaml"
        ti_config_path.write_text(yaml.safe_dump({"enabled": False}), encoding="utf-8")
        assert m._load_active_prefilter_urls(ti_config_path) == set()

    def test_missing_config_yields_no_exclusions(self, tmp_path):
        from scripts import measure_realworld_recall as m

        assert m._load_active_prefilter_urls(tmp_path / "nope.yaml") == set()

    def test_eval_urls_overlapping_prefilter_are_excluded_from_the_run(self, tmp_path):
        from scripts import measure_realworld_recall as m

        eval_feed = tmp_path / "eval.csv"
        pd.DataFrame(
            {
                "url": ["https://excluded-example.com", "https://not-excluded-example.com"],
                "verified": ["yes", "yes"],
                "online": ["yes", "yes"],
            }
        ).to_csv(eval_feed, index=False)

        snapshot_path = tmp_path / "prefilter_snapshot.csv"
        pd.DataFrame({"url": ["https://excluded-example.com"], "verified": ["yes"], "online": ["yes"]}).to_csv(
            snapshot_path, index=False
        )
        ti_config_path = tmp_path / "threat_intel_config.yaml"
        ti_config_path.write_text(
            yaml.safe_dump({"enabled": True, "phishtank_snapshot_path": str(snapshot_path)}), encoding="utf-8"
        )

        report = m.run(eval_feed, sample_size=10, control_sample_size=1, threat_intel_config_path=ti_config_path)
        assert report["excluded_prefilter_urls"] == 1
        assert report["total_sampled"] == 1  # only the non-excluded URL


class TestReportShape:
    def test_report_has_expected_keys(self, tmp_path):
        from scripts import measure_realworld_recall as m

        eval_feed = tmp_path / "eval.csv"
        pd.DataFrame({"url": ["https://a-test-url.example"], "verified": ["yes"], "online": ["yes"]}).to_csv(
            eval_feed, index=False
        )
        report = m.run(eval_feed, sample_size=5, control_sample_size=1)
        expected_keys = {
            "generated_at", "eval_feed", "excluded_prefilter_urls", "total_sampled", "reachable",
            "reachability_rate", "model_only_recall", "fused_recall", "recall_delta",
            "control_set_size", "model_only_fp_rate", "fused_fp_rate", "note",
        }
        assert expected_keys.issubset(report.keys())

    def test_unreachable_urls_yield_none_recall_not_a_crash(self, tmp_path):
        """Every URL fails to fetch (mocked) -- recall is None (no reachable
        rows to compute over), not a crash or a misleading 0.0."""
        from scripts import measure_realworld_recall as m

        eval_feed = tmp_path / "eval.csv"
        pd.DataFrame({"url": ["https://a-test-url.example"], "verified": ["yes"], "online": ["yes"]}).to_csv(
            eval_feed, index=False
        )
        report = m.run(eval_feed, sample_size=5, control_sample_size=1)
        assert report["reachable"] == 0
        assert report["model_only_recall"] is None
        assert report["fused_recall"] is None
        assert report["recall_delta"] is None

    def test_one_url_prediction_failure_does_not_abort_the_run(self, tmp_path):
        from scripts import measure_realworld_recall as m

        eval_feed = tmp_path / "eval.csv"
        pd.DataFrame(
            {"url": ["https://a-test-url.example", "https://b-test-url.example"], "verified": ["yes", "yes"], "online": ["yes", "yes"]}
        ).to_csv(eval_feed, index=False)

        real_predict = m._predict_one
        call_count = {"n": 0}

        def _flaky_predict(*args, **kwargs):
            call_count["n"] += 1
            if call_count["n"] == 1:
                raise RuntimeError("boom")
            return real_predict(*args, **kwargs)

        with mock.patch(f"{MODULE}._predict_one", side_effect=_flaky_predict):
            report = m.run(eval_feed, sample_size=5, control_sample_size=1)
        # One URL failed outright and was skipped; the run still produced a report.
        assert report["total_sampled"] == 2
