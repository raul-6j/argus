"""Tests for src.api.app's Phase-1 additions: _load_detection and
_resolve_threat_feed_snapshot (D1's active-snapshot pointer resolution).

Only the pure loader functions are exercised directly here (no full
create_app() boot needed for these) -- create_app() itself is already
covered end-to-end by tests/api/test_detect.py and test_explain.py via the
session-scoped `app` fixture, which loads the real detection_config.yaml.
"""

from __future__ import annotations

import json

from src.api.app import _load_detection, _resolve_threat_feed_snapshot


class TestLoadDetection:
    def test_missing_config_file_disabled(self, tmp_path):
        state = _load_detection(tmp_path / "nope.yaml")
        assert state["enabled"] is False
        assert state["brand_index"] is None

    def test_disabled_in_config(self, tmp_path):
        config_path = tmp_path / "detection_config.yaml"
        config_path.write_text("enabled: false\n", encoding="utf-8")
        state = _load_detection(config_path)
        assert state["enabled"] is False
        assert state["brand_index"] is None

    def test_enabled_loads_brand_index(self, tmp_path):
        brands_path = tmp_path / "brands.json"
        brands_path.write_text(
            json.dumps({"brands": [{"name": "Acme", "domains": ["acme.com"]}]}), encoding="utf-8"
        )
        config_path = tmp_path / "detection_config.yaml"
        config_path.write_text(
            f"enabled: true\nbrand_reference_path: {brands_path}\nfusion_threshold: 0.3\n",
            encoding="utf-8",
        )
        state = _load_detection(config_path)
        assert state["enabled"] is True
        assert state["brand_index"] is not None
        assert len(state["brand_index"].brands) == 1
        assert state["config"]["fusion_threshold"] == 0.3

    def test_real_shipped_config_loads(self):
        """The actual configs/detection_config.yaml ships with the repo."""
        from pathlib import Path

        real_path = Path(__file__).resolve().parents[2] / "configs" / "detection_config.yaml"
        state = _load_detection(real_path)
        assert state["enabled"] is True
        assert len(state["brand_index"].brands) > 0


class TestResolveThreatFeedSnapshot:
    def test_no_feeds_dir_falls_back_to_pinned_path(self):
        config = {"phishtank_snapshot_path": "data/raw/phishtank_2026-07-02.csv"}
        result = _resolve_threat_feed_snapshot(config)
        assert str(result).endswith("data/raw/phishtank_2026-07-02.csv")

    def test_feeds_dir_without_pointer_file_falls_back(self, tmp_path):
        config = {
            "feeds_dir": str(tmp_path / "feeds"),
            "phishtank_snapshot_path": "data/raw/phishtank_2026-07-02.csv",
        }
        result = _resolve_threat_feed_snapshot(config)
        assert str(result).endswith("data/raw/phishtank_2026-07-02.csv")

    def test_feeds_dir_with_pointer_file_is_preferred(self, tmp_path):
        feeds_dir = tmp_path / "feeds"
        feeds_dir.mkdir()
        snapshot = feeds_dir / "threat_feed_2026-08-01.csv"
        snapshot.write_text("url,verified,online\n", encoding="utf-8")
        (feeds_dir / "active_snapshot.txt").write_text(str(snapshot), encoding="utf-8")

        config = {
            "feeds_dir": str(feeds_dir),
            "phishtank_snapshot_path": "data/raw/phishtank_2026-07-02.csv",
        }
        result = _resolve_threat_feed_snapshot(config)
        assert result == snapshot

    def test_empty_pointer_file_falls_back(self, tmp_path):
        feeds_dir = tmp_path / "feeds"
        feeds_dir.mkdir()
        (feeds_dir / "active_snapshot.txt").write_text("", encoding="utf-8")

        config = {
            "feeds_dir": str(feeds_dir),
            "phishtank_snapshot_path": "data/raw/phishtank_2026-07-02.csv",
        }
        result = _resolve_threat_feed_snapshot(config)
        assert str(result).endswith("data/raw/phishtank_2026-07-02.csv")
