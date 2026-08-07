"""Tests for src.api.app's Phase-1 additions: _load_detection and
_resolve_threat_feed_snapshot (D1's active-snapshot pointer resolution).

Only the pure loader functions are exercised directly here (no full
create_app() boot needed for these) -- create_app() itself is already
covered end-to-end by tests/api/test_detect.py and test_explain.py via the
session-scoped `app` fixture, which loads the real detection_config.yaml.
"""

from __future__ import annotations

import json
import os
from unittest import mock

from src.api.app import (
    _load_detection,
    _load_threat_intel,
    _resolve_threat_feed_snapshot,
    reload_threat_intel,
)


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


def _write_snapshot(path, urls):
    path.write_text(
        "url,verified,online\n" + "".join(f"{u},yes,yes\n" for u in urls), encoding="utf-8"
    )


class TestLoadThreatIntel:
    """Phase 5, F6 (DEC-035): _load_threat_intel now builds a provider list."""

    def test_missing_config_disabled_yields_no_providers(self, tmp_path):
        state = _load_threat_intel(tmp_path / "nope.yaml")
        assert state["enabled"] is False
        assert state["providers"] == []

    def test_disabled_in_config_yields_no_providers(self, tmp_path):
        config_path = tmp_path / "threat_intel_config.yaml"
        config_path.write_text("enabled: false\n", encoding="utf-8")
        state = _load_threat_intel(config_path)
        assert state["enabled"] is False
        assert state["providers"] == []

    def test_enabled_without_gsb_yields_phishtank_only(self, tmp_path):
        snapshot = tmp_path / "snapshot.csv"
        _write_snapshot(snapshot, ["http://evil.example.com/login"])
        config_path = tmp_path / "threat_intel_config.yaml"
        config_path.write_text(f"enabled: true\nphishtank_snapshot_path: {snapshot}\n", encoding="utf-8")

        state = _load_threat_intel(config_path)
        assert state["enabled"] is True
        assert [p.name for p in state["providers"]] == ["phishtank"]

    def test_gsb_enabled_with_env_key_is_included(self, tmp_path):
        snapshot = tmp_path / "snapshot.csv"
        _write_snapshot(snapshot, [])
        config_path = tmp_path / "threat_intel_config.yaml"
        config_path.write_text(
            f"enabled: true\nphishtank_snapshot_path: {snapshot}\ngsb_enabled: true\n", encoding="utf-8"
        )

        with mock.patch.dict(os.environ, {"GSB_API_KEY": "real-key"}):
            state = _load_threat_intel(config_path)
        assert [p.name for p in state["providers"]] == ["gsb", "phishtank"]

    def test_gsb_enabled_without_env_key_falls_back_to_phishtank_only(self, tmp_path):
        snapshot = tmp_path / "snapshot.csv"
        _write_snapshot(snapshot, [])
        config_path = tmp_path / "threat_intel_config.yaml"
        config_path.write_text(
            f"enabled: true\nphishtank_snapshot_path: {snapshot}\ngsb_enabled: true\n", encoding="utf-8"
        )

        with mock.patch.dict(os.environ, {}, clear=True):
            state = _load_threat_intel(config_path)
        assert [p.name for p in state["providers"]] == ["phishtank"]


class TestReloadThreatIntel:
    """Phase 5, F7 (DEC-035): hot-reload without a process restart."""

    def test_reload_picks_up_a_new_snapshot(self, tmp_path):
        snapshot = tmp_path / "snapshot.csv"
        _write_snapshot(snapshot, ["http://old-entry.example.com/"])
        config_path = tmp_path / "threat_intel_config.yaml"
        config_path.write_text(f"enabled: true\nphishtank_snapshot_path: {snapshot}\n", encoding="utf-8")

        fake_app = mock.Mock()
        fake_app.extensions = {"argus": {"threat_intel": _load_threat_intel(config_path)}}

        old_providers = fake_app.extensions["argus"]["threat_intel"]["providers"]
        assert old_providers[0].check("http://new-entry.example.com/") is False

        _write_snapshot(snapshot, ["http://new-entry.example.com/"])
        reload_threat_intel(fake_app, config_path)

        new_providers = fake_app.extensions["argus"]["threat_intel"]["providers"]
        assert new_providers[0].check("http://new-entry.example.com/") is True
        assert new_providers[0].check("http://old-entry.example.com/") is False

    def test_reload_is_atomic_dict_swap_not_mutation(self, tmp_path):
        """A reference held to the old state dict before reload() must stay
        exactly as it was -- reload() replaces the dict, never mutates it,
        so a concurrent request holding the old reference is unaffected."""
        snapshot = tmp_path / "snapshot.csv"
        _write_snapshot(snapshot, [])
        config_path = tmp_path / "threat_intel_config.yaml"
        config_path.write_text(f"enabled: true\nphishtank_snapshot_path: {snapshot}\n", encoding="utf-8")

        fake_app = mock.Mock()
        old_state = _load_threat_intel(config_path)
        fake_app.extensions = {"argus": {"threat_intel": old_state}}

        _write_snapshot(snapshot, ["http://new-entry.example.com/"])
        reload_threat_intel(fake_app, config_path)

        assert fake_app.extensions["argus"]["threat_intel"] is not old_state
        assert old_state["providers"][0].check("http://new-entry.example.com/") is False

    def test_reload_failure_keeps_previous_state(self, tmp_path):
        config_path = tmp_path / "threat_intel_config.yaml"
        config_path.write_text("enabled: true\nphishtank_snapshot_path: missing.csv\n", encoding="utf-8")

        fake_app = mock.Mock()
        sentinel_state = {"enabled": True, "providers": ["sentinel"]}
        fake_app.extensions = {"argus": {"threat_intel": sentinel_state}}

        with mock.patch("src.api.app._load_threat_intel", side_effect=RuntimeError("boom")):
            reload_threat_intel(fake_app, config_path)

        assert fake_app.extensions["argus"]["threat_intel"] is sentinel_state


class TestSighupHandlerRegistration:
    """create_app() wires SIGHUP -> reload_threat_intel (Phase 5, F7).

    Deliberately does NOT fire a real SIGHUP against the shared session
    `app` fixture: signal.signal() registration is process-global, and this
    test suite calls create_app() many times across many test modules (each
    building its own "dedicated, freshly-built app" per conftest.py's own
    documented pattern for rate-limit tests etc.) -- whichever create_app()
    call happens to run last in the whole pytest session is the one an
    actual SIGHUP would reach, not reliably the `app` fixture any one test
    holds a reference to. Mocking signal.signal at registration time proves
    the wiring itself without depending on suite-wide call ordering; the
    reload behavior it wires to is already fully covered, deterministically,
    by TestReloadThreatIntel above.
    """

    def test_create_app_registers_a_sighup_handler_bound_to_reload(self, tmp_path):
        import signal
        import tempfile

        import yaml

        from src.api.app import PROJECT_ROOT, create_app

        api_config = yaml.safe_load((PROJECT_ROOT / "configs" / "api_config.yaml").open())
        api_config["database_url"] = "sqlite:///:memory:"
        api_config["cache"] = {"enabled": False}
        with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False) as fh:
            yaml.safe_dump(api_config, fh)
            tmp_config_path = fh.name

        with mock.patch("signal.signal") as m_signal:
            create_app(config_path=tmp_config_path)

        registered_signals = [call.args[0] for call in m_signal.call_args_list]
        assert signal.SIGHUP in registered_signals
