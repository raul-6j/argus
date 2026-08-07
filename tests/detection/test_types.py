"""Tests for src.detection.types (RiskSignal/FusedVerdict + risk bands, F5)."""

from __future__ import annotations

from src.detection.types import DEFAULT_RISK_BANDS, risk_band_for_score


class TestRiskBandForScoreDefaults:
    def test_low_band(self):
        assert risk_band_for_score(0.0) == "low"
        assert risk_band_for_score(0.1499) == "low"

    def test_caution_band(self):
        assert risk_band_for_score(0.15) == "caution"
        assert risk_band_for_score(0.2999) == "caution"

    def test_suspicious_band_matches_calibrated_model_threshold(self):
        """The suspicious floor (0.30) intentionally equals model_config.yaml's
        calibrated decision threshold (DEC-017) -- so risk_band and the binary
        label never disagree."""
        assert risk_band_for_score(0.30) == "suspicious"
        assert risk_band_for_score(0.4999) == "suspicious"

    def test_high_band(self):
        assert risk_band_for_score(0.50) == "high"
        assert risk_band_for_score(0.7499) == "high"

    def test_critical_band(self):
        assert risk_band_for_score(0.75) == "critical"
        assert risk_band_for_score(1.0) == "critical"

    def test_default_bands_are_five_and_ascending(self):
        floors = [floor for _, floor in DEFAULT_RISK_BANDS]
        assert floors == sorted(floors)
        assert len(DEFAULT_RISK_BANDS) == 5


class TestRiskBandForScoreCustomConfig:
    def test_custom_bands_override_defaults(self):
        custom = [{"name": "chill", "floor": 0.0}, {"name": "yikes", "floor": 0.9}]
        assert risk_band_for_score(0.5, custom) == "chill"
        assert risk_band_for_score(0.95, custom) == "yikes"

    def test_empty_bands_list_falls_back_to_defaults(self):
        assert risk_band_for_score(0.9, []) == "critical"

    def test_none_bands_falls_back_to_defaults(self):
        assert risk_band_for_score(0.9, None) == "critical"
