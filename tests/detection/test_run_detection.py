"""Tests for src.detection.run_detection (the orchestrator)."""

from __future__ import annotations

from unittest import mock

from src.detection import run_detection
from src.detection.brand_reference import Brand, BrandIndex
from src.detection.types import RiskSignal
from src.features.page_artifacts import PageArtifacts

MODULE = "src.detection"

_CONFIG = {
    "enabled": True,
    "fusion_threshold": 0.30,
    "signal_weights": {
        "model": 1.0,
        "typosquat": 0.6,
        "favicon_match": 0.9,
        "brand_mismatch": 0.8,
        "cert_intel": 0.4,
        "redirect_chain": 0.7,
    },
    "hard_override_signals": ["favicon_match"],
    "signal_params": {
        "typosquat": {"max_edit_distance": 2},
        "favicon_match": {"phash_tolerance": 3},
        "redirect_chain": {"max_edit_distance": 2},
    },
}

_BRAND_INDEX = BrandIndex(brands=(Brand(name="PayPal", domains=("paypal.com",), aliases=("paypal",)),))


class TestDisabledConfig:
    def test_disabled_config_reproduces_model_only_decision(self):
        v = run_detection(
            "https://example.com",
            model_proba=0.5,
            page_artifacts=None,
            html_features=None,
            brand_index=_BRAND_INDEX,
            config={"enabled": False},
        )
        assert v.label == "phishing"  # 0.5 >= default threshold
        assert v.signals == []
        assert v.decisive_source == "model"


class TestNoPageArtifacts:
    def test_typosquat_runs_without_page_artifacts(self):
        v = run_detection(
            "https://paypal-secure-login.net",
            model_proba=0.1,
            page_artifacts=None,
            html_features=None,
            brand_index=_BRAND_INDEX,
            config=_CONFIG,
        )
        names = [s.name for s in v.signals]
        assert "typosquat" in names
        assert "favicon_match" not in names
        assert "brand_mismatch" not in names

    def test_typosquat_trigger_reflected_in_verdict(self):
        v = run_detection(
            "https://paypal-secure-login.net",
            model_proba=0.1,
            page_artifacts=None,
            html_features=None,
            brand_index=_BRAND_INDEX,
            config=_CONFIG,
        )
        typo = next(s for s in v.signals if s.name == "typosquat")
        assert typo.triggered is True


class TestFailedPageFetch:
    def test_page_dependent_signals_skipped_when_fetch_failed(self):
        artifacts = PageArtifacts(requested_url="x", html=None, fetch_error="dead")
        v = run_detection(
            "https://example.com",
            model_proba=0.1,
            page_artifacts=artifacts,
            html_features=None,
            brand_index=_BRAND_INDEX,
            config=_CONFIG,
        )
        names = [s.name for s in v.signals]
        assert names == ["typosquat"]


class TestSuccessfulPageFetch:
    def test_all_five_signals_run(self):
        """Phase 1's three page-dependent signals plus Phase 2's A4/A5 --
        all five gated on a successful page fetch, all run together."""
        html = "<html><head><title>Just a page</title></head><body>hello</body></html>"
        artifacts = PageArtifacts(requested_url="x", html=html, final_url="https://example.com")
        v = run_detection(
            "https://example.com",
            model_proba=0.1,
            page_artifacts=artifacts,
            html_features={},
            brand_index=_BRAND_INDEX,
            config=_CONFIG,
        )
        names = {s.name for s in v.signals}
        assert names == {
            "typosquat", "favicon_match", "brand_mismatch", "cert_intel", "redirect_chain",
        }


class TestSignalIsolation:
    def test_one_signal_raising_does_not_sink_the_others(self):
        html = "<html><head><title>PayPal Login</title></head><body><input type=password></body></html>"
        artifacts = PageArtifacts(requested_url="x", html=html, final_url="https://attacker.com")
        with mock.patch(f"{MODULE}.favicon_match.evaluate", side_effect=RuntimeError("boom")):
            v = run_detection(
                "https://attacker.com",
                model_proba=0.1,
                page_artifacts=artifacts,
                html_features={},
                brand_index=_BRAND_INDEX,
                config=_CONFIG,
            )
        favicon_sig = next(s for s in v.signals if s.name == "favicon_match")
        assert favicon_sig.triggered is False
        assert favicon_sig.direction == "neutral"
        # brand_mismatch still ran and could still trigger despite favicon's crash.
        brand_sig = next(s for s in v.signals if s.name == "brand_mismatch")
        assert brand_sig.triggered is True

    def test_typosquat_raising_does_not_crash_orchestrator(self):
        with mock.patch(f"{MODULE}.typosquat.evaluate", side_effect=RuntimeError("boom")):
            v = run_detection(
                "https://example.com",
                model_proba=0.1,
                page_artifacts=None,
                html_features=None,
                brand_index=_BRAND_INDEX,
                config=_CONFIG,
            )
        typo = next(s for s in v.signals if s.name == "typosquat")
        assert typo.triggered is False
        assert v.label == "legitimate"
