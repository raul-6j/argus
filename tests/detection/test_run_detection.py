"""Tests for src.detection.run_detection (the orchestrator)."""

from __future__ import annotations

from unittest import mock

from src.detection import run_detection
from src.detection.brand_reference import Brand, BrandIndex
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
        "credential_context": 0.55,
        "platform_risk": 0.5,
        "semantic_content": 0.45,
    },
    "hard_override_signals": ["favicon_match"],
    "tenant_hosting_platforms": ["wixstudio.com", "vercel.app"],
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
        assert "credential_context" not in names
        assert "semantic_content" not in names

    def test_platform_risk_runs_but_stays_neutral_without_page_artifacts(self):
        """platform_risk is hostname-only, so it still runs when there's no
        page fetch -- but it can never trigger without a corroborating
        page-content signal (brand_mismatch/credential_context), both of
        which require a successful fetch."""
        v = run_detection(
            "https://attacker.wixstudio.com",
            model_proba=0.1,
            page_artifacts=None,
            html_features=None,
            brand_index=_BRAND_INDEX,
            config=_CONFIG,
        )
        platform_sig = next(s for s in v.signals if s.name == "platform_risk")
        assert platform_sig.triggered is False

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
        # platform_risk still runs (it's hostname-only) but stays neutral --
        # example.com isn't a listed tenant-hosting platform, and even if it
        # were, it has nothing to corroborate since brand_mismatch/
        # credential_context never ran without a successful fetch.
        assert names == ["typosquat", "platform_risk"]
        platform_sig = next(s for s in v.signals if s.name == "platform_risk")
        assert platform_sig.triggered is False


class TestSuccessfulPageFetch:
    def test_all_eight_signals_run(self):
        """Phase 1's three page-dependent signals, Phase 2's A4/A5, Phase
        3's F3/F4, and Phase 6's F17 -- all eight run together on a
        successful fetch."""
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
            "credential_context", "platform_risk", "semantic_content",
        }

    def test_semantic_content_triggers_when_corroborated_by_brand_mismatch(self):
        html = (
            "<html><head><title>PayPal</title></head>"
            "<body><p>Your account will be suspended. Act now.</p>"
            "<input type=password></body></html>"
        )
        artifacts = PageArtifacts(requested_url="x", html=html, final_url="https://attacker.com")
        v = run_detection(
            "https://attacker.com",
            model_proba=0.1,
            page_artifacts=artifacts,
            html_features={},
            brand_index=_BRAND_INDEX,
            config=_CONFIG,
        )
        brand_sig = next(s for s in v.signals if s.name == "brand_mismatch")
        assert brand_sig.triggered is True
        semantic_sig = next(s for s in v.signals if s.name == "semantic_content")
        assert semantic_sig.triggered is True
        assert "urgency_threat" in semantic_sig.evidence["matched_categories"]

    def test_platform_risk_triggers_when_corroborated_by_brand_mismatch(self):
        html = (
            "<html><head><title>PayPal</title></head>"
            "<body><input type=password></body></html>"
        )
        artifacts = PageArtifacts(
            requested_url="x", html=html, final_url="https://attacker.wixstudio.com"
        )
        v = run_detection(
            "https://attacker.wixstudio.com",
            model_proba=0.1,
            page_artifacts=artifacts,
            html_features={},
            brand_index=_BRAND_INDEX,
            config=_CONFIG,
        )
        brand_sig = next(s for s in v.signals if s.name == "brand_mismatch")
        assert brand_sig.triggered is True
        platform_sig = next(s for s in v.signals if s.name == "platform_risk")
        assert platform_sig.triggered is True
        assert platform_sig.evidence["platform"] == "wixstudio.com"


class TestCertRedirectRegression:
    """End-to-end regression for the mail.google.com false positive: a
    same-provider redirect (mail.google.com -> accounts.google.com) whose
    final-hop cert covers the final host but not the originally-requested
    one must not push the fused verdict to phishing on cert_intel alone."""

    def test_gmail_style_redirect_stays_legitimate(self):
        cert = {
            "subject": [[["commonName", "accounts.google.com"]]],
            "issuer": [[["organizationName", "Google Trust Services"]]],
            "not_before": "Jan 01 00:00:00 2026 GMT",
            "san": ["accounts.google.com", "mtls.accounts.google.com"],
        }
        html = "<html><head><title>Sign in - Google Accounts</title></head><body></body></html>"
        artifacts = PageArtifacts(
            requested_url="https://mail.google.com/mail/u/0/#inbox",
            final_url="https://accounts.google.com/ServiceLogin?service=mail",
            redirect_chain=["https://mail.google.com/mail/u/0/"],
            html=html,
            tls_cert=cert,
        )
        v = run_detection(
            "https://mail.google.com/mail/u/0/#inbox",
            model_proba=0.05,
            page_artifacts=artifacts,
            html_features={},
            brand_index=BrandIndex(),
            config=_CONFIG,
        )
        cert_sig = next(s for s in v.signals if s.name == "cert_intel")
        assert cert_sig.triggered is False
        assert v.label == "legitimate"
        assert v.risk_score < 0.1


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
