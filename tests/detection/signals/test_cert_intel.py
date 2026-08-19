"""Tests for src.detection.signals.cert_intel (Phase 2, A4)."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

from src.detection.brand_reference import BrandIndex
from src.detection.signals import cert_intel
from src.detection.types import RiskSignal
from src.features.page_artifacts import PageArtifacts


def _cert_date(days_ago: float) -> str:
    dt = datetime.now(timezone.utc) - timedelta(days=days_ago)
    return dt.strftime("%b %d %H:%M:%S %Y GMT")


def _artifacts(cert: dict, final_url="https://example.com") -> PageArtifacts:
    return PageArtifacts(requested_url=final_url, final_url=final_url, tls_cert=cert)


class TestNeutralCases:
    def test_no_page_artifacts_is_neutral(self):
        sig = cert_intel.evaluate(None, "https://example.com", BrandIndex())
        assert sig.triggered is False

    def test_no_tls_cert_is_neutral(self):
        artifacts = PageArtifacts(requested_url="x", tls_cert=None)
        sig = cert_intel.evaluate(artifacts, "https://example.com", BrandIndex())
        assert sig.triggered is False

    def test_old_cert_trusted_ca_is_neutral(self):
        cert = {
            "subject": [[["commonName", "example.com"]]],
            "issuer": [[["organizationName", "DigiCert Inc"]]],
            "not_before": _cert_date(400),
            "san": ["example.com"],
        }
        sig = cert_intel.evaluate(_artifacts(cert), "https://example.com", BrandIndex())
        assert sig.triggered is False

    def test_old_cert_free_ca_is_neutral(self):
        """Free CAs are extremely common among legitimate sites too -- age
        alone, without freshness, must not trigger."""
        cert = {
            "subject": [[["commonName", "example.com"]]],
            "issuer": [[["organizationName", "Let's Encrypt"]]],
            "not_before": _cert_date(200),
            "san": ["example.com"],
        }
        sig = cert_intel.evaluate(_artifacts(cert), "https://example.com", BrandIndex())
        assert sig.triggered is False

    def test_fresh_cert_trusted_ca_only_weakly_or_not_triggers(self):
        """A freshly-issued cert from a normal paid/trusted CA (not a free
        instant-issuance CA) should not hit the strong 'fresh_and_free_ca'
        axis -- only the weaker fresh_cert_only axis, if any."""
        cert = {
            "subject": [[["commonName", "example.com"]]],
            "issuer": [[["organizationName", "DigiCert Inc"]]],
            "not_before": _cert_date(1),
            "san": ["example.com"],
        }
        sig = cert_intel.evaluate(_artifacts(cert), "https://example.com", BrandIndex())
        if sig.triggered:
            assert "fresh_and_free_ca" not in sig.evidence["axes_triggered"]
            assert sig.evidence["is_free_ca"] is False


class TestTriggeredCases:
    def test_fresh_free_ca_cert_triggers_when_domain_is_recently_registered(self):
        cert = {
            "subject": [[["commonName", "totally-legit-bank.tk"]]],
            "issuer": [[["organizationName", "Let's Encrypt"]]],
            "not_before": _cert_date(0.1),
            "san": ["totally-legit-bank.tk"],
        }
        sig = cert_intel.evaluate(
            _artifacts(cert, "https://totally-legit-bank.tk"),
            "https://totally-legit-bank.tk",
            BrandIndex(),
            html_features={"is_recently_registered": True},
        )
        assert sig.triggered is True
        assert "fresh_and_free_ca" in sig.evidence["axes_triggered"]
        assert sig.evidence["is_free_ca"] is True
        assert sig.evidence["cert_age_days"] == 0
        assert sig.evidence["domain_recently_registered"] is True

    def test_fresh_free_ca_cert_triggers_when_corroborated_by_another_signal(self):
        """Domain age isn't the only path to corroboration -- an
        already-triggered brand-identity signal (e.g. brand_mismatch) is
        equally sufficient (DEC-034)."""
        cert = {
            "subject": [[["commonName", "totally-legit-bank.tk"]]],
            "issuer": [[["organizationName", "Let's Encrypt"]]],
            "not_before": _cert_date(0.1),
            "san": ["totally-legit-bank.tk"],
        }
        corroborator = RiskSignal(
            name="brand_mismatch", triggered=True, score=0.8, direction="phishing", evidence={}
        )
        sig = cert_intel.evaluate(
            _artifacts(cert, "https://totally-legit-bank.tk"),
            "https://totally-legit-bank.tk",
            BrandIndex(),
            corroborators=[corroborator],
        )
        assert sig.triggered is True
        assert "fresh_and_free_ca" in sig.evidence["axes_triggered"]
        assert sig.evidence["corroborated_by_other_signal"] is True

    def test_fresh_free_ca_cert_without_corroboration_does_not_trigger(self):
        """DEC-031's core finding: routine cert rotation on an established,
        NOT-recently-registered domain, with nothing else corroborating,
        must not trigger -- this is exactly what flagged PayPal/Google/
        Apple/Bank of America/Yahoo/Steam's real homepages live."""
        cert = {
            "subject": [[["commonName", "paypal.com"]]],
            "issuer": [[["organizationName", "Let's Encrypt"]]],
            "not_before": _cert_date(0.1),
            "san": ["paypal.com"],
        }
        sig = cert_intel.evaluate(
            _artifacts(cert, "https://paypal.com"), "https://paypal.com", BrandIndex()
        )
        assert sig.triggered is False

    def test_hostname_not_covered_by_cert_triggers(self):
        cert = {
            "subject": [[["commonName", "somethingelse.com"]]],
            "issuer": [[["organizationName", "DigiCert Inc"]]],
            "not_before": _cert_date(400),
            "san": ["somethingelse.com"],
        }
        sig = cert_intel.evaluate(
            _artifacts(cert, "https://attacker-domain.com"), "https://attacker-domain.com", BrandIndex()
        )
        assert sig.triggered is True
        assert "hostname_mismatch" in sig.evidence["axes_triggered"]

    def test_wildcard_san_covers_subdomain(self):
        cert = {
            "subject": [[["commonName", "example.com"]]],
            "issuer": [[["organizationName", "DigiCert Inc"]]],
            "not_before": _cert_date(400),
            "san": ["*.example.com"],
        }
        sig = cert_intel.evaluate(
            _artifacts(cert, "https://login.example.com"), "https://login.example.com", BrandIndex()
        )
        assert sig.triggered is False  # wildcard covers it -> no mismatch


class TestRedirectHandling:
    """A cert is captured on the FINAL hop of the redirect chain (see
    PageArtifacts.fetch), so it must be checked against the hostname the
    TLS handshake actually ran against -- not the originally-requested URL.
    Reproduces the real-world false positive: an unauthenticated
    https://mail.google.com/mail/u/0/ request 302s to
    https://accounts.google.com/ServiceLogin, whose genuine Google Trust
    Services cert is scoped to accounts.google.com only (no mail.google.com
    SAN entry) -- checking it against the pre-redirect hostname produced a
    spurious hostname_mismatch on a legitimate same-provider redirect."""

    def test_same_provider_redirect_with_cert_covering_final_host_is_not_flagged(self):
        cert = {
            "subject": [[["commonName", "accounts.google.com"]]],
            "issuer": [[["organizationName", "Google Trust Services"]]],
            "not_before": _cert_date(60),
            "san": ["accounts.google.com", "mtls.accounts.google.com"],
        }
        sig = cert_intel.evaluate(
            _artifacts(cert, final_url="https://accounts.google.com/ServiceLogin?service=mail"),
            "https://mail.google.com/mail/u/0/#inbox",
            BrandIndex(),
        )
        assert sig.triggered is False
        assert sig.evidence == {}

    def test_redirect_target_genuinely_not_covered_by_cert_still_flags(self):
        """A redirect landing on a host the cert genuinely doesn't cover
        must still trigger -- the fix changes WHICH hostname is checked,
        not whether a real mismatch is still caught."""
        cert = {
            "subject": [[["commonName", "somethingelse.com"]]],
            "issuer": [[["organizationName", "DigiCert Inc"]]],
            "not_before": _cert_date(400),
            "san": ["somethingelse.com"],
        }
        sig = cert_intel.evaluate(
            _artifacts(cert, final_url="https://attacker-final-hop.com"),
            "https://mail.google.com/mail/u/0/#inbox",
            BrandIndex(),
        )
        assert sig.triggered is True
        assert "hostname_mismatch" in sig.evidence["axes_triggered"]
        assert sig.evidence["effective_hostname"] == "attacker-final-hop.com"

    def test_missing_final_url_falls_back_to_visited_url(self):
        cert = {
            "subject": [[["commonName", "example.com"]]],
            "issuer": [[["organizationName", "DigiCert Inc"]]],
            "not_before": _cert_date(400),
            "san": ["example.com"],
        }
        artifacts = PageArtifacts(requested_url="x", final_url="", tls_cert=cert)
        sig = cert_intel.evaluate(artifacts, "https://example.com", BrandIndex())
        assert sig.triggered is False


class TestRobustness:
    def test_unparseable_date_does_not_crash(self):
        cert = {
            "subject": [[["commonName", "example.com"]]],
            "issuer": [[["organizationName", "DigiCert Inc"]]],
            "not_before": "not a real date",
            "san": ["example.com"],
        }
        sig = cert_intel.evaluate(_artifacts(cert), "https://example.com", BrandIndex())
        assert sig.triggered in (True, False)  # doesn't raise

    def test_missing_fields_does_not_crash(self):
        sig = cert_intel.evaluate(_artifacts({}), "https://example.com", BrandIndex())
        assert sig.triggered is False

    def test_result_has_latency_recorded(self):
        cert = {
            "subject": [[["commonName", "example.com"]]],
            "issuer": [[["organizationName", "DigiCert Inc"]]],
            "not_before": _cert_date(400),
            "san": ["example.com"],
        }
        sig = cert_intel.evaluate(_artifacts(cert), "https://example.com", BrandIndex())
        assert sig.latency_ms >= 0.0
