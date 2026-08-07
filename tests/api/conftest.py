"""Shared fixtures for tests/api/.

Building the Flask app loads the real trained model and warms up its SHAP
explainer (~3s, dominated by KernelExplainer for the SVM production model) —
scoped to the test session so it only pays that cost once. Network I/O
(HTML fetch, WHOIS/DNS) is mocked per-test at the extract_features call site
in src.api.detect, never real.

The auth/vault database is pointed at an isolated in-memory SQLite instance
for the whole test session (not the real configs/api_config.yaml
``database_url``) — otherwise every test run would create/pollute a real
``argus_dev.db`` file at the project root.
"""

from __future__ import annotations

import tempfile
from pathlib import Path

import pytest
import yaml
from sqlalchemy import delete

PROJECT_ROOT = Path(__file__).resolve().parents[2]
_MODEL_PATH = PROJECT_ROOT / "models" / "production" / "model.joblib"


@pytest.fixture(scope="session")
def app():
    if not _MODEL_PATH.is_file():
        pytest.skip("Run scripts/train.py + scripts/evaluate.py first — no trained model available.")
    from src.api.app import create_app

    api_config = yaml.safe_load((PROJECT_ROOT / "configs" / "api_config.yaml").open())
    api_config["database_url"] = "sqlite:///:memory:"
    # Dev-only OTP-in-response flag (see DEC-021) -- needed so auth tests can
    # complete a signup -> verify-otp flow without a real email backend.
    api_config["auth_dev_return_otp"] = True
    # This app is session-scoped and shared by every test in tests/api/, all
    # calling from the same test-client "IP" -- the real per-route auth
    # limits (5-10/minute) would be exhausted by the test suite itself long
    # before any test intends to check rate-limiting behavior. Relaxed here;
    # the actual production defaults are verified against a dedicated,
    # freshly-built app in tests/api/auth/test_rate_limits.py.
    api_config["auth_rate_limits"] = {
        "login": "10000 per minute",
        "signup": "10000 per minute",
        "verify_otp": "10000 per minute",
    }
    # Same reasoning as auth_rate_limits above: this session-scoped app is
    # shared by every test in tests/api/scan/ (and, since Phase 4, the
    # optional_auth tests in tests/api/auth/ that also POST /scan) from the
    # same test-client "IP" -- the real 20/minute scan_rate_limit would be
    # exhausted by the test suite's own cumulative call volume long before
    # any test intends to check it. scan_rate_limit's actual production
    # default is exercised separately in tests/api/test_rate_limit.py against
    # a dedicated, freshly-built app.
    api_config["scan_rate_limit"] = "10000 per minute"
    # Phase 2 (G1): this app is session-scoped and shared by every test in
    # tests/api/ -- a real verdict cache would leak a mocked extract_features
    # result from one test's URL into a later test mocking the same URL
    # differently. Cache correctness itself is covered by dedicated tests in
    # tests/serving/test_cache.py; disabled here purely for test isolation,
    # matching how auth_rate_limits above is relaxed for the same reason.
    api_config["cache"] = {"enabled": False}

    with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False) as fh:
        yaml.safe_dump(api_config, fh)
        tmp_config_path = fh.name

    return create_app(config_path=tmp_config_path)


@pytest.fixture
def client(app):
    return app.test_client()


@pytest.fixture
def db_session(app):
    """A fresh SQLAlchemy session bound to the test app's in-memory DB."""
    session_factory = app.extensions["argus_auth"]["session_factory"]
    session = session_factory()
    yield session
    session.close()


@pytest.fixture(autouse=True)
def _clean_auth_db(app):
    """Wipe auth/vault tables before every test in tests/api/ (and below).

    The `app` fixture is session-scoped (expensive: model + SHAP explainer
    load), so all tests share one in-memory database. Without this, state
    from one auth/vault test (users, tokens, OTPs) would leak into the next.
    Cheap and harmless for tests that don't touch auth at all.
    """
    from src.api.auth.models import Otp, RefreshToken, User
    from src.api.public.models import ApiKey, ScanJob
    from src.api.scan.models import UserScan
    from src.api.vault.models import VaultEntry

    session_factory = app.extensions["argus_auth"]["session_factory"]
    with session_factory() as session:
        session.execute(delete(VaultEntry))
        session.execute(delete(UserScan))
        session.execute(delete(ScanJob))
        session.execute(delete(ApiKey))
        session.execute(delete(RefreshToken))
        session.execute(delete(Otp))
        session.execute(delete(User))
        session.commit()
    yield
