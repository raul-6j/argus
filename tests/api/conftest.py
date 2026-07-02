"""Shared fixtures for tests/api/.

Building the Flask app loads the real trained model and warms up its SHAP
explainer (~3s, dominated by KernelExplainer for the SVM production model) —
scoped to the test session so it only pays that cost once. Network I/O
(HTML fetch, WHOIS/DNS) is mocked per-test at the extract_features call site
in src.api.detect, never real.
"""

from __future__ import annotations

from pathlib import Path

import pytest

PROJECT_ROOT = Path(__file__).resolve().parents[2]
_MODEL_PATH = PROJECT_ROOT / "models" / "production" / "model.joblib"


@pytest.fixture(scope="session")
def app():
    if not _MODEL_PATH.is_file():
        pytest.skip("Run scripts/train.py + scripts/evaluate.py first — no trained model available.")
    from src.api.app import create_app

    return create_app()


@pytest.fixture
def client(app):
    return app.test_client()
