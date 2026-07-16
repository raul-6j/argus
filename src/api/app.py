"""ARGUS Flask application factory (Phase 6, Tasks 6.1/6.2).

Loads the trained model, its metadata, and a SHAP explainer exactly once at
process startup — never per-request (Task 6.1). Runs a warmup prediction to
catch joblib/sklearn version drift or a missing model file at boot rather
than on the first real request. Registers the ``/health`` and ``/detect`` +
``/explain`` blueprints, applies CORS locked to the configured extension
origin(s), and wires a rate limiter.
"""

from __future__ import annotations

import concurrent.futures
import json
import logging
from pathlib import Path
from typing import Any, Optional

import joblib
import numpy as np
import pandas as pd
import yaml
from flask import Flask, jsonify
from flask_cors import CORS
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

from src.api.auth.routes import auth_bp
from src.api.auth.utils import get_secret_key
from src.api.db import create_db_engine, create_session_factory, init_db
from src.api.detect import detect_bp
from src.api.health import health_bp
from src.api.threat_intel.phishtank import load_phishtank_hostname_index, load_phishtank_index
from src.api.vault.routes import vault_bp
from src.models.contract import FEATURE_ORDER
from src.models.explain import build_explainer, explain_single

logger = logging.getLogger(__name__)

PROJECT_ROOT = Path(__file__).resolve().parents[2]
_DEFAULT_API_CONFIG_PATH = PROJECT_ROOT / "configs" / "api_config.yaml"
_DEFAULT_MODEL_CONFIG_PATH = PROJECT_ROOT / "configs" / "model_config.yaml"
_DEFAULT_THREAT_INTEL_CONFIG_PATH = PROJECT_ROOT / "configs" / "threat_intel_config.yaml"


def _load_config(path: Path) -> dict[str, Any]:
    with path.open("r", encoding="utf-8") as fh:
        return yaml.safe_load(fh)


def _load_threat_intel(config_path: Path) -> dict[str, Any]:
    """Build the threat-intel pre-filter state (DEC-010).

    Backward compatible by design: a deployment without
    ``threat_intel_config.yaml`` (or with ``enabled: false``) gets an
    inert, always-miss pre-filter, and ``/detect`` behaves exactly as it did
    before Phase 9.1.

    Args:
        config_path: Path to ``threat_intel_config.yaml``.

    Returns:
        ``{"enabled": bool, "phishtank_index": frozenset[str],
        "phishtank_hostname_index": frozenset[str]}``.
    """
    empty_state = {
        "enabled": False,
        "phishtank_index": frozenset(),
        "phishtank_hostname_index": frozenset(),
    }
    if not config_path.is_file():
        logger.info("No threat_intel_config.yaml found at %s — pre-filter disabled.", config_path)
        return empty_state

    config = _load_config(config_path)
    if not config.get("enabled", False):
        return empty_state

    snapshot_path = PROJECT_ROOT / config["phishtank_snapshot_path"]
    subdomain_platforms = frozenset(
        p.lower() for p in config.get("subdomain_per_tenant_platforms", [])
    )
    return {
        "enabled": True,
        "phishtank_index": load_phishtank_index(snapshot_path),
        "phishtank_hostname_index": load_phishtank_hostname_index(snapshot_path, subdomain_platforms),
    }


def _load_background_sample(train_path: Path, max_rows: int = 200) -> Optional[np.ndarray]:
    """Load a bounded sample of training features for the SHAP explainer background.

    Args:
        train_path: Path to ``data/processed/train.parquet``.
        max_rows: Cap on rows loaded — the explainer itself further
            summarizes this via k-means (see ``src.models.explain``), so a
            large sample here just wastes memory/load time.

    Returns:
        A ``(n, 18)`` array, or ``None`` if the training split isn't present
        (e.g. a minimal deployment shipping only the model artefact).
    """
    if not train_path.is_file():
        logger.warning(
            "Training split not found at %s — explainer background unavailable", train_path
        )
        return None
    df = pd.read_parquet(train_path)
    if len(df) > max_rows:
        df = df.sample(max_rows, random_state=42)
    return df[list(FEATURE_ORDER)].to_numpy(dtype=float)


def _warmup(pipeline: Any, explainer: Any, model_type: str) -> None:
    """Run one dummy prediction (+ explanation) to catch startup-time failures early.

    Args:
        pipeline: The loaded model pipeline.
        explainer: The built SHAP explainer.
        model_type: The model key, forwarded to the explainer call.

    Raises:
        Exception: Whatever the underlying predict/explain call raises —
            intentionally not caught here, so ``create_app()`` fails loudly
            and immediately if the model/explainer is broken, rather than on
            the first real request.
    """
    dummy_vector = [1] * len(FEATURE_ORDER)
    pipeline.predict_proba([dummy_vector])
    dummy_features = dict(zip(FEATURE_ORDER, dummy_vector))
    explain_single(dummy_features, pipeline, explainer, model_type)
    logger.info("Warmup prediction + explanation succeeded.")


def create_app(
    config_path: Optional[str] = None,
    model_config_path: Optional[str] = None,
    threat_intel_config_path: Optional[str] = None,
) -> Flask:
    """Build and configure the ARGUS Flask application.

    Args:
        config_path: Path to ``api_config.yaml``. Defaults to the project's
            ``configs/api_config.yaml``. Overridable so tests can point at a
            fixture config with different model/CORS settings.
        model_config_path: Path to ``model_config.yaml`` (source of the
            calibrated decision threshold, DEC-017). Defaults to the
            project's ``configs/model_config.yaml``.
        threat_intel_config_path: Path to ``threat_intel_config.yaml``
            (DEC-010). Defaults to the project's
            ``configs/threat_intel_config.yaml``; if that file doesn't
            exist, the pre-filter is disabled and ``/detect`` behaves as it
            did before Phase 9.1.

    Returns:
        A configured :class:`flask.Flask` instance, ready to serve.
    """
    # S6: fail closed on a missing SECRET_KEY, before doing any other work
    # (loading the model takes seconds; no point paying that cost if we're
    # about to refuse to start anyway).
    secret_key = get_secret_key()

    api_config = _load_config(Path(config_path) if config_path else _DEFAULT_API_CONFIG_PATH)
    model_config = _load_config(
        Path(model_config_path) if model_config_path else _DEFAULT_MODEL_CONFIG_PATH
    )

    app = Flask(__name__)
    app.config["ALLOW_LOCALHOST"] = api_config.get("allow_localhost", False)
    app.config["AUTH_DEV_RETURN_OTP"] = api_config.get("auth_dev_return_otp", False)

    db_engine = create_db_engine(api_config.get("database_url", "sqlite:///argus.db"))
    init_db(db_engine)
    session_factory = create_session_factory(db_engine)
    app.extensions["argus_auth"] = {
        "secret_key": secret_key,
        "session_factory": session_factory,
        "db_engine": db_engine,
    }

    model_path = PROJECT_ROOT / api_config["model_path"]
    metadata_path = PROJECT_ROOT / api_config["model_metadata_path"]
    pipeline = joblib.load(model_path)
    metadata = json.loads(metadata_path.read_text()) if metadata_path.is_file() else {}
    model_type = metadata.get("model_type", "svm")

    train_path = PROJECT_ROOT / model_config["data"]["train_path"]
    background_sample = _load_background_sample(train_path)
    explainer = (
        build_explainer(model_type, pipeline, background_sample)
        if background_sample is not None
        else None
    )

    if explainer is not None:
        _warmup(pipeline, explainer, model_type)
    else:
        logger.warning(
            "No explainer background available — skipping warmup and /explain readiness check."
        )

    executor = concurrent.futures.ThreadPoolExecutor(
        max_workers=api_config.get("enrichment_max_workers", 8)
    )

    threat_intel = _load_threat_intel(
        Path(threat_intel_config_path) if threat_intel_config_path else _DEFAULT_THREAT_INTEL_CONFIG_PATH
    )

    app.extensions["argus"] = {
        "pipeline": pipeline,
        "explainer": explainer,
        "model_type": model_type,
        "threshold": model_config.get("threshold", 0.5),
        "executor": executor,
        "config": api_config,
        "threat_intel": threat_intel,
    }

    app.register_blueprint(health_bp)
    app.register_blueprint(detect_bp)
    app.register_blueprint(auth_bp)
    app.register_blueprint(vault_bp)

    CORS(app, resources={r"/*": {"origins": api_config.get("cors_origins", [])}})

    limiter = Limiter(
        key_func=get_remote_address,
        app=app,
        default_limits=[api_config.get("rate_limit", "100 per minute")],
        storage_uri=api_config.get("rate_limit_storage_uri", "memory://"),
    )
    app.extensions["argus"]["limiter"] = limiter

    # Extra, tighter limits on the auth endpoints most attractive to brute
    # force/credential-stuffing, independent of S4's per-account OTP
    # lockout (which only kicks in after an OTP has been issued).
    #
    # limiter.limit(...) returns a LimitDecorator whose __call__ returns a
    # NEW wrapped function -- it does not mutate the view in place. Flask
    # dispatches by looking up app.view_functions[endpoint] on every
    # request, so the wrapped function must be written back into that dict;
    # calling the decorator and discarding the result (as an earlier version
    # of this code did) silently applies no limit at all.
    auth_rate_limits = api_config.get(
        "auth_rate_limits",
        {"login": "10 per minute", "signup": "5 per minute", "verify_otp": "10 per minute"},
    )
    for endpoint, config_key in (
        ("auth.login", "login"),
        ("auth.signup", "signup"),
        ("auth.verify_otp", "verify_otp"),
    ):
        app.view_functions[endpoint] = limiter.limit(auth_rate_limits[config_key])(
            app.view_functions[endpoint]
        )

    @app.errorhandler(404)
    def _not_found(_exc):
        return jsonify(error="not found"), 404

    @app.errorhandler(429)
    def _rate_limited(_exc):
        return jsonify(error="rate limit exceeded"), 429

    return app


# `flask --app src/api/app run` discovers this module-level instance. Only
# built when the model artefacts actually exist, so importing this module
# for testing (with a custom create_app(config_path=...) call) doesn't
# require a trained model to be present.
app: Optional[Flask] = None
if (PROJECT_ROOT / "models" / "production" / "model.joblib").is_file():
    app = create_app()


if __name__ == "__main__":
    (app or create_app()).run(debug=True)
