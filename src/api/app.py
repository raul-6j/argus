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
import os
import signal
import threading
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
from werkzeug.middleware.proxy_fix import ProxyFix

from src.api.auth.api_key_routes import auth_api_keys_bp
from src.api.auth.routes import auth_bp
from src.api.auth.utils import get_secret_key
from src.api.db import create_db_engine, create_session_factory, init_db
from src.api.detect import detect_bp
from src.api.health import health_bp
from src.api.public.routes import public_bp
from src.api.scan.routes import scan_bp
from src.api.threat_intel.phishtank import load_phishtank_hostname_index, load_phishtank_index
from src.api.threat_intel.providers import build_providers
from src.api.vault.routes import vault_bp
from src.api.webapp_routes import webapp_bp
from src.detection.brand_reference import load_brand_index
from src.models.contract import FEATURE_ORDER
from src.models.explain import build_explainer, explain_single
from src.serving.cache import build_cache
from src.serving.onnx_runtime import load_predictor

logger = logging.getLogger(__name__)

PROJECT_ROOT = Path(__file__).resolve().parents[2]
_DEFAULT_API_CONFIG_PATH = PROJECT_ROOT / "configs" / "api_config.yaml"
_DEFAULT_MODEL_CONFIG_PATH = PROJECT_ROOT / "configs" / "model_config.yaml"
_DEFAULT_THREAT_INTEL_CONFIG_PATH = PROJECT_ROOT / "configs" / "threat_intel_config.yaml"
_DEFAULT_DETECTION_CONFIG_PATH = PROJECT_ROOT / "configs" / "detection_config.yaml"


def _load_config(path: Path) -> dict[str, Any]:
    with path.open("r", encoding="utf-8") as fh:
        return yaml.safe_load(fh)


def _load_threat_intel(config_path: Path) -> dict[str, Any]:
    """Build the threat-intel pre-filter state (DEC-010; provider abstraction DEC-035).

    Backward compatible by design: a deployment without
    ``threat_intel_config.yaml`` (or with ``enabled: false``) gets an
    inert, always-miss pre-filter, and ``/detect`` behaves exactly as it did
    before Phase 9.1.

    Args:
        config_path: Path to ``threat_intel_config.yaml``.

    Returns:
        ``{"enabled": bool, "phishtank_index": frozenset[str],
        "phishtank_hostname_index": frozenset[str],
        "providers": list[ThreatIntelProvider]}``. ``check_prefilter``
        (called from ``/detect``, ``/scan``, and the ``/v1`` blueprint) only
        reads ``providers`` — the two frozensets are kept in the returned
        dict for introspection/tests, not because any request path reads
        them directly anymore.
    """
    empty_state = {
        "enabled": False,
        "phishtank_index": frozenset(),
        "phishtank_hostname_index": frozenset(),
        "providers": [],
    }
    if not config_path.is_file():
        logger.info("No threat_intel_config.yaml found at %s — pre-filter disabled.", config_path)
        return empty_state

    config = _load_config(config_path)
    if not config.get("enabled", False):
        return empty_state

    snapshot_path = _resolve_threat_feed_snapshot(config)
    subdomain_platforms = frozenset(
        p.lower() for p in config.get("subdomain_per_tenant_platforms", [])
    )
    phishtank_index = load_phishtank_index(snapshot_path)
    phishtank_hostname_index = load_phishtank_hostname_index(snapshot_path, subdomain_platforms)
    return {
        "enabled": True,
        "phishtank_index": phishtank_index,
        "phishtank_hostname_index": phishtank_hostname_index,
        "providers": build_providers(
            config, phishtank_index, phishtank_hostname_index, gsb_api_key=os.environ.get("GSB_API_KEY")
        ),
    }


def reload_threat_intel(app: Flask, config_path: Path) -> None:
    """Rebuild the threat-intel pre-filter state in place, without a restart (Phase 5, F7).

    Previously, picking up a snapshot ``scripts/refresh_threat_feeds.py``
    (or a config edit like flipping ``gsb_enabled``) required restarting the
    whole process, since ``app.extensions["argus"]["threat_intel"]`` was
    only ever built once, at ``create_app()`` time. This does the same
    build (:func:`_load_threat_intel`) again and swaps the result in with a
    single dict-item assignment, which is atomic under the GIL: any request
    concurrently reading ``app.extensions["argus"]["threat_intel"]`` sees
    either the fully-old or the fully-new dict, never a half-built one —
    same "build it all first, then swap" discipline
    ``scripts/refresh_threat_feeds.py`` already uses for its own
    ``active_snapshot.txt`` pointer file.

    Wired to ``SIGHUP`` in :func:`create_app` (the standard Unix
    "reload config, don't restart the process" signal — the same one
    nginx/gunicorn use for exactly this) rather than a new authenticated
    HTTP endpoint, so this needed no new auth surface. Exposed as a plain
    function (not only reachable via the signal) so it's directly callable
    from tests and from an operator's own tooling.

    Args:
        app: The running Flask app whose ``threat_intel`` state to replace.
        config_path: Path to ``threat_intel_config.yaml`` — the same path
            originally passed to ``create_app()``.
    """
    logger.info("Reloading threat-intel pre-filter from %s...", config_path)
    try:
        new_state = _load_threat_intel(config_path)
    except Exception as exc:  # noqa: BLE001 - a bad reload must never crash a running process
        logger.error(
            "Threat-intel reload failed (%s) — keeping the previous, still-serving state.", exc
        )
        return
    app.extensions["argus"]["threat_intel"] = new_state
    logger.info(
        "Threat-intel pre-filter reloaded: enabled=%s, %d provider(s).",
        new_state["enabled"],
        len(new_state["providers"]),
    )


def _resolve_threat_feed_snapshot(config: dict[str, Any]) -> Path:
    """Resolve the active threat-feed snapshot path (Phase 1, D1).

    Prefers the ``active_snapshot.txt`` pointer written by
    ``scripts/refresh_threat_feeds.py`` inside ``config["feeds_dir"]`` (if
    present) over the manually-pinned ``phishtank_snapshot_path`` — this is
    what lets a scheduled feed refresh actually take effect on the next
    process start, without any code change. Falls back to
    ``phishtank_snapshot_path`` unchanged when no pointer exists yet, so a
    deployment that has never run the refresh script behaves exactly as
    before D1 existed.

    Args:
        config: Loaded ``threat_intel_config.yaml`` contents.

    Returns:
        An absolute path to the CSV snapshot to load.
    """
    feeds_dir = config.get("feeds_dir")
    if feeds_dir:
        pointer_path = PROJECT_ROOT / feeds_dir / "active_snapshot.txt"
        if pointer_path.is_file():
            try:
                relative = pointer_path.read_text(encoding="utf-8").strip()
                if relative:
                    return PROJECT_ROOT / relative
            except Exception as exc:  # noqa: BLE001 - a broken pointer must never crash startup
                logger.warning(
                    "Failed to read active_snapshot pointer %s: %s — falling back to "
                    "phishtank_snapshot_path.",
                    pointer_path,
                    exc,
                )
    return PROJECT_ROOT / config["phishtank_snapshot_path"]


# Bounds every Redis socket operation (connect AND read/write) for both the
# boot-time check below and the rate limiter's own connection (see
# create_app()'s `storage_options` passed to Limiter). Deliberately
# explicit: the redis-py client has no timeout by default, and a Redis
# process that hangs (rather than cleanly refusing) would otherwise block
# every request indefinitely -- discovered during Phase 2 validation, when
# a mid-session Redis failure test hung the whole test process rather than
# failing fast (see docs/DECISIONS.md DEC-027).
_REDIS_SOCKET_TIMEOUT_S = 3.0


def _connect_redis_or_fail(storage_uri: str) -> Optional[Any]:
    """Ping Redis at boot if configured; fail loud rather than silently
    unenforced (Phase 2, G2).

    Mirrors S6's SECRET_KEY fail-closed philosophy: a rate limiter that
    silently falls back to "no limit" on a Redis outage is worse than one
    that refuses to start, since the operator would have no signal that
    every rate limit in the app just stopped being enforced. ``memory://``
    (the dev default) skips this entirely -- no Redis dependency in dev.

    Args:
        storage_uri: The configured ``rate_limit_storage_uri``.

    Returns:
        A connected ``redis.Redis`` client if ``storage_uri`` is a redis
        URL, else ``None`` (memory:// or any other backend).

    Raises:
        RuntimeError: If ``storage_uri`` is a redis URL but the server is
            unreachable (including "connected but not responding within
            ``_REDIS_SOCKET_TIMEOUT_S``" -- a hang, not just a refusal).
    """
    if not storage_uri.startswith("redis://") and not storage_uri.startswith("rediss://"):
        return None

    import redis as redis_lib

    client = redis_lib.Redis.from_url(
        storage_uri,
        socket_connect_timeout=_REDIS_SOCKET_TIMEOUT_S,
        socket_timeout=_REDIS_SOCKET_TIMEOUT_S,
    )
    try:
        client.ping()
    # Broad on purpose: re-raised as a RuntimeError immediately below, so
    # this catches connection refusals, timeouts and auth errors alike.
    except Exception as exc:
        raise RuntimeError(
            f"rate_limit_storage_uri is set to {storage_uri!r} but Redis is unreachable "
            f"({exc}) -- refusing to start rather than silently running with unenforced "
            "rate limits. Fix Redis connectivity, or switch back to memory:// for a "
            "single-process dev deployment."
        ) from exc

    logger.info("Connected to Redis at %s for rate limiting / caching.", storage_uri)
    return client


# Hard ceiling on any request body, in bytes. Werkzeug checks Content-Length
# against this the moment the request stream is first touched and raises 413
# *without reading a single byte* (werkzeug.wsgi.get_input_stream), and for a
# chunked request it wraps the stream in a LimitedStream that aborts once the
# cap is passed. Either way the body is never buffered into memory, which is
# what stops an anonymous caller from spending the process's RAM on a request
# that was never going to be valid (CWE-770).
#
# Note this is enforced at body-read time, not before routing: a view or
# decorator that rejects a request without reading its body (e.g. @require_auth
# returning 401) still wins the race. That is harmless -- the request is
# refused either way and the body is still never read.
#
# 1 MiB is generous for this API: the largest legitimate body is a PUT /vault
# blob (capped separately and lower, in VaultPutSchema), and everything else is
# a URL or a list of at most `batch_max` URLs.
_DEFAULT_MAX_CONTENT_LENGTH = 1 * 1024 * 1024


def _apply_proxy_fix(app: Flask, trusted_proxy_count: int) -> None:
    """Trust exactly ``trusted_proxy_count`` reverse proxies' forwarding headers.

    Without this, ``request.remote_addr`` behind a reverse proxy (Azure
    Container Apps and nginx, the stated deployment targets) is the *proxy's*
    address for every request. flask-limiter keys its per-IP limits on that
    value, so every client in the world would share one bucket: one noisy
    caller would rate-limit everyone else, and the tighter per-IP auth limits
    (``login`` at 10/min) would stop being a brute-force control at all.

    Deliberately opt-in and count-exact rather than simply always-on. ProxyFix
    trusts the *last* ``x_for`` entries of ``X-Forwarded-For``, a header any
    client can send. If the configured count exceeds the number of proxies
    actually in front of the app, a caller can prepend forged entries and
    choose which "IP" it is rate-limited as -- turning a fix for one bypass
    into a different bypass. So the default is 0 (no ProxyFix at all, correct
    for direct exposure and for local dev), and a deployment must state how
    many hops it really has.

    ``x_host``/``x_port``/``x_prefix`` are left at 0 on purpose: nothing here
    generates absolute URLs from the request host, so honouring
    ``X-Forwarded-Host`` would add Host-header poisoning risk for no benefit.

    Args:
        app: The app whose WSGI stack to wrap.
        trusted_proxy_count: Number of trusted proxies between client and app.
            ``0`` disables the middleware entirely.

    Raises:
        ValueError: If the configured count is negative.
    """
    if trusted_proxy_count < 0:
        raise ValueError(
            f"trusted_proxy_count must be >= 0, got {trusted_proxy_count!r}."
        )
    if trusted_proxy_count == 0:
        logger.info(
            "trusted_proxy_count is 0 -- X-Forwarded-* headers are ignored and rate "
            "limits key on the direct peer address. Set it to the exact number of "
            "reverse proxies in front of this app when deploying behind one."
        )
        return

    app.wsgi_app = ProxyFix(  # type: ignore[method-assign]
        app.wsgi_app, x_for=trusted_proxy_count, x_proto=trusted_proxy_count
    )
    logger.info(
        "ProxyFix enabled: trusting the last %d X-Forwarded-For/Proto entry(ies).",
        trusted_proxy_count,
    )


def _load_detection(config_path: Path) -> dict[str, Any]:
    """Build the detection/fusion-layer state (Phase 1, DEC-A).

    Backward compatible by design: a deployment without
    ``detection_config.yaml`` (or with ``enabled: false``) gets an inert,
    disabled state, and ``/detect``/``/explain`` behave exactly as they did
    before Phase 1 — mirrors :func:`_load_threat_intel`'s convention.

    Args:
        config_path: Path to ``detection_config.yaml``.

    Returns:
        ``{"enabled": bool, "config": dict, "brand_index": BrandIndex | None}``.
    """
    empty_state = {"enabled": False, "config": {"enabled": False}, "brand_index": None}
    if not config_path.is_file():
        logger.info("No detection_config.yaml found at %s — detection fusion layer disabled.", config_path)
        return empty_state

    config = _load_config(config_path)
    if not config.get("enabled", False):
        return {"enabled": False, "config": config, "brand_index": None}

    brands_path = PROJECT_ROOT / config.get("brand_reference_path", "data/reference/brands.json")
    brand_index = load_brand_index(brands_path)
    return {"enabled": True, "config": config, "brand_index": brand_index}


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
    detection_config_path: Optional[str] = None,
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
        detection_config_path: Path to ``detection_config.yaml`` (Phase 1,
            DEC-A). Defaults to the project's
            ``configs/detection_config.yaml``; if that file doesn't exist
            or is disabled, the fusion layer is inert and ``/detect``/
            ``/explain`` behave exactly as they did before Phase 1.

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

    # Rejected by Werkzeug without the body ever being read -- see
    # _DEFAULT_MAX_CONTENT_LENGTH. Surfaced as JSON by the 413 handler
    # registered below, like every other error in this API.
    app.config["MAX_CONTENT_LENGTH"] = api_config.get(
        "max_content_length_bytes", _DEFAULT_MAX_CONTENT_LENGTH
    )

    # Must wrap the WSGI app before the limiter is constructed below, so the
    # very first request already sees a corrected remote_addr.
    _apply_proxy_fix(app, int(api_config.get("trusted_proxy_count", 0)))

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

    # F19: a *separate* pool for async scan jobs (POST /v1/scan/async) --
    # deliberately not the enrichment pool above. Async job submissions and
    # synchronous /v1/scan enrichment work would otherwise contend for the
    # same bounded set of workers, letting a burst of one starve the other.
    job_executor = concurrent.futures.ThreadPoolExecutor(
        max_workers=api_config.get("async_job_max_workers", 4)
    )

    resolved_threat_intel_config_path = (
        Path(threat_intel_config_path) if threat_intel_config_path else _DEFAULT_THREAT_INTEL_CONFIG_PATH
    )
    threat_intel = _load_threat_intel(resolved_threat_intel_config_path)

    detection = _load_detection(
        Path(detection_config_path) if detection_config_path else _DEFAULT_DETECTION_CONFIG_PATH
    )

    # Phase 2 (G1): an optional, numerically-validated ONNX inference path
    # for the hot predict_proba call. /explain and /v1/explain deliberately
    # keep using `pipeline` (the sklearn model) directly for SHAP, which
    # depends on the sklearn internals -- `predictor` is only for the
    # plain phishing-probability computation on /detect, /scan, /v1/scan(/batch).
    serving_config = model_config.get("serving", {})
    onnx_path = PROJECT_ROOT / serving_config["onnx_path"] if serving_config.get("onnx_path") else None
    predictor = load_predictor(serving_config.get("backend", "sklearn"), onnx_path, pipeline)

    app.extensions["argus"] = {
        "pipeline": pipeline,
        "predictor": predictor,
        "explainer": explainer,
        "model_type": model_type,
        "threshold": model_config.get("threshold", 0.5),
        "executor": executor,
        "job_executor": job_executor,
        "config": api_config,
        "threat_intel": threat_intel,
        "detection": detection,
    }

    # Phase 5 (F7): SIGHUP triggers an in-place threat-intel reload -- no
    # restart needed to pick up a fresh `scripts/refresh_threat_feeds.py`
    # snapshot or a `gsb_enabled`/`GSB_API_KEY` change. Standard Unix
    # "reload config" convention (nginx/gunicorn use the same signal for
    # the same reason), so no new auth surface was needed. signal.signal()
    # only works from the interpreter's main thread -- guarded rather than
    # asserted, since create_app() is also called from test fixtures/worker
    # threads where registering a handler isn't meaningful anyway.
    if threading.current_thread() is threading.main_thread():
        signal.signal(
            signal.SIGHUP,
            lambda signum, frame: reload_threat_intel(app, resolved_threat_intel_config_path),
        )

    app.register_blueprint(health_bp)
    app.register_blueprint(detect_bp)
    app.register_blueprint(auth_bp)
    app.register_blueprint(auth_api_keys_bp)
    app.register_blueprint(vault_bp)
    app.register_blueprint(scan_bp)
    app.register_blueprint(public_bp)
    app.register_blueprint(webapp_bp)

    CORS(app, resources={r"/*": {"origins": api_config.get("cors_origins", [])}})

    rate_limit_storage_uri = api_config.get("rate_limit_storage_uri", "memory://")
    redis_client = _connect_redis_or_fail(rate_limit_storage_uri)
    app.extensions["argus"]["redis_client"] = redis_client

    # Phase 2 (G1): points at the same Redis *server* the rate limiter
    # below uses (not a shared client object -- Limiter's `storage_uri`
    # makes its own independent connection internally via the `limits`
    # library, same as this one does via _connect_redis_or_fail; two
    # separate connections to one server is normal and cheap, not wasteful).
    # Falls back to an in-process cache when redis_client is None (memory://
    # dev mode).
    app.extensions["argus"]["cache"] = build_cache(api_config, redis_client)

    limiter = Limiter(
        key_func=get_remote_address,
        app=app,
        default_limits=[api_config.get("rate_limit", "100 per minute")],
        storage_uri=rate_limit_storage_uri,
        # Bounds the limiter's own (separate) Redis connection the same way
        # _connect_redis_or_fail's boot-time check is bounded -- without
        # this, a hung (not just refused) Redis leaves every request
        # blocked indefinitely instead of failing fast. No effect when
        # storage_uri is memory:// (the option is simply unused).
        storage_options={
            "socket_connect_timeout": _REDIS_SOCKET_TIMEOUT_S,
            "socket_timeout": _REDIS_SOCKET_TIMEOUT_S,
        },
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

    # Phase 2 (C1): /scan does a real outbound fetch of a user-supplied URL
    # and is public/unauthenticated -- a dedicated, stricter limit than the
    # global default, same retrofit pattern as the auth routes above.
    app.view_functions["scan.create_scan"] = limiter.limit(
        api_config.get("scan_rate_limit", "20 per minute")
    )(app.view_functions["scan.create_scan"])

    # Phase 2 (C3): key management is JWT-authenticated but still worth a
    # dedicated cap -- a stolen access token shouldn't be able to mint an
    # unbounded number of API keys.
    api_key_mgmt_limit = api_config.get("api_key_mgmt_rate_limit", "20 per minute")
    for endpoint in (
        "auth_api_keys.create_api_key",
        "auth_api_keys.list_api_keys",
        "auth_api_keys.revoke_api_key",
    ):
        app.view_functions[endpoint] = limiter.limit(api_key_mgmt_limit)(app.view_functions[endpoint])

    # Phase 2 (C3): /v1/* endpoints are limited per-API-key (not per-IP) --
    # wired inside src.api.public.routes itself via a dynamic key_func,
    # since the limit *value* depends on the caller's tier, which isn't
    # known until the key is verified. See public/routes.py::_configure_limits.
    from src.api.public.routes import configure_limits as _configure_public_limits

    _configure_public_limits(app, limiter, api_config)

    @app.errorhandler(404)
    def _not_found(_exc):
        return jsonify(error="not found"), 404

    @app.errorhandler(429)
    def _rate_limited(_exc):
        return jsonify(error="rate limit exceeded"), 429

    # Werkzeug aborts an over-MAX_CONTENT_LENGTH request itself; without this
    # the caller gets Werkzeug's HTML error page instead of the JSON shape
    # every other error path in this API returns.
    @app.errorhandler(413)
    def _payload_too_large(_exc):
        return jsonify(error="request body too large"), 413

    # Phase 2 (G2): a Redis outage *after* boot (the boot-time check above
    # only catches an outage at startup) makes flask-limiter propagate a
    # raw redis.exceptions.RedisError out of its before_request hook --
    # correctly fail-closed (the request never reaches the view, so no
    # limit is silently bypassed) but, uncaught, that's an ugly unhandled
    # 500/HTML error rather than a clean, intentional response. Mapped to
    # 503 here: "rate limiting is temporarily unavailable, try again" is
    # the honest, correct status for this condition, and keeps every error
    # response in the API JSON-shaped, matching every other error path.
    import redis as _redis_lib

    @app.errorhandler(_redis_lib.exceptions.RedisError)
    def _rate_limit_backend_unavailable(_exc):
        logger.error("Rate limiter's Redis backend is unreachable mid-session: %s", _exc)
        return jsonify(error="rate limiting temporarily unavailable"), 503

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
