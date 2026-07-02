"""``/health`` blueprint (Phase 6, Task 6.1) — liveness + model-loaded probe."""

from __future__ import annotations

import time

from flask import Blueprint, current_app, jsonify

health_bp = Blueprint("health", __name__)


@health_bp.get("/health")
def health():
    """Liveness probe. Every ARGUS endpoint returns latency_ms (Iron Law #4)."""
    start = time.perf_counter()
    model_loaded = bool(current_app.extensions.get("argus", {}).get("pipeline") is not None)
    latency_ms = round((time.perf_counter() - start) * 1000, 3)
    return jsonify(status="ok", model_loaded=model_loaded, latency_ms=latency_ms)
