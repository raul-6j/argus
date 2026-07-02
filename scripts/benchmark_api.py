#!/usr/bin/env python3
# scripts/benchmark_api.py
# Phase 6, Task 6.2 — latency benchmark for the default (lexical-only,
# enrich=false) /detect hot path. Records p50/p95/p99 to reports/api_latency.json.
#
# Run: python scripts/benchmark_api.py

from __future__ import annotations

import json
import logging
import statistics
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import yaml  # noqa: E402

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)-8s %(name)s — %(message)s")
logger = logging.getLogger("argus.benchmark_api")

PROJECT_ROOT = Path(__file__).resolve().parents[1]

# Representative URLs for the lexical-only hot path — varied length/shape so
# the benchmark isn't measuring one degenerate case. No network I/O happens
# for any of these (enrich=false), so validity/reachability doesn't matter.
_BENCHMARK_URLS = [
    "https://example.com",
    "https://www.google.com/search?q=phishing+detection",
    "http://login-secure-update.suspicious-domain.tk/verify/account",
    "https://sub.sub2.example.co.uk/a/very/long/path/that/goes/on/for/a/while",
    "https://bit.ly/3xample",
    "https://192.168.1.1.evil.com/paypal/signin",
    "https://my-bank-account-verification.com:8443/login",
    "https://a.b.c.d.e.f.example.com/",
]

_N_REQUESTS = 200
_WARMUP_REQUESTS = 10


def _percentile(sorted_values: list[float], pct: float) -> float:
    """Nearest-rank percentile (no interpolation) — simple and sufficient
    for a benchmark report, not a statistics library replacement."""
    if not sorted_values:
        return 0.0
    idx = min(len(sorted_values) - 1, int(round(pct / 100 * (len(sorted_values) - 1))))
    return sorted_values[idx]


def run_benchmark() -> dict:
    """Run the lexical-only /detect hot path N times and compute latency percentiles.

    Returns:
        The benchmark summary dict (also written to
        ``reports/api_latency.json``).
    """
    # Use a dedicated high-rate-limit config so the benchmark's request burst
    # isn't itself throttled by the production 100/min default.
    api_config_path = PROJECT_ROOT / "configs" / "api_config.yaml"
    api_config = yaml.safe_load(api_config_path.open())
    api_config["rate_limit"] = "1000000 per minute"

    import tempfile

    with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False) as fh:
        yaml.safe_dump(api_config, fh)
        tmp_config_path = fh.name

    from src.api.app import create_app

    logger.info("Building app (loads model + warms up SHAP explainer)...")
    app = create_app(config_path=tmp_config_path)
    client = app.test_client()

    logger.info("Warming up (%d requests, not measured)...", _WARMUP_REQUESTS)
    for i in range(_WARMUP_REQUESTS):
        client.post("/detect", json={"url": _BENCHMARK_URLS[i % len(_BENCHMARK_URLS)]})

    logger.info("Benchmarking /detect (enrich=false, lexical-only hot path), %d requests...", _N_REQUESTS)
    latencies_wall_ms: list[float] = []
    latencies_reported_ms: list[float] = []
    for i in range(_N_REQUESTS):
        url = _BENCHMARK_URLS[i % len(_BENCHMARK_URLS)]
        start = time.perf_counter()
        resp = client.post("/detect", json={"url": url})
        wall_ms = (time.perf_counter() - start) * 1000
        latencies_wall_ms.append(wall_ms)
        if resp.status_code == 200:
            latencies_reported_ms.append(resp.get_json()["latency_ms"])

    latencies_wall_ms.sort()
    latencies_reported_ms.sort()

    summary = {
        "endpoint": "/detect",
        "enrich": False,
        "n_requests": _N_REQUESTS,
        "n_warmup_requests": _WARMUP_REQUESTS,
        "measured_at": datetime.now(timezone.utc).isoformat(),
        "note": (
            "Measured via Flask's in-process test_client (application-level "
            "latency, not real network/WSGI-server transport overhead). "
            "wall_clock_ms is the full client.post() call duration; "
            "reported_latency_ms is the server-computed latency_ms field "
            "each /detect response returns (Iron Law #4)."
        ),
        "wall_clock_ms": {
            "p50": round(_percentile(latencies_wall_ms, 50), 3),
            "p95": round(_percentile(latencies_wall_ms, 95), 3),
            "p99": round(_percentile(latencies_wall_ms, 99), 3),
            "mean": round(statistics.mean(latencies_wall_ms), 3),
            "min": round(min(latencies_wall_ms), 3),
            "max": round(max(latencies_wall_ms), 3),
        },
        "reported_latency_ms": {
            "p50": round(_percentile(latencies_reported_ms, 50), 3),
            "p95": round(_percentile(latencies_reported_ms, 95), 3),
            "p99": round(_percentile(latencies_reported_ms, 99), 3),
            "mean": round(statistics.mean(latencies_reported_ms), 3),
        },
    }
    logger.info(
        "wall_clock p50=%.2fms p95=%.2fms p99=%.2fms (target: p95 < 200ms)",
        summary["wall_clock_ms"]["p50"], summary["wall_clock_ms"]["p95"], summary["wall_clock_ms"]["p99"],
    )
    return summary


def main() -> None:
    summary = run_benchmark()
    reports_dir = PROJECT_ROOT / "reports"
    reports_dir.mkdir(parents=True, exist_ok=True)
    out_path = reports_dir / "api_latency.json"
    with out_path.open("w") as fh:
        json.dump(summary, fh, indent=2)
    logger.info("Wrote %s", out_path)

    if summary["wall_clock_ms"]["p95"] >= 200:
        logger.warning(
            "p95 (%.2fms) does NOT meet the < 200ms target — see Phase 6 completion criteria.",
            summary["wall_clock_ms"]["p95"],
        )


if __name__ == "__main__":
    main()
