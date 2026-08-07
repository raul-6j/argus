#!/usr/bin/env python
"""Measure real-world recall: fused detection vs. model-only (Phase 1, D2).

Samples verified-online phishing URLs from an **independent** feed (never
the same snapshot the live threat-intel pre-filter loads — that would be
circular: a prefilter hit short-circuits before either verdict path runs, so
any "improvement" measured against the prefilter's own data would just be
re-discovering the prefilter, not the fusion layer) and runs each URL
through both the ML model alone and the full detection fusion layer,
reporting the recall delta. A legitimate-brand control set (the brand
reference's own domains) measures the false-positive rate the fusion layer
introduces.

This is a **post-training validation** run, exactly like
``scripts/validate_phishtank.py`` — it does not change the model or the
brand reference; it only measures them. Reachability is recorded, not
treated as a crash condition (public phishing URLs die fast).

Usage:
    python scripts/measure_realworld_recall.py \\
        --eval-feed data/raw/feeds/threat_feed_2026-08-01.csv \\
        --sample-size 200
"""

from __future__ import annotations

import argparse
import json
import logging
import random
import statistics
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional
from urllib.parse import urlparse

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import joblib
import pandas as pd
import yaml

from src.data.loaders import normalize_url
from src.detection import run_detection
from src.detection.brand_reference import load_brand_index
from src.features import page_artifacts
from src.features.pipeline import extract_features
from src.models.feature_adapter import adapt_to_training_contract

logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")
logger = logging.getLogger("measure_realworld_recall")

_PROJECT_ROOT = Path(__file__).resolve().parents[1]
_RANDOM_SEED = 42  # reproducibility, per CLAUDE.md Iron Law #6


def _load_active_prefilter_urls(threat_intel_config_path: Path) -> set[str]:
    """URLs the *live* prefilter already loads — excluded from evaluation.

    Prevents a circular "improvement": a URL the prefilter already
    short-circuits on never reaches either the model-only or fused
    detection path at all, so it can't demonstrate anything about the
    fusion layer specifically.
    """
    if not threat_intel_config_path.is_file():
        return set()
    config = yaml.safe_load(threat_intel_config_path.read_text(encoding="utf-8")) or {}
    if not config.get("enabled"):
        return set()
    snapshot_path = _PROJECT_ROOT / config["phishtank_snapshot_path"]
    if not snapshot_path.is_file():
        return set()
    df = pd.read_csv(snapshot_path)
    if "url" not in df.columns:
        return set()
    return {normalize_url(u) for u in df["url"].dropna()}


def _hosting_category(url: str, tenant_hosting_platforms: frozenset[str]) -> str:
    """Classify a URL's hostname as ``"tenant_platform"`` or ``"standalone"``.

    Derived, not fabricated: this is the exact axis DEC-018 identified as
    the model's real-world blind spot (a domain-level feature contract
    can't distinguish "a fresh Wix tenant" from "a fresh standalone
    domain"), and it's the same hostname-suffix matching convention already
    used by ``src.api.threat_intel.phishtank.load_phishtank_hostname_index``
    and ``src.detection.signals.platform_risk`` -- deliberately not a
    finer-grained per-platform breakdown, since a modest sample size would
    make most individual platform buckets too small to read anything from.
    """
    try:
        hostname = (urlparse(url).hostname or "").lower()
    except Exception:  # noqa: BLE001 - an unparseable URL just buckets as "standalone"
        return "standalone"
    for platform in tenant_hosting_platforms:
        if hostname == platform or hostname.endswith(f".{platform}"):
            return "tenant_platform"
    return "standalone"


def _predict_one(
    url: str,
    pipeline: Any,
    threshold: float,
    detection_config: dict,
    brand_index: Any,
    tenant_hosting_platforms: frozenset[str] = frozenset(),
) -> dict[str, Any]:
    """Run both the model-only and fused verdict for a single URL."""
    fv_fast = extract_features(url)
    model_input = adapt_to_training_contract(fv_fast.features)
    model_proba = float(pipeline.predict_proba([model_input.to_vector()])[0][1])
    model_only_label = "phishing" if model_proba >= threshold else "legitimate"

    artifacts = page_artifacts.fetch(url)
    fv_full = extract_features(url, html=artifacts.html, include_domain=False)
    fused = run_detection(
        url,
        model_proba=model_proba,
        page_artifacts=artifacts if artifacts.ok else None,
        html_features=fv_full.features,
        brand_index=brand_index,
        config=detection_config,
    )

    triggered_signals = [s.name for s in fused.signals if s.triggered]

    return {
        "url": url,
        "reachable": artifacts.ok,
        "model_only_label": model_only_label,
        "model_proba": model_proba,
        "fused_label": fused.label,
        "risk_score": fused.risk_score,
        "decisive_source": fused.decisive_source,
        "hosting_category": _hosting_category(url, tenant_hosting_platforms),
        "triggered_signals": triggered_signals,
    }


def _recall(results: list[dict[str, Any]], label_key: str) -> Optional[float]:
    reachable = [r for r in results if r["reachable"]]
    if not reachable:
        return None
    tp = sum(1 for r in reachable if r[label_key] == "phishing")
    return tp / len(reachable)


def _recall_breakdown(
    results: list[dict[str, Any]], group_key: str, multi_valued: bool = False
) -> dict[str, dict[str, Any]]:
    """Group reachable results by ``group_key`` and report model-only vs.
    fused recall within each group.

    Args:
        results: The phishing-sample prediction results (not the control set).
        group_key: ``"hosting_category"`` or ``"triggered_signals"``.
        multi_valued: If ``True``, ``group_key``'s value is a list and a
            result can belong to multiple groups (a URL can trigger several
            signals at once) -- ``"none"`` is used for a result that
            triggered no signal at all.

    Returns:
        ``{group_name: {"n": int, "model_only_recall": float|None,
        "fused_recall": float|None}}``, sorted by group name for
        deterministic output.
    """
    reachable = [r for r in results if r["reachable"]]
    groups: dict[str, list[dict[str, Any]]] = {}

    for r in reachable:
        values = r[group_key] if multi_valued else [r[group_key]]
        values = values or ["none"]
        for value in values:
            groups.setdefault(value, []).append(r)

    return {
        name: {
            "n": len(members),
            "model_only_recall": _recall(members, "model_only_label"),
            "fused_recall": _recall(members, "fused_label"),
        }
        for name, members in sorted(groups.items())
    }


def _confidence_stats(results: list[dict[str, Any]]) -> dict[str, Optional[float]]:
    """Summary statistics of the model's raw phishing-probability output
    over reachable phishing-sample results -- tracked run-over-run by
    ``scripts/eval_drift.py`` as a prediction/confidence drift signal."""
    probas = [r["model_proba"] for r in results if r["reachable"]]
    if not probas:
        return {"mean": None, "stdev": None, "min": None, "max": None}
    return {
        "mean": statistics.mean(probas),
        "stdev": statistics.stdev(probas) if len(probas) > 1 else 0.0,
        "min": min(probas),
        "max": max(probas),
    }


def run(
    eval_feed: Path,
    sample_size: int = 200,
    control_sample_size: int = 30,
    threat_intel_config_path: Optional[Path] = None,
) -> dict[str, Any]:
    """Run the fused-vs-model-only recall comparison.

    Args:
        eval_feed: CSV of verified/online phishing URLs, independent of the
            live prefilter's snapshot.
        sample_size: Max phishing URLs to sample from ``eval_feed``.
        control_sample_size: Max legitimate brand domains to sample as an
            FP-rate control set.
        threat_intel_config_path: Override for the live prefilter config
            (used to compute the circularity-guard exclusion set).

    Returns:
        A JSON-serializable report dict.
    """
    api_config = yaml.safe_load((_PROJECT_ROOT / "configs" / "api_config.yaml").open())
    model_config = yaml.safe_load((_PROJECT_ROOT / "configs" / "model_config.yaml").open())
    detection_config = yaml.safe_load((_PROJECT_ROOT / "configs" / "detection_config.yaml").open())
    pipeline = joblib.load(_PROJECT_ROOT / api_config["model_path"])
    threshold = model_config.get("threshold", 0.5)
    brand_index = load_brand_index()

    ti_path = threat_intel_config_path or (_PROJECT_ROOT / "configs" / "threat_intel_config.yaml")
    excluded = _load_active_prefilter_urls(ti_path)

    tenant_hosting_platforms = frozenset(
        p.lower() for p in detection_config.get("tenant_hosting_platforms", [])
    )

    df = pd.read_csv(eval_feed)
    if "verified" in df.columns:
        df = df[df["verified"].astype(str).str.strip().str.lower() == "yes"]
    if "online" in df.columns:
        df = df[df["online"].astype(str).str.strip().str.lower() == "yes"]
    candidate_urls = [u for u in df["url"].dropna().tolist() if normalize_url(u) not in excluded]

    rng = random.Random(_RANDOM_SEED)
    urls = (
        rng.sample(candidate_urls, sample_size)
        if len(candidate_urls) > sample_size
        else candidate_urls
    )

    results = []
    for url in urls:
        try:
            results.append(
                _predict_one(
                    url, pipeline, threshold, detection_config, brand_index, tenant_hosting_platforms
                )
            )
        except Exception as exc:  # noqa: BLE001 - one URL's failure never aborts the run
            logger.warning("Prediction failed for %r: %s", url, exc)

    model_recall = _recall(results, "model_only_label")
    fused_recall = _recall(results, "fused_label")

    # DEC-031/034: previously `brand_index.brands[:control_sample_size]` --
    # literally "the first N brands in list order". brands.json is
    # front-loaded with the most globally dominant household names (PayPal,
    # Google, Microsoft, Apple, Amazon, ...), which are disproportionately
    # old-domain, high-traffic, complex-infrastructure sites (frequent CDN
    # cert rotation) -- not a representative cross-section of the full
    # 166-brand reference. A reproducible random sample (same
    # Iron-Law-#6 seed, independent of the phishing-sample rng above so it
    # doesn't shift with --sample-size) removes that positional bias while
    # keeping the run fully reproducible.
    control_rng = random.Random(_RANDOM_SEED)
    control_brands = list(brand_index.brands)
    control_sample = (
        control_rng.sample(control_brands, control_sample_size)
        if len(control_brands) > control_sample_size
        else control_brands
    )

    control_results = []
    for brand in control_sample:
        if not brand.domains:
            continue
        url = f"https://{brand.domains[0]}"
        try:
            control_results.append(_predict_one(url, pipeline, threshold, detection_config, brand_index))
        except Exception as exc:  # noqa: BLE001
            logger.warning("Control prediction failed for %r: %s", url, exc)

    model_fp_rate = _recall(control_results, "model_only_label")
    fused_fp_rate = _recall(control_results, "fused_label")

    reachable_count = sum(1 for r in results if r["reachable"])
    return {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "eval_feed": str(eval_feed),
        "excluded_prefilter_urls": len(excluded),
        "total_sampled": len(urls),
        "reachable": reachable_count,
        "reachability_rate": reachable_count / len(urls) if urls else 0.0,
        "model_only_recall": model_recall,
        "fused_recall": fused_recall,
        "recall_delta": (
            (fused_recall - model_recall) if (model_recall is not None and fused_recall is not None) else None
        ),
        "control_set_size": len(control_results),
        "model_only_fp_rate": model_fp_rate,
        "fused_fp_rate": fused_fp_rate,
        # Phase 3 (F10) additions -- see EvalRun's docstring for why these
        # are derived breakdowns, not fabricated ground-truth categories.
        "recall_by_hosting_category": _recall_breakdown(results, "hosting_category"),
        "recall_by_signal": _recall_breakdown(results, "triggered_signals", multi_valued=True),
        "confidence_stats": _confidence_stats(results),
        "note": (
            "Post-training validation only -- independent of the live prefilter "
            "snapshot (excluded above); does not modify the model or brand "
            "reference; not training data."
        ),
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--eval-feed", type=Path, required=True)
    parser.add_argument("--sample-size", type=int, default=200)
    parser.add_argument("--control-sample-size", type=int, default=30)
    parser.add_argument("--out-dir", type=Path, default=_PROJECT_ROOT / "reports")
    args = parser.parse_args()

    report = run(args.eval_feed, args.sample_size, args.control_sample_size)
    args.out_dir.mkdir(parents=True, exist_ok=True)
    date_str = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    out_path = args.out_dir / f"realworld_recall_{date_str}.json"
    out_path.write_text(json.dumps(report, indent=2), encoding="utf-8")
    logger.info("Wrote report to %s", out_path)
    logger.info(
        "model_only_recall=%s fused_recall=%s delta=%s",
        report["model_only_recall"],
        report["fused_recall"],
        report["recall_delta"],
    )


if __name__ == "__main__":
    main()
