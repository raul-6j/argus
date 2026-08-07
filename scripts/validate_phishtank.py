#!/usr/bin/env python3
# scripts/validate_phishtank.py
# Phase 5, Task 5.4 — post-training validation against a live PhishTank
# snapshot. This is a VALIDATION layer, not training data (Interim Report):
# the model is trained/selected on UCI+Kaggle only; PhishTank URLs are run
# through the deployed model to measure generalisation to current,
# never-seen-in-training phishing URLs.
#
# Run: python scripts/validate_phishtank.py --snapshot data/raw/phishtank_2026-07-02.csv

from __future__ import annotations

import argparse
import concurrent.futures
import json
import logging
import sys
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import joblib
import pandas as pd
import yaml

from src.features.pipeline import extract_features
from src.models.feature_adapter import adapt_to_training_contract

logging.basicConfig(level=logging.WARNING, format="%(asctime)s %(levelname)-8s %(name)s — %(message)s")
logger = logging.getLogger("argus.validate_phishtank")
logger.setLevel(logging.INFO)

PROJECT_ROOT = Path(__file__).resolve().parents[1]

# Full PhishTank snapshots run 60k+ URLs; at ~0.5-4s/URL for live HTML+WHOIS
# fetches, that's hours-to-days of runtime, infeasible for a one-time
# validation exercise. Sample a reproducible subset instead. See DEC-018.
_DEFAULT_SAMPLE_SIZE = 300
_DEFAULT_MAX_WORKERS = 20


def _predict_one(url: str, pipeline, threshold: float) -> dict:
    """Run the full live pipeline on one URL: extract -> adapt -> predict.

    Args:
        url: A PhishTank URL (all known-phishing, per DEC-007/PhishTank's own
            verified=yes filter).
        pipeline: The loaded production model pipeline.
        threshold: The calibrated decision threshold (DEC-017).

    Returns:
        A per-URL result dict — never raises; extraction/prediction failures
        are captured in the result rather than crashing the batch run.
    """
    try:
        fv = extract_features(url, fetch_html=True, include_domain=True)
        model_input = adapt_to_training_contract(fv.features)
        proba = pipeline.predict_proba([model_input.to_vector()])[0][1]
        predicted_phishing = bool(proba >= threshold)
        return {
            "url": url,
            "reachable": "html" in fv.components_run,
            "domain_intel_ran": "domain_intel" in fv.components_run,
            # DEC-040 split what used to be one muddled counter: `approximated`
            # now means "measured via a proxy" (a fixed property of the
            # derivation), while `unavailable` means "not measurable for this
            # URL" — the number that actually varies per URL and explains a
            # weak score.
            "n_features_approximated": len(model_input.approximated),
            "n_features_unavailable": len(model_input.unavailable),
            "evidence_ratio": round(model_input.evidence_ratio, 4),
            "proba_phishing": float(proba),
            "predicted_phishing": predicted_phishing,
            "error": None,
        }
    except Exception as exc:  # noqa: BLE001 - one bad URL must not kill the batch
        logger.warning("Prediction failed for %r: %s", url, exc)
        return {
            "url": url,
            "reachable": False,
            "domain_intel_ran": False,
            "n_features_approximated": None,
            "n_features_unavailable": None,
            "evidence_ratio": None,
            "proba_phishing": None,
            "predicted_phishing": None,
            "error": str(exc),
        }


def run_validation(
    snapshot_path: Path,
    model_config: dict,
    sample_size: int = _DEFAULT_SAMPLE_SIZE,
    max_workers: int = _DEFAULT_MAX_WORKERS,
    random_state: int = 42,
) -> dict:
    """Sample PhishTank URLs, run the production model, and summarise results.

    Args:
        snapshot_path: Path to a `phishtank_<date>.csv` snapshot (Task 4.3).
        model_config: Parsed model_config.yaml (for the production dir + calibrated threshold).
        sample_size: Number of URLs to sample (reproducibly) and validate.
        max_workers: Thread pool size for concurrent live fetches.
        random_state: Seed for the URL sample.

    Returns:
        The results dict, in the shape `reports/phishtank_validation.json` is
        written as.
    """
    snapshot_path = snapshot_path.resolve()
    df = pd.read_csv(snapshot_path)
    total_urls = len(df)
    sample_size = min(sample_size, total_urls)
    sample = df["url"].sample(sample_size, random_state=random_state).tolist()

    production_dir = PROJECT_ROOT / model_config["output"]["production_dir"]
    pipeline = joblib.load(production_dir / "model.joblib")
    threshold = model_config["threshold"]

    logger.info(
        "Validating %d/%d PhishTank URLs (random_state=%d) against the production "
        "model at threshold=%.2f, %d concurrent workers...",
        sample_size, total_urls, random_state, threshold, max_workers,
    )

    results: list[dict] = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {executor.submit(_predict_one, url, pipeline, threshold): url for url in sample}
        for i, future in enumerate(concurrent.futures.as_completed(futures), 1):
            results.append(future.result())
            if i % 50 == 0:
                logger.info("Processed %d/%d...", i, sample_size)

    reachable = [r for r in results if r["reachable"]]
    predicted = [r for r in reachable if r["predicted_phishing"] is not None]
    tp = sum(1 for r in predicted if r["predicted_phishing"] is True)
    fn = sum(1 for r in predicted if r["predicted_phishing"] is False)

    reachability_rate = len(reachable) / len(results) if results else 0.0
    tp_rate = tp / len(predicted) if predicted else None
    fn_rate = fn / len(predicted) if predicted else None

    summary = {
        "snapshot_path": str(snapshot_path.relative_to(PROJECT_ROOT)),
        "snapshot_date": snapshot_path.stem.replace("phishtank_", ""),
        "total_urls_in_snapshot": total_urls,
        "sample_size": sample_size,
        "sample_random_state": random_state,
        "reachable_urls": len(reachable),
        "reachability_rate": reachability_rate,
        "predicted_urls": len(predicted),
        "tp_rate": tp_rate,
        "fn_rate": fn_rate,
        "true_positives": tp,
        "false_negatives": fn,
        "threshold_used": threshold,
        "evaluated_at": datetime.now(timezone.utc).isoformat(),
        "note": (
            "Post-training validation only, not training data. All PhishTank URLs "
            "are known-phishing (verified=yes per PhishTank's own filter) — this "
            "measures the deployed model's true-positive/false-negative rate on "
            "current real-world phishing it never saw during training, not "
            "precision/accuracy (no legitimate URLs in this sample)."
        ),
        "per_url_results": results,
    }
    logger.info(
        "Reachability: %.1f%% (%d/%d) | TP rate: %s | FN rate: %s (of %d reachable+predicted)",
        reachability_rate * 100, len(reachable), len(results),
        f"{tp_rate:.4f}" if tp_rate is not None else "n/a",
        f"{fn_rate:.4f}" if fn_rate is not None else "n/a",
        len(predicted),
    )
    return summary


def main() -> None:
    parser = argparse.ArgumentParser(description="PhishTank post-training validation (Task 5.4).")
    parser.add_argument("--snapshot", type=Path, required=True, help="Path to phishtank_<date>.csv")
    parser.add_argument("--config", type=Path, default=PROJECT_ROOT / "configs" / "model_config.yaml")
    parser.add_argument("--sample-size", type=int, default=_DEFAULT_SAMPLE_SIZE)
    parser.add_argument("--max-workers", type=int, default=_DEFAULT_MAX_WORKERS)
    args = parser.parse_args()

    with args.config.open() as fh:
        model_config = yaml.safe_load(fh)

    summary = run_validation(
        args.snapshot, model_config, sample_size=args.sample_size, max_workers=args.max_workers
    )

    reports_dir = PROJECT_ROOT / model_config["output"]["reports_dir"]
    reports_dir.mkdir(parents=True, exist_ok=True)
    out_path = reports_dir / "phishtank_validation.json"
    with out_path.open("w") as fh:
        json.dump(summary, fh, indent=2)
    logger.info("Wrote %s", out_path)


if __name__ == "__main__":
    main()
