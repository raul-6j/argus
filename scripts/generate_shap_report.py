#!/usr/bin/env python3
# scripts/generate_shap_report.py
# Phase 5, Task 5.3 — threshold calibration (validation set only) + SHAP
# global summary plots for the production model.
# Run: python scripts/generate_shap_report.py --config configs/model_config.yaml

from __future__ import annotations

import argparse
import json
import logging
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import joblib  # noqa: E402
import matplotlib  # noqa: E402

matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402
import numpy as np  # noqa: E402
import pandas as pd  # noqa: E402
import shap  # noqa: E402
import yaml  # noqa: E402
from sklearn.metrics import f1_score, precision_score, recall_score  # noqa: E402

from src.models.contract import FEATURE_ORDER  # noqa: E402
from src.models.explain import build_explainer  # noqa: E402
from src.models.train import load_split  # noqa: E402

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)-8s %(name)s — %(message)s")
logging.getLogger("shap").setLevel(logging.WARNING)  # shap's own logger is very chatty at INFO
logger = logging.getLogger("argus.generate_shap_report")

PROJECT_ROOT = Path(__file__).resolve().parents[1]

# Number of test rows to run through KernelExplainer for the summary plot.
# Keeps the (SVM/LR) KernelExplainer path bounded — see explain.py's
# _KERNEL_BACKGROUND_SIZE/_KERNEL_NSAMPLES tuning notes.
_SHAP_SUMMARY_SAMPLE_SIZE = 60


def calibrate_threshold(config: dict) -> dict:
    """Sweep decision thresholds 0.3-0.7 on the VALIDATION set (never test).

    Args:
        config: Parsed model_config.yaml.

    Returns:
        Dict with the full sweep table and the chosen threshold (max F1).
    """
    production_dir = PROJECT_ROOT / config["output"]["production_dir"]
    val_path = PROJECT_ROOT / config["data"]["val_path"]
    pipeline = joblib.load(production_dir / "model.joblib")
    X_val, y_val = load_split(val_path)
    proba = pipeline.predict_proba(X_val)[:, 1]

    sweep = []
    for threshold in np.arange(0.30, 0.70 + 1e-9, 0.05):
        threshold = round(float(threshold), 2)
        y_pred = (proba >= threshold).astype(int)
        sweep.append(
            {
                "threshold": threshold,
                "f1": float(f1_score(y_val, y_pred)),
                "precision": float(precision_score(y_val, y_pred, zero_division=0)),
                "recall": float(recall_score(y_val, y_pred, zero_division=0)),
                "fn_rate": float(1 - recall_score(y_val, y_pred, zero_division=0)),
            }
        )

    best = max(sweep, key=lambda row: row["f1"])
    logger.info("Threshold sweep (validation set):")
    for row in sweep:
        logger.info(
            "  threshold=%.2f  f1=%.4f  precision=%.4f  recall=%.4f  fn_rate=%.4f",
            row["threshold"], row["f1"], row["precision"], row["recall"], row["fn_rate"],
        )
    logger.info("Selected threshold=%.2f (max F1=%.4f on validation set)", best["threshold"], best["f1"])
    return {"sweep": sweep, "selected_threshold": best["threshold"], "selected_metrics": best}


def generate_shap_plots(config: dict) -> None:
    """Generate a global SHAP beeswarm + bar summary plot for the production model.

    Args:
        config: Parsed model_config.yaml.
    """
    production_dir = PROJECT_ROOT / config["output"]["production_dir"]
    reports_dir = PROJECT_ROOT / config["output"]["reports_dir"]
    train_path = PROJECT_ROOT / config["data"]["train_path"]
    test_path = PROJECT_ROOT / config["data"]["test_path"]

    metadata = json.loads((production_dir / "metadata.json").read_text())
    model_type = metadata["model_type"]

    pipeline = joblib.load(production_dir / "model.joblib")
    X_train, _ = load_split(train_path)
    X_test, _ = load_split(test_path)

    rng = np.random.default_rng(42)
    sample_size = min(_SHAP_SUMMARY_SAMPLE_SIZE, len(X_test))
    sample_idx = rng.choice(len(X_test), size=sample_size, replace=False)
    X_sample = X_test[sample_idx]

    logger.info(
        "Building %s explainer and computing SHAP values for %d test rows...",
        model_type, sample_size,
    )
    explainer = build_explainer(model_type, pipeline, X_train)
    raw = (
        explainer.shap_values(X_sample)
        if model_type in ("decision_tree", "random_forest")
        else explainer.shap_values(X_sample, nsamples=100, silent=True)
    )
    if isinstance(raw, list):
        shap_values = np.asarray(raw[1])
    else:
        raw = np.asarray(raw)
        shap_values = raw[:, :, 1] if raw.ndim == 3 else raw

    explanation = shap.Explanation(
        values=shap_values, data=X_sample, feature_names=list(FEATURE_ORDER)
    )

    plt.figure()
    shap.plots.beeswarm(explanation, show=False)
    plt.title(f"SHAP Summary (Beeswarm) — {model_type} (production model)")
    plt.tight_layout()
    plt.savefig(reports_dir / "shap_summary_beeswarm.png", dpi=150)
    plt.close()

    plt.figure()
    shap.plots.bar(explanation, show=False)
    plt.title(f"SHAP Mean |Value| — {model_type} (production model)")
    plt.tight_layout()
    plt.savefig(reports_dir / "shap_summary_bar.png", dpi=150)
    plt.close()

    logger.info("Saved SHAP plots to %s", reports_dir)


def main() -> None:
    parser = argparse.ArgumentParser(description="Threshold calibration + SHAP report (Task 5.3).")
    parser.add_argument("--config", type=Path, default=PROJECT_ROOT / "configs" / "model_config.yaml")
    args = parser.parse_args()

    with args.config.open() as fh:
        config = yaml.safe_load(fh)

    calibration = calibrate_threshold(config)

    reports_dir = PROJECT_ROOT / config["output"]["reports_dir"]
    reports_dir.mkdir(parents=True, exist_ok=True)
    with (reports_dir / "threshold_calibration.json").open("w") as fh:
        json.dump(calibration, fh, indent=2)

    generate_shap_plots(config)

    # Patch just the `threshold:` line in place (regex, not a full
    # yaml.safe_dump rewrite) so the file's comments/structure survive.
    import re

    raw_text = args.config.read_text()
    new_threshold = calibration["selected_threshold"]
    patched_text, n_subs = re.subn(
        r"^threshold:.*$",
        f"threshold: {new_threshold}  # calibrated on validation set, {calibration['selected_metrics']['f1']:.4f} F1 (scripts/generate_shap_report.py)",
        raw_text,
        count=1,
        flags=re.MULTILINE,
    )
    if n_subs == 0:
        logger.warning("Could not find a 'threshold:' line in %s — not patched.", args.config)
    else:
        args.config.write_text(patched_text)
        logger.info("Wrote threshold=%.2f to %s", new_threshold, args.config)


if __name__ == "__main__":
    main()
