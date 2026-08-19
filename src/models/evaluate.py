"""Evaluate the 4 trained candidates on the held-out test split — once.

Iron rule (Task 5.2, PHASE_GUIDE.md): the test set is touched exactly once,
here. ``train.py`` never reads ``data/processed/test.parquet``. Every call to
:func:`run_evaluation` appends to ``reports/.test_set_access_log.json`` as an
audit trail — re-running during development is allowed, but any numbers cited
in the thesis must come from a single, deliberate run, and the log makes it
possible to check that after the fact.

Computes F1, ROC-AUC, Precision, Recall, and a confusion matrix per model,
selects the winner by F1 (ROC-AUC tie-break, per ``model_config.yaml``'s
``tiebreak``), promotes the winner to ``models/production/``, and writes
``reports/model_comparison.json`` plus ROC-curve and confusion-matrix plots.
"""

from __future__ import annotations

import json
import logging
import shutil
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import joblib
import matplotlib

matplotlib.use("Agg")  # headless — no display backend required
import matplotlib.pyplot as plt
import numpy as np
import yaml
from sklearn.metrics import (
    ConfusionMatrixDisplay,
    RocCurveDisplay,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
    roc_auc_score,
)

from src.models.train import load_split

logger = logging.getLogger(__name__)

PROJECT_ROOT = Path(__file__).resolve().parents[2]


def _log_test_set_access(reports_dir: Path, note: str) -> None:
    """Append a timestamped entry to the test-set access audit log.

    Args:
        reports_dir: Directory the log file lives in.
        note: Free-text context for this access (e.g. which models were run).
    """
    log_path = reports_dir / ".test_set_access_log.json"
    entries: list[dict[str, str]] = []
    if log_path.is_file():
        try:
            entries = json.loads(log_path.read_text())
        except json.JSONDecodeError:
            logger.warning("Corrupt test-set access log at %s — starting fresh", log_path)
    entries.append({"timestamp": datetime.now(timezone.utc).isoformat(), "note": note})
    log_path.write_text(json.dumps(entries, indent=2))
    if len(entries) > 1:
        logger.warning(
            "Test set has now been accessed %d times (see %s). Any thesis-cited "
            "numbers must come from one deliberate, final run — not the most "
            "convenient one.",
            len(entries), log_path,
        )


def evaluate_one_model(
    name: str, model_path: Path, X_test: np.ndarray, y_test: np.ndarray
) -> dict[str, Any]:
    """Score a single trained candidate on the test set.

    Args:
        name: Model key, for logging/reporting.
        model_path: Path to the candidate's ``.joblib`` file.
        X_test: Test features, shape ``(n_test, 22)``.
        y_test: Test labels.

    Returns:
        A metrics dict: f1, roc_auc, precision, recall, confusion_matrix
        (as a nested list), and the raw predicted probabilities (for the ROC
        plot).
    """
    estimator = joblib.load(model_path)
    y_pred = estimator.predict(X_test)
    y_proba = estimator.predict_proba(X_test)[:, 1]

    cm = confusion_matrix(y_test, y_pred).tolist()
    metrics = {
        "f1": float(f1_score(y_test, y_pred)),
        "roc_auc": float(roc_auc_score(y_test, y_proba)),
        "precision": float(precision_score(y_test, y_pred)),
        "recall": float(recall_score(y_test, y_pred)),
        "confusion_matrix": cm,  # [[TN, FP], [FN, TP]]
    }
    logger.info(
        "%s test set: f1=%.4f roc_auc=%.4f precision=%.4f recall=%.4f",
        name, metrics["f1"], metrics["roc_auc"], metrics["precision"], metrics["recall"],
    )
    return {**metrics, "_y_proba": y_proba, "_estimator": estimator}


def _save_plots(results: dict[str, dict[str, Any]], y_test: np.ndarray, reports_dir: Path) -> None:
    """Write a combined ROC-curve plot and one confusion-matrix plot per model.

    Args:
        results: Mapping of model name -> evaluate_one_model() output.
        y_test: Test labels (shared across all models).
        reports_dir: Directory to write PNGs into.
    """
    fig, ax = plt.subplots(figsize=(6, 6))
    for name, result in results.items():
        RocCurveDisplay.from_predictions(y_test, result["_y_proba"], name=name, ax=ax)
    ax.set_title("ROC Curve — 4-Model Comparison (UCI+Kaggle test set)")
    fig.tight_layout()
    fig.savefig(reports_dir / "roc_curve_comparison.png", dpi=150)
    plt.close(fig)

    for name, result in results.items():
        fig, ax = plt.subplots(figsize=(4, 4))
        cm = np.array(result["confusion_matrix"])
        ConfusionMatrixDisplay(cm, display_labels=["legitimate", "phishing"]).plot(ax=ax, colorbar=False)
        ax.set_title(f"Confusion Matrix — {name}")
        fig.tight_layout()
        fig.savefig(reports_dir / f"confusion_matrix_{name}.png", dpi=150)
        plt.close(fig)


def run_evaluation(config: dict[str, Any]) -> dict[str, Any]:
    """Evaluate every candidate model on the test set and pick a winner.

    Args:
        config: Parsed ``model_config.yaml``.

    Returns:
        The ``model_comparison`` dict (also written to
        ``reports/model_comparison.json``): per-model metrics plus the
        winner and why.
    """
    candidates_dir = PROJECT_ROOT / config["output"]["candidates_dir"]
    production_dir = PROJECT_ROOT / config["output"]["production_dir"]
    reports_dir = PROJECT_ROOT / config["output"]["reports_dir"]
    reports_dir.mkdir(parents=True, exist_ok=True)
    production_dir.mkdir(parents=True, exist_ok=True)

    test_path = PROJECT_ROOT / config["data"]["test_path"]
    logger.info("Loading test split (touched exactly once): %s", test_path)
    X_test, y_test = load_split(test_path)

    model_names = list(config["models"].keys())
    _log_test_set_access(reports_dir, f"evaluate.py run over models: {model_names}")

    results: dict[str, dict[str, Any]] = {}
    for name in model_names:
        model_path = candidates_dir / f"{name}.joblib"
        if not model_path.is_file():
            raise FileNotFoundError(
                f"{model_path} not found — run scripts/train.py first (Task 5.2)."
            )
        results[name] = evaluate_one_model(name, model_path, X_test, y_test)

    tiebreak = config.get("tiebreak", "roc_auc")
    winner = max(results, key=lambda n: (results[n]["f1"], results[n][tiebreak]))
    logger.info("Winner (by F1, %s tie-break): %s", tiebreak, winner)

    _save_plots(results, y_test, reports_dir)

    comparison = {
        "test_set": str(test_path.relative_to(PROJECT_ROOT)),
        "n_test_rows": len(y_test),
        "selection_rule": f"max F1, {tiebreak} tie-break",
        "winner": winner,
        "evaluated_at": datetime.now(timezone.utc).isoformat(),
        "models": {
            name: {k: v for k, v in result.items() if not k.startswith("_")}
            for name, result in results.items()
        },
    }
    with (reports_dir / "model_comparison.json").open("w") as fh:
        json.dump(comparison, fh, indent=2)

    # Promote the actual winner to production (may differ from train.py's
    # provisional val-based pick).
    winner_candidate = candidates_dir / f"{winner}.joblib"
    shutil.copy(winner_candidate, production_dir / "model.joblib")
    winner_metadata_path = candidates_dir / f"{winner}_metadata.json"
    winner_metadata = json.loads(winner_metadata_path.read_text()) if winner_metadata_path.is_file() else {}
    winner_metadata.update(
        {
            "selection_note": "final pick — selected by evaluate.py on the test set",
            "test_f1": results[winner]["f1"],
            "test_roc_auc": results[winner]["roc_auc"],
            "test_precision": results[winner]["precision"],
            "test_recall": results[winner]["recall"],
        }
    )
    with (production_dir / "metadata.json").open("w") as fh:
        json.dump(winner_metadata, fh, indent=2)

    logger.info("Promoted %s to %s", winner, production_dir / "model.joblib")
    return comparison


def main() -> None:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)-8s %(name)s — %(message)s")
    import argparse

    parser = argparse.ArgumentParser(description="Evaluate the ARGUS 4-model comparison on the test set.")
    parser.add_argument("--config", type=Path, default=PROJECT_ROOT / "configs" / "model_config.yaml")
    args = parser.parse_args()

    with args.config.open() as fh:
        config = yaml.safe_load(fh)

    run_evaluation(config)


if __name__ == "__main__":
    main()
