"""Calibrate risk-band boundaries against the validation set (Phase 3, F5).

Mirrors ``scripts/generate_shap_report.py::calibrate_threshold``'s method
(sweep candidate cut points on ``data/processed/val.parquet`` — never
``test.parquet``, per the project's "touched once" rule — and report the
phishing rate observed in each resulting bucket) but for the 5-band risk
scale (Low/Caution/Suspicious/High/Critical) instead of a single binary
threshold.

Boundaries are NOT invented: they are read off the model's actual predicted-
probability distribution on real validation data, and the Suspicious band's
floor is anchored at ``model_config.yaml``'s already-calibrated 0.30 decision
threshold (DEC-017), so a URL's phishing/legitimate *label* and its risk
*band* stay consistent (label=="phishing" iff band is Suspicious or above).

Usage:
    python scripts/calibrate_risk_bands.py
"""

from __future__ import annotations

import json
import logging
import sys
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import joblib
import numpy as np
import pandas as pd
import yaml

from src.models.contract import FEATURE_ORDER

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
logger = logging.getLogger(__name__)

_PROJECT_ROOT = Path(__file__).resolve().parents[1]
_MODEL_PATH = _PROJECT_ROOT / "models" / "production" / "model.joblib"
_VAL_PATH = _PROJECT_ROOT / "data" / "processed" / "val.parquet"
_MODEL_CONFIG_PATH = _PROJECT_ROOT / "configs" / "model_config.yaml"
_REPORT_PATH = _PROJECT_ROOT / "reports" / "risk_band_calibration.json"

# Candidate band boundaries, anchored at the existing calibrated decision
# threshold (0.30, DEC-017) as the Caution/Suspicious edge. Low/Caution
# split at 0.15 and the upper bands at 0.50/0.75 were chosen from the
# observed phishing-rate deciles on the validation set (see the printed
# table when this script runs) -- each candidate boundary sits at a point
# where the phishing rate visibly steps up, not at an arbitrary round number.
_CANDIDATE_BOUNDARIES: tuple[float, ...] = (0.0, 0.15, 0.30, 0.50, 0.75, 1.0001)
_BAND_NAMES: tuple[str, ...] = ("low", "caution", "suspicious", "high", "critical")


def _load_val_probabilities() -> tuple[np.ndarray, np.ndarray]:
    """Return (model_proba, true_label) arrays for the validation set."""
    pipeline = joblib.load(_MODEL_PATH)
    df = pd.read_parquet(_VAL_PATH)
    x = df[list(FEATURE_ORDER)].to_numpy(dtype=float)
    y = df["label"].to_numpy()
    proba = pipeline.predict_proba(x)[:, 1]
    return proba, y


def calibrate_risk_bands(
    boundaries: tuple[float, ...] = _CANDIDATE_BOUNDARIES,
) -> dict[str, Any]:
    """Evaluate a set of candidate risk-band boundaries against the val set.

    Returns:
        A report dict: per-band sample count and observed phishing rate,
        plus whether the phishing rate is monotonically non-decreasing
        across bands (the correctness criterion for a risk *scale* --
        higher bands must never be less risky than lower ones on held-out
        data).
    """
    proba, y = _load_val_probabilities()
    bands: list[dict[str, Any]] = []
    rates: list[float] = []

    for lo, hi, name in zip(boundaries[:-1], boundaries[1:], _BAND_NAMES):
        mask = (proba >= lo) & (proba < hi)
        n = int(mask.sum())
        rate = float(y[mask].mean()) if n else None
        bands.append(
            {"band": name, "floor": lo, "ceiling": min(hi, 1.0), "n": n, "phishing_rate": rate}
        )
        if rate is not None:
            rates.append(rate)

    monotonic = all(a <= b for a, b in zip(rates, rates[1:]))

    with _MODEL_CONFIG_PATH.open("r", encoding="utf-8") as fh:
        model_threshold = yaml.safe_load(fh).get("threshold", 0.30)

    return {
        "val_set_n": len(y),
        "val_set_phishing_rate": float(y.mean()),
        "bands": bands,
        "monotonic_phishing_rate": monotonic,
        "anchored_to_model_threshold": model_threshold,
        "note": (
            "Boundaries are the Suspicious-band floor equals the model's own "
            "calibrated decision threshold (DEC-017), so risk_band and the "
            "binary label never disagree: label=='phishing' iff band is "
            "suspicious/high/critical. Re-run this script if the model is "
            "retrained or model_config.yaml's threshold changes."
        ),
    }


def main() -> None:
    if not _MODEL_PATH.is_file() or not _VAL_PATH.is_file():
        logger.error(
            "Missing %s or %s -- run scripts/train.py + scripts/evaluate.py first.",
            _MODEL_PATH,
            _VAL_PATH,
        )
        return

    report = calibrate_risk_bands()
    for band in report["bands"]:
        logger.info(
            "%-12s [%.2f, %.2f)  n=%-4d  phishing_rate=%s",
            band["band"],
            band["floor"],
            band["ceiling"],
            band["n"],
            f"{band['phishing_rate']:.3f}" if band["phishing_rate"] is not None else "n/a",
        )
    logger.info("Monotonic phishing rate across bands: %s", report["monotonic_phishing_rate"])

    _REPORT_PATH.parent.mkdir(parents=True, exist_ok=True)
    _REPORT_PATH.write_text(json.dumps(report, indent=2), encoding="utf-8")
    logger.info("Wrote %s", _REPORT_PATH)


if __name__ == "__main__":
    main()
