#!/usr/bin/env python
"""Export the trained sklearn pipeline to ONNX (Phase 2, G1).

Converts ``models/production/model.joblib`` (imputer -> scaler -> SVC,
DEC-011/016) to ONNX via ``skl2onnx``, then validates numerical parity
against the original sklearn pipeline across the full held-out test set —
**the export is refused (non-zero exit) if parity doesn't hold within
tolerance**, since a silently-drifted ONNX model would mean ARGUS serves
different verdicts depending on which backend happens to be configured.
This is the mandatory gate ``docs/PHASE_2_IMPLEMENTATION_PLAN.md`` calls
for before ONNX is allowed on the serving path.

Usage:
    python scripts/export_onnx.py [--tolerance 1e-4]

Writes:
    models/production/model.onnx
    reports/onnx_parity.json
"""

from __future__ import annotations

import argparse
import json
import logging
import sys
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import joblib  # noqa: E402
import numpy as np  # noqa: E402
import pandas as pd  # noqa: E402

logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")
logger = logging.getLogger("export_onnx")

_PROJECT_ROOT = Path(__file__).resolve().parents[1]
_DEFAULT_MODEL_PATH = _PROJECT_ROOT / "models" / "production" / "model.joblib"
_DEFAULT_ONNX_PATH = _PROJECT_ROOT / "models" / "production" / "model.onnx"
_DEFAULT_TEST_PATH = _PROJECT_ROOT / "data" / "processed" / "test.parquet"
_DEFAULT_TOLERANCE = 1e-4


def convert_to_onnx(pipeline, n_features: int):
    """Convert a fitted sklearn Pipeline to an ONNX model.

    Args:
        pipeline: The fitted sklearn ``Pipeline``.
        n_features: Number of input features (18, the training contract).

    Returns:
        The ONNX ``ModelProto``.
    """
    from skl2onnx import to_onnx
    from skl2onnx.common.data_types import FloatTensorType

    initial_type = [("input", FloatTensorType([None, n_features]))]
    # zipmap=False: emit a plain (n, 2) probability array instead of a list
    # of {class: proba} dicts -- much simpler/faster to consume in
    # src/serving/onnx_runtime.py, and this is a serving-format choice, not
    # something that affects the actual predicted probabilities.
    return to_onnx(pipeline, initial_types=initial_type, options={id(pipeline): {"zipmap": False}})


def validate_parity(pipeline, onnx_bytes: bytes, X: np.ndarray, tolerance: float) -> dict:
    """Compare ONNX vs. sklearn ``predict_proba`` on the same inputs.

    Args:
        pipeline: The original fitted sklearn pipeline.
        onnx_bytes: The serialized ONNX model.
        X: Feature matrix, shape ``(n, n_features)``.
        tolerance: Maximum allowed absolute difference in phishing-class
            probability between the two backends.

    Returns:
        A report dict with ``max_abs_diff``, ``mean_abs_diff``,
        ``n_samples``, ``tolerance``, and ``passed``.
    """
    import onnxruntime as ort

    sklearn_proba = pipeline.predict_proba(X.astype(np.float64))[:, 1]

    sess = ort.InferenceSession(onnx_bytes)
    outputs = sess.run(None, {"input": X.astype(np.float32)})
    # skl2onnx with zipmap=False emits [labels, probabilities] -- find the
    # (n, 2) float array by shape rather than assuming output order, since
    # that's occasionally version-dependent.
    proba_output = next(o for o in outputs if getattr(o, "ndim", 0) == 2 and o.shape[1] == 2)
    onnx_proba = proba_output[:, 1]

    diff = np.abs(sklearn_proba - onnx_proba)
    return {
        "max_abs_diff": float(diff.max()),
        "mean_abs_diff": float(diff.mean()),
        "n_samples": int(len(X)),
        "tolerance": tolerance,
        "passed": bool(diff.max() <= tolerance),
    }


def run(
    model_path: Path = _DEFAULT_MODEL_PATH,
    onnx_path: Path = _DEFAULT_ONNX_PATH,
    test_path: Path = _DEFAULT_TEST_PATH,
    tolerance: float = _DEFAULT_TOLERANCE,
) -> dict:
    """Export + validate. Returns the parity report; does not write the
    ONNX file if validation fails."""
    from src.models.contract import FEATURE_ORDER

    pipeline = joblib.load(model_path)
    n_features = len(FEATURE_ORDER)

    onnx_model = convert_to_onnx(pipeline, n_features)
    onnx_bytes = onnx_model.SerializeToString()

    if not test_path.is_file():
        logger.warning(
            "Test set not found at %s -- validating against a small synthetic "
            "sample instead of the real held-out test set. Re-run after "
            "scripts/data_prep.py for a real parity guarantee.",
            test_path,
        )
        rng = np.random.default_rng(42)
        X = rng.choice([-1, 0, 1], size=(200, n_features)).astype(np.float64)
    else:
        df = pd.read_parquet(test_path)
        X = df[list(FEATURE_ORDER)].to_numpy(dtype=np.float64)

    report = validate_parity(pipeline, onnx_bytes, X, tolerance)
    report["exported_at"] = datetime.now(timezone.utc).isoformat()
    report["model_path"] = str(model_path)
    report["onnx_path"] = str(onnx_path)

    if not report["passed"]:
        logger.error(
            "ONNX parity FAILED: max_abs_diff=%.6g exceeds tolerance=%.6g -- "
            "refusing to write %s. The existing sklearn model.joblib is unaffected.",
            report["max_abs_diff"], tolerance, onnx_path,
        )
        return report

    onnx_path.parent.mkdir(parents=True, exist_ok=True)
    onnx_path.write_bytes(onnx_bytes)
    logger.info(
        "ONNX parity PASSED: max_abs_diff=%.6g (tolerance=%.6g, n=%d) -- wrote %s",
        report["max_abs_diff"], tolerance, report["n_samples"], onnx_path,
    )
    return report


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--model-path", type=Path, default=_DEFAULT_MODEL_PATH)
    parser.add_argument("--onnx-path", type=Path, default=_DEFAULT_ONNX_PATH)
    parser.add_argument("--test-path", type=Path, default=_DEFAULT_TEST_PATH)
    parser.add_argument("--tolerance", type=float, default=_DEFAULT_TOLERANCE)
    args = parser.parse_args()

    report = run(args.model_path, args.onnx_path, args.test_path, args.tolerance)

    reports_dir = _PROJECT_ROOT / "reports"
    reports_dir.mkdir(parents=True, exist_ok=True)
    (reports_dir / "onnx_parity.json").write_text(json.dumps(report, indent=2), encoding="utf-8")

    sys.exit(0 if report["passed"] else 1)


if __name__ == "__main__":
    main()
