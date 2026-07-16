"""ONNX inference backend (Phase 2, G1).

An optional, numerically-validated alternative to the sklearn pipeline's
own ``predict_proba`` for the hot inference path. **Never used for
``/explain``** — SHAP stays on the original sklearn pipeline + explainer
(``docs/PHASE_2_IMPLEMENTATION_PLAN.md`` §G1), since the explainer was built
against the sklearn model's internals.

``scripts/export_onnx.py`` is the only supported way to produce
``model.onnx`` — it refuses to write the file at all unless the ONNX
output matches the sklearn pipeline within tolerance across the real test
set. This module trusts that gate rather than re-validating on every
load; if the model is ever retrained, re-run the export script.
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any, Optional, Protocol

import numpy as np

logger = logging.getLogger(__name__)


class Predictor(Protocol):
    """The minimal interface both the sklearn pipeline and the ONNX
    wrapper satisfy -- callers depend on this, not on which backend is
    actually in use."""

    def predict_proba(self, X: Any) -> np.ndarray: ...  # noqa: E704


class OnnxPredictor:
    """Wraps an ONNX ``InferenceSession`` behind sklearn's ``predict_proba`` shape."""

    def __init__(self, onnx_path: Path):
        import onnxruntime as ort

        self._session = ort.InferenceSession(str(onnx_path))
        self._input_name = self._session.get_inputs()[0].name

    def predict_proba(self, X: Any) -> np.ndarray:
        """Returns an ``(n, 2)`` array of ``[P(legitimate), P(phishing)]``,
        matching sklearn's ``predict_proba`` output shape exactly."""
        arr = np.asarray(X, dtype=np.float32)
        outputs = self._session.run(None, {self._input_name: arr})
        # skl2onnx (zipmap=False, see scripts/export_onnx.py) emits
        # [labels, probabilities] -- select the (n, 2) float array by shape
        # rather than assuming output order (occasionally version-dependent).
        proba = next(o for o in outputs if getattr(o, "ndim", 0) == 2 and o.shape[1] == 2)
        return np.asarray(proba, dtype=np.float64)


def load_predictor(
    backend: str, onnx_path: Optional[Path], sklearn_pipeline: Any
) -> Predictor:
    """Build the predictor to use for the hot inference path.

    Args:
        backend: ``"onnx"`` or ``"sklearn"`` (any other value falls back
            to sklearn, logged).
        onnx_path: Path to ``model.onnx``. Required (and must exist) if
            ``backend == "onnx"``.
        sklearn_pipeline: The already-loaded sklearn pipeline — used
            directly when ``backend == "sklearn"``, and as the fallback if
            ONNX loading fails for any reason.

    Returns:
        A :class:`Predictor` (either the sklearn pipeline itself or an
        :class:`OnnxPredictor`). **Never raises** — any ONNX load failure
        falls back to the sklearn pipeline with a warning, since serving
        must never go down over an optional optimization.
    """
    if backend != "onnx":
        if backend != "sklearn":
            logger.warning("Unknown serving backend %r; falling back to sklearn.", backend)
        return sklearn_pipeline

    if onnx_path is None or not Path(onnx_path).is_file():
        logger.warning(
            "serving.backend is 'onnx' but %s doesn't exist -- run scripts/export_onnx.py "
            "first. Falling back to sklearn for this process.",
            onnx_path,
        )
        return sklearn_pipeline

    try:
        predictor = OnnxPredictor(Path(onnx_path))
        # Warmup + sanity call -- fail fast at startup rather than on the
        # first real request, mirroring the existing SHAP warmup convention.
        n_features = getattr(sklearn_pipeline, "n_features_in_", None) or 18
        predictor.predict_proba(np.zeros((1, n_features), dtype=np.float32))
        logger.info("Loaded ONNX predictor from %s.", onnx_path)
        return predictor
    except Exception as exc:  # noqa: BLE001 - ONNX is an optimization, never a hard dependency
        logger.warning("Failed to load ONNX predictor from %s: %s -- falling back to sklearn.", onnx_path, exc)
        return sklearn_pipeline
