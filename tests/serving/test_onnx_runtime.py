"""Tests for src.serving.onnx_runtime (Phase 2, G1).

Uses the real exported model.onnx when available (skipped otherwise,
matching the project's "skip if artifact missing" convention) for the
happy-path/parity-adjacent checks, plus fully synthetic cases for the
fallback behavior that don't need any real artifact.
"""

from __future__ import annotations

from pathlib import Path
from unittest import mock

import numpy as np
import pytest

from src.serving.onnx_runtime import OnnxPredictor, load_predictor

PROJECT_ROOT = Path(__file__).resolve().parents[2]
_ONNX_PATH = PROJECT_ROOT / "models" / "production" / "model.onnx"
_MODEL_PATH = PROJECT_ROOT / "models" / "production" / "model.joblib"


class TestLoadPredictorFallbacks:
    def test_sklearn_backend_returns_pipeline_directly(self):
        sentinel_pipeline = object()
        result = load_predictor("sklearn", None, sentinel_pipeline)
        assert result is sentinel_pipeline

    def test_unknown_backend_falls_back_to_sklearn(self):
        sentinel_pipeline = object()
        result = load_predictor("something-else", None, sentinel_pipeline)
        assert result is sentinel_pipeline

    def test_onnx_backend_with_missing_file_falls_back_to_sklearn(self, tmp_path):
        sentinel_pipeline = object()
        result = load_predictor("onnx", tmp_path / "does_not_exist.onnx", sentinel_pipeline)
        assert result is sentinel_pipeline

    def test_onnx_backend_with_none_path_falls_back_to_sklearn(self):
        sentinel_pipeline = object()
        result = load_predictor("onnx", None, sentinel_pipeline)
        assert result is sentinel_pipeline

    def test_onnx_load_failure_falls_back_to_sklearn(self, tmp_path):
        bad_onnx = tmp_path / "corrupt.onnx"
        bad_onnx.write_bytes(b"not a real onnx file")
        sentinel_pipeline = mock.Mock()
        sentinel_pipeline.n_features_in_ = 18
        result = load_predictor("onnx", bad_onnx, sentinel_pipeline)
        assert result is sentinel_pipeline


@pytest.mark.skipif(not _ONNX_PATH.is_file(), reason="Run scripts/export_onnx.py first.")
class TestRealOnnxModel:
    def test_predict_proba_shape(self):
        predictor = OnnxPredictor(_ONNX_PATH)
        X = np.zeros((3, 18), dtype=np.float32)
        proba = predictor.predict_proba(X)
        assert proba.shape == (3, 2)
        # Rows are valid probability distributions.
        assert np.allclose(proba.sum(axis=1), 1.0, atol=1e-3)

    def test_load_predictor_onnx_backend_returns_onnx_predictor(self):
        import joblib

        pipeline = joblib.load(_MODEL_PATH)
        result = load_predictor("onnx", _ONNX_PATH, pipeline)
        assert isinstance(result, OnnxPredictor)

    def test_matches_sklearn_within_tolerance_on_a_sample(self):
        import joblib

        pipeline = joblib.load(_MODEL_PATH)
        predictor = OnnxPredictor(_ONNX_PATH)

        rng = np.random.default_rng(42)
        X = rng.choice([-1, 0, 1], size=(20, 18)).astype(np.float64)

        sklearn_proba = pipeline.predict_proba(X)[:, 1]
        onnx_proba = predictor.predict_proba(X)[:, 1]

        assert np.abs(sklearn_proba - onnx_proba).max() < 1e-3
