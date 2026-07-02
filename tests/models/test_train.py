"""Tests for src.models.train — the reusable, easily-unit-testable pieces.

GridSearchCV/full-model-fitting is exercised by the real end-to-end run
(scripts/train.py against data/processed/), not re-mocked here.
"""

from __future__ import annotations

import pandas as pd
import pytest
from sklearn.linear_model import LogisticRegression
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler
from sklearn.tree import DecisionTreeClassifier

from src.models.contract import FEATURE_ORDER
from src.models.train import build_pipeline, load_split


def test_load_split_reads_features_in_contract_order(tmp_path):
    df = pd.DataFrame({name: [1, -1, 0] for name in FEATURE_ORDER})
    df["label"] = [1, 0, 1]
    path = tmp_path / "split.parquet"
    df.to_parquet(path)

    X, y = load_split(path)
    assert X.shape == (3, len(FEATURE_ORDER))
    assert list(y) == [1, 0, 1]


def test_load_split_missing_file_raises(tmp_path):
    with pytest.raises(FileNotFoundError):
        load_split(tmp_path / "does_not_exist.parquet")


def test_load_split_missing_feature_column_raises(tmp_path):
    df = pd.DataFrame({name: [1] for name in FEATURE_ORDER[:-1]})
    df["label"] = [1]
    path = tmp_path / "incomplete.parquet"
    df.to_parquet(path)

    with pytest.raises(KeyError):
        load_split(path)


def test_build_pipeline_no_scaler_for_tree_models():
    pipeline = build_pipeline(DecisionTreeClassifier, scale_features=False, random_state=42)
    assert isinstance(pipeline, Pipeline)
    assert "scaler" not in dict(pipeline.steps)
    assert pipeline.named_steps["clf"].random_state == 42


def test_build_pipeline_includes_scaler_for_linear_models():
    pipeline = build_pipeline(LogisticRegression, scale_features=True, random_state=42)
    assert isinstance(pipeline.named_steps["scaler"], StandardScaler)
