"""Tests for src.models.explain — per-prediction SHAP explanations.

Uses the trained decision_tree candidate (TreeExplainer — fast, exact) so
the test suite doesn't pay KernelExplainer's cost. KernelExplainer's own
correctness (SVM/LR path) is validated by the real run in
scripts/generate_shap_report.py, not re-tested here.
"""

from __future__ import annotations

import joblib
import pandas as pd
import pytest

from src.models.contract import FEATURE_ORDER
from src.models.explain import build_explainer, explain_single


@pytest.fixture(scope="module")
def decision_tree_setup():
    from pathlib import Path

    project_root = Path(__file__).resolve().parents[2]
    model_path = project_root / "models" / "candidates" / "decision_tree.joblib"
    train_path = project_root / "data" / "processed" / "train.parquet"
    if not model_path.is_file() or not train_path.is_file():
        pytest.skip("Run scripts/train.py first — no trained candidate available.")

    pipeline = joblib.load(model_path)
    train_df = pd.read_parquet(train_path)
    background_X = train_df[list(FEATURE_ORDER)].to_numpy(dtype=float)
    explainer = build_explainer("decision_tree", pipeline, background_X)

    sample_row = train_df.iloc[0]
    features = {name: float(sample_row[name]) for name in FEATURE_ORDER}
    return pipeline, explainer, features


def test_returns_exactly_five_items(decision_tree_setup):
    pipeline, explainer, features = decision_tree_setup
    result = explain_single(features, pipeline, explainer, "decision_tree")
    assert len(result) == 5


def test_ordered_by_abs_shap_descending(decision_tree_setup):
    pipeline, explainer, features = decision_tree_setup
    result = explain_single(features, pipeline, explainer, "decision_tree")
    magnitudes = [abs(item["shap_value"]) for item in result]
    assert magnitudes == sorted(magnitudes, reverse=True)


def test_feature_names_are_from_contract(decision_tree_setup):
    pipeline, explainer, features = decision_tree_setup
    result = explain_single(features, pipeline, explainer, "decision_tree")
    assert all(item["feature"] in FEATURE_ORDER for item in result)


def test_output_shape_per_item(decision_tree_setup):
    pipeline, explainer, features = decision_tree_setup
    result = explain_single(features, pipeline, explainer, "decision_tree")
    for item in result:
        assert set(item.keys()) == {"feature", "shap_value", "feature_value"}
        assert isinstance(item["shap_value"], float)


def test_feature_value_matches_input(decision_tree_setup):
    pipeline, explainer, features = decision_tree_setup
    result = explain_single(features, pipeline, explainer, "decision_tree")
    for item in result:
        assert item["feature_value"] == features[item["feature"]]
