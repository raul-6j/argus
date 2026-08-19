"""Tests for src.models.explain — per-prediction SHAP explanations.

Uses the trained decision_tree candidate (TreeExplainer — fast, exact) so
the test suite doesn't pay KernelExplainer's cost. KernelExplainer's own
correctness (SVM/LR path) is validated by the real run in
scripts/generate_shap_report.py, not re-tested here.
"""

from __future__ import annotations

import math

import joblib
import pandas as pd
import pytest

from src.models.contract import FEATURE_ORDER, MISSING
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


def test_missing_feature_value_is_json_safe_none_not_nan(decision_tree_setup):
    """A missing feature is NaN in the model contract (DEC-040), which is
    exactly right for the imputer -- but `jsonify` emits a bare `NaN` token
    for it, which is not valid JSON and breaks every strict JSON.parse
    caller (every browser's `Response.json()`, including this project's own
    extension/webapp clients). `explain_single` must never hand a raw NaN
    back to an API caller."""
    pipeline, explainer, features = decision_tree_setup
    features = dict(features)
    missing_name = FEATURE_ORDER[0]
    features[missing_name] = MISSING
    result = explain_single(features, pipeline, explainer, "decision_tree")
    for item in result:
        if item["feature"] == missing_name:
            assert item["feature_value"] is None
        else:
            assert not (
                isinstance(item["feature_value"], float) and math.isnan(item["feature_value"])
            )
