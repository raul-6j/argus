"""Tests for src.models.contract — the frozen model I/O contract."""

from __future__ import annotations

from pathlib import Path

import yaml

from src.models.contract import FEATURE_ORDER, VALID_FEATURE_VALUES, ModelInput

_PROJECT_ROOT = Path(__file__).resolve().parents[2]


def test_feature_order_matches_data_config():
    """FEATURE_ORDER must always equal data_config.yaml's feature_columns.

    Guards against the contract silently drifting from what the model is
    actually trained on (see DEC-013/DEC-014/DEC-016 — this list has already
    changed three times as the training pipeline was fixed).
    """
    with (_PROJECT_ROOT / "configs" / "data_config.yaml").open() as fh:
        data_config = yaml.safe_load(fh)
    assert list(FEATURE_ORDER) == data_config["feature_columns"]


def test_feature_order_is_18_features():
    """Sanity check on the current, post-DEC-016 contract size."""
    assert len(FEATURE_ORDER) == 18


def test_valid_feature_values_is_uci_scale():
    assert {-1, 0, 1} == VALID_FEATURE_VALUES


def test_model_input_to_vector_preserves_order():
    values = dict.fromkeys(FEATURE_ORDER, 1)
    values[FEATURE_ORDER[0]] = -1
    model_input = ModelInput(values=values)
    vector = model_input.to_vector()
    assert len(vector) == len(FEATURE_ORDER)
    assert vector[0] == -1
    assert all(v == 1 for v in vector[1:])


def test_model_input_default_approximated_is_empty():
    values = dict.fromkeys(FEATURE_ORDER, 1)
    model_input = ModelInput(values=values)
    assert model_input.approximated == []
