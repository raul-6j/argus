# tests/data/test_preprocessor.py
# Unit tests for src/data/preprocessor.py — split ratios, stratification, reproducibility.

from __future__ import annotations

import json
import tempfile
from pathlib import Path

import numpy as np
import pandas as pd
import pytest

from src.data.preprocessor import (
    align_schemas,
    audit_missing,
    compute_dataset_stats,
    drop_duplicates,
    drop_high_null_columns,
    impute_missing,
    merge_datasets,
    rename_columns,
    save_splits,
    save_stats,
    stratified_split,
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_FEATURE_COLS = [
    "has_ip_address", "url_length_cat", "has_shortening", "has_at_symbol",
    "has_double_slash", "has_prefix_suffix", "subdomain_level", "ssl_state",
    "domain_reg_length", "has_favicon",
]


def _make_df(n: int = 200, phishing_frac: float = 0.55) -> pd.DataFrame:
    """Build a minimal test DataFrame with feature columns + label."""
    rng = np.random.default_rng(42)
    n_phish = int(n * phishing_frac)
    labels = [1] * n_phish + [0] * (n - n_phish)
    data = {col: rng.integers(-1, 2, size=n).tolist() for col in _FEATURE_COLS}
    data["label"] = labels
    return pd.DataFrame(data)


# ---------------------------------------------------------------------------
# rename_columns
# ---------------------------------------------------------------------------


class TestRenameColumns:
    def test_renames_known_columns(self):
        df = pd.DataFrame({"A": [1], "B": [2], "C": [3]})
        rename_map = {"A": "x", "B": "y"}
        result = rename_columns(df, rename_map)
        assert list(result.columns) == ["x", "y"]

    def test_drops_columns_not_in_map(self):
        df = pd.DataFrame({"A": [1], "B": [2], "extra": [99]})
        rename_map = {"A": "x", "B": "y"}
        result = rename_columns(df, rename_map)
        assert "extra" not in result.columns

    def test_unknown_map_keys_are_skipped(self):
        df = pd.DataFrame({"A": [1]})
        rename_map = {"A": "x", "NONEXISTENT": "y"}
        result = rename_columns(df, rename_map)
        assert list(result.columns) == ["x"]


# ---------------------------------------------------------------------------
# align_schemas
# ---------------------------------------------------------------------------


class TestAlignSchemas:
    def test_adds_missing_cols_as_nan(self):
        uci = pd.DataFrame({"has_ip_address": [1], "url_length_cat": [0], "label": [1]})
        kag = pd.DataFrame({"has_ip_address": [1], "label": [0]})  # url_length_cat missing
        feature_cols = ["has_ip_address", "url_length_cat"]
        _uci_aligned, kag_aligned = align_schemas(uci, kag, feature_cols)
        assert "url_length_cat" in kag_aligned.columns
        assert kag_aligned["url_length_cat"].isna().all()

    def test_drops_extra_cols(self):
        uci = pd.DataFrame({"has_ip_address": [1], "extra": [99], "label": [1]})
        kag = pd.DataFrame({"has_ip_address": [0], "label": [0]})
        feature_cols = ["has_ip_address"]
        uci_aligned, _ = align_schemas(uci, kag, feature_cols)
        assert "extra" not in uci_aligned.columns

    def test_both_dfs_have_same_columns_after_align(self):
        uci = pd.DataFrame({"a": [1], "b": [2], "label": [1]})
        kag = pd.DataFrame({"a": [0], "label": [0]})
        feature_cols = ["a", "b"]
        uci_aligned, kag_aligned = align_schemas(uci, kag, feature_cols)
        assert list(uci_aligned.columns) == list(kag_aligned.columns)


# ---------------------------------------------------------------------------
# drop_duplicates
# ---------------------------------------------------------------------------


class TestDropDuplicates:
    def test_removes_exact_duplicates(self):
        df = pd.DataFrame({"a": [1, 1, 2], "label": [0, 0, 1]})
        result, n_removed = drop_duplicates(df)
        assert n_removed == 1
        assert len(result) == 2

    def test_no_duplicates_unchanged(self):
        df = pd.DataFrame({"a": [1, 2, 3], "label": [0, 1, 0]})
        result, n_removed = drop_duplicates(df)
        assert n_removed == 0
        assert len(result) == 3

    def test_index_reset_after_drop(self):
        df = pd.DataFrame({"a": [1, 1, 2], "label": [0, 0, 1]})
        result, _ = drop_duplicates(df)
        assert list(result.index) == list(range(len(result)))


# ---------------------------------------------------------------------------
# audit_missing / drop_high_null_columns / impute_missing
# ---------------------------------------------------------------------------


class TestMissingValue:
    def test_audit_missing_returns_correct_rates(self):
        df = pd.DataFrame({
            "a": [1.0, None, None, None],
            "b": [1.0, 2.0, 3.0, 4.0],
            "label": [1, 0, 1, 0],
        })
        rates = audit_missing(df)
        assert abs(rates["a"] - 0.75) < 1e-6
        assert rates["b"] == 0.0

    def test_drop_high_null_removes_above_threshold(self):
        df = pd.DataFrame({
            "a": [None, None, None, 1.0],   # 75% null — above 0.5 threshold
            "b": [1.0, 2.0, None, 4.0],     # 25% null — below threshold
            "label": [1, 0, 1, 0],
        })
        result, dropped = drop_high_null_columns(df, max_null_rate=0.50)
        assert "a" in dropped
        assert "b" in result.columns

    def test_drop_high_null_never_drops_label(self):
        # label column has 100% nulls — should never be dropped
        df = pd.DataFrame({
            "a": [None] * 4,
            "label": [None, None, None, None],
        })
        _result, dropped = drop_high_null_columns(df, max_null_rate=0.50)
        assert "label" not in dropped

    def test_impute_mode_fills_nulls(self):
        df = pd.DataFrame({
            "a": [1.0, 1.0, None, 1.0],
            "label": [1, 0, 1, 0],
        })
        result = impute_missing(df, strategy="mode")
        assert result["a"].isnull().sum() == 0
        assert result["a"].iloc[2] == 1.0  # mode is 1

    def test_impute_no_nulls_unchanged(self):
        df = _make_df(n=20)
        result = impute_missing(df, strategy="mode")
        assert result.equals(df)


# ---------------------------------------------------------------------------
# merge_datasets
# ---------------------------------------------------------------------------


class TestMergeDatasets:
    def test_merge_row_count(self):
        uci = _make_df(n=100)
        kag = _make_df(n=50)
        merged = merge_datasets(uci, kag)
        assert len(merged) == 150

    def test_merge_preserves_columns(self):
        uci = _make_df(n=30)
        kag = _make_df(n=20)
        merged = merge_datasets(uci, kag)
        assert set(uci.columns) == set(merged.columns)

    def test_merge_no_source_column_in_output(self):
        uci = _make_df(n=30)
        kag = _make_df(n=20)
        merged = merge_datasets(uci, kag)
        assert "_source" not in merged.columns


# ---------------------------------------------------------------------------
# stratified_split — core correctness tests
# ---------------------------------------------------------------------------


class TestStratifiedSplit:
    def test_split_row_counts_sum_to_total(self):
        df = _make_df(n=1000)
        train, val, test = stratified_split(df, 0.70, 0.15, 0.15, random_state=42)
        assert len(train) + len(val) + len(test) == len(df)

    def test_split_ratios_approximately_correct(self):
        df = _make_df(n=1000)
        train, val, test = stratified_split(df, 0.70, 0.15, 0.15, random_state=42)
        assert abs(len(train) / len(df) - 0.70) < 0.02
        assert abs(len(val) / len(df) - 0.15) < 0.02
        assert abs(len(test) / len(df) - 0.15) < 0.02

    def test_stratification_preserves_class_balance(self):
        """Class ratio in each split should be within 2% of full-dataset ratio."""
        df = _make_df(n=1000, phishing_frac=0.60)
        full_ratio = (df["label"] == 1).mean()
        train, val, test = stratified_split(df, 0.70, 0.15, 0.15, random_state=42)
        for split, name in [(train, "train"), (val, "val"), (test, "test")]:
            split_ratio = (split["label"] == 1).mean()
            assert abs(split_ratio - full_ratio) < 0.02, (
                f"{name} split phishing ratio {split_ratio:.3f} deviates from "
                f"full-dataset ratio {full_ratio:.3f}"
            )

    def test_reproducibility_same_seed_identical_splits(self):
        """Same random_state must produce byte-identical splits."""
        df = _make_df(n=500)
        train_a, val_a, test_a = stratified_split(df, random_state=42)
        train_b, val_b, test_b = stratified_split(df, random_state=42)
        pd.testing.assert_frame_equal(train_a, train_b)
        pd.testing.assert_frame_equal(val_a, val_b)
        pd.testing.assert_frame_equal(test_a, test_b)

    def test_different_seed_different_splits(self):
        df = _make_df(n=500)
        train_a, _, _ = stratified_split(df, random_state=42)
        train_b, _, _ = stratified_split(df, random_state=99)
        assert not train_a.equals(train_b)

    def test_ratios_not_summing_to_1_raises(self):
        df = _make_df(n=100)
        with pytest.raises(ValueError, match=r"sum to 1\.0"):
            stratified_split(df, 0.60, 0.15, 0.15, random_state=42)

    def test_index_reset_in_all_splits(self):
        df = _make_df(n=300)
        train, val, test = stratified_split(df, random_state=42)
        for split in (train, val, test):
            assert list(split.index) == list(range(len(split)))

    def test_no_overlap_between_splits(self):
        """Rows should not appear in more than one split."""
        df = _make_df(n=300)
        df["_row_id"] = range(len(df))
        train, val, test = stratified_split(df, random_state=42)
        train_ids = set(train["_row_id"])
        val_ids = set(val["_row_id"])
        test_ids = set(test["_row_id"])
        assert len(train_ids & val_ids) == 0
        assert len(train_ids & test_ids) == 0
        assert len(val_ids & test_ids) == 0


# ---------------------------------------------------------------------------
# save_splits + save_stats
# ---------------------------------------------------------------------------


class TestPersistence:
    @pytest.mark.skipif(
        __import__("importlib").util.find_spec("pyarrow") is None,
        reason="pyarrow not installed",
    )
    def test_save_splits_creates_parquet_files(self):
        train, val, test = stratified_split(_make_df(n=300), random_state=42)
        with tempfile.TemporaryDirectory() as tmpdir:
            paths = save_splits(train, val, test, tmpdir, use_parquet=True)
            for key in ("train", "val", "test"):
                assert Path(paths[key]).exists()
                assert paths[key].endswith(".parquet")

    def test_save_splits_creates_csv_fallback(self):
        train, val, test = stratified_split(_make_df(n=300), random_state=42)
        with tempfile.TemporaryDirectory() as tmpdir:
            paths = save_splits(train, val, test, tmpdir, use_parquet=False)
            for key in ("train", "val", "test"):
                assert Path(paths[key]).exists()
                assert paths[key].endswith(".csv")

    def test_save_stats_writes_valid_json(self):
        df = _make_df(n=300)
        train, val, test = stratified_split(df, random_state=42)
        stats = compute_dataset_stats(train, val, test, 5, ["dropped_col"], {"feat_a": 0.1})
        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as f:
            save_stats(stats, f.name)
            f.seek(0)
            loaded = json.loads(Path(f.name).read_text())
        assert loaded["total_rows"] == len(train) + len(val) + len(test)
        assert "splits" in loaded
        assert set(loaded["splits"].keys()) == {"train", "val", "test"}

    def test_dataset_stats_imbalance_ratio_correct(self):
        df = pd.DataFrame({
            **{col: [1] * 100 for col in _FEATURE_COLS},
            "label": [1] * 60 + [0] * 40,
        })
        train, val, test = stratified_split(df, random_state=42)
        stats = compute_dataset_stats(train, val, test, 0, [], {})
        # 60:40 → ratio ~1.5
        assert 1.4 <= stats["global_imbalance_ratio"] <= 1.6
