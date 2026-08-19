# src/data/preprocessor.py
# Dataset cleaning, schema alignment, merging, and stratified splitting.
# Scaler/imputer are NOT fit here — raw features are persisted for Pipeline use at training time.

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any

import pandas as pd
from sklearn.model_selection import train_test_split

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Kaggle scale normalisation (DEC-014)
# ---------------------------------------------------------------------------
#
# UCI's original 30 features are pre-thresholded into a -1/0/1 categorical
# scheme (Mohammad, Thabtah & McCluskey, 2014). Kaggle's raw columns measure
# the same underlying signals but on continuous/count scales (e.g. raw days,
# raw @ count, raw traffic volume). `kaggle_rename` only renames columns — it
# never converted values — so before this fix the merged 22-feature contract
# silently mixed two incompatible scales in 8 columns (UCI rows clean -1/0/1,
# Kaggle rows raw magnitudes), split cleanly along the source boundary. That
# is a severe source-artifact leakage risk, worse than the 8 columns already
# dropped in DEC-013. This module buckets Kaggle's raw values into UCI's
# categorical scheme *before* rename_columns() runs, operating on Kaggle's
# raw (pre-rename) column names so the existing kaggle_rename map is untouched.
#
# Thresholds are UCI's published rule where the literature is unambiguous
# (domain_registration_length, age_of_domain, having_at_symbol, having_sub_domain).
# Where Kaggle's own metric is not equivalent to UCI's original signal
# (web_traffic, page_rank, links_in_tags, statistical_report — verified via
# empirical class-conditional distributions on data/raw/kaggle_phishing.csv,
# 2 Jul 2026), thresholds are a documented, direction-verified approximation:
# each was confirmed to separate legitimate/phishing medians in the expected
# direction before being hardcoded here. -1 is always the phishing-indicating
# bucket, matching UCI's convention and DEC-007's "assume threat" principle
# for unknown/sentinel values (e.g. -1 in Kaggle's WHOIS-derived columns).


def _bucket_registration_length(days: float) -> int:
    """UCI rule: registration <=365 days -> phishing(-1); >365 -> legit(1).

    Kaggle uses -1 as a sentinel for a failed WHOIS lookup; treated as
    phishing per DEC-007 (assume threat when uncertain).
    """
    if pd.isna(days) or days <= 365:
        return -1
    return 1


def _bucket_domain_age(days: float) -> int:
    """UCI rule: age >=180 days (~6 months) -> legit(1); else phishing(-1).

    Kaggle uses negative sentinels (-1, -2, -12 observed) for failed/invalid
    WHOIS lookups; treated as phishing per DEC-007.
    """
    if pd.isna(days) or days < 180:
        return -1
    return 1


def _bucket_web_traffic(value: float) -> int:
    """Approximated ternary bucket for Kaggle's traffic-volume metric.

    Not Alexa rank (Kaggle's raw scale is 0 to ~10.7M, higher = more
    traffic). Verified empirically (2 Jul 2026): phishing median traffic = 0,
    legitimate median = 25,176, legitimate 75th percentile = 516,310. Buckets
    chosen so 0 traffic (dead/unranked site) reads as phishing(-1), and the
    legitimate median falls inside the middle bucket rather than the top one.
    """
    if pd.isna(value) or value <= 0:
        return -1
    if value <= 100_000:
        return 0
    return 1


def _bucket_page_rank(value: float) -> int:
    """Approximated binary bucket for Kaggle's 0-10 page-rank scale.

    UCI's own page_rank is binary {-1, 1} (normalised Google PageRank).
    Kaggle's is an integer 0-10 scale; verified empirically (2 Jul 2026):
    phishing median = 1, legitimate median = 5. Threshold at the midpoint.
    """
    if pd.isna(value) or value < 5:
        return -1
    return 1


def _bucket_links_in_tags(pct: float) -> int:
    """Ternary bucket for Kaggle's 0-100 internal-tag-link percentage.

    UCI's links_in_tags is ternary {-1, 0, 1}. Kaggle's raw scale is a 0-100
    percentage of internal-domain links inside <meta>/<script>/<link> tags;
    verified empirically (2 Jul 2026) that legitimate pages skew higher
    (median 66.7) than phishing pages (median 33.3) — i.e. higher internal
    ratio reads as more legitimate. Tercile cutoffs chosen to match those
    observed medians.
    """
    if pd.isna(pct) or pct < 33.3:
        return -1
    if pct <= 66.7:
        return 0
    return 1


def _bucket_statistical_report(value: float) -> int:
    """UCI rule: flagged in a phishing statistical report -> -1; else 1.

    Kaggle's raw column is mostly 0 (not flagged) with rare 1/2 values;
    verified empirically (2 Jul 2026) that phishing rows are flagged ~8x more
    often than legitimate rows, confirming any nonzero value is a phishing
    signal.
    """
    if pd.isna(value) or value == 0:
        return 1
    return -1


def _bucket_at_symbol_count(count: float) -> int:
    """UCI rule: any '@' present -> phishing(-1); none -> legit(1)."""
    if pd.isna(count) or count > 0:
        return -1
    return 1


def _bucket_subdomain_count(count: float) -> int:
    """UCI rule (dot-count analogue): 1 subdomain level -> legit(1);
    2 -> suspicious(0); >=3 -> phishing(-1).

    Kaggle's nb_subdomains is already a level count (observed range 1-3),
    directly analogous to UCI's own dot-count thresholding.
    """
    if pd.isna(count) or count <= 1:
        return 1
    if count == 2:
        return 0
    return -1


# Kaggle raw column name -> bucketing function. Applied in place so the
# existing `kaggle_rename` map (which only renames, does not transform)
# continues to work unchanged downstream.
_KAGGLE_SCALE_BUCKETS: dict[str, Any] = {
    "domain_registration_length": _bucket_registration_length,
    "domain_age": _bucket_domain_age,
    "web_traffic": _bucket_web_traffic,
    "page_rank": _bucket_page_rank,
    "links_in_tags": _bucket_links_in_tags,
    "statistical_report": _bucket_statistical_report,
    "nb_at": _bucket_at_symbol_count,
    "nb_subdomains": _bucket_subdomain_count,
}


def bucket_kaggle_scale(df: pd.DataFrame) -> pd.DataFrame:
    """Convert Kaggle's raw continuous/count columns to UCI's -1/0/1 scale.

    Must run on the raw Kaggle DataFrame (original column names) before
    :func:`rename_columns`. Columns not present in ``df`` are skipped (keeps
    this safe to call even if Kaggle's schema drifts). See DEC-014.

    Args:
        df: Raw Kaggle DataFrame (post label-normalisation, pre-rename).

    Returns:
        A copy of ``df`` with the 8 scale-mismatched columns bucketed to
        UCI's categorical scheme; all other columns unchanged.
    """
    df = df.copy()
    applied = []
    for col, bucket_fn in _KAGGLE_SCALE_BUCKETS.items():
        if col in df.columns:
            df[col] = df[col].apply(bucket_fn)
            applied.append(col)
    logger.info("Kaggle scale normalisation applied to %d columns: %s", len(applied), applied)
    return df


# ---------------------------------------------------------------------------
# Renaming & schema alignment
# ---------------------------------------------------------------------------


def rename_columns(df: pd.DataFrame, rename_map: dict[str, str]) -> pd.DataFrame:
    """Rename DataFrame columns using a mapping dict, skipping unknown keys.

    Only columns present in both ``df`` and ``rename_map`` are renamed.
    Columns not in the map are dropped (Kaggle has 87 features; we keep only
    the ones that overlap with the UCI feature contract).

    Args:
        df: Input DataFrame.
        rename_map: Mapping of {original_col: internal_col}. Must include the
            label column mapped to ``"label"``.

    Returns:
        New DataFrame with only the columns that appear in ``rename_map``
        values, renamed accordingly.
    """
    applicable = {k: v for k, v in rename_map.items() if k in df.columns}
    renamed = df.rename(columns=applicable)
    kept_cols = list(applicable.values())
    dropped = set(df.columns) - set(applicable.keys())
    if dropped:
        logger.debug("Dropping %d columns not in rename map: %s", len(dropped), sorted(dropped))
    return renamed[kept_cols]


def align_schemas(
    uci_df: pd.DataFrame,
    kaggle_df: pd.DataFrame,
    feature_columns: list[str],
) -> tuple[pd.DataFrame, pd.DataFrame]:
    """Align UCI and Kaggle DataFrames to the shared feature contract.

    After renaming, both DataFrames may have different column sets. This
    function ensures both have exactly ``feature_columns + ['label']``.
    Missing columns are added as NaN (logged). Extra columns are dropped.

    Args:
        uci_df: UCI DataFrame after :func:`rename_columns`.
        kaggle_df: Kaggle DataFrame after :func:`rename_columns`.
        feature_columns: Ordered list of feature names from ``data_config.yaml``.

    Returns:
        Tuple of (aligned_uci, aligned_kaggle) with identical column sets.
    """
    target_cols = [*feature_columns, "label"]

    def _align(df: pd.DataFrame, name: str) -> pd.DataFrame:
        missing = [c for c in target_cols if c not in df.columns]
        extra = [c for c in df.columns if c not in target_cols]
        if missing:
            logger.warning(
                "%s: %d feature columns missing, will be NaN after merge: %s",
                name, len(missing), missing,
            )
            for col in missing:
                df[col] = pd.NA
        if extra:
            logger.debug("%s: dropping %d extra columns: %s", name, len(extra), extra)
            df = df.drop(columns=extra)
        return df[target_cols]

    return _align(uci_df.copy(), "UCI"), _align(kaggle_df.copy(), "Kaggle")


# ---------------------------------------------------------------------------
# Cleaning
# ---------------------------------------------------------------------------


def drop_duplicates(df: pd.DataFrame) -> tuple[pd.DataFrame, int]:
    """Drop exact duplicate rows (all columns identical).

    Args:
        df: Input DataFrame.

    Returns:
        Tuple of (deduplicated DataFrame, number of rows removed).
    """
    before = len(df)
    df = df.drop_duplicates().reset_index(drop=True)
    n_removed = before - len(df)
    logger.info("Duplicate removal: %d rows removed (%d → %d)", n_removed, before, len(df))
    return df, n_removed


def audit_missing(df: pd.DataFrame) -> dict[str, float]:
    """Compute per-column null rate.

    Args:
        df: Input DataFrame.

    Returns:
        Dict mapping column name → null rate (0.0–1.0).
    """
    null_rates = (df.isnull().sum() / len(df)).to_dict()
    high_null = {col: rate for col, rate in null_rates.items() if rate > 0.0}
    if high_null:
        logger.info(
            "Columns with nulls: %s",
            {col: f"{rate:.1%}" for col, rate in sorted(high_null.items(), key=lambda x: -x[1])},
        )
    else:
        logger.info("No null values found.")
    return null_rates


def drop_high_null_columns(
    df: pd.DataFrame, max_null_rate: float = 0.50
) -> tuple[pd.DataFrame, list[str]]:
    """Drop columns where null rate exceeds ``max_null_rate``.

    Args:
        df: Input DataFrame.
        max_null_rate: Threshold above which a column is dropped (0.0–1.0).

    Returns:
        Tuple of (cleaned DataFrame, list of dropped column names).
    """
    null_rates = df.isnull().sum() / len(df)
    to_drop = [col for col, rate in null_rates.items() if rate > max_null_rate and col != "label"]
    if to_drop:
        logger.warning(
            "Dropping %d high-null columns (>%.0f%% missing): %s",
            len(to_drop), max_null_rate * 100, to_drop,
        )
        df = df.drop(columns=to_drop)
    return df, to_drop


def fit_imputer(train_df: pd.DataFrame, strategy: str = "mode") -> dict[str, object]:
    """Compute per-column fill values from the training set only.

    Call this on the training split, then pass the result to
    :func:`apply_imputer` for the validation and test splits.
    This prevents imputation leakage (TD-3): val/test statistics must not
    influence the fill values seen during training.

    Args:
        train_df: Training split DataFrame (label column excluded from fit).
        strategy: Only ``"mode"`` is supported — all ARGUS features are
            categorical integers (-1/0/1) so mode is the correct fill.

    Returns:
        Dict mapping column name → fill value, covering only columns that
        have at least one null in ``train_df``. Columns with no nulls are
        omitted (no fill needed).

    Raises:
        ValueError: If ``strategy`` is not ``"mode"``.
    """
    if strategy != "mode":
        raise ValueError(f"Unsupported impute strategy '{strategy}'. Use 'mode'.")

    feature_cols = [c for c in train_df.columns if c != "label"]
    null_cols = [c for c in feature_cols if train_df[c].isnull().any()]
    fill_values: dict[str, object] = {}
    for col in null_cols:
        mode_series = train_df[col].mode(dropna=True)
        fill_values[col] = mode_series.iloc[0] if len(mode_series) > 0 else 0
        logger.info("Imputer fit: '%s' → mode=%s (from train set)", col, fill_values[col])
    return fill_values


def apply_imputer(
    df: pd.DataFrame, fill_values: dict[str, object]
) -> pd.DataFrame:
    """Apply pre-fitted fill values to a DataFrame.

    Uses fill values computed by :func:`fit_imputer` on the training set.
    Safe to call on train, val, and test splits — always uses training-set
    statistics, never the split's own statistics.

    Args:
        df: DataFrame to impute. Columns absent from ``fill_values`` are left
            unchanged (no nulls expected, or not a feature column).
        fill_values: Dict from :func:`fit_imputer`.

    Returns:
        Copy of ``df`` with nulls in ``fill_values`` columns filled.
    """
    if not fill_values:
        logger.info("No nulls to impute.")
        return df

    df = df.copy()
    for col, fill_val in fill_values.items():
        if col not in df.columns:
            continue
        n_filled = int(df[col].isnull().sum())
        if n_filled > 0:
            df[col] = df[col].fillna(fill_val)
            logger.info("Imputed %d nulls in '%s' with mode=%s", n_filled, col, fill_val)
    return df


def impute_missing(df: pd.DataFrame, strategy: str = "mode") -> pd.DataFrame:
    """Fill remaining nulls using ``strategy`` per column.

    .. deprecated::
        Use :func:`fit_imputer` + :func:`apply_imputer` instead to avoid
        imputation leakage (TD-3). This function computes fill values from
        ``df`` itself, which is safe only when ``df`` is the training split.

    Args:
        df: Input DataFrame (label column excluded from imputation).
        strategy: Imputation strategy. Only ``"mode"`` is supported for
            categorical integer features. Pass ``"mode"`` always.

    Returns:
        DataFrame with no remaining nulls in feature columns.
    """
    fill_values = fit_imputer(df, strategy=strategy)
    return apply_imputer(df, fill_values)


# ---------------------------------------------------------------------------
# Merge
# ---------------------------------------------------------------------------


def merge_datasets(
    uci_df: pd.DataFrame,
    kaggle_df: pd.DataFrame,
) -> pd.DataFrame:
    """Concatenate UCI and Kaggle DataFrames into a single dataset.

    Both DataFrames must have identical column sets (call :func:`align_schemas`
    first). A ``source`` column is added for auditability, then dropped before
    returning — it is logged but not persisted as a feature.

    Args:
        uci_df: Aligned UCI DataFrame.
        kaggle_df: Aligned Kaggle DataFrame.

    Returns:
        Merged DataFrame with reset index.
    """
    uci_df = uci_df.copy()
    kaggle_df = kaggle_df.copy()
    uci_df["_source"] = "uci"
    kaggle_df["_source"] = "kaggle"

    merged = pd.concat([uci_df, kaggle_df], ignore_index=True)
    logger.info(
        "Merged: UCI=%d rows + Kaggle=%d rows → %d total",
        len(uci_df), len(kaggle_df), len(merged),
    )

    # Log per-source class distribution before dropping _source
    for src in ("uci", "kaggle"):
        sub = merged[merged["_source"] == src]
        n_phish = int((sub["label"] == 1).sum())
        n_legit = int((sub["label"] == 0).sum())
        logger.info("%s: %d phishing, %d legit", src.upper(), n_phish, n_legit)

    merged.drop(columns=["_source"], inplace=True)
    return merged


# ---------------------------------------------------------------------------
# Stratified split
# ---------------------------------------------------------------------------


def stratified_split(
    df: pd.DataFrame,
    train_ratio: float = 0.70,
    val_ratio: float = 0.15,
    test_ratio: float = 0.15,
    random_state: int = 42,
) -> tuple[pd.DataFrame, pd.DataFrame, pd.DataFrame]:
    """Split dataset into train / val / test with stratification on label.

    Performs two consecutive stratified splits:
    1. Full → train (70%) + temp (30%)
    2. Temp → val (15%) + test (15%)

    This preserves class balance in all three splits.

    Args:
        df: Fully preprocessed DataFrame with ``label`` column.
        train_ratio: Fraction for training set.
        val_ratio: Fraction for validation set.
        test_ratio: Fraction for test set.
        random_state: Random seed for reproducibility (always 42, per Iron Law #6).

    Returns:
        Tuple of (train_df, val_df, test_df).

    Raises:
        ValueError: If ratios do not sum to ~1.0.
    """
    total = train_ratio + val_ratio + test_ratio
    if abs(total - 1.0) > 1e-6:
        raise ValueError(
            f"Split ratios must sum to 1.0, got {total:.4f} "
            f"({train_ratio} + {val_ratio} + {test_ratio})"
        )

    # Step 1: train vs temp
    temp_ratio = val_ratio + test_ratio
    train_df, temp_df = train_test_split(
        df,
        test_size=temp_ratio,
        random_state=random_state,
        stratify=df["label"],
    )

    # Step 2: val vs test (equal halves of temp)
    val_df, test_df = train_test_split(
        temp_df,
        test_size=0.5,
        random_state=random_state,
        stratify=temp_df["label"],
    )

    for name, split_df in [("train", train_df), ("val", val_df), ("test", test_df)]:
        n = len(split_df)
        n_phish = int((split_df["label"] == 1).sum())
        n_legit = int((split_df["label"] == 0).sum())
        logger.info(
            "Split %-5s: %5d rows | phishing=%d (%.1f%%) | legit=%d (%.1f%%)",
            name, n,
            n_phish, 100 * n_phish / n,
            n_legit, 100 * n_legit / n,
        )

    return (
        train_df.reset_index(drop=True),
        val_df.reset_index(drop=True),
        test_df.reset_index(drop=True),
    )


# ---------------------------------------------------------------------------
# Persistence
# ---------------------------------------------------------------------------


def save_splits(
    train_df: pd.DataFrame,
    val_df: pd.DataFrame,
    test_df: pd.DataFrame,
    output_dir: str | Path,
    use_parquet: bool = True,
) -> dict[str, str]:
    """Serialise train/val/test splits to disk.

    Saves to Parquet (preferred) or CSV fallback. Scaler is NOT fit here —
    raw features are persisted. Fitting happens inside the sklearn Pipeline
    at training time (see DATASET_NOTES.md leakage rule).

    Args:
        train_df: Training split.
        val_df: Validation split.
        test_df: Test split.
        output_dir: Directory for output files.
        use_parquet: If True, save as ``.parquet``; if False, save as ``.csv``.

    Returns:
        Dict mapping split name → saved file path.
    """
    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    ext = "parquet" if use_parquet else "csv"
    paths: dict[str, str] = {}

    for name, df in [("train", train_df), ("val", val_df), ("test", test_df)]:
        fpath = output_dir / f"{name}.{ext}"
        if use_parquet:
            df.to_parquet(fpath, index=False)
        else:
            df.to_csv(fpath, index=False)
        paths[name] = str(fpath)
        logger.info("Saved %s split → %s (%d rows)", name, fpath, len(df))

    return paths


def compute_dataset_stats(
    train_df: pd.DataFrame,
    val_df: pd.DataFrame,
    test_df: pd.DataFrame,
    n_duplicates_removed: int,
    dropped_columns: list[str],
    null_rates: dict[str, float],
) -> dict[str, Any]:
    """Compute summary statistics for dataset_stats.json.

    Args:
        train_df: Training split.
        val_df: Validation split.
        test_df: Test split.
        n_duplicates_removed: Number of duplicate rows removed during prep.
        dropped_columns: Column names dropped due to high null rate.
        null_rates: Per-column null rate before imputation (from audit_missing).

    Returns:
        Dict suitable for JSON serialisation.
    """
    def _split_stats(df: pd.DataFrame, name: str) -> dict[str, Any]:
        n = len(df)
        n_phish = int((df["label"] == 1).sum())
        n_legit = int((df["label"] == 0).sum())
        return {
            "rows": n,
            "phishing": n_phish,
            "legit": n_legit,
            "phishing_pct": round(100 * n_phish / n, 2) if n else 0.0,
            "legit_pct": round(100 * n_legit / n, 2) if n else 0.0,
            "imbalance_ratio": round(n_phish / max(n_legit, 1), 3),
        }

    total = len(train_df) + len(val_df) + len(test_df)
    all_df = pd.concat([train_df, val_df, test_df])
    total_phish = int((all_df["label"] == 1).sum())
    total_legit = int((all_df["label"] == 0).sum())

    stats: dict[str, Any] = {
        "total_rows": total,
        "total_phishing": total_phish,
        "total_legit": total_legit,
        "global_imbalance_ratio": round(total_phish / max(total_legit, 1), 3),
        "duplicates_removed": n_duplicates_removed,
        "columns_dropped_high_null": dropped_columns,
        "splits": {
            "train": _split_stats(train_df, "train"),
            "val": _split_stats(val_df, "val"),
            "test": _split_stats(test_df, "test"),
        },
        "null_rates_pre_imputation": {
            col: round(rate, 4)
            for col, rate in sorted(null_rates.items(), key=lambda x: -x[1])
            if rate > 0.0
        },
        "feature_count": len([c for c in train_df.columns if c != "label"]),
        "feature_columns": [c for c in train_df.columns if c != "label"],
    }
    return stats


def save_stats(stats: dict[str, Any], path: str | Path) -> None:
    """Write dataset_stats.json to disk.

    Args:
        stats: Dict from :func:`compute_dataset_stats`.
        path: Output file path.
    """
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(stats, f, indent=2)
    logger.info("Dataset stats written to %s", path)
