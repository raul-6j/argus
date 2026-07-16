#!/usr/bin/env python3
# scripts/data_prep.py
# End-to-end ARGUS data pipeline: download → validate → clean → merge → split → serialise.
# Run: python scripts/data_prep.py --config configs/data_config.yaml
# Run (download only): python scripts/data_prep.py --config configs/data_config.yaml --download
# Run (prep only, skip download): python scripts/data_prep.py --config configs/data_config.yaml --no-download

from __future__ import annotations

import argparse
import logging
import subprocess
import sys
from pathlib import Path

import yaml

# ---------------------------------------------------------------------------
# Logging setup — must happen before any src imports so handler is attached
# ---------------------------------------------------------------------------
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s  %(levelname)-8s  %(name)s — %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger("argus.data_prep")

# ---------------------------------------------------------------------------
# Project root — allows running from any cwd
# ---------------------------------------------------------------------------
PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from src.data.loaders import (  # noqa: E402
    load_kaggle,
    load_uci,
    normalise_labels,
)
from src.data.preprocessor import (  # noqa: E402
    align_schemas,
    apply_imputer,
    audit_missing,
    bucket_kaggle_scale,
    compute_dataset_stats,
    drop_duplicates,
    drop_high_null_columns,
    fit_imputer,
    merge_datasets,
    rename_columns,
    save_splits,
    save_stats,
    stratified_split,
)


# ---------------------------------------------------------------------------
# Config loader
# ---------------------------------------------------------------------------


def load_config(config_path: str | Path) -> dict:
    """Load and return the YAML data configuration.

    Args:
        config_path: Path to ``configs/data_config.yaml``.

    Returns:
        Parsed config dict.

    Raises:
        FileNotFoundError: If the config file does not exist.
    """
    config_path = Path(config_path)
    if not config_path.exists():
        raise FileNotFoundError(f"Config not found: {config_path}")
    with open(config_path, encoding="utf-8") as f:
        return yaml.safe_load(f)


# ---------------------------------------------------------------------------
# Download helpers
# ---------------------------------------------------------------------------


def download_uci(config: dict) -> Path:
    """Download UCI dataset via ucimlrepo and save to raw CSV.

    Args:
        config: Parsed data_config.yaml dict.

    Returns:
        Path to the saved UCI CSV file.
    """
    try:
        from ucimlrepo import fetch_ucirepo  # type: ignore[import]
    except ImportError:
        logger.error(
            "ucimlrepo is not installed. Run: pip install ucimlrepo"
        )
        sys.exit(1)

    repo_id: int = config["download"]["uci_repo_id"]
    out_path = PROJECT_ROOT / config["paths"]["uci_csv"]
    out_path.parent.mkdir(parents=True, exist_ok=True)

    if out_path.exists():
        logger.info("UCI CSV already exists at %s — skipping download.", out_path)
        return out_path

    logger.info("Fetching UCI dataset (id=%d) via ucimlrepo ...", repo_id)
    dataset = fetch_ucirepo(id=repo_id)

    # ucimlrepo returns dataset.data.features (X) and dataset.data.targets (y)
    import pandas as pd  # noqa: PLC0415

    df = pd.concat(
        [dataset.data.features, dataset.data.targets],
        axis=1,
    )
    df.to_csv(out_path, index=False)
    logger.info("UCI CSV saved to %s (%d rows)", out_path, len(df))
    return out_path


def download_kaggle(config: dict) -> Path:
    """Download Kaggle dataset via kaggle CLI and save raw CSV.

    Requires ``~/.kaggle/kaggle.json`` with a valid API token.
    See setup instructions printed on failure.

    Args:
        config: Parsed data_config.yaml dict.

    Returns:
        Path to the saved Kaggle CSV file.
    """
    out_path = PROJECT_ROOT / config["paths"]["kaggle_csv"]
    out_path.parent.mkdir(parents=True, exist_ok=True)

    if out_path.exists():
        logger.info("Kaggle CSV already exists at %s — skipping download.", out_path)
        return out_path

    dataset_slug: str = config["download"]["kaggle_dataset"]
    raw_dir = out_path.parent

    logger.info("Downloading Kaggle dataset '%s' ...", dataset_slug)

    # Check kaggle CLI is available
    try:
        subprocess.run(
            ["kaggle", "--version"],
            check=True,
            capture_output=True,
        )
    except (FileNotFoundError, subprocess.CalledProcessError):
        _print_kaggle_setup_instructions(dataset_slug)
        sys.exit(1)

    try:
        subprocess.run(
            [
                "kaggle", "datasets", "download",
                "--dataset", dataset_slug,
                "--path", str(raw_dir),
                "--unzip",
            ],
            check=True,
        )
    except subprocess.CalledProcessError as exc:
        logger.error("kaggle CLI download failed: %s", exc)
        _print_kaggle_setup_instructions(dataset_slug)
        sys.exit(1)

    # The dataset zip unpacks to a folder — find the CSV
    csv_files = list(raw_dir.glob("*.csv"))
    if not csv_files:
        logger.error(
            "No CSV found in %s after Kaggle download. "
            "Check that the dataset contains a CSV file.",
            raw_dir,
        )
        sys.exit(1)

    # If multiple CSVs, pick the largest (most likely the main dataset file)
    main_csv = max(csv_files, key=lambda p: p.stat().st_size)
    if main_csv != out_path:
        main_csv.rename(out_path)

    logger.info("Kaggle CSV saved to %s", out_path)
    return out_path


def _print_kaggle_setup_instructions(dataset_slug: str) -> None:
    """Print Kaggle API setup instructions to stdout."""
    print(
        "\n"
        "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n"
        "  Kaggle API setup required (one-time, ~2 minutes)\n"
        "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n"
        "\n"
        "  1. Go to https://www.kaggle.com → Account → API → 'Create New Token'\n"
        "     This downloads kaggle.json\n"
        "\n"
        "  2. Move it to the right place:\n"
        "     mkdir -p ~/.kaggle && mv ~/Downloads/kaggle.json ~/.kaggle/\n"
        "     chmod 600 ~/.kaggle/kaggle.json\n"
        "\n"
        "  3. Install the Kaggle CLI:\n"
        "     pip install kaggle\n"
        "\n"
        "  4. Accept the dataset licence (one-time, web browser):\n"
        f"     https://www.kaggle.com/datasets/{dataset_slug}\n"
        "     (click 'Download' — this accepts the terms)\n"
        "\n"
        "  5. Re-run this script:\n"
        "     python scripts/data_prep.py --config configs/data_config.yaml\n"
        "\n"
        "  Alternatively, download manually:\n"
        f"     kaggle datasets download -d {dataset_slug} --unzip -p data/raw/\n"
        "     mv data/raw/<downloaded_filename>.csv data/raw/kaggle_phishing.csv\n"
        "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n",
        file=sys.stdout,
    )


# ---------------------------------------------------------------------------
# Parquet availability check
# ---------------------------------------------------------------------------


def _parquet_available() -> bool:
    """Return True if pyarrow is installed (required for Parquet)."""
    try:
        import pyarrow  # noqa: F401
        return True
    except ImportError:
        return False


# ---------------------------------------------------------------------------
# Main pipeline
# ---------------------------------------------------------------------------


def run_pipeline(config: dict, uci_only: bool = False) -> None:
    """Execute the full data preparation pipeline.

    Steps:
        1. Load + validate UCI CSV (and Kaggle CSV unless uci_only=True)
        2. Normalise labels (apply suspicious-class policy)
        3. Rename columns to internal names
        4. Align schemas (fill missing cols with NaN)
        5. Merge datasets (or use UCI only)
        6. Drop exact duplicates
        7. Missing-value audit + high-null column drop
        8. Stratified 70/15/15 split  ← split BEFORE imputation (TD-3 fix)
        9. Fit mode imputer on train split only, apply to val + test
        10. Persist raw features to parquet/csv
        11. Write dataset_stats.json

    **Leakage guard (TD-3):** Imputation statistics are computed on the
    training split only (step 9), then applied to val and test. This prevents
    val/test statistics from leaking into the fill values used during training.
    No scaler is fit here — StandardScaler lives inside the sklearn Pipeline
    at training time.

    Args:
        config: Parsed data_config.yaml dict.
        uci_only: If True, skip Kaggle loading and train on UCI alone.
            Use this when Kaggle credentials are not yet configured.
    """
    label_cfg = config["labels"]
    suspicious_policy = label_cfg["suspicious_class_policy"]
    feature_columns: list[str] = config["feature_columns"]
    max_null_rate: float = config["preprocessing"]["max_null_rate"]
    impute_strategy: str = config["preprocessing"]["impute_strategy"]["categorical_int"]

    split_cfg = config["split"]
    processed_dir = PROJECT_ROOT / config["paths"]["processed_dir"]
    stats_path = PROJECT_ROOT / config["output"]["stats_json"]

    # ------------------------------------------------------------------
    # Step 1: Load + validate
    # ------------------------------------------------------------------
    logger.info("=" * 60)
    logger.info("STEP 1: Load and validate datasets")
    logger.info("=" * 60)

    uci_raw = load_uci(PROJECT_ROOT / config["paths"]["uci_csv"])

    if uci_only:
        logger.warning(
            "Running in UCI-only mode. Kaggle dataset skipped. "
            "Re-run without --uci-only once kaggle.json is configured."
        )
        kaggle_raw = None
    else:
        kaggle_raw = load_kaggle(
            PROJECT_ROOT / config["paths"]["kaggle_csv"],
            label_col=label_cfg["kaggle_label_col"],
        )

    # ------------------------------------------------------------------
    # Step 2: Normalise labels
    # ------------------------------------------------------------------
    logger.info("=" * 60)
    logger.info("STEP 2: Normalise labels (suspicious_policy=%s)", suspicious_policy)
    logger.info("=" * 60)

    uci_normed = normalise_labels(
        uci_raw,
        source="uci",
        suspicious_policy=suspicious_policy,
    )

    if kaggle_raw is not None:
        kaggle_normed = normalise_labels(
            kaggle_raw,
            source="kaggle",
            kaggle_label_col=label_cfg["kaggle_label_col"],
            kaggle_phishing_raw=label_cfg["kaggle_phishing_raw"],
            kaggle_legit_raw=label_cfg["kaggle_legit_raw"],
        )
    else:
        kaggle_normed = None

    # ------------------------------------------------------------------
    # Step 2b: Bucket Kaggle's raw continuous/count columns onto UCI's
    # -1/0/1 scale (DEC-014) — must run before rename, on raw column names.
    # ------------------------------------------------------------------
    if kaggle_normed is not None:
        logger.info("=" * 60)
        logger.info("STEP 2b: Bucket Kaggle columns to UCI scale (DEC-014)")
        logger.info("=" * 60)
        kaggle_normed = bucket_kaggle_scale(kaggle_normed)

    # ------------------------------------------------------------------
    # Step 3: Rename columns to internal names
    # ------------------------------------------------------------------
    logger.info("=" * 60)
    logger.info("STEP 3: Rename columns")
    logger.info("=" * 60)

    uci_renamed = rename_columns(uci_normed, config["uci_rename"])
    logger.info("UCI after rename: %d cols", len(uci_renamed.columns))

    if kaggle_normed is not None:
        kaggle_renamed = rename_columns(kaggle_normed, config["kaggle_rename"])
        logger.info("Kaggle after rename: %d cols", len(kaggle_renamed.columns))
    else:
        kaggle_renamed = None

    # ------------------------------------------------------------------
    # Step 4: Align schemas
    # ------------------------------------------------------------------
    logger.info("=" * 60)
    logger.info("STEP 4: Align schemas to %d-feature contract", len(feature_columns))
    logger.info("=" * 60)

    if kaggle_renamed is not None:
        uci_aligned, kaggle_aligned = align_schemas(uci_renamed, kaggle_renamed, feature_columns)
    else:
        # UCI-only: align UCI alone against the feature contract
        import pandas as _pd  # noqa: PLC0415
        dummy_kaggle = _pd.DataFrame(columns=feature_columns + ["label"])
        uci_aligned, _ = align_schemas(uci_renamed, dummy_kaggle, feature_columns)
        kaggle_aligned = None

    # ------------------------------------------------------------------
    # Step 5: Merge
    # ------------------------------------------------------------------
    logger.info("=" * 60)
    if kaggle_aligned is not None:
        logger.info("STEP 5: Merge UCI + Kaggle")
    else:
        logger.info("STEP 5: UCI-only mode — skipping merge")
    logger.info("=" * 60)

    if kaggle_aligned is not None:
        merged = merge_datasets(uci_aligned, kaggle_aligned)
    else:
        merged = uci_aligned.reset_index(drop=True)
        logger.info("UCI-only: %d rows", len(merged))

    # ------------------------------------------------------------------
    # Step 6: Drop duplicates
    # ------------------------------------------------------------------
    logger.info("=" * 60)
    logger.info("STEP 6: Remove duplicates")
    logger.info("=" * 60)

    if config["preprocessing"]["drop_duplicates"]:
        merged, n_dupes = drop_duplicates(merged)
    else:
        n_dupes = 0
        logger.info("Duplicate removal disabled in config.")

    # ------------------------------------------------------------------
    # Step 7: Missing-value audit + high-null column drop
    # ------------------------------------------------------------------
    logger.info("=" * 60)
    logger.info("STEP 7: Missing-value audit")
    logger.info("=" * 60)

    null_rates = audit_missing(merged)
    merged, dropped_cols = drop_high_null_columns(merged, max_null_rate=max_null_rate)

    # ------------------------------------------------------------------
    # Step 8: Stratified split  ← BEFORE imputation (TD-3 fix)
    # ------------------------------------------------------------------
    logger.info("=" * 60)
    logger.info("STEP 8: Stratified split (%.0f/%.0f/%.0f) — BEFORE imputation",
                split_cfg["train_ratio"] * 100,
                split_cfg["val_ratio"] * 100,
                split_cfg["test_ratio"] * 100)
    logger.info("=" * 60)

    train_df, val_df, test_df = stratified_split(
        merged,
        train_ratio=split_cfg["train_ratio"],
        val_ratio=split_cfg["val_ratio"],
        test_ratio=split_cfg["test_ratio"],
        random_state=split_cfg["random_state"],
    )

    # ------------------------------------------------------------------
    # Step 9: Fit imputer on train only, apply to val + test (TD-3 fix)
    # ------------------------------------------------------------------
    logger.info("=" * 60)
    logger.info("STEP 9: Impute nulls — fit on train only, apply to val + test (strategy=%s)",
                impute_strategy)
    logger.info("=" * 60)

    fill_values = fit_imputer(train_df, strategy=impute_strategy)
    train_df = apply_imputer(train_df, fill_values)
    val_df = apply_imputer(val_df, fill_values)
    test_df = apply_imputer(test_df, fill_values)

    # Final null check across all splits
    for split_name, split_df in [("train", train_df), ("val", val_df), ("test", test_df)]:
        remaining_nulls = int(split_df.isnull().sum().sum())
        if remaining_nulls > 0:
            logger.error(
                "LEAKAGE GUARD: %d nulls remain in %s after imputation!",
                remaining_nulls, split_name,
            )
            sys.exit(1)
    logger.info("Post-imputation null check passed: 0 nulls across all splits.")

    # ------------------------------------------------------------------
    # Step 10: Persist splits (raw features — no scaler)
    # ------------------------------------------------------------------
    logger.info("=" * 60)
    logger.info("STEP 10: Persist raw splits")
    logger.info("=" * 60)

    use_parquet = _parquet_available()
    if not use_parquet:
        logger.warning(
            "pyarrow not installed — falling back to CSV. "
            "Install with: pip install pyarrow"
        )

    save_splits(train_df, val_df, test_df, processed_dir, use_parquet=use_parquet)

    # ------------------------------------------------------------------
    # Step 11: Write dataset_stats.json
    # ------------------------------------------------------------------
    logger.info("=" * 60)
    logger.info("STEP 11: Write dataset_stats.json")
    logger.info("=" * 60)

    stats = compute_dataset_stats(
        train_df=train_df,
        val_df=val_df,
        test_df=test_df,
        n_duplicates_removed=n_dupes,
        dropped_columns=dropped_cols,
        null_rates=null_rates,
    )
    save_stats(stats, stats_path)

    logger.info("=" * 60)
    logger.info("Pipeline complete.")
    logger.info(
        "  Total rows: %d  |  Train: %d  |  Val: %d  |  Test: %d",
        stats["total_rows"], stats["splits"]["train"]["rows"],
        stats["splits"]["val"]["rows"], stats["splits"]["test"]["rows"],
    )
    logger.info(
        "  Global imbalance ratio (phishing:legit): %.2f:1",
        stats["global_imbalance_ratio"],
    )
    logger.info("  Outputs in: %s", processed_dir)
    logger.info("=" * 60)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def build_arg_parser() -> argparse.ArgumentParser:
    """Build the CLI argument parser."""
    parser = argparse.ArgumentParser(
        description="ARGUS data preparation pipeline",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Examples:\n"
            "  # Full run (download + prep):\n"
            "  python scripts/data_prep.py --config configs/data_config.yaml\n\n"
            "  # Download only:\n"
            "  python scripts/data_prep.py --config configs/data_config.yaml --download\n\n"
            "  # Prep only (CSVs already in data/raw/):\n"
            "  python scripts/data_prep.py --config configs/data_config.yaml --no-download\n"
        ),
    )
    parser.add_argument(
        "--config",
        type=str,
        default="configs/data_config.yaml",
        help="Path to data_config.yaml (default: configs/data_config.yaml)",
    )
    parser.add_argument(
        "--download",
        action="store_true",
        default=False,
        help="Run download step only, then exit.",
    )
    parser.add_argument(
        "--no-download",
        action="store_true",
        default=False,
        help="Skip download step (CSVs must already exist in data/raw/).",
    )
    parser.add_argument(
        "--uci-only",
        action="store_true",
        default=False,
        help=(
            "Run pipeline with UCI dataset only (skip Kaggle). "
            "Use when kaggle.json is not yet configured. "
            "Re-run without this flag once Kaggle credentials are set up."
        ),
    )
    return parser


def main() -> None:
    """Entry point for scripts/data_prep.py."""
    parser = build_arg_parser()
    args = parser.parse_args()

    config = load_config(Path(args.config) if not Path(args.config).is_absolute()
                         else args.config)

    uci_only: bool = getattr(args, "uci_only", False)

    # ── Download step ──────────────────────────────────────────────────
    if not args.no_download:
        logger.info("Starting download step ...")
        download_uci(config)
        if not uci_only:
            download_kaggle(config)
        if args.download:
            logger.info("Download complete. Re-run without --download to run the pipeline.")
            return

    # ── Prep step ──────────────────────────────────────────────────────
    run_pipeline(config, uci_only=uci_only)


if __name__ == "__main__":
    main()
