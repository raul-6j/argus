"""Train the 4-model comparison (DT/RF/LR/SVM) on the UCI+Kaggle training split.

Iron rules (Task 5.2, PHASE_GUIDE.md):
    * ``data/processed/test.parquet`` is never touched here — it is read
      exactly once, by ``evaluate.py``.
    * Every model is a ``sklearn.Pipeline([SimpleImputer -> StandardScaler?
      -> classifier])``. ``StandardScaler`` is included only for
      ``logistic_regression``/``svm`` (``scale_features: true`` in
      ``model_config.yaml``) — tree-based models don't need it.
    * ``random_state=42`` everywhere; ``class_weight="balanced"`` everywhere
      (class imbalance is expected even though the DEC-014 fix made it mild).
    * Feature input is the 22-feature contract
      (:data:`src.models.contract.FEATURE_ORDER`), not the live-extractor's
      feature space (see DEC-015).

For each of the 4 model types: run ``GridSearchCV`` (stratified 5-fold CV,
scoring from config) on the training split, refit the best estimator on the
full training split, score it on the validation split, and persist it. All 4
candidates are saved to ``models/candidates/``; the CV/val-preferred one is
also copied to ``models/production/`` as a provisional pick — ``evaluate.py``
makes the final, test-set-backed call (and may pick a different model).
"""

from __future__ import annotations

import importlib
import json
import logging
import shutil
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import joblib
import numpy as np
import pandas as pd
import sklearn
import yaml
from sklearn.impute import SimpleImputer
from sklearn.metrics import f1_score, roc_auc_score
from sklearn.model_selection import GridSearchCV, StratifiedKFold
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler

from src.models.contract import FEATURE_ORDER

logger = logging.getLogger(__name__)

PROJECT_ROOT = Path(__file__).resolve().parents[2]


def _import_class(dotted_path: str) -> type:
    """Import a class from a dotted path (e.g. ``"sklearn.tree.DecisionTreeClassifier"``).

    Args:
        dotted_path: Fully-qualified class path.

    Returns:
        The imported class object.
    """
    module_path, class_name = dotted_path.rsplit(".", 1)
    module = importlib.import_module(module_path)
    return getattr(module, class_name)


def load_split(path: Path) -> tuple[np.ndarray, np.ndarray]:
    """Load a processed parquet split as (X, y) in :data:`FEATURE_ORDER`.

    Args:
        path: Path to a ``{train,val,test}.parquet`` file.

    Returns:
        ``(X, y)`` — ``X`` is a 2-D array in contract feature order, ``y`` is
        the label array.

    Raises:
        FileNotFoundError: If ``path`` does not exist.
        KeyError: If the parquet file is missing a contract feature column.
    """
    if not path.is_file():
        raise FileNotFoundError(
            f"{path} not found — run scripts/data_prep.py first (Phase 4)."
        )
    df = pd.read_parquet(path)
    missing = [c for c in FEATURE_ORDER if c not in df.columns]
    if missing:
        raise KeyError(f"{path} is missing contract features: {missing}")
    X = df[list(FEATURE_ORDER)].to_numpy(dtype=float)
    y = df["label"].to_numpy(dtype=int)
    return X, y


def build_pipeline(model_class: type, scale_features: bool, random_state: int) -> Pipeline:
    """Build the ``SimpleImputer -> [StandardScaler] -> classifier`` pipeline.

    Args:
        model_class: The sklearn estimator class to instantiate (params are
            supplied later via ``GridSearchCV``'s ``param_grid``, prefixed
            ``"clf__"``).
        scale_features: Whether to insert a ``StandardScaler`` step (True for
            ``logistic_regression``/``svm``; False for tree-based models).
        random_state: Seed forwarded to the classifier if it accepts one.

    Returns:
        An unfitted sklearn ``Pipeline``.
    """
    steps: list[tuple[str, Any]] = [("imputer", SimpleImputer(strategy="most_frequent"))]
    if scale_features:
        steps.append(("scaler", StandardScaler()))

    try:
        clf = model_class(random_state=random_state)
    except TypeError:
        # Some estimators (none of the current 4, but defensive) don't accept
        # random_state directly.
        clf = model_class()
    steps.append(("clf", clf))
    return Pipeline(steps)


def train_one_model(
    name: str,
    model_cfg: dict[str, Any],
    X_train: np.ndarray,
    y_train: np.ndarray,
    X_val: np.ndarray,
    y_val: np.ndarray,
    *,
    cv_folds: int,
    scoring: str,
    random_state: int,
) -> tuple[Pipeline, dict[str, Any]]:
    """Grid-search, refit, and validate a single model.

    Args:
        name: Model key (e.g. ``"decision_tree"``), used only for logging.
        model_cfg: This model's entry from ``model_config.yaml`` (``class``,
            ``scale_features``, ``params``).
        X_train: Training features, shape ``(n_train, 22)``.
        y_train: Training labels.
        X_val: Validation features, shape ``(n_val, 22)``.
        y_val: Validation labels.
        cv_folds: Number of stratified CV folds.
        scoring: sklearn scoring string for ``GridSearchCV`` (e.g. ``"f1"``).
        random_state: Seed for the CV splitter and the classifier.

    Returns:
        ``(best_estimator, metadata)`` — the refit best pipeline, and a dict
        of everything ``EXPERIMENTS.md``/``metadata.json`` need to cite.
    """
    model_class = _import_class(model_cfg["class"])
    pipeline = build_pipeline(model_class, model_cfg["scale_features"], random_state)

    param_grid = {f"clf__{k}": v for k, v in model_cfg["params"].items()}
    cv = StratifiedKFold(n_splits=cv_folds, shuffle=True, random_state=random_state)

    logger.info("Training %s — grid: %s", name, param_grid)
    search = GridSearchCV(
        pipeline, param_grid=param_grid, scoring=scoring, cv=cv, n_jobs=1, refit=True
    )
    search.fit(X_train, y_train)

    best_estimator: Pipeline = search.best_estimator_
    cv_mean = float(search.best_score_)
    cv_std = float(search.cv_results_["std_test_score"][search.best_index_])

    val_pred = best_estimator.predict(X_val)
    val_proba = best_estimator.predict_proba(X_val)[:, 1]
    val_f1 = float(f1_score(y_val, val_pred))
    val_roc_auc = float(roc_auc_score(y_val, val_proba))

    metadata = {
        "model_type": name,
        "sklearn_class": model_cfg["class"],
        "best_params": {k.replace("clf__", ""): v for k, v in search.best_params_.items()},
        "cv_folds": cv_folds,
        "cv_scoring": scoring,
        "cv_mean_score": cv_mean,
        "cv_std_score": cv_std,
        "val_f1": val_f1,
        "val_roc_auc": val_roc_auc,
        "feature_order": list(FEATURE_ORDER),
        "dataset": "UCI+Kaggle (DEC-013/014 22-feature contract)",
        "train_date": datetime.now(timezone.utc).isoformat(),
        "sklearn_version": sklearn.__version__,
        "random_state": random_state,
    }
    logger.info(
        "%s: cv_%s=%.4f (+/-%.4f) val_f1=%.4f val_roc_auc=%.4f best_params=%s",
        name, scoring, cv_mean, cv_std, val_f1, val_roc_auc, metadata["best_params"],
    )
    return best_estimator, metadata


def run_training(config: dict[str, Any]) -> dict[str, dict[str, Any]]:
    """Train all configured models and persist candidates + a provisional pick.

    Args:
        config: Parsed ``model_config.yaml``.

    Returns:
        Mapping of model name -> metadata dict (as also written to each
        candidate's ``metadata.json``).
    """
    random_state = config["random_state"]
    cv_folds = config["cv_folds"]
    scoring = config["scoring"]

    train_path = PROJECT_ROOT / config["data"]["train_path"]
    val_path = PROJECT_ROOT / config["data"]["val_path"]
    candidates_dir = PROJECT_ROOT / config["output"]["candidates_dir"]
    production_dir = PROJECT_ROOT / config["output"]["production_dir"]
    candidates_dir.mkdir(parents=True, exist_ok=True)
    production_dir.mkdir(parents=True, exist_ok=True)

    logger.info("Loading train split: %s", train_path)
    X_train, y_train = load_split(train_path)
    logger.info("Loading val split: %s", val_path)
    X_val, y_val = load_split(val_path)
    logger.info("train=%d rows, val=%d rows, %d features", len(y_train), len(y_val), X_train.shape[1])

    all_metadata: dict[str, dict[str, Any]] = {}
    for name, model_cfg in config["models"].items():
        estimator, metadata = train_one_model(
            name, model_cfg, X_train, y_train, X_val, y_val,
            cv_folds=cv_folds, scoring=scoring, random_state=random_state,
        )
        model_path = candidates_dir / f"{name}.joblib"
        joblib.dump(estimator, model_path)
        with (candidates_dir / f"{name}_metadata.json").open("w") as fh:
            json.dump(metadata, fh, indent=2)
        all_metadata[name] = metadata
        logger.info("Saved candidate: %s", model_path)

    # Provisional pick: best val_f1, roc_auc tie-break — evaluate.py makes the
    # authoritative call using the test set.
    tiebreak = config.get("tiebreak", "roc_auc")
    best_name = max(
        all_metadata,
        key=lambda n: (all_metadata[n]["val_f1"], all_metadata[n][f"val_{tiebreak}"]),
    )
    shutil.copy(candidates_dir / f"{best_name}.joblib", production_dir / "model.joblib")
    with (production_dir / "metadata.json").open("w") as fh:
        json.dump(
            dict(all_metadata[best_name], selection_note="provisional pick by val_f1; see evaluate.py for the test-set-backed decision"),
            fh, indent=2,
        )
    logger.info("Provisional production pick (by val_%s): %s", scoring, best_name)

    return all_metadata


def main() -> None:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)-8s %(name)s — %(message)s")
    import argparse

    parser = argparse.ArgumentParser(description="Train the ARGUS 4-model comparison.")
    parser.add_argument("--config", type=Path, default=PROJECT_ROOT / "configs" / "model_config.yaml")
    args = parser.parse_args()

    with args.config.open() as fh:
        config = yaml.safe_load(fh)

    run_training(config)


if __name__ == "__main__":
    main()
