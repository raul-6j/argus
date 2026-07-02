"""Per-prediction SHAP explanations (Phase 5, Task 5.3).

Every model type needs a different SHAP explainer for reasonable speed:
tree models (Decision Tree / Random Forest) get the fast, exact
``TreeExplainer``; Logistic Regression and SVM go through
``KernelExplainer`` against a small k-means-summarized background (SVM's
RBF kernel has no closed-form SHAP solution, and LinearExplainer would
require reasoning about the pipeline's internal StandardScaler directly —
KernelExplainer instead treats ``pipeline.predict_proba`` as a black box,
so the SHAP input space always matches the model's public input space:
the 18-feature training contract, exactly what
``src.models.contract.FEATURE_ORDER``/``feature_adapter`` produce).

``build_explainer()`` is a one-time, per-model setup cost; ``explain_single()``
is meant to run per-request (e.g. from the Phase 6 API).
"""

from __future__ import annotations

from typing import Any, Union

import numpy as np
import shap
from sklearn.pipeline import Pipeline

from src.models.contract import FEATURE_ORDER

# Tree models get the fast, exact TreeExplainer; everything else falls back
# to KernelExplainer against the pipeline's predict_proba (model-agnostic).
_TREE_MODEL_TYPES = frozenset({"decision_tree", "random_forest"})

# KernelExplainer speed knobs — validated empirically (2 Jul 2026): a 10-point
# k-means background + nsamples=100 explains one row in ~0.1s (vs ~4.6s/row
# with a 25-point background and shap's default nsamples), fast enough for a
# per-request API call while still being a reasonable local approximation.
_KERNEL_BACKGROUND_SIZE = 10
_KERNEL_NSAMPLES = 100

Explainer = Union["shap.TreeExplainer", "shap.KernelExplainer"]


def build_explainer(model_type: str, pipeline: Pipeline, background_X: np.ndarray) -> Explainer:
    """Build the appropriate SHAP explainer for a trained candidate.

    Args:
        model_type: One of the keys in ``model_config.yaml -> models``
            (``"decision_tree"``, ``"random_forest"``, ``"logistic_regression"``,
            ``"svm"``).
        pipeline: The fitted ``Pipeline`` (imputer -> [scaler] -> classifier).
        background_X: A representative sample of training features, shape
            ``(n, 18)`` — used as the KernelExplainer background (ignored for
            tree models, which don't need one).

    Returns:
        A fitted SHAP explainer, ready for ``.shap_values()``.
    """
    if model_type in _TREE_MODEL_TYPES:
        return shap.TreeExplainer(pipeline.named_steps["clf"])
    background = shap.kmeans(background_X, min(_KERNEL_BACKGROUND_SIZE, len(background_X)))
    return shap.KernelExplainer(pipeline.predict_proba, background)


def _phishing_class_shap_values(explainer: Explainer, model_type: str, X: np.ndarray) -> np.ndarray:
    """Extract SHAP values for the phishing class (label=1) in a uniform shape.

    Different SHAP explainer/version combinations return either a list of
    per-class arrays or a single ``(n, features, n_classes)`` array. This
    normalizes both to ``(n, features)`` for the phishing class.

    Args:
        explainer: A fitted explainer from :func:`build_explainer`.
        model_type: Used only to pick ``nsamples`` for KernelExplainer.
        X: Feature rows to explain, shape ``(n, 18)``.

    Returns:
        SHAP values for the phishing class, shape ``(n, 18)``.
    """
    if model_type in _TREE_MODEL_TYPES:
        raw = explainer.shap_values(X)
    else:
        raw = explainer.shap_values(X, nsamples=_KERNEL_NSAMPLES, silent=True)

    if isinstance(raw, list):
        return np.asarray(raw[1])
    raw = np.asarray(raw)
    if raw.ndim == 3:
        return raw[:, :, 1]
    return raw


def explain_single(
    features: dict[str, float], model_pipeline: Pipeline, explainer: Explainer, model_type: str
) -> list[dict[str, Any]]:
    """Return the top-5 SHAP feature attributions for one prediction.

    Args:
        features: A single row's contract feature values (e.g.
            ``ModelInput.values`` from :func:`src.models.feature_adapter.adapt_to_training_contract`),
            keyed by name, one entry per :data:`FEATURE_ORDER` feature.
        model_pipeline: The fitted pipeline the prediction came from (unused
            directly here — kept in the signature per the frozen Task 5.3
            contract, for callers that want to assert consistency between
            ``explainer`` and ``model_pipeline``).
        explainer: A fitted explainer from :func:`build_explainer`, built for
            the same model as ``model_pipeline``.
        model_type: The model key (determines SHAP-value extraction shape).

    Returns:
        Up to 5 ``{"feature": str, "shap_value": float, "feature_value": Any}``
        dicts, ordered by ``abs(shap_value)`` descending.

    Raises:
        KeyError: If ``features`` is missing a contract feature.
    """
    del model_pipeline  # part of the frozen signature; not needed directly
    x = np.array([[features[name] for name in FEATURE_ORDER]], dtype=float)
    shap_values = _phishing_class_shap_values(explainer, model_type, x)[0]

    attributions = [
        {"feature": name, "shap_value": float(shap_values[i]), "feature_value": features[name]}
        for i, name in enumerate(FEATURE_ORDER)
    ]
    attributions.sort(key=lambda a: abs(a["shap_value"]), reverse=True)
    return attributions[:5]
