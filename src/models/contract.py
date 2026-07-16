"""Frozen model I/O contract.

The trained model consumes exactly the 18 features listed in
``configs/data_config.yaml -> feature_columns`` (see DEC-013, DEC-014, DEC-016), on
UCI's ``-1/0/1`` categorical scale. This is a *different* feature space from
``configs/feature_config.yaml -> feature_order`` (Tier 1/2/3/4 live-extractor
output) — see the feature-space-schism note in project memory. ``FEATURE_ORDER``
here always reflects the training contract; nothing in this module hardcodes
the 18 names, so a future change to ``data_config.yaml`` propagates
automatically (enforced by ``tests/models/test_contract.py``).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

import yaml

_PROJECT_ROOT = Path(__file__).resolve().parents[2]
_DATA_CONFIG_PATH = _PROJECT_ROOT / "configs" / "data_config.yaml"


def _load_feature_order(config_path: Path = _DATA_CONFIG_PATH) -> tuple[str, ...]:
    """Load the training feature contract from ``data_config.yaml``.

    Args:
        config_path: Path to the data config YAML.

    Returns:
        The ordered tuple of feature names the model is trained on.

    Raises:
        FileNotFoundError: If ``config_path`` does not exist.
        KeyError: If the config lacks a ``feature_columns`` list.
    """
    if not config_path.is_file():
        raise FileNotFoundError(f"Data config not found: {config_path}")
    with config_path.open("r", encoding="utf-8") as fh:
        data = yaml.safe_load(fh)
    if not isinstance(data, dict) or not data.get("feature_columns"):
        raise KeyError(f"'feature_columns' missing or empty in {config_path}")
    return tuple(str(name) for name in data["feature_columns"])


# The model's frozen input contract, read from data_config.yaml (single
# source of truth — never hardcode this list elsewhere in src/).
FEATURE_ORDER: tuple[str, ...] = _load_feature_order()

# UCI's categorical scheme: every trained feature is one of these three values.
VALID_FEATURE_VALUES: frozenset[int] = frozenset({-1, 0, 1})


@dataclass
class ModelInput:
    """A single model-ready feature row, in :data:`FEATURE_ORDER`.

    Attributes:
        values: Mapping of feature name -> value (each in
            :data:`VALID_FEATURE_VALUES`).
        approximated: Names of features whose value was not derived from a
            live signal (stubbed with a training-set mode default, or
            approximated from a related-but-not-identical live signal). Empty
            when built from processed UCI/Kaggle training data; non-empty
            when built by the live-extractor adapter for real-time inference.
    """

    values: dict[str, int]
    approximated: list[str] = field(default_factory=list)

    def to_vector(self) -> list[int]:
        """Materialize as a list in :data:`FEATURE_ORDER`.

        Returns:
            A list of ints, one per feature in contract order.

        Raises:
            KeyError: If ``values`` is missing a contract feature.
        """
        return [self.values[name] for name in FEATURE_ORDER]


@dataclass
class ModelOutput:
    """A single prediction result.

    Attributes:
        label: ``"phishing"`` or ``"legitimate"``.
        confidence: Predicted-class probability, 0.0-1.0.
        shap_top5: Top-5 SHAP feature attributions (name -> contribution),
            populated in Phase 5.3. ``None`` until then.
        latency_ms: Wall-clock inference time (Iron Law #4 — every API
            response must report this).
    """

    label: str
    confidence: float
    latency_ms: float
    shap_top5: Optional[dict[str, float]] = None
