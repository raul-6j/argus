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

import math
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional

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

# UCI's categorical scheme: every *observed* trained feature value is one of
# these three. Note this is the set of values the model was trained on — it is
# deliberately NOT the set of values a live row may carry, because a live row
# may additionally be :data:`MISSING` (see below).
VALID_FEATURE_VALUES: frozenset[int] = frozenset({-1, 0, 1})

# The explicit "this feature could not be measured for this URL" value.
#
# DEC-040: the adapter used to encode an unmeasurable feature as ``-1``, which
# is *also* UCI's "phishing" value — so "we didn't fetch the page" and "the page
# is hostile" were indistinguishable to the model. NaN separates them. Every
# trained pipeline begins with a fitted ``SimpleImputer(strategy="most_frequent")``
# (see ``src/models/train.py``), so NaN is resolved to the training-set mode for
# that column — the statistically neutral fill — instead of to a hand-picked
# constant that happens to mean "malicious". Verified to round-trip identically
# through both serving backends (sklearn and ONNX agree to 7 d.p. on NaN input).
MISSING: float = float("nan")


def is_missing(value: Any) -> bool:
    """Whether ``value`` represents an unmeasurable feature.

    Args:
        value: A contract feature value.

    Returns:
        ``True`` for ``None`` or NaN, ``False`` otherwise.
    """
    if value is None:
        return True
    return isinstance(value, float) and math.isnan(value)


@dataclass
class ModelInput:
    """A single model-ready feature row, in :data:`FEATURE_ORDER`.

    Attributes:
        values: Mapping of feature name -> value. Each is either a member of
            :data:`VALID_FEATURE_VALUES` (measured) or :data:`MISSING`
            (unmeasurable — resolved by the pipeline's fitted imputer).
        approximated: Names of features derived from a *proxy* signal rather
            than a direct live equivalent (e.g. ``domain_reg_length``, which
            the live extractor cannot measure directly and which is inferred
            from ``domain_age_days + days_until_expiry``). A value is still
            genuinely measured — this flags reduced fidelity, not absence.
        unavailable: Names of features that could not be measured at all and
            were therefore set to :data:`MISSING`. Empty when built from
            processed UCI/Kaggle training data; typically non-empty on the
            live lexical-only path, where no page or WHOIS data exists.
    """

    values: dict[str, float]
    approximated: list[str] = field(default_factory=list)
    unavailable: list[str] = field(default_factory=list)

    def to_vector(self) -> list[float]:
        """Materialize as a list in :data:`FEATURE_ORDER`.

        Returns:
            A list of floats, one per feature in contract order. Entries for
            unmeasurable features are :data:`MISSING` (NaN) and are resolved
            downstream by the pipeline's fitted imputer.

        Raises:
            KeyError: If ``values`` is missing a contract feature.
        """
        return [float(self.values[name]) for name in FEATURE_ORDER]

    @property
    def measured(self) -> list[str]:
        """Contract features that carry a real measurement for this row."""
        return [n for n in FEATURE_ORDER if not is_missing(self.values.get(n))]

    @property
    def evidence_ratio(self) -> float:
        """Fraction of the contract actually measured for this row, ``0.0``-``1.0``.

        Callers should treat a low ratio as "this score is weakly evidenced"
        rather than as a confident verdict. It matters more after DEC-040 than
        before: when unmeasurable features were forced to ``-1`` they pushed
        every score toward *phishing*, so a thin row failed loudly. Now they
        are imputed to the training mode, which pushes a thin row toward
        *legitimate* — a quieter and more dangerous failure. On the lexical-only
        path this ratio is ~0.39 (7 of 18), which is not enough evidence for a
        confident "legitimate" no matter what probability comes back.
        """
        if not FEATURE_ORDER:
            return 0.0
        return len(self.measured) / len(FEATURE_ORDER)


@dataclass(frozen=True)
class LiveFeatures:
    """A live URL's full-precision feature record (DEC-040).

    The 18-feature :data:`FEATURE_ORDER` contract is a *lossy projection* of
    what the live extractor actually knows: it is fixed to UCI's ``-1/0/1``
    alphabet because that is what the deployed model was trained on, so a
    continuous measurement like ``domain_age_days=4211`` has to be squashed
    into a single trit before the model can consume it.

    This record keeps both views side by side:

        * :attr:`contract` — the squashed, model-ready projection. Unchanged
          in shape, so every existing call site keeps working.
        * :attr:`values` — the unsquashed measurements, in
          :data:`~src.models.feature_adapter.LIVE_FEATURE_ORDER`. Nothing is bucketed and nothing is
          defaulted; an unmeasurable feature is ``None``.

    :attr:`values` is the input a model retrained on live-domain data should
    consume. It is deliberately *not* fed to the current model, which would
    treat continuous values as out-of-distribution garbage.

    Attributes:
        contract: The model-ready ``-1/0/1``-or-NaN projection.
        values: Full-precision measurements keyed by
            :data:`~src.models.feature_adapter.LIVE_FEATURE_ORDER` name; ``None`` where unmeasurable.
        components_missing: Which live tiers produced nothing
            (``"html"``, ``"domain_intel"``), inferred from the input dict.
    """

    contract: ModelInput
    values: dict[str, Optional[float]]
    components_missing: tuple[str, ...] = ()

    def to_live_vector(self, order: tuple[str, ...]) -> list[float]:
        """Materialize the continuous view in an explicit feature order.

        Args:
            order: The feature names to emit, in order — normally
                :data:`~src.models.feature_adapter.LIVE_FEATURE_ORDER`,
                passed explicitly so a retrained
                model can pin its own subset.

        Returns:
            A list of floats, with :data:`MISSING` for unmeasurable features.
        """
        return [
            MISSING if self.values.get(n) is None else float(self.values[n])
            for n in order
        ]


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
