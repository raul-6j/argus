"""Live-extractor -> training-contract adapter (DEC-015, DEC-016, DEC-040).

``src/features/pipeline.py`` produces a live URL's raw signals (Tier 1
lexical, Tier 4 HTML, Tier 2/3 domain intelligence). The trained model
consumes a different, UCI-scaled 18-feature contract
(:data:`src.models.contract.FEATURE_ORDER`). This module bridges the two —
see the feature-space-schism note in project memory for why they're
different in the first place.

DEC-040 — why this module was redesigned
----------------------------------------
The original adapter fused *measurement* and *encoding* into a single
lambda per feature: each one read raw keys and returned a ``-1/0/1`` trit
directly. Three defects followed from that shape, all confirmed by
measurement rather than inspection:

1. **Unavailable was encoded as phishing.** A missing input returned ``-1``,
   which is *also* UCI's "phishing" value. On the default lexical-only path
   (no page fetch, no WHOIS) 11 of the 18 contract features have no input at
   all, so 11 features were pinned to a constant ``-1`` for every URL on
   Earth. Measured over a 20-URL sample, all 10 legitimate URLs collapsed to
   one *byte-identical* feature vector scoring a constant ``p=0.2175``.
2. **The fitted imputer was dead code.** Every trained pipeline starts with
   ``SimpleImputer(strategy="most_frequent")`` fitted on the training set.
   Because the adapter never emitted NaN, that step was a no-op and the
   statistically correct fill was replaced by a hand-picked constant.
3. **Measurement precision was destroyed at the source.** Because the
   lambdas returned trits, the underlying quantity (a domain age of 4211
   days, a link ratio of 0.34) was discarded the instant it was computed and
   could never be recovered by anything downstream.

The redesign splits every feature into a :class:`Derivation` with two
independent halves — :attr:`Derivation.measure` (full precision, ``None``
when genuinely unmeasurable) and :attr:`Derivation.encode` (projection onto
the contract alphabet). Discretization now happens *only* at the model
boundary, and only because the deployed model requires it.

Why the contract projection is still discretized
------------------------------------------------
It is not a free choice. ``models/production/model.joblib`` is an
``SVC`` behind a ``StandardScaler`` fitted on columns whose observed
alphabet is exactly ``{-1, 0, 1}``. Feeding it a raw ``domain_age_days``
would be out-of-distribution input — strictly worse than the bug being
fixed. So the contract track keeps the trits, and the full-precision
measurements are preserved alongside it in
:class:`~src.models.contract.LiveFeatures` for the fusion layer and for a
model retrained on live-domain data. See :data:`LIVE_FEATURE_ORDER`.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Any, Callable, Optional

from src.models.contract import (
    FEATURE_ORDER,
    MISSING,
    LiveFeatures,
    ModelInput,
)

logger = logging.getLogger(__name__)

# Per-column value alphabets actually observed in the merged UCI+Kaggle
# training frame (data/processed/{train,val}.parquet).
#
# This matters because the encoders below are allowed to use the ``0``
# ("suspicious") band only where the model has actually seen it. Emitting a
# ``0`` into a column whose training values are exclusively ``{-1, 1}`` would
# be out-of-distribution — the same class of mistake DEC-040 is fixing. Two
# columns are genuinely binary in the merged data; the rest carry all three.
# ``tests/models/test_feature_adapter.py::test_alphabets_match_training_data``
# re-derives this from the parquet files when they are present, so a retrain
# that changes a column's alphabet fails loudly instead of silently.
_BINARY_COLUMNS: frozenset[str] = frozenset(
    {"has_at_symbol", "domain_reg_length", "domain_age_cat"}
)


@dataclass(frozen=True)
class Derivation:
    """How one contract feature is obtained from live extractor output.

    The two halves are deliberately separate. :attr:`measure` answers "what
    is the real value of this quantity for this URL?" at full precision;
    :attr:`encode` answers "how is that value expressed in the alphabet the
    deployed model was trained on?". Keeping them apart is what lets the
    continuous track exist at all — the old design's single trit-returning
    lambda threw the measurement away before anyone else could see it.

    Attributes:
        live_name: Name of this quantity in the continuous feature space
            (:data:`LIVE_FEATURE_ORDER`). Deliberately descriptive of the
            *measurement* rather than of the contract slot, because the two
            often differ: contract ``has_prefix_suffix`` is a trit, while its
            measurement ``hyphens_in_hostname`` is a count.
        inputs: Live extractor keys this derivation reads. Used only for
            diagnostics.
        measure: Full-precision measurement, or ``None`` when the signal is
            genuinely unavailable. Must never invent a value.
        encode: Projection of a (non-``None``) measurement onto the contract
            alphabet. Never called with ``None``, so it never has to invent a
            missing-value default — that is the whole point.
        approximated: ``True`` when the measurement is a proxy rather than a
            direct live equivalent of the trained feature.
        note: Human-readable rationale, surfaced in :func:`describe`.
    """

    live_name: str
    inputs: tuple[str, ...]
    measure: Callable[[dict[str, Any]], Optional[float]]
    encode: Callable[[float], int]
    approximated: bool = False
    note: str = ""


# --------------------------------------------------------------------------
# Measurement helpers — full precision, None when genuinely unavailable.
# --------------------------------------------------------------------------


def _flag(key: str) -> Callable[[dict[str, Any]], Optional[float]]:
    """Measure a boolean live signal as ``1.0``/``0.0``, ``None`` if absent.

    Args:
        key: The live extractor key to read.

    Returns:
        A measurement function for :attr:`Derivation.measure`.
    """

    def _measure(features: dict[str, Any]) -> Optional[float]:
        value = features.get(key)
        return None if value is None else float(bool(value))

    return _measure


def _number(key: str) -> Callable[[dict[str, Any]], Optional[float]]:
    """Measure a numeric live signal verbatim, ``None`` if absent or non-numeric.

    Args:
        key: The live extractor key to read.

    Returns:
        A measurement function for :attr:`Derivation.measure`.
    """

    def _measure(features: dict[str, Any]) -> Optional[float]:
        value = features.get(key)
        if isinstance(value, bool) or not isinstance(value, (int, float)):
            return None
        return float(value)

    return _measure


def _measure_registration_span(features: dict[str, Any]) -> Optional[float]:
    """Total creation-to-expiry span in days.

    The live extractor has no direct "registration length" field, so this is
    approximated as ``domain_age_days + days_until_expiry`` — the same proxy
    the original adapter used, but retained at full precision instead of being
    immediately bucketed.
    """
    age = features.get("domain_age_days")
    expiry = features.get("days_until_expiry")
    if age is None or expiry is None:
        return None
    return float(age) + float(expiry)


def _measure_explicit_port(features: dict[str, Any]) -> Optional[float]:
    """The explicit port in the URL, or ``0.0`` when none is present.

    Returns the port *number* rather than a bare boolean so the encoder can
    distinguish an explicit-but-standard port (``:443``, unusual to write out
    but harmless) from an explicit non-standard one (``:8080``, a genuine
    phishing tell). The old adapter collapsed both to ``-1``.
    """
    has_port = features.get("has_port")
    if has_port is None:
        return None
    if not has_port:
        return 0.0
    port = features.get("port_number")
    if isinstance(port, bool) or not isinstance(port, (int, float)):
        # We know a port is present but not which one — that is still a real
        # measurement of "explicit port", just without the number. Encode it
        # at the suspicious end using a sentinel outside the standard set.
        return -1.0
    return float(port)


def _measure_https_token(features: dict[str, Any]) -> Optional[float]:
    """Whether the literal token ``https`` appears inside the domain name.

    UCI's ``HTTPS_token`` means the deceptive practice of embedding "https" in
    the hostname itself (``https-paypal-secure.tk``) to make a padlock-free URL
    read as secure. It does *not* mean "the URL's scheme is TLS" — which is
    what the original adapter fed into this contract slot.

    Kept as a measurement on the continuous track only. It is deliberately NOT
    used for the contract projection: see :func:`_measure_uses_https` for the
    measured reason why correcting the mismatch there would be a net loss.
    """
    domain = features.get("domain")
    if not isinstance(domain, str) or not domain:
        return None
    return float("https" in domain.lower())


def _measure_uses_https(features: dict[str, Any]) -> Optional[float]:
    """Whether the URL's scheme is TLS — the contract's ``https_in_domain`` input.

    This is a *knowing* semantic compromise, and the only place in this module
    where the contract projection is not the most faithful reading available.

    The faithful reading is :func:`_measure_https_token`. Substituting it was
    tried and measured: over 400 real PhishTank URLs plus 173 legitimate brand
    domains it cost **0.016 live ROC-AUC** (0.672 -> 0.656), because almost no
    real hostname contains the literal token, so the column goes constant and
    stops separating anything, while the scheme genuinely does correlate with
    the classes in live traffic.

    So the scheme keeps the slot: dropping a signal that measurably separates
    live URLs, in exchange for nothing the current model can use, would be the
    same information loss this redesign exists to remove. The mismatch is real
    and is recorded rather than silently tolerated — both quantities travel
    separately on the continuous track (``uses_https`` and
    ``https_token_in_domain``), so the retrain that owns the feature space can
    give each its own column and retire the compromise.
    """
    value = features.get("has_https")
    return None if value is None else float(bool(value))


def _measure_form_handler_risk(features: dict[str, Any]) -> Optional[float]:
    """Form-action risk as an ordinal ``0.0`` (safe) / ``0.5`` / ``1.0`` (worst).

    UCI's ``SFH`` is genuinely three-valued, so unlike the boolean signals this
    one loses nothing in the contract projection.
    """
    is_blank = features.get("form_action_is_empty_or_blank")
    is_external = features.get("form_action_is_external")
    if is_blank is None and is_external is None:
        return None
    if is_blank:
        return 1.0
    if is_external:
        return 0.5
    return 0.0


# --------------------------------------------------------------------------
# Encoders — measurement -> contract alphabet. Never see None.
# --------------------------------------------------------------------------


def _phishing_when_true(value: float) -> int:
    """``1.0`` -> ``-1`` (phishing), ``0.0`` -> ``1`` (legitimate)."""
    return -1 if value else 1


def _legit_when_true(value: float) -> int:
    """``1.0`` -> ``1`` (legitimate), ``0.0`` -> ``-1`` (phishing)."""
    return 1 if value else -1


def _encode_hyphens(value: float) -> int:
    """Hyphen count -> trit, using the ``0`` band the old adapter never emitted.

    UCI's ``Prefix_Suffix`` is documented as binary ("any hyphen -> phishing"),
    but the merged training column carries all three values (the Kaggle half
    is scaled differently), so ``0`` is in-distribution here. Grading matters
    because a single hyphen is overwhelmingly ordinary — ``my-bank.co.uk`` is
    a real bank — while ``secure-login-paypal-verify.tk`` is not. The old
    all-or-nothing rule scored those two identically.
    """
    if value <= 0:
        return 1
    if value == 1:
        return 0
    return -1


def _encode_subdomain_level(value: float) -> int:
    """0-1 subdomain levels -> legit(1); 2 -> suspicious(0); >=3 -> phishing(-1).

    ``num_subdomains`` counts tldextract subdomain parts (``www.example.com``
    -> 1), so a single common ``www`` level stays legit rather than suspicious.
    """
    if value <= 1:
        return 1
    if value == 2:
        return 0
    return -1


def _encode_registration_span(value: float) -> int:
    """<=1 year -> phishing(-1), else legit(1).

    Stays binary despite the loss of resolution: ``domain_reg_length`` is one
    of the columns whose merged training alphabet contains no ``0``, so
    emitting a middle band would be out-of-distribution. The full span in days
    survives on the continuous track instead.
    """
    return -1 if value <= 365 else 1


def _encode_domain_age(value: float) -> int:
    """<6 months -> phishing(-1), else legit(1).

    UCI documents a three-band scheme (<6mo / 6-12mo / >12mo) and the middle
    band is exactly the resolution this feature wants, but the merged training
    column contains only ``{-1, 1}`` — so the ``0`` band cannot be used without
    inventing a value the model never saw. Full precision is kept in
    ``domain_age_days`` on the continuous track.
    """
    return -1 if value < 180 else 1


def _encode_link_ratio(value: float) -> int:
    """Tercile split on the extractor's 0.0-1.0 internal-link ratio."""
    if value < 0.333:
        return -1
    if value <= 0.667:
        return 0
    return 1


def _encode_port(value: float) -> int:
    """No explicit port -> legit(1); standard port written out -> 0; else -1.

    ``-1.0`` is the "port present, number unknown" sentinel from
    :func:`_measure_explicit_port`.
    """
    if value == 0:
        return 1
    if value in (80.0, 443.0):
        return 0
    return -1


def _encode_form_handler(value: float) -> int:
    """Ordinal form-action risk -> trit (blank -> -1, external -> 0, same -> 1)."""
    if value >= 1.0:
        return -1
    if value > 0.0:
        return 0
    return 1


# --------------------------------------------------------------------------
# The derivation table: one entry per contract feature.
# --------------------------------------------------------------------------

_DERIVATIONS: dict[str, Derivation] = {
    "has_ip_address": Derivation(
        live_name="host_is_ip",
        inputs=("has_ip_address",),
        measure=_flag("has_ip_address"),
        encode=_phishing_when_true,
    ),
    "has_shortening": Derivation(
        live_name="is_shortened",
        inputs=("has_shortening",),
        measure=_flag("has_shortening"),
        encode=_phishing_when_true,
    ),
    "has_at_symbol": Derivation(
        live_name="has_at_symbol",
        inputs=("has_at_symbol",),
        measure=_flag("has_at_symbol"),
        encode=_phishing_when_true,
    ),
    "has_prefix_suffix": Derivation(
        live_name="hyphens_in_hostname",
        inputs=("num_hyphens_in_hostname",),
        measure=_number("num_hyphens_in_hostname"),
        encode=_encode_hyphens,
        note="graded by hyphen count instead of any-hyphen",
    ),
    "subdomain_level": Derivation(
        live_name="subdomain_count",
        inputs=("num_subdomains",),
        measure=_number("num_subdomains"),
        encode=_encode_subdomain_level,
    ),
    "domain_reg_length": Derivation(
        live_name="registration_span_days",
        inputs=("domain_age_days", "days_until_expiry"),
        measure=_measure_registration_span,
        encode=_encode_registration_span,
        approximated=True,
        note="proxy: creation-to-expiry span, no direct live equivalent",
    ),
    "has_favicon": Derivation(
        live_name="favicon_present",
        inputs=("has_favicon",),
        measure=_flag("has_favicon"),
        encode=_legit_when_true,
        approximated=True,
        note="live signal is 'favicon exists', UCI's is 'favicon is same-origin'",
    ),
    "has_port": Derivation(
        live_name="explicit_port",
        inputs=("has_port", "port_number"),
        measure=_measure_explicit_port,
        encode=_encode_port,
        note="graded by port number instead of port-present",
    ),
    "https_in_domain": Derivation(
        live_name="uses_https",
        inputs=("has_https",),
        measure=_measure_uses_https,
        encode=_legit_when_true,
        approximated=True,
        note="known mismatch: UCI means token-in-domain, this is scheme-is-TLS; "
        "kept deliberately, see _measure_uses_https",
    ),
    "links_in_tags": Derivation(
        live_name="internal_tag_link_ratio",
        inputs=("internal_tag_link_ratio",),
        measure=_number("internal_tag_link_ratio"),
        encode=_encode_link_ratio,
    ),
    "server_form_handler": Derivation(
        live_name="form_handler_risk",
        inputs=("form_action_is_empty_or_blank", "form_action_is_external"),
        measure=_measure_form_handler_risk,
        encode=_encode_form_handler,
    ),
    "submits_to_email": Derivation(
        live_name="form_submits_to_email",
        inputs=("form_submits_to_email",),
        measure=_flag("form_submits_to_email"),
        encode=_phishing_when_true,
    ),
    "has_onmouseover": Derivation(
        live_name="has_onmouseover",
        inputs=("has_onmouseover",),
        measure=_flag("has_onmouseover"),
        encode=_phishing_when_true,
    ),
    "right_click_disabled": Derivation(
        live_name="right_click_disabled",
        inputs=("has_right_click_disabled",),
        measure=_flag("has_right_click_disabled"),
        encode=_phishing_when_true,
    ),
    "has_popup": Derivation(
        live_name="has_suspicious_popup",
        inputs=("has_suspicious_popup",),
        measure=_flag("has_suspicious_popup"),
        encode=_phishing_when_true,
    ),
    "has_iframe": Derivation(
        live_name="has_iframe",
        inputs=("has_iframe",),
        measure=_flag("has_iframe"),
        encode=_phishing_when_true,
    ),
    "domain_age_cat": Derivation(
        live_name="domain_age_days",
        inputs=("domain_age_days",),
        measure=_number("domain_age_days"),
        encode=_encode_domain_age,
    ),
    "has_dns_record": Derivation(
        live_name="has_dns_a_record",
        inputs=("has_dns_a_record",),
        measure=_flag("has_dns_a_record"),
        encode=_legit_when_true,
    ),
}


# Live signals the extractor already produces that the 18-feature contract has
# no slot for at all. The old adapter discarded every one of them; they are the
# single largest block of recoverable information in this module, and they are
# what a retrained model would gain access to. Kept as (live_name, measure).
_EXTRA_MEASUREMENTS: tuple[tuple[str, Callable[[dict[str, Any]], Optional[float]]], ...] = (
    # Tier 1 — lexical. Available on every request, including the fast path.
    ("url_length", _number("url_length")),
    ("hostname_length", _number("hostname_length")),
    ("path_length", _number("path_length")),
    ("num_dots_in_url", _number("num_dots_in_url")),
    ("num_dots_in_hostname", _number("num_dots_in_hostname")),
    ("url_entropy", _number("url_entropy")),
    ("digit_ratio_in_url", _number("digit_ratio_in_url")),
    # The faithful reading of UCI's HTTPS_token, which the contract slot cannot
    # currently carry (see _measure_uses_https). Kept here so the retrain can
    # give the two quantities separate columns instead of conflating them.
    ("https_token_in_domain", _measure_https_token),
    ("has_double_slash_redirect", _flag("has_double_slash_redirect")),
    ("is_suspicious_tld", _flag("is_suspicious_tld")),
    ("has_suspicious_keywords", _flag("has_suspicious_keywords")),
    # Tier 4 — HTML/content.
    ("num_external_links", _number("num_external_links")),
    ("num_internal_links", _number("num_internal_links")),
    ("external_link_ratio", _number("external_link_ratio")),
    ("num_forms", _number("num_forms")),
    ("has_password_field", _flag("has_password_field")),
    ("has_hidden_elements", _flag("has_hidden_elements")),
    ("num_images", _number("num_images")),
    ("num_scripts", _number("num_scripts")),
    ("title_length", _number("title_length")),
    ("meta_description_length", _number("meta_description_length")),
    ("page_text_length", _number("page_text_length")),
    ("has_copyright", _flag("has_copyright")),
    # Tier 2/3 — domain intelligence.
    ("days_until_expiry", _number("days_until_expiry")),
    ("is_recently_registered", _flag("is_recently_registered")),
    ("has_mx_record", _flag("has_mx_record")),
)

# The continuous feature space: every contract feature's underlying
# measurement, followed by the signals the contract cannot carry. This is the
# input space for a model retrained on live-domain data — deliberately NOT fed
# to the current UCI-trained model.
LIVE_FEATURE_ORDER: tuple[str, ...] = tuple(
    _DERIVATIONS[name].live_name for name in FEATURE_ORDER
) + tuple(name for name, _ in _EXTRA_MEASUREMENTS)


def _missing_components(features: dict[str, Any]) -> tuple[str, ...]:
    """Which live tiers produced nothing, inferred from the feature dict.

    Args:
        features: The live extractor's flat feature dict.

    Returns:
        Some subset of ``("html", "domain_intel")``, in that order.
    """
    missing: list[str] = []
    if features.get("internal_tag_link_ratio") is None and features.get("num_forms") is None:
        missing.append("html")
    if features.get("has_dns_a_record") is None and features.get("domain_age_days") is None:
        missing.append("domain_intel")
    return tuple(missing)


def adapt_live(features: dict[str, Any]) -> LiveFeatures:
    """Build the full live feature record for one extracted URL.

    Runs each :class:`Derivation`'s measurement once, keeps it at full
    precision in the continuous track, and projects it onto the contract
    alphabet for the deployed model. A feature that cannot be measured is
    :data:`~src.models.contract.MISSING` in the contract track and ``None`` in
    the continuous track — never a fabricated ``-1``.

    Args:
        features: The ``.features`` dict from a live-extracted
            :class:`~src.features.pipeline.FeatureVector` (union of lexical +
            HTML + domain-intel keys; any subset may be missing or ``None``
            when a tier did not run).

    Returns:
        A :class:`~src.models.contract.LiveFeatures` carrying both views.
    """
    contract_values: dict[str, float] = {}
    live_values: dict[str, Optional[float]] = {}
    approximated: list[str] = []
    unavailable: list[str] = []

    for name in FEATURE_ORDER:
        derivation = _DERIVATIONS.get(name)
        if derivation is None:
            raise KeyError(
                f"feature_adapter has no derivation for contract feature {name!r} — "
                "adapter is out of sync with data_config.yaml feature_columns"
            )

        measured = derivation.measure(features)
        live_values[derivation.live_name] = measured

        if measured is None:
            contract_values[name] = MISSING
            unavailable.append(name)
            continue

        encoded = derivation.encode(measured)
        if encoded == 0 and name in _BINARY_COLUMNS:
            # Defensive: an encoder must never emit a band the model has not
            # seen for that column. Reaching here is a code bug, not bad input.
            logger.error(
                "feature_adapter: encoder for %r emitted an out-of-distribution "
                "0 band; treating as unmeasurable",
                name,
            )
            contract_values[name] = MISSING
            unavailable.append(name)
            continue

        contract_values[name] = float(encoded)
        if derivation.approximated:
            approximated.append(name)

    for live_name, measure in _EXTRA_MEASUREMENTS:
        live_values[live_name] = measure(features)

    if unavailable:
        logger.info(
            "feature_adapter: %d/%d contract features unmeasurable (imputed from "
            "training mode, not defaulted to phishing): %s",
            len(unavailable),
            len(FEATURE_ORDER),
            unavailable,
        )

    return LiveFeatures(
        contract=ModelInput(
            values=contract_values,
            approximated=approximated,
            unavailable=unavailable,
        ),
        values=live_values,
        components_missing=_missing_components(features),
    )


def adapt_to_training_contract(features: dict[str, Any]) -> ModelInput:
    """Map a live feature dict onto the model's 18-feature training contract.

    Backward-compatible entry point: same name, same signature, same return
    type as before DEC-040, so every existing call site is unchanged. It is now
    a thin projection of :func:`adapt_live` — prefer that when you want the
    full-precision measurements too.

    Args:
        features: The ``.features`` dict from a live-extracted
            :class:`~src.features.pipeline.FeatureVector`.

    Returns:
        A :class:`~src.models.contract.ModelInput` with all 18
        :data:`~src.models.contract.FEATURE_ORDER` features populated. Values
        are ``-1/0/1`` where measured and
        :data:`~src.models.contract.MISSING` where not.

    Raises:
        KeyError: If a contract feature has no registered derivation —
            signals the adapter is out of sync with ``data_config.yaml``.
    """
    return adapt_live(features).contract


def describe() -> list[dict[str, Any]]:
    """Introspect the derivation table, for docs and diagnostics.

    Returns:
        One dict per contract feature, in :data:`FEATURE_ORDER`, describing
        which live keys feed it, what its continuous measurement is called,
        and whether it is a proxy.
    """
    return [
        {
            "contract_feature": name,
            "live_measurement": _DERIVATIONS[name].live_name,
            "inputs": list(_DERIVATIONS[name].inputs),
            "approximated": _DERIVATIONS[name].approximated,
            "binary_column": name in _BINARY_COLUMNS,
            "note": _DERIVATIONS[name].note,
        }
        for name in FEATURE_ORDER
    ]
