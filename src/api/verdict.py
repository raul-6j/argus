"""The shared "score one URL" core used by every scanning endpoint.

Before this module existed, the same three-step decision — run the model,
then either fuse it with the Phase-1 detection signals or fall back to the
bare threshold — was written out five separate times: in ``/detect``,
``/explain``, ``POST /scan``, ``/v1/scan(/batch)``, and ``/v1/explain``.
The copies had already drifted apart in incidental ways (different local
variable names, different orderings, one computing ``risk_band`` inline and
another not), which made it genuinely hard to confirm that all five agreed
on the verdict itself.

They are collapsed here into :func:`resolve_verdict`, which returns a
:class:`Verdict` and leaves *serialization* to each caller — that split
matters, because the endpoints legitimately differ in which fields they
expose (``/detect``'s model-only path deliberately omits ``risk_score`` /
``risk_band`` / ``signals``, while ``/v1/scan`` always includes them). Only
the shared decision moved; every endpoint's response body is unchanged.

:func:`run_scan` is the full stateless single-URL pipeline (pre-filter →
fetch → extract → :func:`resolve_verdict`) behind ``/v1/scan``. It lives
here rather than in ``src.api.public.routes`` because
``src.api.public.jobs`` also needs it: that module previously imported it as
a private name (``from src.api.public.routes import _run_scan``) from
*inside a function body*, purely to break the resulting import cycle. With
the core in its own module both importers are ordinary module-level imports
and the cycle is gone.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Optional

from flask import current_app

from src.api.route_utils import risk_bands_config
from src.api.threat_intel.prefilter import check_prefilter
from src.detection import run_detection
from src.detection.types import risk_band_for_score
from src.features import page_artifacts
from src.features.pipeline import extract_features
from src.models.feature_adapter import adapt_to_training_contract


@dataclass
class Verdict:
    """One URL's resolved verdict, independent of how any endpoint renders it.

    Attributes:
        label: ``"phishing"`` or ``"legitimate"``.
        confidence: Confidence in ``label``, ``0.0``-``1.0``.
        risk_score: Fused phishing-likelihood score (equals ``model_proba``
            when the fusion layer is off or no signal contributed).
        source: What decided the label — ``"model"``, ``"fusion"``, or a
            signal name for a hard override.
        signals: Each evaluated signal, already in its public dict shape.
        fused: Whether the fusion layer actually ran. Distinct from
            ``source == "fusion"``: a fusion run in which no signal
            contributed still reports ``source == "model"``, and ``/detect``
            keys its response shape off *this* flag (it omits
            ``risk_score``/``risk_band``/``signals`` only on the genuinely
            model-only fast path).
    """

    label: str
    confidence: float
    risk_score: float
    source: str
    signals: list[dict[str, Any]] = field(default_factory=list)
    fused: bool = False

    def risk_band(self, argus: Optional[dict[str, Any]] = None) -> str:
        """This verdict's named risk band under the configured boundaries."""
        return risk_band_for_score(self.risk_score, risk_bands_config(argus))


def prefilter_source(url: str, argus: dict[str, Any]) -> Optional[str]:
    """Check the threat-intel pre-filter, honouring its ``enabled`` flag.

    Args:
        url: The URL to look up.
        argus: The ``app.extensions["argus"]`` dict.

    Returns:
        The matching provider's name (``"phishtank"``, ``"gsb"``), or
        ``None`` for a miss or a disabled pre-filter.
    """
    threat_intel = argus.get("threat_intel", {})
    if not threat_intel.get("enabled"):
        return None
    return check_prefilter(url, threat_intel.get("providers", []))


def model_proba(model_input, argus: dict[str, Any]) -> float:
    """The model's phishing-class probability for one adapted feature vector.

    Goes through ``argus["predictor"]`` — the ONNX backend when one is
    configured and numerically validated, the sklearn pipeline otherwise
    (Phase 2, G1).
    """
    return float(argus["predictor"].predict_proba([model_input.to_vector()])[0][1])


def resolve_verdict(
    url: str,
    *,
    proba: float,
    artifacts: Optional[page_artifacts.PageArtifacts],
    html_features: Optional[dict[str, Any]],
    argus: dict[str, Any],
    use_detection: bool,
) -> Verdict:
    """Turn a model probability into a final verdict, fusing signals if enabled.

    Args:
        url: The URL being scored.
        proba: The model's phishing-class probability for ``url``.
        artifacts: The shared single-fetch page context, or ``None`` on a
            lexical-only path (page-dependent signals go neutral by
            themselves in that case).
        html_features: The live extractor's feature dict, forwarded to the
            signals that corroborate against it.
        argus: The ``app.extensions["argus"]`` dict.
        use_detection: Whether this call site wants the fusion layer at all
            — ``/detect`` only fuses on its enriched path, while
            ``/explain`` always does. The layer's own ``enabled`` config
            flag is checked here on top of this.

    Returns:
        The resolved :class:`Verdict`. Falls back to the plain
        ``proba >= threshold`` decision whenever fusion is not in play,
        which is byte-for-byte what each endpoint did inline before.
    """
    detection_state = argus.get("detection", {})
    if use_detection and detection_state.get("enabled"):
        fused = run_detection(
            url,
            model_proba=proba,
            page_artifacts=artifacts,
            html_features=html_features,
            brand_index=detection_state["brand_index"],
            config=detection_state["config"],
        )
        return Verdict(
            label=fused.label,
            confidence=fused.confidence,
            risk_score=fused.risk_score,
            source=fused.decisive_source,
            signals=[s.to_dict() for s in fused.signals],
            fused=True,
        )

    is_phishing = bool(proba >= argus["threshold"])
    return Verdict(
        label="phishing" if is_phishing else "legitimate",
        confidence=float(proba if is_phishing else 1 - proba),
        risk_score=proba,
        source="model",
        signals=[],
    )


def extract(url: str, *, enrich: bool):
    """Fetch (if enriching) and extract features for one URL.

    Returns:
        ``(FeatureVector, Optional[PageArtifacts])`` — artifacts are
        ``None`` on the lexical-only path, where no page is fetched.
    """
    if not enrich:
        return extract_features(url), None
    artifacts = page_artifacts.fetch(url)
    return extract_features(url, html=artifacts.html, include_domain=True), artifacts


def run_scan(url: str, enrich: bool) -> dict[str, Any]:
    """Run the full stateless scan pipeline for one URL and shape the response.

    This is the ``/v1/scan`` response body (also reused per-item by
    ``/v1/scan/batch`` and by async jobs). Unlike :func:`resolve_verdict`,
    it *does* include every field unconditionally — that is the ``/v1``
    contract.
    """
    argus = current_app.extensions["argus"]

    source = prefilter_source(url, argus)
    if source is not None:
        return {
            "url": url, "label": "phishing", "confidence": 1.0, "verdict": "phishing",
            "risk_score": 1.0, "risk_band": "critical", "signals": [], "source": source,
        }

    fv, artifacts = extract(url, enrich=enrich)
    verdict = resolve_verdict(
        url,
        proba=model_proba(adapt_to_training_contract(fv.features), argus),
        artifacts=artifacts,
        html_features=fv.features,
        argus=argus,
        use_detection=enrich,
    )
    return {
        "url": url,
        "label": verdict.label,
        "confidence": verdict.confidence,
        "verdict": verdict.label,
        "risk_score": verdict.risk_score,
        "risk_band": verdict.risk_band(argus),
        "signals": verdict.signals,
        "source": verdict.source,
    }
