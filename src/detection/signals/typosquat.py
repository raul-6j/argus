"""Typosquatting / homograph / IDN brand-impersonation signal (Phase 1, A3).

Pure lexical — hostname only, no page fetch — so this signal is cheap
(sub-millisecond, in-memory) and, unlike A2/A1, does not depend on a
successful page fetch. It runs whenever the detection fusion layer is
enabled (see ``src/detection/__init__.py::run_detection``).

Techniques (in priority order — first match wins, so ``evidence`` cites the
most specific technique):
    1. Homograph — the domain's root label is *visually* identical to a
       brand's root label after confusable-character normalization and
       punycode/IDN decoding, but not byte-identical (e.g. Cyrillic "а"
       swapped for Latin "a").
    2. TLD swap — the domain's root label is byte-identical to a brand's
       root label, but the full registered domain isn't one of the brand's
       real domains (e.g. ``paypal.tk`` vs. the real ``paypal.com``).
    3. Edit distance — a small (1-2 character) Damerau-Levenshtein edit
       away from a brand's root label (e.g. ``paypaI.com``, ``paypal1.com``).
       Requires both roots to be at least ``_MIN_EDIT_DISTANCE_ROOT_LENGTH``
       characters (DEC-031/034) — below that, a distance of 1-2 is too large
       a fraction of the string to distinguish a typosquat from two
       unrelated short brand names (e.g. ``usps.com`` vs. ``UPS``, both
       real, distance 1). Not previously guarded; only became visible once
       the brand reference grew to 166 entries and produced frequent
       false positives between unrelated brands' own real domains.
    4. Brand-in-subdomain — the brand's name/alias appears as a full
       subdomain label while the registered domain is unrelated (e.g.
       ``paypal.attacker.com``).
    5. Combosquat — a brand alias appears as a substring of (but not equal
       to) the domain's root label (e.g. ``paypal-secure.com``).

A domain that *is* one of the brand's own real domains (or a subdomain of
one) never reaches any of these checks — see the allowlist check below.
"""

from __future__ import annotations

import logging
import time
from typing import TYPE_CHECKING

from src.detection.types import RiskSignal
from src.utils.domains import get_extractor, registered_domain

if TYPE_CHECKING:
    from src.detection.brand_reference import BrandIndex

logger = logging.getLogger(__name__)

_SIGNAL_NAME = "typosquat"

# Curated confusable-character map: visually similar characters (mostly
# Cyrillic/Greek, plus a handful of common leetspeak digit substitutions)
# mapped to their Latin look-alike. Not exhaustive — covers the characters
# most commonly abused in real phishing domains; a small, reviewable list
# (mirrors feature_config.yaml's convention of keeping such lists explicit
# and citable rather than pulling in a large third-party confusables table).
_CONFUSABLES: dict[str, str] = {
    "а": "a", "А": "a",  # Cyrillic a / A
    "е": "e", "Е": "e",  # Cyrillic ie / IE
    "о": "o", "О": "o",  # Cyrillic o / O
    "р": "p", "Р": "p",  # Cyrillic er / ER
    "с": "c", "С": "c",  # Cyrillic es / ES
    "у": "y", "У": "y",  # Cyrillic u / U
    "х": "x", "Х": "x",  # Cyrillic ha / HA
    "і": "i", "І": "i",  # Cyrillic/Ukrainian i / I
    "ј": "j",             # Cyrillic je
    "ѕ": "s",             # Cyrillic dze
    "ԁ": "d",             # Cyrillic komi de
    "α": "a", "Α": "a",  # Greek alpha
    "β": "b",             # Greek beta
    "ο": "o", "Ο": "o",  # Greek omicron
    "ρ": "p",             # Greek rho
    "ν": "v",             # Greek nu
    "ℓ": "l",             # script small l
    "ı": "i",             # dotless i
    "0": "o",
    "1": "l",
    "3": "e",
    "5": "s",
}

_MIN_BRAND_ROOT_LENGTH = 3
_MIN_ALIAS_COMBOSQUAT_LENGTH = 4

# DEC-031/034: the edit-distance technique specifically needs a stricter
# floor than _MIN_BRAND_ROOT_LENGTH. At 166 brands, several genuine,
# unrelated short root labels (3-4 chars) sit within max_edit_distance=2 of
# each other -- e.g. "usps"/"ups" (distance 1), "dhl"/"aol" (2),
# "ebay"/"etsy" (2), "chase"/"cash" (2), "hsbc"/"sbi" (2) -- because for a
# 3-4 character string, an edit distance of 1-2 is 25-65% of the string,
# not a small typo. Homograph/tld_swap/brand-in-subdomain/combosquat are
# exact- or substring-anchored and don't share this failure mode, so only
# the fuzzy edit-distance technique is restricted here. This necessarily
# narrows edit-distance coverage for short-named brands (e.g. a genuine
# "irss.com" typosquat of a 3-letter brand would no longer be caught by
# this technique alone) -- a deliberate trade-off, not an oversight; see
# DEC-034.
_MIN_EDIT_DISTANCE_ROOT_LENGTH = 5


def _normalize_confusables(text: str) -> str:
    """Map every confusable character in ``text`` to its Latin look-alike."""
    return "".join(_CONFUSABLES.get(ch, ch) for ch in text.lower())


def _decode_punycode_label(label: str) -> str:
    """Decode one ``xn--...`` IDN label to Unicode; pass through otherwise."""
    if not label.lower().startswith("xn--"):
        return label
    try:
        return label.encode("ascii").decode("idna")
    except Exception:  # noqa: BLE001 - malformed punycode -> leave as-is
        return label


def _damerau_levenshtein(a: str, b: str) -> int:
    """Damerau-Levenshtein edit distance (insert/delete/substitute/transpose)."""
    la, lb = len(a), len(b)
    if la == 0:
        return lb
    if lb == 0:
        return la
    d = [[0] * (lb + 1) for _ in range(la + 1)]
    for i in range(la + 1):
        d[i][0] = i
    for j in range(lb + 1):
        d[0][j] = j
    for i in range(1, la + 1):
        for j in range(1, lb + 1):
            cost = 0 if a[i - 1] == b[j - 1] else 1
            d[i][j] = min(
                d[i - 1][j] + 1,       # deletion
                d[i][j - 1] + 1,       # insertion
                d[i - 1][j - 1] + cost,  # substitution
            )
            if i > 1 and j > 1 and a[i - 1] == b[j - 2] and a[i - 2] == b[j - 1]:
                d[i][j] = min(d[i][j], d[i - 2][j - 2] + cost)  # transposition
    return d[la][lb]


def _distance_score(distance: int, max_distance: int) -> float:
    """Map an edit distance to a phishing-likelihood score in [0.5, 0.85]."""
    if max_distance <= 1:
        return 0.85
    span = max_distance - 1
    frac = (max_distance - distance) / span
    return round(0.5 + 0.35 * frac, 4)


def _subdomain_labels(url: str) -> list[str]:
    """Return the subdomain labels of ``url`` (e.g. ``["paypal"]`` for
    ``paypal.attacker.com``)."""
    candidate = url if "://" in url else f"https://{url}"
    ext = get_extractor()(candidate)
    return [p.lower() for p in ext.subdomain.split(".") if p] if ext.subdomain else []


def _is_own_domain(domain: str, brand_domains: tuple[str, ...]) -> bool:
    return domain in brand_domains or any(
        domain.endswith("." + d) for d in brand_domains
    )


def _elapsed(start: float) -> float:
    return round((time.perf_counter() - start) * 1000, 3)


def _neutral(start: float) -> RiskSignal:
    return RiskSignal(
        name=_SIGNAL_NAME, triggered=False, score=0.0, direction="neutral",
        evidence={}, latency_ms=_elapsed(start),
    )


def _trigger(
    technique: str, brand_name: str, brand_domain: str, score: float, start: float, **extra
) -> RiskSignal:
    evidence = {"impersonated_brand": brand_name, "brand_domain": brand_domain, "technique": technique}
    evidence.update(extra)
    return RiskSignal(
        name=_SIGNAL_NAME, triggered=True, score=score, direction="phishing",
        evidence=evidence, latency_ms=_elapsed(start),
    )


def evaluate(url: str, brand_index: "BrandIndex", max_edit_distance: int = 2) -> RiskSignal:
    """Evaluate a URL for typosquatting/homograph/IDN brand impersonation.

    Args:
        url: The URL (or bare hostname) being evaluated.
        brand_index: The loaded brand reference. An empty index makes this
            a safe no-op.
        max_edit_distance: Maximum Damerau-Levenshtein distance (inclusive)
            to still count as a typosquat.

    Returns:
        A :class:`RiskSignal`; never raises.
    """
    start = time.perf_counter()
    try:
        domain = registered_domain(url) if "://" in url else registered_domain(f"https://{url}")
        if not domain or not brand_index.brands:
            return _neutral(start)

        # A domain that is itself the verified real domain of some OTHER
        # cataloged brand cannot simultaneously be a typosquat of a
        # different brand -- e.g. github.com ("github", 6-char root) sits
        # at Damerau-Levenshtein distance 2 from GitLab's "gitlab" root,
        # past the short-root guard below, and was flagged as impersonating
        # GitLab. The per-brand `_is_own_domain` check further down only
        # exempts a domain from the ONE brand entry it's being compared
        # against; it never learns that the domain is independently
        # verified as a different real brand's own home. This reuses the
        # same brand-reference domain data already loaded for this
        # signal -- domain-ownership corroboration, not a blind allowlist.
        if brand_index.brand_for_domain(domain) is not None:
            return _neutral(start)

        domain_labels = domain.split(".")
        decoded_domain = ".".join(_decode_punycode_label(lbl) for lbl in domain_labels)
        domain_root_raw = decoded_domain.split(".")[0]
        domain_root_normalized = _normalize_confusables(domain_root_raw)

        subdomain_labels = _subdomain_labels(url)

        for brand in brand_index.brands:
            if _is_own_domain(domain, brand.domains):
                continue
            if len(brand.name) < _MIN_BRAND_ROOT_LENGTH:
                continue

            for brand_domain in brand.domains:
                brand_root = brand_domain.split(".")[0]
                if len(brand_root) < _MIN_BRAND_ROOT_LENGTH:
                    continue
                brand_root_normalized = _normalize_confusables(brand_root)

                # 1) Homograph: visually identical root, different bytes.
                if (
                    domain_root_normalized == brand_root_normalized
                    and domain_root_raw != brand_root
                    and domain != brand_domain
                ):
                    return _trigger("homograph", brand.name, brand_domain, 0.9, start)

                # 2) TLD swap: byte-identical root, different (non-brand) TLD.
                if domain_root_raw == brand_root and domain != brand_domain:
                    return _trigger("tld_swap", brand.name, brand_domain, 0.75, start)

                # 3) Edit distance on the normalized root. Guarded against
                #    short-root collisions (DEC-031/034) -- see
                #    _MIN_EDIT_DISTANCE_ROOT_LENGTH above.
                shorter_root = min(len(domain_root_normalized), len(brand_root_normalized))
                if shorter_root < _MIN_EDIT_DISTANCE_ROOT_LENGTH:
                    continue
                distance = _damerau_levenshtein(domain_root_normalized, brand_root_normalized)
                if 0 < distance <= max_edit_distance:
                    return _trigger(
                        "edit_distance", brand.name, brand_domain,
                        _distance_score(distance, max_edit_distance), start, distance=distance,
                    )

            # 4) Brand-in-subdomain: brand name/alias as a full subdomain
            #    label, registered domain unrelated to the brand.
            needles = {brand.name.lower(), *brand.aliases}
            if any(label in needles for label in subdomain_labels):
                return _trigger("brand_in_subdomain", brand.name, brand.domains[0], 0.75, start)

            # 5) Combosquat: brand alias as a substring (not equal) of the
            #    domain root, e.g. "paypal-secure.com".
            for alias in brand.aliases:
                alias_compact = alias.replace(" ", "")
                if (
                    len(alias_compact) >= _MIN_ALIAS_COMBOSQUAT_LENGTH
                    and alias_compact in domain_root_normalized
                    and domain_root_normalized != alias_compact
                ):
                    return _trigger("combosquat", brand.name, brand.domains[0], 0.65, start)

        return _neutral(start)
    except Exception as exc:  # noqa: BLE001 - Iron Law #3
        logger.warning("typosquat signal failed for %r: %s", url, exc)
        return _neutral(start)
