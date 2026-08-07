"""HTML / page-content feature extraction (Tier 4).

Given already-fetched HTML as a string, extract structural and content signals
used to distinguish phishing pages from legitimate ones. No network I/O is
performed here — fetching is the caller's responsibility.

Parsing uses BeautifulSoup with the ``lxml`` parser, which is faster and far
more tolerant of malformed markup than the stdlib ``html.parser`` (see
CLAUDE.md gotchas). Every feature is computed defensively: a failure in one
field sets only that field to ``None``; unusable input or a total parse failure
yields an all-``None`` dict.

Example:
    >>> from src.features.html_content import extract_html_features
    >>> feats = extract_html_features("<html><title>Hi</title></html>",
    ...                               base_url="https://example.com")
    >>> feats["title_length"]
    2
"""

from __future__ import annotations

import logging
import re
from typing import Any, Callable, Optional
from urllib.parse import urljoin, urlparse

from bs4 import BeautifulSoup

from src.utils.domains import registered_domain as _registered_domain_util

logger = logging.getLogger(__name__)

# Inline-style patterns that hide an element from view.
_HIDDEN_STYLE_RE = re.compile(
    r"display\s*:\s*none|visibility\s*:\s*hidden", re.IGNORECASE
)

# Tags whose text is not user-visible and must be stripped before counting text.
_NON_VISIBLE_TAGS = ("script", "style", "noscript", "template", "head")

# Regex patterns for JS-behavior signals (DEC-015). These are best-effort
# static checks on the raw markup/script text, not a JS interpreter — a page
# that constructs these handlers dynamically (e.g. via string concatenation)
# will not be detected. That's an accepted limitation, matching how UCI's
# original on_mouseover/rightclick/popup features were themselves reproduced
# by later researchers without a live browser.
_ONMOUSEOVER_RE = re.compile(r"onmouseover\s*=", re.IGNORECASE)
_RIGHT_CLICK_DISABLED_RE = re.compile(
    r"oncontextmenu\s*=|event\.button\s*==\s*2|event\.button\s*==\s*3", re.IGNORECASE
)
_POPUP_RE = re.compile(r"window\.open\s*\(", re.IGNORECASE)

# Canonical ordering of every feature this module produces.
FEATURE_KEYS: tuple[str, ...] = (
    "num_external_links",
    "num_internal_links",
    "num_forms",
    "has_password_field",
    "has_iframe",
    "has_hidden_elements",
    "num_images",
    "num_scripts",
    "has_favicon",
    "title_length",
    "meta_description_length",
    "page_text_length",
    "has_copyright",
    "external_link_ratio",
    "form_action_is_external",
    "form_action_is_empty_or_blank",
    "form_submits_to_email",
    "has_onmouseover",
    "has_right_click_disabled",
    "has_suspicious_popup",
    "internal_tag_link_ratio",
)


def _safe(feature_name: str, func: Callable[[], Any]) -> Optional[Any]:
    """Run a feature computation, returning ``None`` on any failure.

    Args:
        feature_name: Name of the feature, used in the warning log.
        func: Zero-argument callable that computes the feature value.

    Returns:
        The computed value, or ``None`` if ``func`` raised.
    """
    try:
        return func()
    except Exception as exc:  # noqa: BLE001 - defensive by design
        logger.warning("HTML feature %r failed: %s", feature_name, exc)
        return None


def _empty_features() -> dict[str, Any]:
    """Build a result dict with every feature set to ``None``."""
    return dict.fromkeys(FEATURE_KEYS)


def _registered_domain(url: Optional[str]) -> str:
    """Return the registered domain of a URL, or ``""`` if undeterminable.

    Args:
        url: An absolute URL, or ``None``.

    Returns:
        The registered domain (e.g. ``"example.com"``), or ``""``.
    """
    if not url:
        return ""
    return _registered_domain_util(url).lower()


def _classify_links(soup: BeautifulSoup, base_url: Optional[str]) -> tuple[int, int]:
    """Count internal vs external anchor links.

    A link is *external* when it resolves to a registered domain different from
    the base domain. Relative links, fragments, and non-HTTP schemes
    (``mailto:``, ``tel:``, ``javascript:``) are treated as internal. When no
    ``base_url`` is given, any link with a network host is treated as external.

    Args:
        soup: Parsed document.
        base_url: The page's own URL, used to resolve relatives and compare
            domains. May be ``None``.

    Returns:
        ``(num_external_links, num_internal_links)``.
    """
    base_domain = _registered_domain(base_url)
    external = 0
    internal = 0

    for anchor in soup.find_all("a", href=True):
        href = anchor["href"].strip()
        if not href:
            continue

        scheme = urlparse(href).scheme.lower()
        if scheme in ("mailto", "tel", "javascript") or href.startswith("#"):
            internal += 1
            continue

        absolute = urljoin(base_url, href) if base_url else href
        link_domain = _registered_domain(absolute)

        if not link_domain:
            # Relative / hostless link → same site.
            internal += 1
        elif base_domain:
            if link_domain != base_domain:
                external += 1
            else:
                internal += 1
        else:
            # No base to compare against: a hosted link is treated as external.
            external += 1

    return external, internal


def has_password_input(soup: BeautifulSoup) -> bool:
    """Whether the parsed page contains at least one ``<input type=password>``.

    Public because the Phase-1 brand-mismatch signal
    (``src.detection.signals.brand_mismatch``) needs exactly this test to
    decide whether a page is asking for credentials, and previously carried
    a byte-identical private copy of the loop below.

    Args:
        soup: An already-parsed document — the caller owns parsing, so a
            page that has been fetched once is never re-parsed just for this.
    """
    return any(
        str(inp.get("type", "")).strip().lower() == "password"
        for inp in soup.find_all("input")
    )


def extract_html_features(
    html: Any, base_url: Optional[str] = None
) -> dict[str, Any]:
    """Extract Tier 4 page-content features from HTML.

    No network I/O is performed. Each feature is computed defensively: a failure
    in one field sets only that field to ``None``. If ``html`` is unusable or
    cannot be parsed at all, every feature is ``None``.

    Args:
        html: The page HTML as a string. Non-string or empty input yields an
            all-``None`` result.
        base_url: The URL the HTML was fetched from. Required to distinguish
            internal from external links accurately; if omitted, hosted links
            are counted as external.

    Returns:
        A dict keyed by :data:`FEATURE_KEYS`:
            num_external_links (int), num_internal_links (int), num_forms (int),
            has_password_field (bool), has_iframe (bool),
            has_hidden_elements (bool), num_images (int), num_scripts (int),
            has_favicon (bool), title_length (int), meta_description_length (int),
            page_text_length (int), has_copyright (bool),
            external_link_ratio (float), form_action_is_external (bool),
            form_action_is_empty_or_blank (bool), form_submits_to_email (bool),
            has_onmouseover (bool), has_right_click_disabled (bool),
            has_suspicious_popup (bool), internal_tag_link_ratio (float).
    """
    if not isinstance(html, str) or not html.strip():
        logger.warning("extract_html_features received unusable input: %r", type(html))
        return _empty_features()

    try:
        soup = BeautifulSoup(html, "lxml")
    except Exception as exc:  # noqa: BLE001 - malformed beyond lxml's tolerance
        logger.warning("HTML parse failed: %s", exc)
        return _empty_features()

    link_counts = _safe("link_counts", lambda: _classify_links(soup, base_url))
    num_external = link_counts[0] if link_counts is not None else None
    num_internal = link_counts[1] if link_counts is not None else None

    def _external_link_ratio() -> float:
        if link_counts is None:
            raise ValueError("link counts unavailable")
        ext, intern = link_counts
        total = ext + intern
        return ext / total if total else 0.0

    def _has_hidden_elements() -> bool:
        return any(_HIDDEN_STYLE_RE.search(element["style"]) for element in soup.find_all(style=True))

    def _has_favicon() -> bool:
        for link in soup.find_all("link"):
            rel = link.get("rel")
            rel_str = " ".join(rel) if isinstance(rel, list) else str(rel or "")
            if "icon" in rel_str.lower():
                return True
        return False

    def _title_length() -> int:
        title = soup.title
        return len(title.get_text(strip=True)) if title is not None else 0

    def _meta_description_length() -> int:
        meta = soup.find("meta", attrs={"name": re.compile(r"^description$", re.I)})
        if meta is None:
            return 0
        content = meta.get("content", "")
        return len(content.strip()) if isinstance(content, str) else 0

    def _page_text_length() -> int:
        clone = BeautifulSoup(str(soup), "lxml")
        for tag in clone(_NON_VISIBLE_TAGS):
            tag.decompose()
        text = clone.get_text(separator=" ", strip=True)
        return len(text)

    def _has_copyright() -> bool:
        text = soup.get_text(separator=" ", strip=True)
        return "©" in text or "copyright" in text.lower()

    def _form_actions() -> list[str]:
        return [str(form.get("action", "")).strip() for form in soup.find_all("form")]

    def _form_action_is_external() -> bool:
        base_domain = _registered_domain(base_url)
        for action in _form_actions():
            if not action or action.lower() in ("#", "about:blank"):
                continue
            scheme = urlparse(action).scheme.lower()
            if scheme in ("mailto", "tel", "javascript"):
                continue
            absolute = urljoin(base_url, action) if base_url else action
            action_domain = _registered_domain(absolute)
            if action_domain and base_domain and action_domain != base_domain:
                return True
        return False

    def _form_action_is_empty_or_blank() -> bool:
        return any(
            not action or action.lower() in ("#", "about:blank")
            for action in _form_actions()
        )

    def _form_submits_to_email() -> bool:
        return any(action.lower().startswith("mailto:") for action in _form_actions())

    def _has_onmouseover() -> bool:
        return _ONMOUSEOVER_RE.search(html) is not None

    def _has_right_click_disabled() -> bool:
        return _RIGHT_CLICK_DISABLED_RE.search(html) is not None

    def _has_suspicious_popup() -> bool:
        return _POPUP_RE.search(html) is not None

    def _internal_tag_link_ratio() -> float:
        # UCI's Links_in_tags: proportion of <script src>/<link href> resource
        # references that point to the page's own domain, vs. an external one.
        base_domain = _registered_domain(base_url)
        refs: list[str] = []
        for tag_name, attr in (("script", "src"), ("link", "href")):
            for tag in soup.find_all(tag_name):
                value = tag.get(attr)
                if value:
                    refs.append(str(value).strip())
        if not refs:
            # No tag-embedded resource links at all — neutral/good default,
            # matching this run's empirically-confirmed direction (higher
            # internal ratio = more legitimate; see DEC-014).
            return 1.0
        internal = 0
        for ref in refs:
            absolute = urljoin(base_url, ref) if base_url else ref
            ref_domain = _registered_domain(absolute)
            if not ref_domain or (base_domain and ref_domain == base_domain):
                internal += 1
        return internal / len(refs)

    return {
        "num_external_links": num_external,
        "num_internal_links": num_internal,
        "num_forms": _safe("num_forms", lambda: len(soup.find_all("form"))),
        "has_password_field": _safe("has_password_field", lambda: has_password_input(soup)),
        "has_iframe": _safe("has_iframe", lambda: len(soup.find_all("iframe")) > 0),
        "has_hidden_elements": _safe("has_hidden_elements", _has_hidden_elements),
        "num_images": _safe("num_images", lambda: len(soup.find_all("img"))),
        "num_scripts": _safe("num_scripts", lambda: len(soup.find_all("script"))),
        "has_favicon": _safe("has_favicon", _has_favicon),
        "title_length": _safe("title_length", _title_length),
        "meta_description_length": _safe(
            "meta_description_length", _meta_description_length
        ),
        "page_text_length": _safe("page_text_length", _page_text_length),
        "has_copyright": _safe("has_copyright", _has_copyright),
        "external_link_ratio": _safe("external_link_ratio", _external_link_ratio),
        "form_action_is_external": _safe(
            "form_action_is_external", _form_action_is_external
        ),
        "form_action_is_empty_or_blank": _safe(
            "form_action_is_empty_or_blank", _form_action_is_empty_or_blank
        ),
        "form_submits_to_email": _safe(
            "form_submits_to_email", _form_submits_to_email
        ),
        "has_onmouseover": _safe("has_onmouseover", _has_onmouseover),
        "has_right_click_disabled": _safe(
            "has_right_click_disabled", _has_right_click_disabled
        ),
        "has_suspicious_popup": _safe("has_suspicious_popup", _has_suspicious_popup),
        "internal_tag_link_ratio": _safe(
            "internal_tag_link_ratio", _internal_tag_link_ratio
        ),
    }
