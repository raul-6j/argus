"""Tests for src.features.html_content — page-content feature extraction.

Fixture HTML lives in tests/fixtures/. No network access occurs.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from src.features.html_content import (
    FEATURE_KEYS,
    extract_html_features,
)

FIXTURES = Path(__file__).resolve().parents[1] / "fixtures"


def _load(name: str) -> str:
    """Read a fixture HTML file as text."""
    return (FIXTURES / name).read_text(encoding="utf-8")


# --------------------------------------------------------------------------- #
# Legitimate page
# --------------------------------------------------------------------------- #
def test_legit_page_all_keys_present():
    """A normal page yields every declared feature key."""
    feats = extract_html_features(_load("legit_page.html"), base_url="https://example.com")
    assert set(feats.keys()) == set(FEATURE_KEYS)


def test_legit_page_link_classification():
    """Internal vs external links are split by registered domain."""
    feats = extract_html_features(_load("legit_page.html"), base_url="https://example.com")
    # Internal: /, /products, /about, example.com/contact (4)
    # External: partner-site.org (1)
    assert feats["num_internal_links"] == 4
    assert feats["num_external_links"] == 1
    assert feats["external_link_ratio"] == pytest.approx(1 / 5)


def test_legit_page_content_features():
    """Title, meta, images, scripts, favicon, copyright on a clean page."""
    feats = extract_html_features(_load("legit_page.html"), base_url="https://example.com")
    assert feats["title_length"] == len("Example Company — Home")
    assert feats["meta_description_length"] == len(
        "The official Example Company website with products and support."
    )
    assert feats["num_images"] == 2
    assert feats["num_scripts"] == 2
    assert feats["has_favicon"] is True
    assert feats["has_copyright"] is True
    assert feats["has_password_field"] is False
    assert feats["has_iframe"] is False
    assert feats["has_hidden_elements"] is False
    assert feats["num_forms"] == 0
    assert feats["page_text_length"] > 0


# --------------------------------------------------------------------------- #
# Phishing page
# --------------------------------------------------------------------------- #
def test_phishing_page_signals():
    """A phishing-style page trips the high-signal boolean features."""
    feats = extract_html_features(
        _load("phishing_page.html"), base_url="https://evil-domain.net"
    )
    assert feats["has_password_field"] is True  # type="Password" (case-insensitive)
    assert feats["has_iframe"] is True
    assert feats["has_hidden_elements"] is True  # display:none + visibility:hidden
    assert feats["num_forms"] == 1
    assert feats["has_favicon"] is False
    assert feats["has_copyright"] is False


def test_phishing_page_links():
    """External brand links dominate; # and mailto are internal."""
    feats = extract_html_features(
        _load("phishing_page.html"), base_url="https://evil-domain.net"
    )
    # External: paypal, facebook, twitter (3)
    # Internal: "#", mailto: (2)
    assert feats["num_external_links"] == 3
    assert feats["num_internal_links"] == 2
    assert feats["external_link_ratio"] == pytest.approx(3 / 5)


def test_password_field_case_insensitive():
    """type='PASSWORD' in any casing is detected."""
    html = "<form><input type='PASSWORD'></form>"
    feats = extract_html_features(html, base_url="https://x.com")
    assert feats["has_password_field"] is True


# --------------------------------------------------------------------------- #
# Malformed HTML
# --------------------------------------------------------------------------- #
def test_malformed_html_does_not_crash():
    """lxml tolerates malformed markup; features are still computed."""
    feats = extract_html_features(
        _load("malformed_page.html"), base_url="https://my-site.com"
    )
    assert set(feats.keys()) == set(FEATURE_KEYS)
    # The broken page still has a recoverable password input and an external link.
    assert feats["has_password_field"] is True
    assert feats["num_external_links"] == 1  # other-domain.com
    assert feats["title_length"] > 0


# --------------------------------------------------------------------------- #
# Link edge cases
# --------------------------------------------------------------------------- #
def test_no_links_ratio_is_zero():
    """external_link_ratio is 0.0 when there are no links."""
    feats = extract_html_features("<html><body><p>hi</p></body></html>", base_url="https://x.com")
    assert feats["num_external_links"] == 0
    assert feats["num_internal_links"] == 0
    assert feats["external_link_ratio"] == 0.0


def test_relative_links_are_internal():
    """Relative and fragment links count as internal."""
    html = '<a href="/a">a</a><a href="page.html">b</a><a href="#top">c</a>'
    feats = extract_html_features(html, base_url="https://site.com")
    assert feats["num_internal_links"] == 3
    assert feats["num_external_links"] == 0


def test_subdomain_is_internal():
    """A link to a subdomain of the base registered domain is internal."""
    html = '<a href="https://mail.site.com/x">mail</a><a href="https://other.com">o</a>'
    feats = extract_html_features(html, base_url="https://www.site.com")
    assert feats["num_internal_links"] == 1
    assert feats["num_external_links"] == 1


def test_no_base_url_treats_hosted_as_external():
    """Without a base_url, hosted links are external, relatives internal."""
    html = '<a href="https://anything.com/x">x</a><a href="/local">y</a>'
    feats = extract_html_features(html, base_url=None)
    assert feats["num_external_links"] == 1
    assert feats["num_internal_links"] == 1


# --------------------------------------------------------------------------- #
# Content edge cases
# --------------------------------------------------------------------------- #
def test_missing_title_and_meta_are_zero():
    """Absent title and meta description yield length 0, not None."""
    feats = extract_html_features("<html><body>no head here</body></html>", base_url="https://x.com")
    assert feats["title_length"] == 0
    assert feats["meta_description_length"] == 0


def test_script_text_excluded_from_page_text():
    """Script/style text is not counted in visible page_text_length."""
    visible = "<html><body><p>hello</p></body></html>"
    with_script = "<html><body><p>hello</p><script>var aaaaaaaaaaaaaaaa=1;</script></body></html>"
    len_visible = extract_html_features(visible, base_url="https://x.com")["page_text_length"]
    len_with_script = extract_html_features(with_script, base_url="https://x.com")["page_text_length"]
    assert len_visible == len_with_script


def test_copyright_symbol_detected():
    """The © symbol alone triggers has_copyright."""
    feats = extract_html_features("<p>© 2026</p>", base_url="https://x.com")
    assert feats["has_copyright"] is True


# --------------------------------------------------------------------------- #
# Behavioral / form signals (DEC-015)
# --------------------------------------------------------------------------- #
def test_behavioral_phishing_signals():
    """Onmouseover, right-click-disable, popup, and external form action all trip."""
    feats = extract_html_features(
        _load("behavioral_phishing_page.html"), base_url="https://phish-login.net"
    )
    assert feats["has_onmouseover"] is True
    assert feats["has_right_click_disabled"] is True
    assert feats["has_suspicious_popup"] is True
    assert feats["form_action_is_external"] is True
    assert feats["form_submits_to_email"] is True
    assert feats["form_action_is_empty_or_blank"] is False
    # script src + link href both point off-domain -> 0.0 internal ratio
    assert feats["internal_tag_link_ratio"] == 0.0


def test_blank_form_action_flagged():
    """An empty form action is flagged, and is not also counted as external."""
    feats = extract_html_features(
        _load("blank_form_action_page.html"), base_url="https://phish-login.net"
    )
    assert feats["form_action_is_empty_or_blank"] is True
    assert feats["form_action_is_external"] is False


def test_legit_page_has_no_behavioral_signals():
    """The clean legit fixture trips none of the new behavioral checks."""
    feats = extract_html_features(_load("legit_page.html"), base_url="https://example.com")
    assert feats["has_onmouseover"] is False
    assert feats["has_right_click_disabled"] is False
    assert feats["has_suspicious_popup"] is False
    assert feats["form_action_is_external"] is False
    assert feats["form_submits_to_email"] is False
    assert feats["form_action_is_empty_or_blank"] is False


def test_internal_tag_link_ratio_no_tag_links_defaults_to_one():
    """No <script src>/<link href> at all -> neutral default of 1.0."""
    feats = extract_html_features("<html><body><p>hi</p></body></html>", base_url="https://x.com")
    assert feats["internal_tag_link_ratio"] == 1.0


# --------------------------------------------------------------------------- #
# Unusable input
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize("bad", [None, "", "   ", 123, []])
def test_unusable_input_returns_all_none(bad):
    """Non-string / empty input yields an all-None dict."""
    feats = extract_html_features(bad)
    assert set(feats.keys()) == set(FEATURE_KEYS)
    assert all(v is None for v in feats.values())
