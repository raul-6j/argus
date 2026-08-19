"""WCAG 2.1 contrast audit of the ARGUS design tokens.

Parses the real stylesheets — ``webapp/style.css`` (dark + light) and
``extension/lib/argus-ui.css`` (dark only) — rather than a hardcoded copy of
the palette, so it cannot drift from what actually ships.

Two thresholds apply (WCAG 2.1 SC 1.4.3 / 1.4.11):

* **4.5:1** for normal-size text.
* **3:1** for graphical objects — risk-band bars, focus rings, status dots.

The "soft" badge backgrounds are translucent, so each is composited over the
surface it really sits on (a card) before measuring; measuring the raw rgba()
against a card would report a contrast no user ever sees.

Usage::

    python scripts/check_contrast.py          # exits non-zero on any failure
    python scripts/check_contrast.py --quiet  # failures only
"""

from __future__ import annotations

import argparse
import logging
import re
import sys
from pathlib import Path
from typing import Optional

logger = logging.getLogger(__name__)

REPO_ROOT = Path(__file__).resolve().parents[1]
WEBAPP_CSS = REPO_ROOT / "webapp" / "style.css"
EXTENSION_CSS = REPO_ROOT / "extension" / "lib" / "argus-ui.css"

AA_TEXT = 4.5
AA_NON_TEXT = 3.0

Rgb = tuple[int, int, int]


# --------------------------------------------------------------- colour --

def _srgb(channel: float) -> float:
    """Linearise one 0-255 sRGB channel."""
    c = channel / 255
    return c / 12.92 if c <= 0.04045 else ((c + 0.055) / 1.055) ** 2.4


def relative_luminance(rgb: Rgb) -> float:
    """WCAG relative luminance of an opaque colour."""
    r, g, b = rgb
    return 0.2126 * _srgb(r) + 0.7152 * _srgb(g) + 0.0722 * _srgb(b)


def contrast_ratio(fg: Rgb, bg: Rgb) -> float:
    """WCAG contrast ratio between two opaque colours (1.0 – 21.0)."""
    a, b = relative_luminance(fg), relative_luminance(bg)
    lighter, darker = max(a, b), min(a, b)
    return (lighter + 0.05) / (darker + 0.05)


def parse_colour(value: str) -> Optional[tuple[Rgb, float]]:
    """Parse ``#rgb``/``#rrggbb``/``rgba(...)`` into (rgb, alpha).

    Returns None for anything else (``var(...)``, gradients, ``color-mix``),
    which the caller resolves or skips.
    """
    value = value.strip()

    hex_match = re.fullmatch(r"#([0-9a-fA-F]{3}|[0-9a-fA-F]{6})", value)
    if hex_match:
        digits = hex_match.group(1)
        if len(digits) == 3:
            digits = "".join(c * 2 for c in digits)
        return (tuple(int(digits[i:i + 2], 16) for i in (0, 2, 4)), 1.0)

    rgba_match = re.fullmatch(
        r"rgba?\(\s*([\d.]+)[,\s]+([\d.]+)[,\s]+([\d.]+)(?:[,\s/]+([\d.]+))?\s*\)",
        value,
    )
    if rgba_match:
        r, g, b = (round(float(rgba_match.group(i))) for i in (1, 2, 3))
        alpha = float(rgba_match.group(4)) if rgba_match.group(4) else 1.0
        return ((r, g, b), alpha)

    return None


def composite(fg: Rgb, alpha: float, bg: Rgb) -> Rgb:
    """Flatten a translucent colour onto an opaque background."""
    return tuple(round(fg[i] * alpha + bg[i] * (1 - alpha)) for i in range(3))


# ------------------------------------------------------------- parsing --

def extract_tokens(css: str, selector: str) -> dict[str, str]:
    """Pull the ``--name: value;`` pairs out of one rule block."""
    start = css.find(selector)
    if start == -1:
        raise ValueError(f"selector {selector!r} not found")
    open_brace = css.index("{", start)
    close_brace = css.index("}", open_brace)
    block = css[open_brace + 1:close_brace]
    return {
        name: value.strip()
        for name, value in re.findall(r"(--[\w-]+)\s*:\s*([^;]+);", block)
    }


def resolve(tokens: dict[str, str], name: str, _depth: int = 0) -> Optional[tuple[Rgb, float]]:
    """Resolve a token to a concrete colour, following ``var()`` aliases."""
    if _depth > 10 or name not in tokens:
        return None
    value = tokens[name]
    parsed = parse_colour(value)
    if parsed:
        return parsed
    alias = re.fullmatch(r"var\((--[\w-]+)\)", value.strip())
    if alias:
        return resolve(tokens, alias.group(1), _depth + 1)
    return None


# --------------------------------------------------------------- checks --

class Auditor:
    """Collects pass/fail results for one theme."""

    def __init__(self, label: str, tokens: dict[str, str]) -> None:
        self.label = label
        self.tokens = tokens
        self.failures: list[str] = []
        self.checks = 0

    def _rgb(self, name: str) -> Optional[Rgb]:
        resolved = resolve(self.tokens, name)
        return resolved[0] if resolved else None

    def check(self, fg_name: str, bg_name: str, threshold: float, note: str) -> None:
        """Opaque foreground on an opaque background."""
        fg, bg = self._rgb(fg_name), self._rgb(bg_name)
        if fg is None or bg is None:
            return
        self._record(contrast_ratio(fg, bg), threshold, note)

    def check_on_soft(self, fg_name: str, soft_name: str, surface_name: str, note: str) -> None:
        """Badge text on its own translucent wash, over a real surface."""
        fg = self._rgb(fg_name)
        soft = resolve(self.tokens, soft_name)
        surface = self._rgb(surface_name)
        if fg is None or soft is None or surface is None:
            return
        soft_rgb, alpha = soft
        self._record(contrast_ratio(fg, composite(soft_rgb, alpha, surface)), AA_TEXT, note)

    def check_literal(self, fg: Rgb, bg_name: str, threshold: float, note: str) -> None:
        bg = self._rgb(bg_name)
        if bg is None:
            return
        self._record(contrast_ratio(fg, bg), threshold, note)

    def _record(self, ratio: float, threshold: float, note: str) -> None:
        self.checks += 1
        ok = ratio >= threshold
        logger.info("    %-52s %5.2f  %s", note, ratio, "PASS" if ok else "FAIL")
        if not ok:
            self.failures.append(f"{self.label}: {note} = {ratio:.2f} (needs {threshold})")


SURFACES = ("--bg", "--bg-alt", "--surface")

BADGES = [
    ("--danger-text", "--danger-soft"),
    ("--success", "--success-soft"),
    ("--warning", "--warning-soft"),
    ("--info", "--info-soft"),
    ("--phishing-text", "--phishing-soft"),
    ("--legitimate-text", "--legitimate-soft"),
    ("--band-low-text", "--band-low-soft"),
    ("--band-caution-text", "--band-caution-soft"),
    ("--band-suspicious-text", "--band-suspicious-soft"),
    ("--band-high-text", "--band-high-soft"),
    ("--band-critical-text", "--band-critical-soft"),
    ("--accent-hover", "--accent-soft"),
]

BARS = (
    "--band-low", "--band-caution", "--band-suspicious",
    "--band-high", "--band-critical", "--accent",
)


def audit(label: str, tokens: dict[str, str]) -> Auditor:
    auditor = Auditor(label, tokens)
    logger.info("\n=== %s %s", label, "=" * max(0, 56 - len(label)))

    logger.info("\n  text on every surface it can sit on (needs %.1f)", AA_TEXT)
    for text_token in ("--text", "--text-secondary", "--text-muted"):
        for surface in SURFACES:
            auditor.check(text_token, surface, AA_TEXT,
                          f"{text_token} on {surface}")

    logger.info("\n  link text (needs %.1f)", AA_TEXT)
    for surface in SURFACES:
        auditor.check("--accent-hover", surface, AA_TEXT, f"link on {surface}")
        auditor.check("--accent-bright", surface, AA_TEXT, f"link:hover on {surface}")

    logger.info("\n  badge text on its own soft wash, over a card (needs %.1f)", AA_TEXT)
    for fg, soft in BADGES:
        auditor.check_on_soft(fg, soft, "--surface", f"{fg} on {soft}")

    logger.info("\n  filled-button label (needs %.1f)", AA_TEXT)
    auditor.check_literal((255, 255, 255), "--accent-solid", AA_TEXT,
                          "white on --accent-solid")
    auditor.check_literal((255, 255, 255), "--accent-solid-hover", AA_TEXT,
                          "white on --accent-solid-hover")

    logger.info("\n  graphical objects vs their track (needs %.1f)", AA_NON_TEXT)
    for bar in BARS:
        auditor.check(bar, "--bg-alt", AA_NON_TEXT, f"{bar} vs --bg-alt")

    return auditor


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--quiet", action="store_true", help="report failures only")
    args = parser.parse_args()

    logging.basicConfig(
        level=logging.WARNING if args.quiet else logging.INFO,
        format="%(message)s",
    )

    webapp_css = WEBAPP_CSS.read_text(encoding="utf-8")
    extension_css = EXTENSION_CSS.read_text(encoding="utf-8")

    auditors = [
        audit("WEBAPP / DARK", extract_tokens(webapp_css, ":root {")),
        audit("WEBAPP / LIGHT",
              {**extract_tokens(webapp_css, ":root {"),
               **extract_tokens(webapp_css, ':root[data-theme="light"]')}),
        audit("EXTENSION / DARK", extract_tokens(extension_css, ":root {")),
    ]

    failures = [f for auditor in auditors for f in auditor.failures]
    total = sum(auditor.checks for auditor in auditors)

    print(f"\n{'=' * 64}")
    if failures:
        print(f"{len(failures)} of {total} checks BELOW WCAG AA:")
        for failure in failures:
            print(f"  - {failure}")
        return 1

    print(f"All {total} token pairs meet WCAG AA.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
