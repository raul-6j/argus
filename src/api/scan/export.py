"""Investigation-report export (Phase 4, F13): JSON/CSV/PDF, one shared helper.

Reused by both the anonymous permalink endpoint (``GET /scan/<scan_id>/export``)
and the authenticated history endpoint (``GET /scan/history/<id>/export``) —
both already have the full report dict in hand (nothing new is fetched or
computed here, purely re-serialization of already-stored data). Because of
that, these exports don't carry a ``latency_ms`` field the way live detection
endpoints must (see CLAUDE.md's iron laws): there's no inference/enrichment
work happening, so a timing figure would be meaningless noise in a downloaded
report.
"""

from __future__ import annotations

import csv
import io
import json
import logging
from typing import Any

from fpdf import FPDF

logger = logging.getLogger(__name__)

EXPORT_FORMATS = ("json", "csv", "pdf")

_MIME_TYPES = {
    "json": "application/json",
    "csv": "text/csv",
    "pdf": "application/pdf",
}

_TOP_LEVEL_FIELDS = (
    "scan_id",
    "url",
    "label",
    "confidence",
    "risk_score",
    "risk_band",
    "source",
    "plain_explanation",
    "created_at",
)


def build_export(report: dict[str, Any], fmt: str) -> tuple[bytes, str, str]:
    """Serialize a scan report dict to ``fmt``.

    :param report: a report dict shaped like the ``GET /scan/<id>`` response
        (``url``, ``label``, ``confidence``, ``risk_score``, ``risk_band``,
        ``signals``, ``plain_explanation``, ``source``, ``created_at``, and
        optionally ``scan_id``).
    :param fmt: one of :data:`EXPORT_FORMATS`.
    :returns: ``(content_bytes, mimetype, filename)``.
    :raises ValueError: if ``fmt`` isn't a supported format.
    """
    if fmt not in _MIME_TYPES:
        raise ValueError(f"unsupported export format: {fmt!r}")

    slug = str(report.get("scan_id") or "argus-report")
    filename = f"{slug}.{fmt}"

    if fmt == "json":
        content = json.dumps(report, indent=2).encode("utf-8")
    elif fmt == "csv":
        content = _build_csv(report)
    else:
        content = _build_pdf(report)

    return content, _MIME_TYPES[fmt], filename


def _build_csv(report: dict[str, Any]) -> bytes:
    buffer = io.StringIO()
    writer = csv.writer(buffer)

    writer.writerow(_TOP_LEVEL_FIELDS)
    writer.writerow([report.get(field, "") for field in _TOP_LEVEL_FIELDS])

    writer.writerow([])
    writer.writerow(["signal_name", "triggered", "direction", "evidence"])
    for signal in report.get("signals", []):
        writer.writerow(
            [
                signal.get("name", ""),
                signal.get("triggered", ""),
                signal.get("direction", ""),
                json.dumps(signal.get("evidence", {})),
            ]
        )

    return buffer.getvalue().encode("utf-8")


_PDF_CHAR_SUBSTITUTIONS = {
    "—": "-",  # em dash
    "–": "-",  # en dash
    "‘": "'",  # left single quote
    "’": "'",  # right single quote
    "“": '"',  # left double quote
    "”": '"',  # right double quote
    "…": "...",  # ellipsis
}


def _pdf_safe(text: str) -> str:
    """fpdf2's core Helvetica font only covers Latin-1.

    ``explain_plain``'s generated text (and, in principle, an attacker-
    controlled ``url``) can contain characters outside that range (e.g. the
    em dash in "No phishing indicators found — ..."). Rather than bundling a
    Unicode TTF just for a handful of common punctuation marks, transliterate
    the common cases and drop anything else that still doesn't fit.
    """
    for char, replacement in _PDF_CHAR_SUBSTITUTIONS.items():
        text = text.replace(char, replacement)
    return text.encode("latin-1", errors="replace").decode("latin-1")


def _build_pdf(report: dict[str, Any]) -> bytes:
    pdf = FPDF(format="A4")
    pdf.set_auto_page_break(auto=True, margin=15)
    pdf.add_page()

    pdf.set_font("Helvetica", "B", 16)
    pdf.cell(0, 10, "ARGUS Investigation Report", new_x="LMARGIN", new_y="NEXT")

    pdf.set_font("Helvetica", "", 11)
    pdf.multi_cell(
        0, 7, _pdf_safe(f"URL: {report.get('url', '')}"), wrapmode="CHAR", new_x="LMARGIN", new_y="NEXT"
    )

    verdict = str(report.get("label", "")).upper()
    pdf.set_font("Helvetica", "B", 13)
    pdf.cell(0, 8, _pdf_safe(f"Verdict: {verdict}"), new_x="LMARGIN", new_y="NEXT")

    pdf.set_font("Helvetica", "", 11)
    pdf.cell(
        0,
        7,
        _pdf_safe(
            f"Risk band: {report.get('risk_band', 'n/a')}   "
            f"Risk score: {report.get('risk_score', 0):.3f}   "
            f"Confidence: {report.get('confidence', 0):.3f}"
        ),
        new_x="LMARGIN",
        new_y="NEXT",
    )
    pdf.cell(0, 7, _pdf_safe(f"Decisive source: {report.get('source', '')}"), new_x="LMARGIN", new_y="NEXT")
    if report.get("created_at"):
        pdf.cell(0, 7, _pdf_safe(f"Scanned at: {report['created_at']}"), new_x="LMARGIN", new_y="NEXT")

    pdf.ln(4)
    pdf.set_font("Helvetica", "B", 12)
    pdf.cell(0, 8, "Explanation", new_x="LMARGIN", new_y="NEXT")
    pdf.set_font("Helvetica", "", 11)
    pdf.multi_cell(
        0,
        7,
        _pdf_safe(report.get("plain_explanation", "")),
        wrapmode="CHAR",
        new_x="LMARGIN",
        new_y="NEXT",
    )

    signals = report.get("signals", [])
    if signals:
        pdf.ln(4)
        pdf.set_font("Helvetica", "B", 12)
        pdf.cell(0, 8, "Detection signals", new_x="LMARGIN", new_y="NEXT")
        pdf.set_font("Helvetica", "", 10)
        for signal in signals:
            state = "triggered" if signal.get("triggered") else "not triggered"
            pdf.multi_cell(
                0,
                6,
                _pdf_safe(
                    f"- {signal.get('name', '')} ({state}, direction={signal.get('direction', '')}): "
                    f"{json.dumps(signal.get('evidence', {}))}"
                ),
                wrapmode="CHAR",
                new_x="LMARGIN",
                new_y="NEXT",
            )

    return bytes(pdf.output())
