#!/usr/bin/env python
"""ARGUS developer API — command-line client (Phase 3, F12).

A thin wrapper over ``argus_client.py`` (this directory) for CI/security-
automation use: scan a URL or a file of URLs from a shell script or CI
pipeline step without writing any Python. No dependencies beyond
``argus_client.py``'s own (``requests``) -- copy both files together, or
vendor them as-is, same convention as the rest of ``sdk/python/``.

Usage:
    export ARGUS_API_KEY=argus_...
    export ARGUS_BASE_URL=https://argus.example.com   # optional, has a default

    python argus_cli.py scan https://example.com
    python argus_cli.py scan https://example.com --enrich --format json
    python argus_cli.py scan-batch urls.txt --format csv --output report.csv
    python argus_cli.py explain https://example.com
    python argus_cli.py health

Exit codes (for CI gating):
    0 - ran successfully, no URL was flagged as phishing
    1 - ran successfully, at least one URL was flagged as phishing
    2 - couldn't run at all (missing API key, bad input, network/API error)
"""

from __future__ import annotations

import argparse
import csv
import io
import json
import os
import sys
from pathlib import Path
from typing import Any, Optional

# argus_client.py lives alongside this file, not on a package path -- this
# mirrors the "copy both files together" vendoring convention already
# documented in argus_client.py's own docstring, rather than assuming this
# repo's src/ layout (a real external consumer wouldn't have that).
sys.path.insert(0, str(Path(__file__).resolve().parent))

from argus_client import ArgusApiError, ArgusClient

_DEFAULT_BASE_URL = "https://api.argus.example.com"


def resolve_api_key(cli_value: Optional[str]) -> str:
    """Resolve the API key: ``--api-key`` flag, else ``ARGUS_API_KEY`` env var.

    Raises:
        ValueError: If neither is set.
    """
    value = cli_value or os.environ.get("ARGUS_API_KEY")
    if not value:
        raise ValueError(
            "No API key given -- pass --api-key or set the ARGUS_API_KEY environment variable."
        )
    return value


def resolve_base_url(cli_value: Optional[str]) -> str:
    """Resolve the base URL: ``--base-url`` flag, else ``ARGUS_BASE_URL`` env
    var, else a documented placeholder default (never a real hardcoded
    endpoint -- mirrors the browser extension's "nothing is hardcoded"
    convention, see extension/README.md's S8 note)."""
    return cli_value or os.environ.get("ARGUS_BASE_URL") or _DEFAULT_BASE_URL


def read_urls_file(path: Path) -> list[str]:
    """Read one URL per line from a file, skipping blank lines and
    ``#``-prefixed comments."""
    urls = []
    for line in path.read_text(encoding="utf-8").splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        urls.append(stripped)
    return urls


def format_single(result: dict[str, Any], fmt: str) -> str:
    """Format one scan/explain result for stdout/file output."""
    if fmt == "json":
        return json.dumps(result, indent=2)
    if fmt == "csv":
        return _to_csv([result])
    return _to_text_line(result)


def format_batch(results: list[dict[str, Any]], fmt: str) -> str:
    """Format a list of scan results (from ``scan-batch``)."""
    if fmt == "json":
        return json.dumps(results, indent=2)
    if fmt == "csv":
        return _to_csv(results)
    return "\n".join(_to_text_line(r) for r in results)


_CSV_FIELDS = ("url", "label", "confidence", "risk_score", "risk_band", "source", "error")


def _to_csv(results: list[dict[str, Any]]) -> str:
    buf = io.StringIO()
    writer = csv.DictWriter(buf, fieldnames=_CSV_FIELDS, extrasaction="ignore", restval="")
    writer.writeheader()
    for r in results:
        writer.writerow(r)
    return buf.getvalue().rstrip("\n")


def _to_text_line(result: dict[str, Any]) -> str:
    if "error" in result:
        return f"{result.get('url', '?')}: ERROR - {result['error']}"
    label = result.get("label", "?")
    confidence = result.get("confidence")
    confidence_str = f"{confidence * 100:.1f}%" if isinstance(confidence, (int, float)) else "?"
    band = f" [{result['risk_band']}]" if result.get("risk_band") else ""
    marker = "⚠" if label == "phishing" else "✓"
    return f"{marker} {result.get('url', '?')}: {label}{band} (confidence {confidence_str})"


def any_flagged(results: list[dict[str, Any]]) -> bool:
    """Whether any result (or single-result list) is labeled phishing --
    drives the CLI's CI-friendly exit code."""
    return any(r.get("label") == "phishing" for r in results)


def _write_output(text: str, output_path: Optional[Path]) -> None:
    if output_path is not None:
        output_path.write_text(text + "\n", encoding="utf-8")
    else:
        print(text)


def run(argv: Optional[list[str]] = None) -> int:
    """Parse arguments and execute the requested subcommand.

    Returns:
        The process exit code (see module docstring).
    """
    parser = argparse.ArgumentParser(
        prog="argus",
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--api-key", default=None, help="Overrides the ARGUS_API_KEY environment variable")
    parser.add_argument("--base-url", default=None, help="Overrides the ARGUS_BASE_URL environment variable")
    parser.add_argument("--format", choices=("text", "json", "csv"), default="text")
    parser.add_argument("--output", type=Path, default=None, help="Write to this file instead of stdout")

    subparsers = parser.add_subparsers(dest="command", required=True)

    scan_parser = subparsers.add_parser("scan", help="Scan a single URL")
    scan_parser.add_argument("url")
    scan_parser.add_argument(
        "--enrich", action="store_true", help="Run the full detection fusion layer (slower)"
    )

    batch_parser = subparsers.add_parser("scan-batch", help="Scan every URL in a file (one per line)")
    batch_parser.add_argument("urls_file", type=Path)
    batch_parser.add_argument("--enrich", action="store_true")

    explain_parser = subparsers.add_parser("explain", help="Explain a single URL's verdict")
    explain_parser.add_argument("url")

    subparsers.add_parser("health", help="Check API liveness (no API key required)")

    args = parser.parse_args(argv)

    try:
        base_url = resolve_base_url(args.base_url)

        if args.command == "health":
            client = ArgusClient(api_key="", base_url=base_url)
            result = client.health()
            _write_output(format_single(result, args.format), args.output)
            return 0

        api_key = resolve_api_key(args.api_key)
        client = ArgusClient(api_key=api_key, base_url=base_url)

        if args.command == "scan":
            result = client.scan(args.url, enrich=args.enrich)
            _write_output(format_single(result, args.format), args.output)
            return 1 if any_flagged([result]) else 0

        if args.command == "scan-batch":
            urls = read_urls_file(args.urls_file)
            if not urls:
                print(f"No URLs found in {args.urls_file}", file=sys.stderr)
                return 2
            results = client.scan_batch(urls, enrich=args.enrich)
            _write_output(format_batch(results, args.format), args.output)
            return 1 if any_flagged(results) else 0

        if args.command == "explain":
            result = client.explain(args.url)
            _write_output(format_single(result, args.format), args.output)
            return 0

        return 2  # unreachable given `required=True` above, kept defensive
    except ValueError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 2
    except FileNotFoundError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 2
    except ArgusApiError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 2


def main() -> None:
    sys.exit(run())


if __name__ == "__main__":
    main()
