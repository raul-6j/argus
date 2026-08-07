"""Tests for sdk/python/argus_cli.py (Phase 3, F12).

argus_cli.py is deliberately outside src/ (it's a vendorable SDK artifact,
not part of the app), so it isn't on the normal package path -- inserted
directly, mirroring how a real external consumer would run it standalone.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import ClassVar
from unittest import mock

import pytest

_SDK_PYTHON_DIR = Path(__file__).resolve().parents[2] / "sdk" / "python"
sys.path.insert(0, str(_SDK_PYTHON_DIR))

import argus_cli as cli  # noqa: E402 - must follow the sys.path.insert above


@pytest.fixture(autouse=True)
def _clean_env(monkeypatch):
    monkeypatch.delenv("ARGUS_API_KEY", raising=False)
    monkeypatch.delenv("ARGUS_BASE_URL", raising=False)


class TestResolveApiKey:
    def test_cli_flag_wins(self, monkeypatch):
        monkeypatch.setenv("ARGUS_API_KEY", "argus_env")
        assert cli.resolve_api_key("argus_flag") == "argus_flag"

    def test_falls_back_to_env_var(self, monkeypatch):
        monkeypatch.setenv("ARGUS_API_KEY", "argus_env")
        assert cli.resolve_api_key(None) == "argus_env"

    def test_raises_when_neither_set(self):
        with pytest.raises(ValueError, match="No API key"):
            cli.resolve_api_key(None)


class TestResolveBaseUrl:
    def test_cli_flag_wins(self, monkeypatch):
        monkeypatch.setenv("ARGUS_BASE_URL", "https://env.example.com")
        assert cli.resolve_base_url("https://flag.example.com") == "https://flag.example.com"

    def test_falls_back_to_env_var(self, monkeypatch):
        monkeypatch.setenv("ARGUS_BASE_URL", "https://env.example.com")
        assert cli.resolve_base_url(None) == "https://env.example.com"

    def test_falls_back_to_default_placeholder(self):
        assert cli.resolve_base_url(None) == cli._DEFAULT_BASE_URL


class TestReadUrlsFile:
    def test_reads_one_url_per_line(self, tmp_path):
        p = tmp_path / "urls.txt"
        p.write_text("https://a.com\nhttps://b.com\n", encoding="utf-8")
        assert cli.read_urls_file(p) == ["https://a.com", "https://b.com"]

    def test_skips_blank_lines_and_comments(self, tmp_path):
        p = tmp_path / "urls.txt"
        p.write_text("https://a.com\n\n# a comment\nhttps://b.com\n", encoding="utf-8")
        assert cli.read_urls_file(p) == ["https://a.com", "https://b.com"]

    def test_strips_whitespace(self, tmp_path):
        p = tmp_path / "urls.txt"
        p.write_text("  https://a.com  \n", encoding="utf-8")
        assert cli.read_urls_file(p) == ["https://a.com"]


class TestFormatting:
    _RESULT: ClassVar[dict] = {
        "url": "https://example.com",
        "label": "phishing",
        "confidence": 0.9,
        "risk_band": "critical",
    }

    def test_format_single_text(self):
        text = cli.format_single(self._RESULT, "text")
        assert "phishing" in text
        assert "critical" in text
        assert "⚠" in text

    def test_format_single_text_legitimate_marker(self):
        text = cli.format_single({"url": "https://a.com", "label": "legitimate", "confidence": 0.95}, "text")
        assert "✓" in text

    def test_format_single_json_roundtrips(self):
        text = cli.format_single(self._RESULT, "json")
        assert json.loads(text) == self._RESULT

    def test_format_single_csv_has_header_and_row(self):
        text = cli.format_single(self._RESULT, "csv")
        lines = text.splitlines()
        assert lines[0] == ",".join(cli._CSV_FIELDS)
        assert "example.com" in lines[1]

    def test_format_error_result_as_text(self):
        text = cli.format_single({"url": "ftp://bad", "error": "invalid scheme"}, "text")
        assert "ERROR" in text
        assert "invalid scheme" in text

    def test_format_batch_json_is_a_list(self):
        results = [self._RESULT, {"url": "https://b.com", "label": "legitimate", "confidence": 0.8}]
        parsed = json.loads(cli.format_batch(results, "json"))
        assert len(parsed) == 2

    def test_format_batch_csv_has_one_header_and_n_rows(self):
        results = [self._RESULT, {"url": "https://b.com", "error": "boom"}]
        lines = cli.format_batch(results, "csv").splitlines()
        assert len(lines) == 3  # header + 2 rows


class TestAnyFlagged:
    def test_true_when_any_result_is_phishing(self):
        assert cli.any_flagged([{"label": "legitimate"}, {"label": "phishing"}]) is True

    def test_false_when_none_flagged(self):
        assert cli.any_flagged([{"label": "legitimate"}, {"label": "legitimate"}]) is False

    def test_false_for_empty_list(self):
        assert cli.any_flagged([]) is False

    def test_error_entries_do_not_count_as_flagged(self):
        assert cli.any_flagged([{"url": "ftp://bad", "error": "bad scheme"}]) is False


class TestRunExitCodes:
    def test_scan_legitimate_exits_zero(self, tmp_path, capsys):
        with mock.patch.object(cli, "ArgusClient") as MockClient:
            MockClient.return_value.scan.return_value = {
                "url": "https://example.com", "label": "legitimate", "confidence": 0.9,
            }
            code = cli.run(["--api-key", "argus_test", "scan", "https://example.com"])
        assert code == 0
        assert "legitimate" in capsys.readouterr().out

    def test_scan_phishing_exits_one(self, capsys):
        with mock.patch.object(cli, "ArgusClient") as MockClient:
            MockClient.return_value.scan.return_value = {
                "url": "https://evil.com", "label": "phishing", "confidence": 0.95,
            }
            code = cli.run(["--api-key", "argus_test", "scan", "https://evil.com"])
        assert code == 1

    def test_missing_api_key_exits_two(self, capsys):
        code = cli.run(["scan", "https://example.com"])
        assert code == 2
        assert "No API key" in capsys.readouterr().err

    def test_scan_batch_exits_one_if_any_flagged(self, tmp_path):
        urls_file = tmp_path / "urls.txt"
        urls_file.write_text("https://a.com\nhttps://b.com\n", encoding="utf-8")
        with mock.patch.object(cli, "ArgusClient") as MockClient:
            MockClient.return_value.scan_batch.return_value = [
                {"url": "https://a.com", "label": "legitimate", "confidence": 0.9},
                {"url": "https://b.com", "label": "phishing", "confidence": 0.8},
            ]
            code = cli.run(["--api-key", "argus_test", "scan-batch", str(urls_file)])
        assert code == 1

    def test_scan_batch_empty_file_exits_two(self, tmp_path, capsys):
        urls_file = tmp_path / "urls.txt"
        urls_file.write_text("# nothing here\n", encoding="utf-8")
        code = cli.run(["--api-key", "argus_test", "scan-batch", str(urls_file)])
        assert code == 2
        assert "No URLs found" in capsys.readouterr().err

    def test_health_needs_no_api_key(self, capsys):
        with mock.patch.object(cli, "ArgusClient") as MockClient:
            MockClient.return_value.health.return_value = {"status": "ok"}
            code = cli.run(["health"])
        assert code == 0

    def test_explain_exits_zero_regardless_of_label(self):
        with mock.patch.object(cli, "ArgusClient") as MockClient:
            MockClient.return_value.explain.return_value = {
                "url": "https://evil.com", "top5_features": [], "plain_explanation": "..."
            }
            code = cli.run(["--api-key", "argus_test", "explain", "https://evil.com"])
        assert code == 0

    def test_api_error_exits_two(self, capsys):
        from argus_client import ArgusApiError

        with mock.patch.object(cli, "ArgusClient") as MockClient:
            MockClient.return_value.scan.side_effect = ArgusApiError(503, "model not ready")
            code = cli.run(["--api-key", "argus_test", "scan", "https://example.com"])
        assert code == 2
        assert "model not ready" in capsys.readouterr().err

    def test_output_file_is_written(self, tmp_path):
        out_path = tmp_path / "out.json"
        with mock.patch.object(cli, "ArgusClient") as MockClient:
            MockClient.return_value.scan.return_value = {
                "url": "https://example.com", "label": "legitimate", "confidence": 0.9,
            }
            code = cli.run(
                ["--api-key", "argus_test", "--format", "json", "--output", str(out_path), "scan", "https://example.com"]
            )
        assert code == 0
        assert json.loads(out_path.read_text())["label"] == "legitimate"
