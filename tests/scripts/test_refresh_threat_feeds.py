"""Tests for scripts/refresh_threat_feeds.py (Phase 1, D1)."""

from __future__ import annotations

from unittest import mock

import yaml

from scripts import refresh_threat_feeds as rtf

MODULE = "scripts.refresh_threat_feeds"


class TestNormalizers:
    def test_phishtank_normalizer(self):
        raw = b"url,verified,online\nhttp://evil1.com,yes,yes\nhttp://evil2.com,no,no\n"
        rows = rtf._normalize_phishtank_text(raw)
        assert rows == [
            {"url": "http://evil1.com", "verified": "yes", "online": "yes"},
            {"url": "http://evil2.com", "verified": "no", "online": "no"},
        ]

    def test_openphish_normalizer_skips_blank_and_comment_lines(self):
        raw = b"http://evil3.com/x\n\n#comment\nhttp://evil4.com/y\n"
        rows = rtf._normalize_openphish_text(raw)
        assert [r["url"] for r in rows] == ["http://evil3.com/x", "http://evil4.com/y"]
        assert all(r["verified"] == "yes" and r["online"] == "yes" for r in rows)

    def test_urlhaus_normalizer(self):
        raw = (
            b"# comment header\n"
            b'1,2026-01-01,"http://evil5.com",online,mal,tag,link,rep\n'
            b'2,2026-01-01,"http://evil6.com",offline,mal,tag,link,rep\n'
        )
        rows = rtf._normalize_urlhaus_text(raw)
        assert rows == [
            {"url": "http://evil5.com", "verified": "yes", "online": "yes"},
            {"url": "http://evil6.com", "verified": "yes", "online": "no"},
        ]

    def test_urlhaus_normalizer_skips_short_rows(self):
        raw = b"a,b\n"
        assert rtf._normalize_urlhaus_text(raw) == []


class TestRefresh:
    def _config(self, tmp_path, feeds):
        config_path = tmp_path / "threat_intel_config.yaml"
        config_path.write_text(
            yaml.safe_dump({"feeds_dir": str(tmp_path / "feeds"), "feeds": feeds}), encoding="utf-8"
        )
        return config_path

    def test_no_feeds_configured_returns_none(self, tmp_path):
        config_path = self._config(tmp_path, [])
        assert rtf.refresh(config_path) is None

    def test_missing_config_returns_none(self, tmp_path):
        assert rtf.refresh(tmp_path / "nope.yaml") is None

    def test_all_feeds_failing_returns_none_and_writes_nothing(self, tmp_path):
        config_path = self._config(
            tmp_path, [{"name": "phishtank", "parser": "phishtank", "url": "http://example.invalid/feed.csv"}]
        )
        with mock.patch(f"{MODULE}._download", return_value=None):
            result = rtf.refresh(config_path)
        assert result is None
        assert not (tmp_path / "feeds" / "active_snapshot.txt").exists()

    def test_successful_refresh_writes_snapshot_and_pointer(self, tmp_path):
        config_path = self._config(
            tmp_path,
            [
                {"name": "phishtank", "parser": "phishtank", "url": "http://a.invalid"},
                {"name": "openphish", "parser": "openphish", "url": "http://b.invalid"},
            ],
        )
        pt_csv = b"url,verified,online\nhttp://evil1.com,yes,yes\n"
        op_txt = b"http://evil2.com/x\n"

        with mock.patch(f"{MODULE}._download", side_effect=[pt_csv, op_txt]):
            result = rtf.refresh(config_path)

        assert result is not None
        assert result.is_file()
        pointer = tmp_path / "feeds" / "active_snapshot.txt"
        assert pointer.is_file()

        import pandas as pd

        df = pd.read_csv(result)
        assert set(df["url"]) == {"http://evil1.com", "http://evil2.com/x"}

    def test_dedupes_across_feeds_by_normalized_url(self, tmp_path):
        config_path = self._config(
            tmp_path,
            [
                {"name": "phishtank", "parser": "phishtank", "url": "http://a.invalid"},
                {"name": "openphish", "parser": "openphish", "url": "http://b.invalid"},
            ],
        )
        pt_csv = b"url,verified,online\nHTTP://EVIL.com/x,yes,yes\n"
        op_txt = b"http://evil.com/x\n"  # same URL, different case -> should dedupe

        with mock.patch(f"{MODULE}._download", side_effect=[pt_csv, op_txt]):
            result = rtf.refresh(config_path)

        import pandas as pd

        df = pd.read_csv(result)
        assert len(df) == 1

    def test_one_feed_failing_does_not_abort_the_others(self, tmp_path):
        config_path = self._config(
            tmp_path,
            [
                {"name": "phishtank", "parser": "phishtank", "url": "http://a.invalid"},
                {"name": "openphish", "parser": "openphish", "url": "http://b.invalid"},
            ],
        )
        op_txt = b"http://evil1.com\n"

        with mock.patch(f"{MODULE}._download", side_effect=[None, op_txt]):
            result = rtf.refresh(config_path)

        assert result is not None
        import pandas as pd

        df = pd.read_csv(result)
        assert list(df["url"]) == ["http://evil1.com"]

    def test_unknown_parser_is_skipped(self, tmp_path):
        config_path = self._config(
            tmp_path, [{"name": "mystery", "parser": "does_not_exist", "url": "http://a.invalid"}]
        )
        result = rtf.refresh(config_path)
        assert result is None
