"""Tests for src.api.threat_intel.phishtank.load_phishtank_index."""

from __future__ import annotations

import pandas as pd

from src.api.threat_intel.phishtank import load_phishtank_hostname_index, load_phishtank_index
from src.data.loaders import normalize_url


def _make_df(n: int = 5, *, verified: str = "yes", online: str = "yes") -> pd.DataFrame:
    return pd.DataFrame(
        {
            "phish_id": range(n),
            "url": [f"http://phish{i}.evil.com/login" for i in range(n)],
            "submission_time": ["2026-05-01 12:00:00 UTC"] * n,
            "verified": [verified] * n,
            "online": [online] * n,
        }
    )


def test_happy_path_returns_normalized_frozenset(tmp_path):
    df = _make_df(n=5)
    path = tmp_path / "phishtank.csv"
    df.to_csv(path, index=False)

    index = load_phishtank_index(path)

    assert isinstance(index, frozenset)
    assert len(index) == 5
    assert normalize_url("http://phish0.evil.com/login") in index


def test_unverified_entries_excluded(tmp_path):
    df = pd.concat([_make_df(n=3, verified="yes"), _make_df(n=2, verified="no")])
    df["url"] = [f"http://u{i}.example.com/" for i in range(len(df))]
    path = tmp_path / "phishtank.csv"
    df.to_csv(path, index=False)

    index = load_phishtank_index(path)

    assert len(index) == 3


def test_offline_entries_excluded(tmp_path):
    """An 'online=no' entry may have been reclaimed by a legitimate party
    since — must not be included in a pre-filter that skips the model."""
    df = pd.concat([_make_df(n=3, online="yes"), _make_df(n=2, online="no")])
    df["url"] = [f"http://u{i}.example.com/" for i in range(len(df))]
    path = tmp_path / "phishtank.csv"
    df.to_csv(path, index=False)

    index = load_phishtank_index(path)

    assert len(index) == 3


def test_missing_online_column_includes_all_verified(tmp_path):
    df = _make_df(n=4).drop(columns=["online"])
    path = tmp_path / "phishtank.csv"
    df.to_csv(path, index=False)

    index = load_phishtank_index(path)

    assert len(index) == 4


def test_missing_file_returns_empty_frozenset(tmp_path):
    index = load_phishtank_index(tmp_path / "does_not_exist.csv")
    assert index == frozenset()


def test_missing_required_columns_returns_empty_frozenset(tmp_path):
    df = _make_df(n=3).drop(columns=["verified"])
    path = tmp_path / "phishtank_bad.csv"
    df.to_csv(path, index=False)

    index = load_phishtank_index(path)

    assert index == frozenset()


def test_malformed_csv_returns_empty_frozenset(tmp_path):
    path = tmp_path / "not_a_csv.csv"
    path.write_bytes(b"\x00\x01\x02 this is not valid csv \xff\xfe")

    index = load_phishtank_index(path)

    assert index == frozenset()


def test_urls_are_normalized(tmp_path):
    df = _make_df(n=1)
    df["url"] = ["HTTP://PHISH.COM/Login#frag"]
    path = tmp_path / "phishtank.csv"
    df.to_csv(path, index=False)

    index = load_phishtank_index(path)

    assert normalize_url("HTTP://PHISH.COM/Login#frag") in index
    assert "http://phish.com/Login" in index


class TestLoadPhishtankHostnameIndex:
    """Coarser hostname-only index for subdomain-per-tenant platforms."""

    def test_matching_platform_host_is_included(self, tmp_path):
        df = _make_df(n=1)
        df["url"] = ["https://attacker-site.wixstudio.com/en-us"]
        path = tmp_path / "phishtank.csv"
        df.to_csv(path, index=False)

        index = load_phishtank_hostname_index(path, frozenset({"wixstudio.com"}))

        assert index == frozenset({"attacker-site.wixstudio.com"})

    def test_non_matching_platform_host_is_excluded(self, tmp_path):
        """A hostname not ending in a configured platform never gets a
        hostname-level entry -- exact-URL matching remains the only path."""
        df = _make_df(n=1)
        df["url"] = ["http://phish0.evil.com/login"]
        path = tmp_path / "phishtank.csv"
        df.to_csv(path, index=False)

        index = load_phishtank_hostname_index(path, frozenset({"wixstudio.com"}))

        assert index == frozenset()

    def test_empty_platform_set_returns_empty_index(self, tmp_path):
        df = _make_df(n=3)
        path = tmp_path / "phishtank.csv"
        df.to_csv(path, index=False)

        index = load_phishtank_hostname_index(path, frozenset())

        assert index == frozenset()

    def test_bare_apex_platform_domain_matches_itself(self, tmp_path):
        df = _make_df(n=1)
        df["url"] = ["https://github.io/some-path"]
        path = tmp_path / "phishtank.csv"
        df.to_csv(path, index=False)

        index = load_phishtank_hostname_index(path, frozenset({"github.io"}))

        assert index == frozenset({"github.io"})

    def test_hostnames_are_lowercased(self, tmp_path):
        df = _make_df(n=1)
        df["url"] = ["https://Attacker-Site.WixStudio.com/en-us"]
        path = tmp_path / "phishtank.csv"
        df.to_csv(path, index=False)

        index = load_phishtank_hostname_index(path, frozenset({"wixstudio.com"}))

        assert index == frozenset({"attacker-site.wixstudio.com"})

    def test_respects_verified_and_online_filters(self, tmp_path):
        df = pd.concat(
            [
                _make_df(n=1, verified="yes", online="yes"),
                _make_df(n=1, verified="no", online="yes"),
                _make_df(n=1, verified="yes", online="no"),
            ]
        )
        df["url"] = [
            "https://good.wixstudio.com/a",
            "https://unverified.wixstudio.com/b",
            "https://offline.wixstudio.com/c",
        ]
        path = tmp_path / "phishtank.csv"
        df.to_csv(path, index=False)

        index = load_phishtank_hostname_index(path, frozenset({"wixstudio.com"}))

        assert index == frozenset({"good.wixstudio.com"})

    def test_missing_file_returns_empty_frozenset(self, tmp_path):
        index = load_phishtank_hostname_index(
            tmp_path / "does_not_exist.csv", frozenset({"wixstudio.com"})
        )
        assert index == frozenset()
