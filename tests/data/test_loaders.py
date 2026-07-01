# tests/data/test_loaders.py
# Unit tests for src/data/loaders.py — uses inline fixtures, no real dataset files.

from __future__ import annotations

import tempfile
from pathlib import Path

import pandas as pd
import pytest

from src.data.loaders import (
    LABEL_LEGIT,
    LABEL_PHISHING,
    DataValidationError,
    load_kaggle,
    load_phishtank,
    load_tranco,
    load_uci,
    normalize_url,
    normalise_labels,
)

# ---------------------------------------------------------------------------
# Fixtures — minimal inline DataFrames, no real files
# ---------------------------------------------------------------------------

# All 31 UCI columns (30 features + Result)
_UCI_FEATURE_COLS = [
    "having_IP_Address", "URL_Length", "Shortining_Service", "having_At_Symbol",
    "double_slash_redirecting", "Prefix_Suffix", "having_Sub_Domain", "SSLfinal_State",
    "Domain_registeration_length", "Favicon", "port", "HTTPS_token", "Request_URL",
    "URL_of_Anchor", "Links_in_tags", "SFH", "Submitting_to_email", "Abnormal_URL",
    "Redirect", "on_mouseover", "RightClick", "popUpWidnow", "Iframe", "age_of_domain",
    "DNSRecord", "web_traffic", "Page_Rank", "Google_Index", "Links_pointing_to_page",
    "Statistical_report",
]


def _make_uci_df(n: int = 11_055, labels: list[int] | None = None) -> pd.DataFrame:
    """Build a minimal UCI-schema DataFrame for testing."""
    if labels is None:
        # Distribute -1 (phishing), 0 (suspicious), 1 (legit)
        labels = [-1] * (n // 2) + [0] * (n // 10) + [1] * (n - n // 2 - n // 10)
    data = {col: [1] * len(labels) for col in _UCI_FEATURE_COLS}
    data["Result"] = labels
    return pd.DataFrame(data)


def _write_csv(df: pd.DataFrame) -> Path:
    """Write df to a temp CSV and return its path."""
    tmp = tempfile.NamedTemporaryFile(suffix=".csv", delete=False)
    df.to_csv(tmp.name, index=False)
    return Path(tmp.name)


# ---------------------------------------------------------------------------
# load_uci — happy path
# ---------------------------------------------------------------------------


class TestLoadUci:
    def test_happy_path_returns_dataframe(self):
        df = _make_uci_df()
        path = _write_csv(df)
        result = load_uci(path)
        assert isinstance(result, pd.DataFrame)
        assert len(result) == 11_055
        assert "Result" in result.columns

    def test_returns_all_31_columns(self):
        df = _make_uci_df()
        path = _write_csv(df)
        result = load_uci(path)
        assert set(_UCI_FEATURE_COLS + ["Result"]).issubset(set(result.columns))

    def test_missing_column_raises(self):
        df = _make_uci_df()
        df = df.drop(columns=["having_IP_Address", "Iframe"])
        path = _write_csv(df)
        with pytest.raises(DataValidationError, match="missing required columns"):
            load_uci(path)

    def test_wrong_row_count_raises(self):
        # Only 10 rows — far outside tolerance
        df = _make_uci_df(n=10, labels=[-1] * 5 + [1] * 5)
        path = _write_csv(df)
        with pytest.raises(DataValidationError, match="rows"):
            load_uci(path)

    def test_row_count_within_tolerance_passes(self):
        # 11,055 ± 50 should pass
        df = _make_uci_df(n=11_005)
        path = _write_csv(df)
        result = load_uci(path)
        assert len(result) == 11_005

    def test_missing_file_raises_file_not_found(self):
        with pytest.raises(FileNotFoundError):
            load_uci("/nonexistent/path/uci.csv")


# ---------------------------------------------------------------------------
# load_kaggle — happy path
# ---------------------------------------------------------------------------


def _make_kaggle_df(n: int = 11_430, label_col: str = "status") -> pd.DataFrame:
    """Build a minimal Kaggle-schema DataFrame."""
    half = n // 2
    labels = ["phishing"] * half + ["legitimate"] * (n - half)
    return pd.DataFrame({
        "ip": [1] * n,
        "nb_subdomains": [1] * n,
        "shortening_service": [-1] * n,
        "iframe": [-1] * n,
        label_col: labels,
    })


class TestLoadKaggle:
    def test_happy_path_returns_dataframe(self):
        df = _make_kaggle_df()
        path = _write_csv(df)
        result = load_kaggle(path, label_col="status")
        assert isinstance(result, pd.DataFrame)
        assert len(result) == 11_430

    def test_missing_label_column_raises(self):
        df = _make_kaggle_df()
        df = df.rename(columns={"status": "wrong_col"})
        path = _write_csv(df)
        with pytest.raises(DataValidationError, match="label column"):
            load_kaggle(path, label_col="status")

    def test_too_few_rows_raises(self):
        df = _make_kaggle_df(n=100, label_col="status")
        path = _write_csv(df)
        with pytest.raises(DataValidationError, match="rows"):
            load_kaggle(path, label_col="status")

    def test_missing_file_raises_file_not_found(self):
        with pytest.raises(FileNotFoundError):
            load_kaggle("/nonexistent/path/kaggle.csv")


# ---------------------------------------------------------------------------
# normalise_labels — UCI
# ---------------------------------------------------------------------------


class TestNormaliseLabelsUci:
    def test_phishing_maps_to_1(self):
        df = pd.DataFrame({"Result": [-1, -1, 1], "feature_a": [0, 0, 0]})
        result = normalise_labels(df, "uci")
        assert all(result.loc[result.index[:2], "label"] == LABEL_PHISHING)

    def test_legit_maps_to_0(self):
        df = pd.DataFrame({"Result": [1, 1], "feature_a": [0, 0]})
        result = normalise_labels(df, "uci")
        assert all(result["label"] == LABEL_LEGIT)

    def test_suspicious_merge_policy_maps_to_phishing(self):
        df = pd.DataFrame({"Result": [0, 0, 0], "feature_a": [0, 0, 0]})
        result = normalise_labels(df, "uci", suspicious_policy="merge_phishing")
        assert all(result["label"] == LABEL_PHISHING)

    def test_suspicious_drop_policy_removes_rows(self):
        df = pd.DataFrame({"Result": [-1, 0, 1, 0, -1], "feature_a": [0] * 5})
        result = normalise_labels(df, "uci", suspicious_policy="drop")
        assert len(result) == 3
        assert set(result["label"].unique()).issubset({LABEL_PHISHING, LABEL_LEGIT})

    def test_original_label_column_dropped(self):
        df = pd.DataFrame({"Result": [-1, 1], "feature_a": [0, 0]})
        result = normalise_labels(df, "uci")
        assert "Result" not in result.columns
        assert "label" in result.columns

    def test_no_unexpected_label_values(self):
        df = _make_uci_df(n=100)
        result = normalise_labels(df, "uci", suspicious_policy="merge_phishing")
        assert set(result["label"].unique()).issubset({LABEL_PHISHING, LABEL_LEGIT})

    def test_invalid_suspicious_policy_raises(self):
        df = pd.DataFrame({"Result": [-1], "feature_a": [0]})
        with pytest.raises(ValueError, match="suspicious_policy"):
            normalise_labels(df, "uci", suspicious_policy="third_class")  # type: ignore[arg-type]


# ---------------------------------------------------------------------------
# normalise_labels — Kaggle
# ---------------------------------------------------------------------------


class TestNormaliseLabelsKaggle:
    def test_phishing_string_maps_to_1(self):
        df = pd.DataFrame({"status": ["phishing", "phishing"], "feat": [0, 0]})
        result = normalise_labels(df, "kaggle")
        assert all(result["label"] == LABEL_PHISHING)

    def test_legit_string_maps_to_0(self):
        df = pd.DataFrame({"status": ["legitimate", "legitimate"], "feat": [0, 0]})
        result = normalise_labels(df, "kaggle")
        assert all(result["label"] == LABEL_LEGIT)

    def test_case_insensitive_matching(self):
        df = pd.DataFrame({"status": ["Phishing", "LEGITIMATE"], "feat": [0, 0]})
        result = normalise_labels(df, "kaggle")
        assert result["label"].tolist() == [LABEL_PHISHING, LABEL_LEGIT]

    def test_whitespace_stripped_in_labels(self):
        df = pd.DataFrame({"status": ["  phishing  ", " legitimate "], "feat": [0, 0]})
        result = normalise_labels(df, "kaggle")
        assert result["label"].tolist() == [LABEL_PHISHING, LABEL_LEGIT]

    def test_integer_labels_supported(self):
        df = pd.DataFrame({"status": [1, 0, 1], "feat": [0, 0, 0]})
        result = normalise_labels(df, "kaggle")
        assert result["label"].tolist() == [LABEL_PHISHING, LABEL_LEGIT, LABEL_PHISHING]

    def test_original_label_column_dropped(self):
        df = pd.DataFrame({"status": ["phishing"], "feat": [0]})
        result = normalise_labels(df, "kaggle")
        assert "status" not in result.columns
        assert "label" in result.columns

    def test_custom_label_column_name(self):
        df = pd.DataFrame({"target": ["phishing", "legitimate"], "feat": [0, 0]})
        result = normalise_labels(df, "kaggle", kaggle_label_col="target")
        assert result["label"].tolist() == [LABEL_PHISHING, LABEL_LEGIT]


# ---------------------------------------------------------------------------
# normalize_url
# ---------------------------------------------------------------------------


class TestNormalizeUrl:
    def test_idempotent(self):
        url = "HTTP://WWW.Example.COM/Path?q=1#frag"
        once = normalize_url(url)
        assert normalize_url(once) == once

    def test_lowercases_scheme(self):
        assert normalize_url("HTTP://example.com/").startswith("http://")

    def test_lowercases_host(self):
        result = normalize_url("https://EXAMPLE.COM/path")
        assert "example.com" in result
        assert "EXAMPLE" not in result

    def test_strips_fragment(self):
        result = normalize_url("https://example.com/path#section")
        assert "#" not in result
        assert "section" not in result

    def test_preserves_path_and_query(self):
        result = normalize_url("https://example.com/path?foo=bar")
        assert "/path" in result
        assert "foo=bar" in result

    def test_strip_www_removes_prefix(self):
        result = normalize_url("https://www.example.com/", strip_www=True)
        assert "www." not in result
        assert "example.com" in result

    def test_strip_www_false_preserves_www(self):
        result = normalize_url("https://www.example.com/", strip_www=False)
        assert "www.example.com" in result

    def test_no_scheme_defaults_to_https(self):
        result = normalize_url("example.com/path")
        assert result.startswith("https://")
        assert "example.com" in result

    def test_whitespace_stripped(self):
        result = normalize_url("  https://example.com/  ")
        assert result == normalize_url("https://example.com/")


# ---------------------------------------------------------------------------
# Helpers — PhishTank + Tranco inline fixtures
# ---------------------------------------------------------------------------


def _make_phishtank_df(
    n: int = 10,
    *,
    all_verified: bool = True,
    include_unverified: int = 0,
) -> pd.DataFrame:
    """Minimal PhishTank-schema DataFrame for testing."""
    verified_vals = ["yes"] * n
    urls = [f"http://phish{i}.evil.com/login/steal.html" for i in range(n)]
    times = ["2026-05-01 12:00:00 UTC"] * n

    if include_unverified:
        verified_vals += ["no"] * include_unverified
        urls += [f"http://unverified{i}.example.com/" for i in range(include_unverified)]
        times += ["2026-04-01 12:00:00 UTC"] * include_unverified

    return pd.DataFrame({
        "phish_id": range(n + include_unverified),
        "url": urls,
        "phish_detail_url": ["https://phishtank.org/phish_detail.php?phish_id=1"] * (n + include_unverified),
        "submission_time": times,
        "verified": verified_vals,
        "verification_time": times,
        "online": ["yes"] * (n + include_unverified),
        "target": ["PayPal"] * (n + include_unverified),
    })


def _make_tranco_df(n_total: int = 1_500) -> pd.DataFrame:
    """Minimal Tranco-schema DataFrame spanning multiple rank strata."""
    ranks = list(range(1, n_total + 1))
    domains = [f"domain{r}.com" for r in ranks]
    return pd.DataFrame({"rank": ranks, "domain": domains})


# ---------------------------------------------------------------------------
# load_phishtank
# ---------------------------------------------------------------------------


class TestLoadPhishTank:
    def test_happy_path_returns_dataframe(self, tmp_path):
        df = _make_phishtank_df(n=20)
        path = tmp_path / "phishtank.csv"
        df.to_csv(path, index=False)
        result = load_phishtank(path)
        assert isinstance(result, pd.DataFrame)
        assert len(result) == 20

    def test_returns_url_and_label_columns(self, tmp_path):
        df = _make_phishtank_df(n=5)
        path = tmp_path / "phishtank.csv"
        df.to_csv(path, index=False)
        result = load_phishtank(path)
        assert "url" in result.columns
        assert "label" in result.columns
        assert "submission_time" in result.columns

    def test_all_labels_are_phishing(self, tmp_path):
        df = _make_phishtank_df(n=10)
        path = tmp_path / "phishtank.csv"
        df.to_csv(path, index=False)
        result = load_phishtank(path)
        assert (result["label"] == LABEL_PHISHING).all()
        assert (result["label"] != LABEL_LEGIT).all()

    def test_unverified_rows_are_filtered(self, tmp_path):
        df = _make_phishtank_df(n=8, include_unverified=4)
        path = tmp_path / "phishtank.csv"
        df.to_csv(path, index=False)
        result = load_phishtank(path)
        # Only the 8 verified rows should remain
        assert len(result) == 8

    def test_snapshot_date_stored_in_attrs(self, tmp_path):
        df = _make_phishtank_df(n=5)
        path = tmp_path / "phishtank.csv"
        df.to_csv(path, index=False)
        result = load_phishtank(path)
        assert "snapshot_date" in result.attrs
        assert result.attrs["snapshot_date"] != "unknown"

    def test_source_attr_is_phishtank(self, tmp_path):
        df = _make_phishtank_df(n=3)
        path = tmp_path / "phishtank.csv"
        df.to_csv(path, index=False)
        result = load_phishtank(path)
        assert result.attrs["source"] == "phishtank"

    def test_missing_required_column_raises(self, tmp_path):
        df = _make_phishtank_df(n=5).drop(columns=["verified"])
        path = tmp_path / "phishtank_bad.csv"
        df.to_csv(path, index=False)
        with pytest.raises(DataValidationError, match="missing required columns"):
            load_phishtank(path)

    def test_all_unverified_raises(self, tmp_path):
        df = _make_phishtank_df(n=0, include_unverified=5)
        path = tmp_path / "phishtank_unverified.csv"
        df.to_csv(path, index=False)
        with pytest.raises(DataValidationError, match="no verified phishing URLs"):
            load_phishtank(path)

    def test_missing_file_raises(self):
        with pytest.raises(FileNotFoundError):
            load_phishtank("/nonexistent/phishtank.csv")

    def test_urls_are_normalised(self, tmp_path):
        """URLs should be lowercased and fragment-stripped after load."""
        df = _make_phishtank_df(n=3)
        df["url"] = ["HTTP://PHISH.COM/LOGIN#frag", "https://Evil.org/", "http://test.net/"]
        path = tmp_path / "phishtank_case.csv"
        df.to_csv(path, index=False)
        result = load_phishtank(path)
        assert all(u == u.lower() or "#" not in u for u in result["url"])
        assert not any("#" in u for u in result["url"])


# ---------------------------------------------------------------------------
# load_tranco
# ---------------------------------------------------------------------------


class TestLoadTranco:
    def test_happy_path_top_n(self, tmp_path):
        df = _make_tranco_df(n_total=200)
        path = tmp_path / "tranco.csv"
        df.to_csv(path, index=False)
        result = load_tranco(path, n=50, strategy="top-n")
        assert isinstance(result, pd.DataFrame)
        assert len(result) == 50

    def test_happy_path_rank_stratified(self, tmp_path):
        df = _make_tranco_df(n_total=1_500)
        path = tmp_path / "tranco.csv"
        df.to_csv(path, index=False)
        result = load_tranco(path, n=100, strategy="rank-stratified")
        assert len(result) == 100

    def test_all_labels_are_legit(self, tmp_path):
        df = _make_tranco_df(n_total=200)
        path = tmp_path / "tranco.csv"
        df.to_csv(path, index=False)
        result = load_tranco(path, n=50, strategy="top-n")
        assert (result["label"] == LABEL_LEGIT).all()
        assert (result["label"] != LABEL_PHISHING).all()

    def test_top_n_honours_n_parameter(self, tmp_path):
        df = _make_tranco_df(n_total=200)
        path = tmp_path / "tranco.csv"
        df.to_csv(path, index=False)
        for n in [10, 50, 100]:
            result = load_tranco(path, n=n, strategy="top-n")
            assert len(result) == n

    def test_rank_stratified_honours_n_parameter(self, tmp_path):
        df = _make_tranco_df(n_total=1_500)
        path = tmp_path / "tranco.csv"
        df.to_csv(path, index=False)
        result = load_tranco(path, n=80, strategy="rank-stratified")
        assert len(result) == 80

    def test_top_n_selects_lowest_ranks(self, tmp_path):
        df = _make_tranco_df(n_total=200)
        path = tmp_path / "tranco.csv"
        df.to_csv(path, index=False)
        # top-n should give ranks 1..n (most popular)
        # We can't directly check ranks since they're not in result,
        # but we can check the URLs are derived from the top domains.
        result = load_tranco(path, n=10, strategy="top-n")
        # domain1.com through domain10.com should be present
        top_domains = {f"domain{i}.com" for i in range(1, 11)}
        result_domains = {u.replace("https://", "").rstrip("/") for u in result["url"]}
        assert result_domains == top_domains

    def test_urls_are_constructed_with_https(self, tmp_path):
        df = _make_tranco_df(n_total=50)
        path = tmp_path / "tranco.csv"
        df.to_csv(path, index=False)
        result = load_tranco(path, n=10, strategy="top-n")
        assert all(u.startswith("https://") for u in result["url"])

    def test_list_id_stored_in_attrs(self, tmp_path):
        df = _make_tranco_df(n_total=50)
        path = tmp_path / "tranco.csv"
        df.to_csv(path, index=False)
        result = load_tranco(path, n=10, strategy="top-n", list_id="K93XZ")
        assert result.attrs["list_id"] == "K93XZ"

    def test_source_attr_is_tranco(self, tmp_path):
        df = _make_tranco_df(n_total=50)
        path = tmp_path / "tranco.csv"
        df.to_csv(path, index=False)
        result = load_tranco(path, n=5, strategy="top-n")
        assert result.attrs["source"] == "tranco"

    def test_strategy_stored_in_attrs(self, tmp_path):
        df = _make_tranco_df(n_total=200)
        path = tmp_path / "tranco.csv"
        df.to_csv(path, index=False)
        result = load_tranco(path, n=10, strategy="rank-stratified")
        assert result.attrs["strategy"] == "rank-stratified"

    def test_headerless_csv_supported(self, tmp_path):
        """Tranco CSVs often ship without a header row."""
        path = tmp_path / "tranco_no_header.csv"
        path.write_text("\n".join(f"{r},domain{r}.com" for r in range(1, 51)))
        result = load_tranco(path, n=20, strategy="top-n")
        assert len(result) == 20
        assert (result["label"] == LABEL_LEGIT).all()

    def test_n_exceeds_list_size_raises(self, tmp_path):
        df = _make_tranco_df(n_total=10)
        path = tmp_path / "tranco_small.csv"
        df.to_csv(path, index=False)
        with pytest.raises(DataValidationError, match="only contains"):
            load_tranco(path, n=100, strategy="top-n")

    def test_unknown_strategy_raises(self, tmp_path):
        df = _make_tranco_df(n_total=50)
        path = tmp_path / "tranco.csv"
        df.to_csv(path, index=False)
        with pytest.raises(ValueError, match="Unknown strategy"):
            load_tranco(path, n=10, strategy="random")  # type: ignore[arg-type]

    def test_missing_file_raises(self):
        with pytest.raises(FileNotFoundError):
            load_tranco("/nonexistent/tranco.csv", n=10)

    def test_missing_required_column_raises(self, tmp_path):
        df = pd.DataFrame({"rank": [1, 2, 3]})  # missing "domain"
        path = tmp_path / "tranco_bad.csv"
        df.to_csv(path, index=False)
        with pytest.raises(DataValidationError, match="missing required columns"):
            load_tranco(path, n=2, strategy="top-n")
