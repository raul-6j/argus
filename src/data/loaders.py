# src/data/loaders.py
# Loads, validates, and normalises datasets for ARGUS.
# Sources: UCI (pre-engineered), Kaggle (pre-engineered), PhishTank (raw URLs),
# Tranco (raw domains for legitimate class).
# All downstream code reads LABEL_PHISHING / LABEL_LEGIT — never raw -1/0/1.

from __future__ import annotations

import logging
from pathlib import Path
from typing import Literal
from urllib.parse import urlparse, urlunparse

import pandas as pd

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Public label constants — use these everywhere; never raw integers past here
# ---------------------------------------------------------------------------
LABEL_PHISHING: int = 1
LABEL_LEGIT: int = 0

SuspiciousPolicy = Literal["merge_phishing", "drop"]

# ---------------------------------------------------------------------------
# Exceptions
# ---------------------------------------------------------------------------


class DataValidationError(ValueError):
    """Raised when a loaded dataset fails schema or row-count validation."""


# ---------------------------------------------------------------------------
# UCI loader
# ---------------------------------------------------------------------------

# Expected UCI columns (30 features + label) — lowercase as returned by ucimlrepo.
# Note: original UCI column names used mixed case (e.g. "having_IP_Address") but
# ucimlrepo normalises them to lowercase at download time.
_UCI_REQUIRED_COLS: set[str] = {
    "having_ip_address", "url_length", "shortining_service", "having_at_symbol",
    "double_slash_redirecting", "prefix_suffix", "having_sub_domain", "sslfinal_state",
    "domain_registration_length", "favicon", "port", "https_token", "request_url",
    "url_of_anchor", "links_in_tags", "sfh", "submitting_to_email", "abnormal_url",
    "redirect", "on_mouseover", "rightclick", "popupwindow", "iframe", "age_of_domain",
    "dnsrecord", "web_traffic", "page_rank", "google_index", "links_pointing_to_page",
    "statistical_report", "result",
}
_UCI_EXPECTED_ROWS: int = 11_055
_UCI_ROW_TOLERANCE: int = 50  # allow ±50 rows across dataset versions


def load_uci(path: str | Path) -> pd.DataFrame:
    """Load and validate the UCI Phishing Websites dataset from a CSV file.

    Args:
        path: Path to the UCI CSV file (produced by the download step in
            scripts/data_prep.py). The file must contain the original 30
            feature columns plus the ``Result`` label column.

    Returns:
        Raw DataFrame with original UCI column names and dtypes preserved.
        No label normalisation is applied here; call :func:`normalise_labels`
        next.

    Raises:
        FileNotFoundError: If ``path`` does not exist.
        DataValidationError: If required columns are missing or row count is
            outside the expected range.
    """
    path = Path(path)
    if not path.exists():
        raise FileNotFoundError(
            f"UCI CSV not found at {path}. "
            "Run scripts/data_prep.py --download to fetch it first."
        )

    logger.info("Loading UCI dataset from %s", path)
    df = pd.read_csv(path)

    # Strip any leading/trailing whitespace from column names
    df.columns = [c.strip() for c in df.columns]

    # Schema check
    missing_cols = _UCI_REQUIRED_COLS - set(df.columns)
    if missing_cols:
        raise DataValidationError(
            f"UCI dataset is missing required columns: {sorted(missing_cols)}. "
            f"Found: {sorted(df.columns)}"
        )

    # Row-count sanity check
    n_rows = len(df)
    if abs(n_rows - _UCI_EXPECTED_ROWS) > _UCI_ROW_TOLERANCE:
        raise DataValidationError(
            f"UCI dataset has {n_rows} rows; expected ~{_UCI_EXPECTED_ROWS} "
            f"(tolerance ±{_UCI_ROW_TOLERANCE}). Check that the correct file was downloaded."
        )

    logger.info("UCI dataset loaded: %d rows, %d columns", n_rows, df.shape[1])
    return df


# ---------------------------------------------------------------------------
# Kaggle loader
# ---------------------------------------------------------------------------

# Minimum required columns from the Kaggle dataset.
# Only the label column is strictly required; feature columns are handled
# by the rename + alignment step in preprocessor.py.
_KAGGLE_MIN_ROWS: int = 5_000


def load_kaggle(path: str | Path, label_col: str = "status") -> pd.DataFrame:
    """Load and validate the Kaggle phishing dataset from a CSV file.

    Args:
        path: Path to the Kaggle CSV file.
        label_col: Name of the label column in the Kaggle CSV.
            Defaults to ``"status"`` (shashwatwork dataset).

    Returns:
        Raw DataFrame with original Kaggle column names preserved.
        No label normalisation applied here.

    Raises:
        FileNotFoundError: If ``path`` does not exist.
        DataValidationError: If the label column is missing or row count is
            suspiciously low.
    """
    path = Path(path)
    if not path.exists():
        raise FileNotFoundError(
            f"Kaggle CSV not found at {path}. "
            "Run scripts/data_prep.py --download to fetch it first."
        )

    logger.info("Loading Kaggle dataset from %s", path)
    df = pd.read_csv(path)
    df.columns = [c.strip() for c in df.columns]

    if label_col not in df.columns:
        raise DataValidationError(
            f"Kaggle dataset is missing label column '{label_col}'. "
            f"Found columns: {sorted(df.columns)}"
        )

    n_rows = len(df)
    if n_rows < _KAGGLE_MIN_ROWS:
        raise DataValidationError(
            f"Kaggle dataset has only {n_rows} rows (minimum expected: {_KAGGLE_MIN_ROWS}). "
            "Check that the correct file was downloaded."
        )

    logger.info("Kaggle dataset loaded: %d rows, %d columns", n_rows, df.shape[1])
    return df


# ---------------------------------------------------------------------------
# Label normalisation
# ---------------------------------------------------------------------------


def normalise_labels(
    df: pd.DataFrame,
    source: Literal["uci", "kaggle"],
    *,
    suspicious_policy: SuspiciousPolicy = "merge_phishing",
    uci_label_col: str = "result",
    kaggle_label_col: str = "status",
    kaggle_phishing_raw: str = "phishing",
    kaggle_legit_raw: str = "legitimate",
) -> pd.DataFrame:
    """Normalise raw dataset labels to LABEL_PHISHING (1) / LABEL_LEGIT (0).

    UCI encoding:  -1 = phishing,  0 = suspicious,  1 = legitimate.
    Kaggle encoding: string values (e.g. 'phishing' / 'legitimate').

    The suspicious class policy is read from the ``suspicious_policy``
    argument (set via ``data_config.yaml`` — never hardcoded):

    - ``"merge_phishing"``: UCI label 0 → LABEL_PHISHING (conservative;
      see DECISIONS.md DEC-007).
    - ``"drop"``: Rows with UCI label 0 are removed.

    Args:
        df: Raw DataFrame from :func:`load_uci` or :func:`load_kaggle`.
        source: Which dataset this DataFrame came from.
        suspicious_policy: How to handle UCI label=0. See above.
        uci_label_col: Label column name in the UCI DataFrame.
        kaggle_label_col: Label column name in the Kaggle DataFrame.
        kaggle_phishing_raw: Raw string value representing phishing in Kaggle.
        kaggle_legit_raw: Raw string value representing legitimate in Kaggle.

    Returns:
        DataFrame with a new integer ``label`` column (values: 0 or 1) and
        the original raw label column dropped.

    Raises:
        DataValidationError: If unexpected label values are encountered after
            normalisation.
        ValueError: If ``suspicious_policy`` is not a supported value.
    """
    df = df.copy()

    if source == "uci":
        _normalise_uci_labels(
            df,
            label_col=uci_label_col,
            suspicious_policy=suspicious_policy,
        )
    elif source == "kaggle":
        _normalise_kaggle_labels(
            df,
            label_col=kaggle_label_col,
            phishing_raw=kaggle_phishing_raw,
            legit_raw=kaggle_legit_raw,
        )
    else:
        raise ValueError(f"Unknown source '{source}'. Expected 'uci' or 'kaggle'.")

    # Final sanity check — only 0/1 should remain
    unexpected = set(df["label"].unique()) - {LABEL_PHISHING, LABEL_LEGIT}
    if unexpected:
        raise DataValidationError(
            f"Unexpected label values after normalisation: {unexpected}. "
            "Check the label mapping logic and suspicious_policy setting."
        )

    n_phishing = int((df["label"] == LABEL_PHISHING).sum())
    n_legit = int((df["label"] == LABEL_LEGIT).sum())
    logger.info(
        "%s labels normalised: %d phishing, %d legitimate (ratio %.2f:1)",
        source.upper(),
        n_phishing,
        n_legit,
        n_phishing / max(n_legit, 1),
    )
    return df


def _normalise_uci_labels(
    df: pd.DataFrame,
    label_col: str,
    suspicious_policy: SuspiciousPolicy,
) -> None:
    """Mutates df in-place to add a normalised 'label' column (UCI source).

    Args:
        df: DataFrame to mutate.
        label_col: Name of the raw UCI label column.
        suspicious_policy: Policy for UCI label=0 rows.

    Raises:
        ValueError: If ``suspicious_policy`` is unsupported.
    """
    if suspicious_policy not in ("merge_phishing", "drop"):
        raise ValueError(
            f"Unsupported suspicious_policy '{suspicious_policy}'. "
            "Use 'merge_phishing' or 'drop'."
        )

    n_suspicious = int((df[label_col] == 0).sum())
    logger.info(
        "UCI suspicious class (label=0): %d rows — applying policy '%s'",
        n_suspicious,
        suspicious_policy,
    )

    if suspicious_policy == "drop":
        df.drop(df[df[label_col] == 0].index, inplace=True)
        df.reset_index(drop=True, inplace=True)
        logger.info("Dropped %d suspicious-class rows.", n_suspicious)

    # Map: -1 (phishing) → 1, 0 (suspicious, if kept) → 1, 1 (legit) → 0
    mapping = {-1: LABEL_PHISHING, 0: LABEL_PHISHING, 1: LABEL_LEGIT}
    df["label"] = df[label_col].map(mapping)
    df.drop(columns=[label_col], inplace=True)


def _normalise_kaggle_labels(
    df: pd.DataFrame,
    label_col: str,
    phishing_raw: str,
    legit_raw: str,
) -> None:
    """Mutates df in-place to add a normalised 'label' column (Kaggle source).

    Handles both string labels (e.g. 'phishing'/'legitimate') and
    integer labels (e.g. 1/0) defensively.

    Args:
        df: DataFrame to mutate.
        label_col: Name of the raw Kaggle label column.
        phishing_raw: Raw value that means phishing.
        legit_raw: Raw value that means legitimate.
    """
    raw = df[label_col]

    # Handle integer-encoded Kaggle datasets (1=phishing, 0=legit)
    if pd.api.types.is_integer_dtype(raw):
        logger.info("Kaggle label column is integer-typed — mapping 1→1, 0→0 directly.")
        df["label"] = raw.map({1: LABEL_PHISHING, 0: LABEL_LEGIT})
    else:
        # String labels — strip whitespace and lowercase for robustness
        raw_clean = raw.str.strip().str.lower()
        phishing_key = phishing_raw.strip().lower()
        legit_key = legit_raw.strip().lower()
        df["label"] = raw_clean.map(
            {phishing_key: LABEL_PHISHING, legit_key: LABEL_LEGIT}
        )

    df.drop(columns=[label_col], inplace=True)


# ---------------------------------------------------------------------------
# URL normalisation (used identically for PhishTank and Tranco so that
# deduplication across sources is meaningful)
# ---------------------------------------------------------------------------


def normalize_url(url: str, *, strip_www: bool = False) -> str:
    """Normalise a URL for consistent cross-source deduplication.

    Lowercases the scheme and hostname, strips the URL fragment (``#...``),
    and optionally removes a leading ``www.`` subdomain.  Safe to call
    multiple times — idempotent by design.

    If the input has no scheme, ``https://`` is prepended so that
    ``urlparse`` correctly identifies the netloc vs. the path component.

    Args:
        url: Raw URL string. May or may not include a scheme.
        strip_www: If ``True``, remove the leading ``www.`` from the
            hostname before returning.

    Returns:
        Normalised URL string with lowercase scheme + host, no fragment,
        and the original path/query preserved verbatim.

    Examples:
        >>> normalize_url("HTTP://WWW.Example.COM/Path?q=1#frag")
        'http://www.example.com/Path?q=1'
        >>> normalize_url("example.com/path")
        'https://example.com/path'
        >>> normalize_url("https://www.example.com/", strip_www=True)
        'https://example.com/'
    """
    url = url.strip()

    # Prepend a scheme when absent so urlparse can split netloc from path.
    # Check case-insensitively because callers may pass "HTTP://" or "FTP://".
    url_lower = url.lower()
    if not url_lower.startswith(("http://", "https://", "ftp://", "ftps://")):
        url = "https://" + url

    parsed = urlparse(url)
    scheme = parsed.scheme.lower()
    netloc = parsed.netloc.lower()

    if strip_www and netloc.startswith("www."):
        netloc = netloc[4:]

    # Reconstruct without the fragment component.
    return urlunparse((scheme, netloc, parsed.path, parsed.params, parsed.query, ""))


# ---------------------------------------------------------------------------
# PhishTank loader
# ---------------------------------------------------------------------------

# Columns that must be present in any PhishTank CSV export.
# Full schema: phish_id, url, phish_detail_url, submission_time,
#              verified, verification_time, online, target
_PHISHTANK_REQUIRED_COLS: frozenset[str] = frozenset(
    {"url", "verified", "submission_time"}
)


def load_phishtank(path: str | Path) -> pd.DataFrame:
    """Load and validate a pinned PhishTank snapshot CSV.

    Reads the PhishTank ``online-valid.csv`` export (or a locally renamed
    copy such as ``phishtank_YYYYMMDD.csv``), filters to verified phishing
    entries, normalises all URLs with :func:`normalize_url`, and assigns
    ``label = LABEL_PHISHING`` to every row.

    The snapshot date (maximum ``submission_time``) is stored in
    ``df.attrs["snapshot_date"]`` (ISO-8601 string) so downstream code and
    the thesis methodology can cite the exact corpus version.
    ``submission_time`` is retained as a column to support temporal
    train/test splitting (see Phase 4 strategy plan, point 5).

    Args:
        path: Path to the PhishTank CSV file.  Supports both ``.csv`` and
            ``.csv.bz2`` / ``.bz2`` compressed variants (pandas handles
            compression automatically).

    Returns:
        DataFrame with columns ``["url", "label", "submission_time"]`` where
        all ``label`` values equal :data:`LABEL_PHISHING`.
        ``df.attrs["snapshot_date"]`` contains the latest submission date as
        an ISO-8601 string; ``df.attrs["source"]`` is ``"phishtank"``.

    Raises:
        FileNotFoundError: If ``path`` does not exist.
        DataValidationError: If required columns are absent, or if no
            verified phishing URLs remain after filtering.
    """
    path = Path(path)
    if not path.exists():
        raise FileNotFoundError(
            f"PhishTank snapshot not found at {path}. "
            "Download from https://data.phishtank.com/data/online-valid.csv.bz2 "
            "and rename to phishtank_YYYYMMDD.csv before running the pipeline."
        )

    logger.info("Loading PhishTank snapshot from %s", path)
    df = pd.read_csv(path)  # pandas auto-detects .bz2 compression
    df.columns = [c.strip() for c in df.columns]

    # Schema check
    missing = _PHISHTANK_REQUIRED_COLS - set(df.columns)
    if missing:
        raise DataValidationError(
            f"PhishTank snapshot is missing required columns: {sorted(missing)}. "
            f"Found: {sorted(df.columns)}"
        )

    # Filter to verified entries only
    n_before = len(df)
    df = df[df["verified"].str.strip().str.lower() == "yes"].copy()
    n_dropped = n_before - len(df)
    if n_dropped:
        logger.info(
            "Dropped %d unverified entries from PhishTank snapshot.", n_dropped
        )

    if len(df) == 0:
        raise DataValidationError(
            "PhishTank snapshot contains no verified phishing URLs after filtering. "
            "Check that the file is the 'online-valid' export, not the full database."
        )

    # Normalise URLs so deduplication against Tranco is consistent
    df["url"] = df["url"].apply(normalize_url)

    # Assign label by source (PhishTank = phishing)
    df["label"] = LABEL_PHISHING

    # Record snapshot metadata in DataFrame attrs
    try:
        snapshot_date = (
            pd.to_datetime(df["submission_time"], utc=True, errors="coerce")
            .max()
            .date()
            .isoformat()
        )
    except Exception:  # noqa: BLE001 - malformed timestamps must not crash loading
        snapshot_date = "unknown"

    result = df[["url", "label", "submission_time"]].reset_index(drop=True)
    result.attrs["snapshot_date"] = snapshot_date
    result.attrs["source"] = "phishtank"

    logger.info(
        "PhishTank: %d verified phishing URLs loaded (snapshot_date=%s).",
        len(result),
        snapshot_date,
    )
    return result


# ---------------------------------------------------------------------------
# Tranco loader
# ---------------------------------------------------------------------------

TrancoStrategy = Literal["top-n", "rank-stratified"]

# Columns that must be present in the Tranco CSV.
_TRANCO_REQUIRED_COLS: frozenset[str] = frozenset({"rank", "domain"})

# Log-spaced rank strata for rank-stratified sampling (lower boundary exclusive,
# upper boundary inclusive).  The boundaries are fixed so the thesis can cite
# them exactly, and so the sampling is deterministic and reproducible.
_RANK_STRATA_LOWER_BOUNDS: list[int] = [0, 1_000, 10_000, 100_000, 1_000_000]


def load_tranco(
    path: str | Path,
    n: int,
    strategy: TrancoStrategy = "rank-stratified",
    *,
    list_id: str | None = None,
    strip_www: bool = True,
    random_state: int = 42,
) -> pd.DataFrame:
    """Load, sample, and label domains from a pinned Tranco list.

    Reads a Tranco CSV (with or without a header row), samples ``n`` domains
    according to ``strategy``, constructs full URLs as ``https://<domain>/``
    (matching the structural form of PhishTank entries — see Phase 4 strategy
    plan, point 1), normalises each URL with :func:`normalize_url`, and
    assigns ``label = LABEL_LEGIT`` to every row.

    Sampling strategies:

    * ``"top-n"``: take the ``n`` lowest-rank (most popular) domains.
    * ``"rank-stratified"``: divide the rank range into log-spaced strata
      (boundaries: 0–1K, 1K–10K, 10K–100K, 100K–1M, 1M+) and draw as
      equally as possible from each non-empty stratum.  This avoids the
      trivially-legit bias that results from sampling only the top-1K
      mega-corporations.

    The Tranco list ID (``list_id``) is stored in ``df.attrs["list_id"]``
    for thesis citation.

    Args:
        path: Path to the Tranco CSV file (rank,domain — with or without
            a header row).
        n: Number of domains to sample.
        strategy: Sampling strategy.  One of ``"top-n"`` or
            ``"rank-stratified"``.
        list_id: Tranco list identifier (e.g. ``"K93XZ"`` from
            ``https://tranco-list.eu/list/K93XZ/full``).  Stored in
            ``df.attrs`` for reproducibility.  Pass ``None`` if unknown.
        strip_www: If ``True``, remove ``www.`` prefix from constructed
            URLs before normalisation.  Defaults to ``True`` because Tranco
            domains are registered domains without the ``www.`` prefix.
        random_state: Random seed for sampling reproducibility.  Must match
            ``random_state=42`` in all ARGUS experiments (Iron Law #6).

    Returns:
        DataFrame with columns ``["url", "label"]`` where all ``label``
        values equal :data:`LABEL_LEGIT`.  ``df.attrs`` contains
        ``"source"``, ``"list_id"``, ``"n_sampled"``, and ``"strategy"``.

    Raises:
        FileNotFoundError: If ``path`` does not exist.
        DataValidationError: If required columns are absent, or if ``n``
            exceeds the number of available domains in the list.
        ValueError: If ``strategy`` is not a recognised value.
    """
    path = Path(path)
    if not path.exists():
        raise FileNotFoundError(
            f"Tranco list not found at {path}. "
            "Download from https://tranco-list.eu and record the list ID."
        )

    logger.info(
        "Loading Tranco list from %s (n=%d, strategy=%s, list_id=%s)",
        path,
        n,
        strategy,
        list_id or "unknown",
    )

    # Detect whether the CSV has a header row: the first field of the first
    # line is a digit for headerless files ("1,google.com").
    with open(path) as _f:
        _first_line = _f.readline().strip()

    has_header = not _first_line.split(",")[0].strip().isdigit()

    if has_header:
        df = pd.read_csv(path)
        df.columns = [c.strip() for c in df.columns]
    else:
        df = pd.read_csv(path, header=None, names=["rank", "domain"])

    missing = _TRANCO_REQUIRED_COLS - set(df.columns)
    if missing:
        raise DataValidationError(
            f"Tranco list is missing required columns: {sorted(missing)}. "
            f"Found: {sorted(df.columns)}"
        )

    # Coerce rank to int; drop malformed rows
    df["rank"] = pd.to_numeric(df["rank"], errors="coerce")
    df = df.dropna(subset=["rank", "domain"]).copy()
    df["rank"] = df["rank"].astype(int)

    if n > len(df):
        raise DataValidationError(
            f"Requested n={n} samples but Tranco list only contains {len(df)} "
            "valid entries after cleaning."
        )

    if strategy == "top-n":
        sampled = df.nsmallest(n, "rank").copy()
    elif strategy == "rank-stratified":
        sampled = _stratified_sample(df, n=n, random_state=random_state)
    else:
        raise ValueError(
            f"Unknown strategy '{strategy}'. Expected 'top-n' or 'rank-stratified'."
        )

    # Construct root URLs from bare domains and normalise
    sampled["url"] = sampled["domain"].apply(
        lambda d: normalize_url(f"https://{d}/", strip_www=strip_www)
    )
    sampled["label"] = LABEL_LEGIT

    result = sampled[["url", "label"]].reset_index(drop=True)
    result.attrs["source"] = "tranco"
    result.attrs["list_id"] = list_id or "unknown"
    result.attrs["n_sampled"] = n
    result.attrs["strategy"] = strategy

    logger.info(
        "Tranco: %d legitimate URLs constructed (list_id=%s, strategy=%s).",
        len(result),
        list_id or "unknown",
        strategy,
    )
    return result


def _stratified_sample(
    df: pd.DataFrame, n: int, random_state: int = 42
) -> pd.DataFrame:
    """Sample ``n`` rows from a Tranco DataFrame using log-spaced rank strata.

    Divides the rank range using :data:`_RANK_STRATA_LOWER_BOUNDS` and draws
    as equally as possible from each non-empty stratum.  If the total drawn
    falls short of ``n`` (due to small strata), the shortfall is filled from
    the remaining un-sampled rows chosen randomly.

    Args:
        df: Tranco DataFrame with a ``"rank"`` column (int).
        n: Total number of rows to return.
        random_state: Seed for reproducibility.  Each stratum uses
            ``random_state + stratum_index`` to avoid identical samples
            across strata.

    Returns:
        Sampled DataFrame of length ``n``, with the original ``"rank"`` and
        ``"domain"`` columns preserved.
    """
    max_rank = int(df["rank"].max())

    # Attach a temporary column FIRST so bucket slices inherit it.
    df = df.copy()
    df["_row_id"] = range(len(df))

    # Build strata using fixed lower bounds; add max_rank+1 as the final edge.
    lower_bounds = [b for b in _RANK_STRATA_LOWER_BOUNDS if b <= max_rank]
    upper_bounds = [*lower_bounds[1:], max_rank + 1]

    buckets: list[pd.DataFrame] = [
        df[(df["rank"] > lo) & (df["rank"] <= hi)]
        for lo, hi in zip(lower_bounds, upper_bounds)
        if not df[(df["rank"] > lo) & (df["rank"] <= hi)].empty
    ]

    n_per_bucket = max(1, n // len(buckets))

    parts: list[pd.DataFrame] = []
    sampled_row_ids: set[int] = set()

    for i, bucket in enumerate(buckets):
        k = min(n_per_bucket, len(bucket))
        chunk = bucket.sample(n=k, random_state=random_state + i)
        parts.append(chunk)
        sampled_row_ids.update(chunk["_row_id"].tolist())

    result = pd.concat(parts)

    # Top up to exactly n if some strata were smaller than n_per_bucket.
    if len(result) < n:
        remainder = df[~df["_row_id"].isin(sampled_row_ids)]
        shortfall = n - len(result)
        if not remainder.empty:
            top_up = remainder.sample(
                n=min(shortfall, len(remainder)), random_state=random_state
            )
            result = pd.concat([result, top_up])

    return result.drop(columns=["_row_id"]).head(n).reset_index(drop=True)
