#!/usr/bin/env python
"""Chart stored EvalRun history over time (Phase 3, F10).

Reads every :class:`~src.api.evalruns.models.EvalRun` row from the database
(oldest first) and renders trend charts to ``reports/drift_charts/`` --
the "measured over time" half of the drift harness (``scripts/eval_drift.py``
produces the rows; this script visualizes them). A single run has nothing
to trend, so this is meant to be re-run periodically as more runs
accumulate, not after every single ``eval_drift.py`` invocation.

Usage:
    python scripts/plot_drift.py
    python scripts/plot_drift.py --database-url sqlite:///argus_dev.db --limit 50
"""

from __future__ import annotations

import argparse
import logging
import sys
from pathlib import Path
from typing import Optional

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import matplotlib

matplotlib.use("Agg")  # headless -- no display backend required
import matplotlib.pyplot as plt
import yaml

from src.api.db import create_db_engine, create_session_factory
from src.api.evalruns.models import EvalRun

logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")
logger = logging.getLogger("plot_drift")

_PROJECT_ROOT = Path(__file__).resolve().parents[1]
_DEFAULT_API_CONFIG_PATH = _PROJECT_ROOT / "configs" / "api_config.yaml"
_DEFAULT_OUT_DIR = _PROJECT_ROOT / "reports" / "drift_charts"


def load_runs(database_url: str, limit: Optional[int] = None) -> list[EvalRun]:
    """Load stored runs, oldest first (chronological, for plotting).

    Args:
        database_url: SQLAlchemy URL -- same DB ``eval_drift.py`` writes to.
        limit: If given, only the most recent ``limit`` runs (still
            returned oldest-first).

    Returns:
        A list of :class:`EvalRun` rows -- empty if the table doesn't exist
        yet or has no rows (a fresh deployment that hasn't run
        ``eval_drift.py`` yet), never raises for that case.
    """
    engine = create_db_engine(database_url)
    session = create_session_factory(engine)()
    try:
        query = session.query(EvalRun).order_by(EvalRun.created_at.desc())
        if limit:
            query = query.limit(limit)
        return list(reversed(query.all()))
    except Exception as exc:  # noqa: BLE001 - a missing/empty eval_runs table is a normal first-run state
        logger.warning("Could not load eval_runs (has eval_drift.py ever run?): %s", exc)
        return []
    finally:
        session.close()


def _plot_recall(runs: list[EvalRun], out_dir: Path) -> None:
    fig, ax = plt.subplots(figsize=(8, 4.5))
    xs = list(range(len(runs)))
    model_only = [r.model_only_recall for r in runs]
    fused = [r.fused_recall for r in runs]
    ax.plot(xs, model_only, marker="o", label="model-only recall")
    ax.plot(xs, fused, marker="o", label="fused recall")
    ax.set_xticks(xs)
    ax.set_xticklabels([r.created_at.strftime("%Y-%m-%d") for r in runs], rotation=45, ha="right")
    ax.set_ylabel("Recall on live phishing sample")
    ax.set_title("Real-world recall over time (DEC-018 gap, tracked)")
    ax.legend()
    ax.set_ylim(0, 1)
    fig.tight_layout()
    fig.savefig(out_dir / "recall_over_time.png", dpi=150)
    plt.close(fig)


def _plot_fp_rate(runs: list[EvalRun], out_dir: Path) -> None:
    fig, ax = plt.subplots(figsize=(8, 4.5))
    xs = list(range(len(runs)))
    model_only = [r.model_only_fp_rate for r in runs]
    fused = [r.fused_fp_rate for r in runs]
    ax.plot(xs, model_only, marker="o", label="model-only FP rate")
    ax.plot(xs, fused, marker="o", label="fused FP rate")
    ax.set_xticks(xs)
    ax.set_xticklabels([r.created_at.strftime("%Y-%m-%d") for r in runs], rotation=45, ha="right")
    ax.set_ylabel("False-positive rate on legitimate-brand control set")
    ax.set_title("False-positive rate over time")
    ax.legend()
    ax.set_ylim(0, 1)
    fig.tight_layout()
    fig.savefig(out_dir / "fp_rate_over_time.png", dpi=150)
    plt.close(fig)


def _plot_confidence(runs: list[EvalRun], out_dir: Path) -> None:
    fig, ax = plt.subplots(figsize=(8, 4.5))
    xs = list(range(len(runs)))
    means = [r.mean_model_confidence for r in runs]
    stds = [r.confidence_std or 0.0 for r in runs]
    ax.errorbar(xs, means, yerr=stds, marker="o", capsize=3, label="mean model probability +/- 1 stdev")
    ax.set_xticks(xs)
    ax.set_xticklabels([r.created_at.strftime("%Y-%m-%d") for r in runs], rotation=45, ha="right")
    ax.set_ylabel("Model phishing-probability output")
    ax.set_title("Prediction/confidence drift over time")
    ax.legend()
    fig.tight_layout()
    fig.savefig(out_dir / "confidence_drift_over_time.png", dpi=150)
    plt.close(fig)


def generate_charts(runs: list[EvalRun], out_dir: Path) -> list[Path]:
    """Render every drift chart. Returns the list of written file paths.

    Fewer than 2 runs produces no chart (nothing to trend yet) rather than
    an empty/degenerate plot -- returns an empty list in that case.
    """
    if len(runs) < 2:
        logger.warning("Fewer than 2 stored runs (%d) -- nothing to chart yet.", len(runs))
        return []

    out_dir.mkdir(parents=True, exist_ok=True)
    _plot_recall(runs, out_dir)
    _plot_fp_rate(runs, out_dir)
    _plot_confidence(runs, out_dir)
    return [
        out_dir / "recall_over_time.png",
        out_dir / "fp_rate_over_time.png",
        out_dir / "confidence_drift_over_time.png",
    ]


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--database-url", type=str, default=None)
    parser.add_argument("--limit", type=int, default=None, help="Only chart the N most recent runs")
    parser.add_argument("--out-dir", type=Path, default=_DEFAULT_OUT_DIR)
    args = parser.parse_args()

    database_url = args.database_url
    if database_url is None:
        api_config = yaml.safe_load(_DEFAULT_API_CONFIG_PATH.read_text(encoding="utf-8"))
        database_url = api_config.get("database_url", "sqlite:///argus_dev.db")

    runs = load_runs(database_url, args.limit)
    written = generate_charts(runs, args.out_dir)
    for path in written:
        logger.info("Wrote %s", path)
    if not written:
        logger.info(
            "No charts written (need at least 2 stored runs -- run "
            "scripts/eval_drift.py more than once)."
        )


if __name__ == "__main__":
    main()
