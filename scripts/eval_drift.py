#!/usr/bin/env python
"""Scheduled real-world evaluation harness (Phase 3, F10).

Turns ``scripts/measure_realworld_recall.py``'s one-shot measurement into a
tracked-over-time drift signal: each run is persisted as one
:class:`~src.api.evalruns.models.EvalRun` row (same database
``create_app()`` uses -- no new infrastructure), and compared against the
immediately-previous stored run so a genuine regression (falling recall,
rising false-positive rate, drifting mean confidence) is visible run over
run, not just as a single static number that can go stale unnoticed. This
is what makes DEC-018's documented real-world generalisation gap a
*measured* quantity rather than a one-off finding.

Orchestrates, in order:
    1. optionally refresh threat-intel feeds (``--refresh-feeds``, needs
       network) via ``scripts/refresh_threat_feeds.py``
    2. resolve which feed to evaluate against (explicit ``--eval-feed``, or
       the freshest snapshot ``refresh_threat_feeds.py`` already wrote)
    3. run ``measure_realworld_recall.run()``
    4. persist the result, compute drift vs. the previous run
    5. write a timestamped JSON report (matches the project's existing
       ``reports/`` convention)

Takes no schedule argument itself -- wire this into cron / a systemd timer
/ a CI schedule at deploy time, mirroring
``scripts/refresh_threat_feeds.py``'s identical "the script doesn't invent
its own scheduler" convention (Iron Law #2: no implicit magic).

Usage:
    python scripts/eval_drift.py --sample-size 200 --refresh-feeds
    python scripts/eval_drift.py --eval-feed data/raw/feeds/x.csv
"""

from __future__ import annotations

import argparse
import json
import logging
import sys
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import yaml

from scripts import measure_realworld_recall, refresh_threat_feeds
from src.api.db import create_db_engine, create_session_factory, init_db
from src.api.evalruns.models import EvalRun

logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")
logger = logging.getLogger("eval_drift")

_PROJECT_ROOT = Path(__file__).resolve().parents[1]
_DEFAULT_API_CONFIG_PATH = _PROJECT_ROOT / "configs" / "api_config.yaml"
_DEFAULT_THREAT_INTEL_CONFIG_PATH = _PROJECT_ROOT / "configs" / "threat_intel_config.yaml"


def _resolve_eval_feed(explicit: Optional[Path], threat_intel_config_path: Path) -> Path:
    """Resolve which feed to evaluate against.

    Prefers an explicitly-given ``--eval-feed``. Otherwise falls back to
    the freshest snapshot ``scripts/refresh_threat_feeds.py`` has written
    (its ``active_snapshot.txt`` pointer) -- mirrors
    ``src.api.app._resolve_threat_feed_snapshot``'s identical convention.

    Raises:
        FileNotFoundError: If neither an explicit feed nor a resolvable
            pointer exists -- there's nothing sensible to evaluate against.
    """
    if explicit is not None:
        return explicit
    if not threat_intel_config_path.is_file():
        raise FileNotFoundError(
            "No --eval-feed given and no threat_intel_config.yaml found to resolve one from."
        )
    config = yaml.safe_load(threat_intel_config_path.read_text(encoding="utf-8")) or {}
    feeds_dir = config.get("feeds_dir")
    if feeds_dir:
        pointer_path = _PROJECT_ROOT / feeds_dir / "active_snapshot.txt"
        if pointer_path.is_file():
            relative = pointer_path.read_text(encoding="utf-8").strip()
            if relative:
                return _PROJECT_ROOT / relative
    raise FileNotFoundError(
        "No --eval-feed given and no active_snapshot.txt pointer found -- run "
        "scripts/refresh_threat_feeds.py first (or with --refresh-feeds), or "
        "pass --eval-feed explicitly."
    )


def _previous_run(session: Any) -> Optional[EvalRun]:
    return session.query(EvalRun).order_by(EvalRun.created_at.desc()).first()


def _delta(current: Optional[float], prior: Optional[float]) -> Optional[float]:
    if current is None or prior is None:
        return None
    return current - prior


def _drift_vs_previous(report: dict[str, Any], previous: Optional[EvalRun]) -> dict[str, Optional[float]]:
    """Compute simple deltas against the immediately-previous stored run.

    Every key is ``None`` when there is no previous run -- the first run
    against a fresh database has nothing to drift against; that's a normal
    starting state, not an error.
    """
    if previous is None:
        return {
            "fused_recall_drift": None,
            "model_only_recall_drift": None,
            "fused_fp_rate_drift": None,
            "mean_confidence_drift": None,
        }
    return {
        "fused_recall_drift": _delta(report["fused_recall"], previous.fused_recall),
        "model_only_recall_drift": _delta(report["model_only_recall"], previous.model_only_recall),
        "fused_fp_rate_drift": _delta(report["fused_fp_rate"], previous.fused_fp_rate),
        "mean_confidence_drift": _delta(report["confidence_stats"]["mean"], previous.mean_model_confidence),
    }


def run_and_persist(
    eval_feed: Path,
    sample_size: int = 200,
    control_sample_size: int = 30,
    database_url: str = "sqlite:///argus_dev.db",
) -> dict[str, Any]:
    """Run one evaluation, persist it as an :class:`EvalRun`, and return
    the report plus its drift against the previous stored run.

    Args:
        eval_feed: CSV of verified/online phishing URLs (see
            ``measure_realworld_recall.run``).
        sample_size: Max phishing URLs to sample.
        control_sample_size: Max legitimate brand domains for the FP-rate
            control set.
        database_url: SQLAlchemy URL -- same DB ``create_app()`` uses by
            default, so this needs no new infrastructure.

    Returns:
        ``{"run_id": str, "report": dict, "drift_vs_previous_run": dict}``.
    """
    report = measure_realworld_recall.run(eval_feed, sample_size, control_sample_size)

    engine = create_db_engine(database_url)
    init_db(engine)
    session = create_session_factory(engine)()
    try:
        previous = _previous_run(session)
        drift = _drift_vs_previous(report, previous)

        run_id = f"eval_{datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')}_{uuid.uuid4().hex[:8]}"
        row = EvalRun(
            run_id=run_id,
            eval_feed=report["eval_feed"],
            total_sampled=report["total_sampled"],
            reachable=report["reachable"],
            reachability_rate=report["reachability_rate"],
            model_only_recall=report["model_only_recall"],
            fused_recall=report["fused_recall"],
            recall_delta=report["recall_delta"],
            control_set_size=report["control_set_size"],
            model_only_fp_rate=report["model_only_fp_rate"],
            fused_fp_rate=report["fused_fp_rate"],
            recall_by_hosting_category_json=json.dumps(report["recall_by_hosting_category"]),
            recall_by_signal_json=json.dumps(report["recall_by_signal"]),
            mean_model_confidence=report["confidence_stats"]["mean"],
            confidence_std=report["confidence_stats"]["stdev"],
            report_json=json.dumps(report),
        )
        session.add(row)
        session.commit()
    finally:
        session.close()

    return {"run_id": run_id, "report": report, "drift_vs_previous_run": drift}


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--eval-feed",
        type=Path,
        default=None,
        help="Override feed; otherwise resolved from refresh_threat_feeds.py's active snapshot pointer",
    )
    parser.add_argument("--sample-size", type=int, default=200)
    parser.add_argument("--control-sample-size", type=int, default=30)
    parser.add_argument(
        "--refresh-feeds",
        action="store_true",
        help="Run scripts/refresh_threat_feeds.py first (needs network)",
    )
    parser.add_argument(
        "--database-url", type=str, default=None, help="Override configs/api_config.yaml's database_url"
    )
    parser.add_argument("--out-dir", type=Path, default=_PROJECT_ROOT / "reports")
    parser.add_argument("--threat-intel-config", type=Path, default=_DEFAULT_THREAT_INTEL_CONFIG_PATH)
    args = parser.parse_args()

    if args.refresh_feeds:
        logger.info("Refreshing threat-intel feeds before evaluating...")
        refresh_threat_feeds.refresh()

    eval_feed = _resolve_eval_feed(args.eval_feed, args.threat_intel_config)

    database_url = args.database_url
    if database_url is None:
        api_config = yaml.safe_load(_DEFAULT_API_CONFIG_PATH.read_text(encoding="utf-8"))
        database_url = api_config.get("database_url", "sqlite:///argus_dev.db")

    result = run_and_persist(eval_feed, args.sample_size, args.control_sample_size, database_url)

    args.out_dir.mkdir(parents=True, exist_ok=True)
    out_path = args.out_dir / f"eval_drift_{result['run_id']}.json"
    out_path.write_text(json.dumps(result, indent=2), encoding="utf-8")

    logger.info("Persisted run %s to %s", result["run_id"], database_url)
    logger.info("Wrote %s", out_path)
    logger.info(
        "fused_recall=%s (drift %s) fused_fp_rate=%s (drift %s)",
        result["report"]["fused_recall"],
        result["drift_vs_previous_run"]["fused_recall_drift"],
        result["report"]["fused_fp_rate"],
        result["drift_vs_previous_run"]["fused_fp_rate_drift"],
    )


if __name__ == "__main__":
    main()
