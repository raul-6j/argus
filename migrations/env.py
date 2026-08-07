"""Alembic environment for ARGUS.

Resolves the target database from the same place the app does, so a migration
can never be applied to a different database than the one the app will use:

    1. A ``sqlalchemy.url`` already set on the Alembic ``Config`` — how a
       programmatic caller (``src.api.db.stamp_head``, the test suite) names
       the exact engine it means. This MUST come first: without it those
       callers would silently fall through to the file-configured database and
       migrate the wrong one, which during development here meant a test
       attempting to migrate the developer's real ``argus_dev.db``.
    2. ``DATABASE_URL`` environment variable — the production path, keeping
       credentials out of the repository.
    3. ``configs/api_config.yaml`` -> ``database_url`` — the dev default.

``alembic.ini`` deliberately carries no ``sqlalchemy.url`` of its own, so the
CLI falls straight through to (2) or (3) and there is no fourth, stale source
of truth to drift from the others.
"""

from __future__ import annotations

import os
import sys
from logging.config import fileConfig
from pathlib import Path

import yaml
from alembic import context
from sqlalchemy import engine_from_config, pool

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT))

# Imported for its side effect of registering every model on Base.metadata --
# see src/api/metadata.py for why this must be an explicit, single import point
# and not left to whatever the app happens to import.
from src.api.metadata import target_metadata  # noqa: E402

config = context.config

# Logging is configured only when Alembic is driven from the command line.
#
# alembic.ini's [logger_*] sections are a *whole-process* logging config:
# fileConfig replaces the root logger's handlers and, by default, disables
# every logger that already exists. That is fine for `alembic upgrade head` in
# a shell, where Alembic is the only thing running. It is actively harmful
# in-process -- src.api.db.stamp_head runs `alembic stamp` during create_app()
# on a fresh database, so this would hijack ARGUS's root handlers and silence
# its existing loggers for the rest of the process's life, with (by
# construction) nothing in the logs to explain it.
#
# src.api.db._alembic_config sets configure_logger=False for exactly that
# reason; the CLI sets no attributes, so it still gets the config below.
if config.config_file_name is not None and config.attributes.get("configure_logger", True):
    fileConfig(config.config_file_name, disable_existing_loggers=False)


def _database_url() -> str:
    """Resolve the database URL. See the module docstring for the precedence."""
    configured = config.get_main_option("sqlalchemy.url", None)
    if configured:
        return configured

    env_url = os.environ.get("DATABASE_URL")
    if env_url:
        return env_url

    api_config_path = PROJECT_ROOT / "configs" / "api_config.yaml"
    if api_config_path.is_file():
        with api_config_path.open("r", encoding="utf-8") as fh:
            api_config = yaml.safe_load(fh) or {}
        url = api_config.get("database_url")
        if url:
            return url

    raise RuntimeError(
        "No database URL: set the DATABASE_URL environment variable, or add "
        "`database_url` to configs/api_config.yaml."
    )


def run_migrations_offline() -> None:
    """Emit SQL to stdout instead of connecting (``alembic upgrade --sql``).

    Useful when a DBA, not the deploy job, applies the change.
    """
    context.configure(
        url=_database_url(),
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
        # SQLite cannot ALTER most columns in place; batch mode rewrites the
        # table instead. Harmless on PostgreSQL, and required for any future
        # column alteration to work on the dev database at all.
        render_as_batch=True,
        compare_type=True,
    )
    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online() -> None:
    """Connect and apply migrations directly (the normal path)."""
    section = config.get_section(config.config_ini_section) or {}
    section["sqlalchemy.url"] = _database_url()

    connectable = engine_from_config(
        section, prefix="sqlalchemy.", poolclass=pool.NullPool
    )

    with connectable.connect() as connection:
        context.configure(
            connection=connection,
            target_metadata=target_metadata,
            render_as_batch=True,
            # Without this, a column type change is silently invisible to
            # --autogenerate, which is one of the exact failure modes adopting
            # Alembic is meant to close.
            compare_type=True,
        )
        with context.begin_transaction():
            context.run_migrations()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
