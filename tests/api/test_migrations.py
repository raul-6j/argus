"""Tests for the Alembic migration setup and its integration with ``init_db``.

The failure these guard against is quiet, not loud:
``Base.metadata.create_all()`` creates missing *tables* but never alters an
existing one, so before migrations existed a new column on an existing table
did nothing at startup and the app failed later, at query time, on whatever
code path first touched it.

The most valuable test here is ``test_migration_matches_the_models``: it
applies every migration to an empty database and asserts Alembic sees no
remaining difference from the models. That is what stops the migration history
and the ORM definitions from drifting apart, which is the way a migration setup
usually rots.
"""

from __future__ import annotations

import logging

import pytest
from sqlalchemy import inspect, text

from src.api.db import (
    Base,
    check_schema_current,
    create_db_engine,
    init_db,
    stamp_head,
)
from src.api.metadata import target_metadata

alembic = pytest.importorskip("alembic", reason="alembic is required for migrations")

from alembic import command  # noqa: E402
from alembic.config import Config  # noqa: E402
from alembic.script import ScriptDirectory  # noqa: E402

from src.api.db import PROJECT_ROOT, _alembic_config, _head_revision  # noqa: E402


@pytest.fixture
def file_db(tmp_path):
    """A real file-backed SQLite database.

    File-backed, not ``:memory:``, on purpose: ``init_db`` deliberately skips
    all Alembic work for the in-memory test engine, so an in-memory database
    would exercise none of the behaviour under test here.
    """
    return create_db_engine(f"sqlite:///{tmp_path / 'argus_test.db'}")


def _config_for(engine) -> Config:
    return _alembic_config(engine)


class TestMigrationScripts:
    def test_there_is_exactly_one_head(self):
        """Two heads means a branched history that ``upgrade head`` refuses to
        apply — usually the result of two people generating a migration from
        the same parent."""
        script = ScriptDirectory(str(PROJECT_ROOT / "migrations"))
        assert len(script.get_heads()) == 1

    def test_every_revision_is_reachable_from_head(self):
        script = ScriptDirectory(str(PROJECT_ROOT / "migrations"))
        head = script.get_current_head()
        walked = {rev.revision for rev in script.walk_revisions()}
        assert head in walked

    def test_upgrade_creates_every_table(self, file_db):
        command.upgrade(_config_for(file_db), "head")

        created = set(inspect(file_db).get_table_names())
        expected = set(target_metadata.tables)
        assert expected <= created

    def test_migration_matches_the_models(self, file_db):
        """Apply every migration, then diff the result against the ORM models.

        A non-empty diff means a model changed without a migration (or vice
        versa) — the drift that makes a migration setup worse than useless,
        because it looks maintained while no longer describing reality.
        """
        from alembic.autogenerate import compare_metadata
        from alembic.runtime.migration import MigrationContext

        command.upgrade(_config_for(file_db), "head")

        with file_db.connect() as connection:
            context = MigrationContext.configure(connection)
            diff = compare_metadata(context, target_metadata)

        assert diff == [], f"models and migrations have drifted: {diff}"

    def test_downgrade_to_base_removes_every_table(self, file_db):
        """A migration that cannot be rolled back is a migration you cannot
        deploy safely."""
        config = _config_for(file_db)
        command.upgrade(config, "head")
        command.downgrade(config, "base")

        remaining = set(inspect(file_db).get_table_names()) - {"alembic_version"}
        assert remaining == set()


class TestInitDbIntegration:
    def test_a_new_database_is_stamped_at_head(self, file_db):
        """Otherwise a create_all-built database sits permanently outside
        Alembic's control and the first real migration fails on it."""
        init_db(file_db)

        with file_db.connect() as connection:
            stamped = connection.execute(
                text("SELECT version_num FROM alembic_version")
            ).scalar()
        assert stamped == _head_revision()

    def test_init_db_still_creates_the_tables(self, file_db):
        init_db(file_db)
        assert set(target_metadata.tables) <= set(inspect(file_db).get_table_names())

    def test_in_memory_database_is_left_unstamped(self):
        """The test engine is ephemeral and single-connection; stamping it
        would add an Alembic import and a write to every app build for a
        database that can never be migrated."""
        engine = create_db_engine("sqlite:///:memory:")
        init_db(engine)
        assert "alembic_version" not in inspect(engine).get_table_names()

    def test_init_db_is_idempotent(self, file_db):
        init_db(file_db)
        init_db(file_db)  # must not raise
        assert set(target_metadata.tables) <= set(inspect(file_db).get_table_names())

    def test_stamped_database_reports_current(self, file_db):
        init_db(file_db)
        assert check_schema_current(file_db) == _head_revision()


class TestSchemaDriftDetection:
    def test_warns_when_the_database_predates_migrations(self, file_db, caplog):
        """A database built by create_all before Alembic existed has tables but
        no revision stamp — exactly the state every existing ARGUS dev DB is
        in right now."""
        Base.metadata.create_all(file_db)  # no stamp: the pre-Alembic world

        with caplog.at_level(logging.WARNING):
            result = check_schema_current(file_db)

        assert result is None
        assert "no Alembic revision stamp" in caplog.text

    def test_warns_when_the_database_is_behind_head(self, file_db, caplog):
        """The F19 scenario: a column was added, the running database never got
        it, and nothing said so until a query failed."""
        stamp_head(file_db)
        with file_db.connect() as connection:
            connection.execute(text("UPDATE alembic_version SET version_num = 'stale'"))
            connection.commit()

        with caplog.at_level(logging.WARNING):
            result = check_schema_current(file_db)

        assert result == "stale"
        assert "alembic upgrade head" in caplog.text

    def test_does_not_warn_when_current(self, file_db, caplog):
        stamp_head(file_db)
        with caplog.at_level(logging.WARNING):
            check_schema_current(file_db)
        assert "alembic upgrade head" not in caplog.text

    def test_running_alembic_in_process_leaves_app_logging_alone(self, file_db, caplog):
        """``alembic.ini``'s ``[logger_*]`` sections are a whole-process logging
        config: ``fileConfig`` replaces the root logger's handlers and disables
        pre-existing loggers.

        ``migrations/env.py`` runs in-process — ``init_db`` stamps a fresh
        database during ``create_app()`` — so applying it there would hijack
        ARGUS's own logging for the rest of the process's life, with (by
        construction) nothing in the logs to explain it. env.py applies that
        config only under the CLI; this asserts the in-process path stays
        inert.
        """
        app_logger = logging.getLogger("src.api.some_module")
        root_handlers_before = list(logging.getLogger().handlers)

        stamp_head(file_db)  # runs migrations/env.py in this process

        assert not app_logger.disabled
        assert logging.getLogger().handlers == root_handlers_before
        with caplog.at_level(logging.WARNING):
            app_logger.warning("still logging")
        assert "still logging" in caplog.text

    def test_drift_check_never_raises_on_a_broken_setup(self, file_db, monkeypatch):
        """A diagnostic must not be able to take the app down at startup."""
        monkeypatch.setattr(
            "src.api.db._head_revision",
            lambda: (_ for _ in ()).throw(RuntimeError("alembic exploded")),
        )
        assert check_schema_current(file_db) is None
