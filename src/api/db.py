"""Shared SQLAlchemy setup for auth + vault (Phase 8).

One declarative Base and one engine/session factory, shared by
``src.api.auth.models`` and ``src.api.vault.models`` so both write to the
same SQLite (dev) / configured database file. Plain SQLAlchemy rather than
flask-sqlalchemy — an explicit session factory is easier to point at an
isolated in-memory database per test than working around Flask-SQLAlchemy's
app-context-bound session.
"""

from __future__ import annotations

import logging
import threading
from pathlib import Path
from typing import Callable, Optional, Union

from sqlalchemy import Engine, create_engine, inspect
from sqlalchemy.orm import DeclarativeBase, Session, sessionmaker
from sqlalchemy.pool import StaticPool

logger = logging.getLogger(__name__)

PROJECT_ROOT = Path(__file__).resolve().parents[2]
_ALEMBIC_INI = PROJECT_ROOT / "alembic.ini"


class Base(DeclarativeBase):
    """Shared declarative base for all ARGUS auth/vault tables."""


def create_db_engine(database_url: str) -> Engine:
    """Create the SQLAlchemy engine for the given database URL.

    Args:
        database_url: A SQLAlchemy connection string, e.g.
            ``"sqlite:///argus.db"`` or ``"sqlite:///:memory:"`` for tests.

    Returns:
        A configured :class:`~sqlalchemy.Engine`.

    Note:
        SQLite's ``:memory:`` database is normally per-connection — a new
        connection gets a brand-new, empty database, silently losing
        everything written by a previous connection. Since each request
        here opens its own ``Session`` (a new connection), that would
        otherwise make an in-memory test database appear to forget every
        write. ``StaticPool`` forces all connections through a single
        shared in-memory connection so state actually persists across
        requests within a test, matching how the real file-backed database
        behaves.
    """
    if not database_url.startswith("sqlite"):
        return create_engine(database_url)
    if ":memory:" in database_url:
        return create_engine(
            database_url,
            connect_args={"check_same_thread": False},
            poolclass=StaticPool,
        )
    return create_engine(database_url, connect_args={"check_same_thread": False})


def _alembic_config(engine: Engine):
    """Build an Alembic ``Config`` pointed at ``engine``'s URL.

    Imported lazily: Alembic is only needed at schema-management time, and
    keeping it off the module import path means offline scripts and the test
    suite never pay for it.
    """
    from alembic.config import Config

    config = Config(str(_ALEMBIC_INI))
    config.set_main_option("script_location", str(PROJECT_ROOT / "migrations"))
    config.set_main_option("sqlalchemy.url", engine.url.render_as_string(hide_password=False))
    # Stops migrations/env.py applying alembic.ini's whole-process logging
    # config -- which replaces the root logger's handlers -- to the running
    # app. See the comment at that call site.
    config.attributes["configure_logger"] = False
    return config


def _head_revision() -> Optional[str]:
    """The newest revision id on disk, or ``None`` if unavailable."""
    from alembic.script import ScriptDirectory

    return ScriptDirectory(str(PROJECT_ROOT / "migrations")).get_current_head()


def _current_revision(engine: Engine) -> Optional[str]:
    """The revision the database reports being at, or ``None`` if unstamped."""
    from alembic.runtime.migration import MigrationContext

    with engine.connect() as connection:
        return MigrationContext.configure(connection).get_current_revision()


def stamp_head(engine: Engine) -> None:
    """Record the database as being at the latest revision, without running it.

    For a database this process just created with :func:`create_all`, the
    tables already match the newest migration — running that migration would
    fail with "table already exists". Stamping records the revision so the
    *next* migration applies cleanly. Without it, a ``create_all``-created
    database is permanently outside Alembic's control, which is the situation
    this whole module is meant to end.
    """
    from alembic import command

    command.stamp(_alembic_config(engine), "head")


def check_schema_current(engine: Engine) -> Optional[str]:
    """Warn if the database's schema is behind the newest migration.

    This is the guard for the failure mode that motivated adopting Alembic:
    ``create_all`` creates missing *tables* but never alters an existing one,
    so a new column on an existing table silently does nothing at startup and
    the app then fails at query time — potentially long after deploy, on a
    code path nobody exercised immediately. F19 adding ``webhook_secret`` to
    ``api_keys`` was exactly this: an existing dev database would not have
    picked it up.

    Deliberately a loud warning and not a hard failure. Refusing to boot on a
    schema mismatch turns a degraded deployment into a total outage, and the
    mismatch is just as often "migration is about to run in the deploy
    pipeline" as it is a real defect. Operators get an unmissable log line;
    ``/health`` is the right place to make it actionable if that is ever
    wanted.

    Args:
        engine: The engine whose database to inspect.

    Returns:
        The database's current revision, or ``None`` if it could not be
        determined (Alembic missing, or the database unstamped).
    """
    try:
        head = _head_revision()
        current = _current_revision(engine)
    except Exception as exc:  # noqa: BLE001 - a diagnostic must never break startup
        logger.debug("Could not determine schema revision: %s", exc)
        return None

    if current is None:
        logger.warning(
            "Database has tables but no Alembic revision stamp. It predates migrations; "
            "run `alembic stamp head` once so future migrations can be applied to it."
        )
        return None
    if current != head:
        logger.warning(
            "Database schema is at revision %s but the newest migration is %s. "
            "Run `alembic upgrade head` -- until then, any column added since %s is "
            "missing and queries touching it will fail.",
            current,
            head,
            current,
        )
    return current


def init_db(engine: Engine) -> None:
    """Create all tables that don't already exist, and keep Alembic in step.

    ``create_all`` remains how a fresh database gets its schema — it is fast,
    dependency-free, and exactly right for dev and for the test suite. What it
    cannot do is *change* an existing table, which is why migrations now exist
    alongside it. The two are reconciled here:

    * A database this call creates from nothing is stamped at ``head``, so it
      starts out under Alembic's control rather than outside it.
    * A database that already had tables is checked, and a warning is logged
      if it is behind (see :func:`check_schema_current`).

    Args:
        engine: The engine to create tables on.
    """
    already_populated = bool(inspect(engine).get_table_names())
    Base.metadata.create_all(engine)

    # In-memory SQLite is per-process and thrown away at exit (the test
    # suite's engine, see create_db_engine). Stamping it would add an Alembic
    # import and a write to every app build for a database that can never be
    # migrated.
    if _uses_static_pool(engine):
        return

    if already_populated:
        check_schema_current(engine)
        return

    try:
        stamp_head(engine)
    except Exception as exc:  # noqa: BLE001 - a fresh DB must still boot without Alembic
        logger.warning(
            "Created a new database but could not stamp its Alembic revision (%s). "
            "Run `alembic stamp head` manually before applying future migrations.",
            exc,
        )


def _uses_static_pool(engine: Engine) -> bool:
    """Whether this engine is the ``sqlite:///:memory:`` test configuration.

    ``StaticPool`` is only ever set by :func:`create_db_engine` for an
    in-memory SQLite URL, so this doubles as "is this database ephemeral and
    single-connection?" — the property both :func:`_needs_session_lock` and
    :func:`init_db`'s Alembic handling actually care about.
    """
    return isinstance(engine.pool, StaticPool)


def _needs_session_lock(engine: Engine) -> bool:
    """Whether ``Session``s against this engine must be transparently
    serialized (F19).

    ``StaticPool`` (used only for ``sqlite:///:memory:``, above) forces
    every ``Session`` onto one shared, single physical connection. That was
    safe as long as only one thread ever touched the DB at a time -- true of
    every request handler before F19 (Flask's test client and the dev
    server's default single-threaded request handling never overlapped two
    DB-touching code paths). F19's background job executor breaks that
    assumption: its worker threads now commit concurrently with the request
    thread's own DB access (including, e.g., ``src.api.public.auth``'s own
    unrelated per-request session lookup, not just F19's own code). Genuinely
    concurrent use of one shared ``sqlite3.Connection`` from multiple threads
    is unsafe -- this was found as a real, reproducible segfault inside
    SQLAlchemy's cursor/type machinery under concurrent async-job test load,
    not a hypothetical. File-backed SQLite and PostgreSQL each give every
    ``Session`` its own connection, so this is always ``False`` for them --
    no locking overhead outside the ``:memory:`` test configuration.
    """
    return _uses_static_pool(engine)


def create_session_factory(engine: Engine) -> Union[sessionmaker[Session], Callable[[], Session]]:
    """Build a session factory bound to the given engine.

    Args:
        engine: The engine sessions should use.

    Returns:
        A callable — call it to get a new ``Session``. For a
        ``StaticPool``-backed engine (see :func:`_needs_session_lock`), every
        ``Session`` returned is transparently serialized behind one shared
        lock -- acquired when the ``Session`` is created here, released when
        the caller calls ``.close()`` on it (including via ``with
        session_factory() as session:``, since ``Session.__exit__`` calls
        ``close()`` internally). This makes locking automatic for *every*
        call site, present and future, rather than requiring each one to
        remember to opt in -- deliberately chosen after a partial, per-call-
        site version of this fix during F19 development still left one
        pre-existing, unrelated call site (``require_api_key``'s own session
        lookup) unlocked, which kept crashing tests. Zero behavior change
        for file-backed SQLite/PostgreSQL, where every ``Session`` already
        gets its own connection.
    """
    raw_factory = sessionmaker(bind=engine, expire_on_commit=False)
    if not _needs_session_lock(engine):
        return raw_factory

    # RLock, not Lock: several existing call sites legitimately open a
    # second Session on the same thread while a first is still open (e.g. a
    # decorator's own session, closed only after the view it wraps -- which
    # may open its own session -- returns). A plain Lock deadlocks a thread
    # against itself the moment that happens (found as a real full-suite
    # hang, not a hypothetical); RLock permits same-thread re-entry while
    # still giving the mutual exclusion this exists for: blocking a
    # *different* thread (e.g. F19's job executor) until the first is done.
    lock = threading.RLock()

    def locked_factory() -> Session:
        lock.acquire()
        session = raw_factory()
        original_close = session.close

        def _close_and_release() -> None:
            # Deliberately *not* an explicit session.rollback() here: that
            # expires every attribute on every object still attached to the
            # session (SQLAlchemy's documented rollback behavior, regardless
            # of expire_on_commit), which breaks the established pattern
            # elsewhere in this codebase of reading an object's attributes
            # right after session.close() relying on expire_on_commit=False
            # (e.g. create_api_key reading api_key.created_at post-close) --
            # a real DetachedInstanceError, caught while fixing this. Plain
            # close() already ends the connection's transaction via the
            # pool's own checkin reset (rollback at the DBAPI level, not the
            # ORM level) without touching Python-side object state.
            try:
                original_close()
            finally:
                lock.release()

        session.close = _close_and_release  # type: ignore[method-assign]
        return session

    return locked_factory
