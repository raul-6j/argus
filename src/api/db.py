"""Shared SQLAlchemy setup for auth + vault (Phase 8).

One declarative Base and one engine/session factory, shared by
``src.api.auth.models`` and ``src.api.vault.models`` so both write to the
same SQLite (dev) / configured database file. Plain SQLAlchemy rather than
flask-sqlalchemy — an explicit session factory is easier to point at an
isolated in-memory database per test than working around Flask-SQLAlchemy's
app-context-bound session.
"""

from __future__ import annotations

import threading
from typing import Callable, Union

from sqlalchemy import Engine, create_engine
from sqlalchemy.orm import DeclarativeBase, Session, sessionmaker
from sqlalchemy.pool import StaticPool


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


def init_db(engine: Engine) -> None:
    """Create all tables that don't already exist.

    Args:
        engine: The engine to create tables on.
    """
    Base.metadata.create_all(engine)


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
    return isinstance(engine.pool, StaticPool)


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
