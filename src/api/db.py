"""Shared SQLAlchemy setup for auth + vault (Phase 8).

One declarative Base and one engine/session factory, shared by
``src.api.auth.models`` and ``src.api.vault.models`` so both write to the
same SQLite (dev) / configured database file. Plain SQLAlchemy rather than
flask-sqlalchemy — an explicit session factory is easier to point at an
isolated in-memory database per test than working around Flask-SQLAlchemy's
app-context-bound session.
"""

from __future__ import annotations

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


def create_session_factory(engine: Engine) -> sessionmaker[Session]:
    """Build a session factory bound to the given engine.

    Args:
        engine: The engine sessions should use.

    Returns:
        A ``sessionmaker`` callable — call it to get a new ``Session``.
    """
    return sessionmaker(bind=engine, expire_on_commit=False)
