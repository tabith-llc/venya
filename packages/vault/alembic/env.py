"""Alembic environment for PostgreSQL.

Usage:
    VENYA_DB_URL=postgresql://user:pass@localhost/venya alembic upgrade head

Or for encrypted SQLite:
    VENYA_DB_PATH=/path/to/db.db VENYA_DB_KEY=mykey alembic upgrade head
"""

import os
import sys
from logging.config import fileConfig

# Patch sqlite3 with sqlcipher3 BEFORE sqlalchemy imports it.
# sqlcipher3 does not automatically replace the stdlib sqlite3 module,
# and SQLAlchemy imports sqlite3.dbapi2 directly. We create a wrapper
# module that provides sqlite3.dbapi2 pointing to sqlcipher3.dbapi2.
try:
    import sqlcipher3.dbapi2 as _sc
    _sqlite3_patch = type(sys)("sqlite3")
    _sqlite3_patch.dbapi2 = _sc
    _sqlite3_patch.__file__ = _sc.__file__
    for _attr in dir(_sc):
        if not _attr.startswith("_"):
            setattr(_sqlite3_patch, _attr, getattr(_sc, _attr))
    sys.modules["sqlite3"] = _sqlite3_patch
except ImportError:
    pass  # sqlcipher3 not installed; use plain sqlite3

from alembic import context
from sqlalchemy import Engine, event, engine_from_config, pool, text

# Add the vault source to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from vault.iam.models import Base  # noqa: E402

target_metadata = Base.metadata


def _get_db_url():
    """Get the database URL from environment.

    Supports VENYA_DB_URL (full URL, e.g. postgresql://... or sqlite:///...)
    and falls back to constructing from VENYA_DB_PATH + VENYA_DB_KEY.
    """
    url = os.environ.get("VENYA_DB_URL", "")
    if url:
        return url

    db_path = os.environ.get("VENYA_DB_PATH", "")
    if db_path:
        return f"sqlite:///{db_path}"

    return ""


def _get_db_key():
    """Get the database encryption key (SQLCipher)."""
    return os.environ.get("VENYA_DB_KEY", "")


def _is_sqlite(url: str) -> bool:
    """Check if the URL is for SQLite."""
    return url.startswith("sqlite")


def run_migrations_offline():
    """Run migrations in 'offline' mode."""
    url = _get_db_url()
    if not url:
        raise RuntimeError(
            "VENYA_DB_URL environment variable must be set. Example:\n"
            "  VENYA_DB_URL=postgresql://user:pass@localhost/venya "
            "alembic upgrade head"
        )

    context.configure(
        url=url,
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
    )

    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online():
    """Run migrations in 'online' mode."""
    url = _get_db_url()
    if not url:
        raise RuntimeError(
            "VENYA_DB_URL environment variable must be set. Example:\n"
            "  VENYA_DB_URL=postgresql://user:pass@localhost/venya "
            "alembic upgrade head"
        )

    configuration = context.config.get_section(context.config.config_ini_section)
    configuration["sqlalchemy.url"] = url

    connectable = engine_from_config(
        configuration,
        prefix="sqlalchemy.",
        poolclass=pool.NullPool,
    )

    # Set SQLCipher key on connect for encrypted SQLite
    db_key = _get_db_key()
    if _is_sqlite(url) and db_key:
        @event.listens_for(connectable, "connect")
        def set_sqlcipher_key(dbapi_connection, connection_record):
            cursor = dbapi_connection.cursor()
            cursor.execute(f"PRAGMA key = '{db_key}'")
            cursor.execute("PRAGMA journal_mode = WAL")
            cursor.execute("PRAGMA foreign_keys = ON")
            cursor.close()

    with connectable.connect() as connection:
        context.configure(
            connection=connection,
            target_metadata=target_metadata,
        )

        with context.begin_transaction():
            context.run_migrations()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
