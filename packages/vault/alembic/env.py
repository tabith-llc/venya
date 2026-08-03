"""Alembic environment for SQLCipher SQLite.

PRAGMA key must be set before any schema inspection. The approach:
1. Use pysqlcipher dialect with a placeholder passphrase in the URL
2. In the connect event listener, set the real key and REKEY the DB
3. This ensures the real key is used for all schema operations

Usage:
    VENYA_DB_PATH=./venya.db VENYA_DB_KEY=mysecret alembic upgrade head
"""

import os
import sys
from logging.config import fileConfig

from alembic import context
from sqlalchemy import engine_from_config, event, pool, text

# Add the vault source to path (for editable installs this is not needed,
# but ensures `venya` imports work when running alembic from the package dir)
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from venya.iam.models import Base  # noqa: E402

target_metadata = Base.metadata

# Use the real DB key as the passphrase in the URL.
# The pysqlcipher dialect's on_connect handler will set PRAGMA key
# to this value. Our connect event listener then sets additional PRAGMAs.
# This avoids the rekey issue while ensuring the real key is used.


def _get_db_path():
    """Get the database path from environment."""
    return os.environ.get("VENYA_DB_PATH", "venya_migrations.db")


def _get_db_key():
    """Get the database key from environment."""
    return os.environ.get("VENYA_DB_KEY", "")


def run_migrations_offline():
    """Run migrations in 'offline' mode.

    Generates SQL without connecting to the database.
    """
    db_key = _get_db_key()
    if not db_key:
        db_key = "venya-default-key"
    url = f"sqlite+pysqlcipher://:{db_key}@//:memory:"
    context.configure(
        url=url,
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
    )

    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online():
    """Run migrations in 'online' mode.

    Uses pysqlcipher dialect with placeholder passphrase, then rekeys
    to the real passphrase in the connect event listener.
    """
    db_path = _get_db_path()
    db_key = _get_db_key()

    if not db_key:
        raise RuntimeError(
            "VENYA_DB_KEY environment variable must be set for "
            "SQLCipher migrations. Example:\n"
            "  VENYA_DB_KEY=mysecret VENYA_DB_PATH=./venya.db "
            "alembic upgrade head"
        )

    url = f"sqlite+pysqlcipher://:{db_key}@//{db_path}"

    configuration = context.config.get_section(context.config.config_ini_section)
    configuration["sqlalchemy.url"] = url

    connectable = engine_from_config(
        configuration,
        prefix="sqlalchemy.",
        poolclass=pool.NullPool,
    )

    # CRITICAL: The pysqlcipher dialect's on_connect handler sets PRAGMA key
    # to the placeholder passphrase. We must rekey to the real passphrase
    # BEFORE Alembic calls inspect() on the connection.
    @event.listens_for(connectable, "connect")
    def set_sqlcipher_pragmas(dbapi_connection, connection_record):
        """Set additional SQLCipher PRAGMAs on every new connection.

        The pysqlcipher dialect's on_connect handler has already set
        PRAGMA key to the real passphrase (from the URL). We just need
        to set journal_mode and foreign_keys.
        """
        cursor = dbapi_connection.cursor()
        cursor.execute("PRAGMA journal_mode = WAL")
        cursor.execute("PRAGMA foreign_keys = ON")
        cursor.close()

    with connectable.connect() as connection:
        context.configure(
            connection=connection,
            target_metadata=target_metadata,
            render_as_batch=True,  # Required for SQLite schema changes
        )

        with context.begin_transaction():
            context.run_migrations()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
