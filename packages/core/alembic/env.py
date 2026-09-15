# Copyright (c) 2026 Tabith LLC.
# Use of this source code is governed by the Business Source License 1.1
# included in the LICENSE file at the root of this repository. As of the
# Change Date listed there, the work is available under MPL 2.0.
# SPDX-License-Identifier: BUSL-1.1

"""Alembic environment for PostgreSQL.

Usage:
    VENYA_DB_URL=postgresql://user:pass@localhost/venya alembic upgrade head
"""

import os
import sys

from alembic import context
from sqlalchemy import engine_from_config, pool

# Add the core source to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from core.iam.models import Base

target_metadata = Base.metadata


def _get_db_url():
    """Get the database URL from VENYA_DB_URL environment variable."""
    return os.environ.get("VENYA_DB_URL", "")


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
