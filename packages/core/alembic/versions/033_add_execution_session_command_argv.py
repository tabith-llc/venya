# Copyright (c) 2026 Tabith LLC.
# Use of this source code is governed by the Business Source License 1.1
# included in the LICENSE file at the root of this repository. As of the
# Change Date listed there, the work is available under MPL 2.0.
# SPDX-License-Identifier: BUSL-1.1

"""execution_sessions.command_argv — true argv list alongside the display text

Revision ID: 033
Revises: 032
Create Date: 2026-10-02

Ticket execution-command-wire-unstructured-string #322, ruling Q4=D2: the
command wire becomes a structured argv list; `command` stays as the rendered
display text (existing readers unchanged) and this nullable JSON column stores
the true argument list so the args stay recoverable from the audit row.
Pre-change rows stay NULL (nothing to backfill — the string form was the only
truth they ever carried). ADD COLUMN only; portable schema DDL: sa.JSON with
a PostgreSQL JSONB variant (secrets.metadata precedent, migration 023),
identical on the SQLite dev/test path.
"""

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision = "033"
down_revision = "032"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "execution_sessions",
        sa.Column(
            "command_argv",
            sa.JSON().with_variant(postgresql.JSONB(), "postgresql"),
            nullable=True,
        ),
    )


def downgrade() -> None:
    op.drop_column("execution_sessions", "command_argv")
