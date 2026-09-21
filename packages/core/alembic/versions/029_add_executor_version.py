# Copyright (c) 2026 Tabith LLC.
# Use of this source code is governed by the Business Source License 1.1
# included in the LICENSE file at the root of this repository. As of the
# Change Date listed there, the work is available under MPL 2.0.
# SPDX-License-Identifier: BUSL-1.1

"""executors.version — heartbeat-reported executor build (nullable, no backfill)

Revision ID: 029
Revises: 028
Create Date: 2026-09-20

Observability only (feature/version-surfaces ruling): daemons report their
dist version on the heartbeat; the column stores the last report. NULL means
"daemon predates version reporting" — a distinct, honest signal. No backfill:
there is nothing to backfill from, and running daemons populate it on their
next heartbeat (~30 s cadence). ADD COLUMN only; portable across PostgreSQL
(installer path) and SQLite (dev/test).
"""

import sqlalchemy as sa
from alembic import op

revision = "029"
down_revision = "028"
branch_labels = None
depends_on = None

ADD_VERSION_COLUMN = "ALTER TABLE executors ADD COLUMN version VARCHAR"


def upgrade() -> None:
    op.execute(ADD_VERSION_COLUMN)
    # Column comment (metadata only; SQLite ignores COMMENT syntax, PG applies)
    conn = op.get_bind()
    if conn.dialect.name == "postgresql":
        conn.execute(
            sa.text(
                "COMMENT ON COLUMN executors.version IS "
                "'Executor dist version reported via heartbeat; NULL = pre-version daemon'"
            )
        )


def downgrade() -> None:
    op.execute("ALTER TABLE executors DROP COLUMN version")
