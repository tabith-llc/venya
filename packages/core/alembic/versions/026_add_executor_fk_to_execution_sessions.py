# Copyright (c) 2026 Tabith LLC.
# Use of this source code is governed by the Business Source License 1.1
# included in the LICENSE file at the root of this repository. As of the
# Change Date listed there, the work is available under MPL 2.0.
# SPDX-License-Identifier: BUSL-1.1

"""Add FK constraint on execution_sessions.executor_id → executors.id

Revision ID: 026
Revises: 025
Create Date: 2026-09-02
"""

from alembic import op

revision = "026"
down_revision = "025"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_foreign_key(
        "fk_execution_sessions_executor_id",
        "execution_sessions",
        "executors",
        ["executor_id"],
        ["id"],
    )


def downgrade() -> None:
    op.drop_constraint("fk_execution_sessions_executor_id", "execution_sessions")
