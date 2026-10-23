# Copyright (c) 2026 Tabith LLC.
# Use of this source code is governed by the Business Source License 1.1
# included in the LICENSE file at the root of this repository. As of the
# Change Date listed there, the work is available under MPL 2.0.
# SPDX-License-Identifier: BUSL-1.1

"""Remove binding_hash column from executor_enrollment_tokens.

The binding_hash column is no longer needed — executor_id binding
is enforced by the DB column + application-level check. Token
hashing uses HMAC-SHA256 with the server pepper for keyed hashing.

Revision ID: 010_remove_executor_token_binding
Revises: 009_executor_id_constraints
Create Date: 2026-08-15
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "010_remove_executor_token_binding"
down_revision: str | None = "009_executor_id_constraints"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    """Drop binding_hash from executor_enrollment_tokens."""
    # Widen alembic's bookkeeping column: this revision's own ID (33 chars)
    # overflows the auto-created VARCHAR(32) that Alembic makes on first run.
    op.alter_column(
        "alembic_version",
        "version_num",
        type_=sa.String(length=64),
        existing_type=sa.String(length=32),
    )
    op.drop_column("executor_enrollment_tokens", "binding_hash")


def downgrade() -> None:
    """Re-add binding_hash column."""
    # Restore original column width (009's ID fits in 32 chars).
    op.alter_column(
        "alembic_version",
        "version_num",
        type_=sa.String(length=32),
        existing_type=sa.String(length=64),
    )
    op.add_column(
        "executor_enrollment_tokens",
        op.Column("binding_hash", sa.String(64), nullable=False, server_default=""),
    )
