# Copyright (c) 2026 Tabith LLC.
# Use of this source code is governed by the Business Source License 1.1
# included in the LICENSE file at the root of this repository. As of the
# Change Date listed there, the work is available under MPL 2.0.
# SPDX-License-Identifier: BUSL-1.1

"""add unique constraint on secrets(key, created_by)

Revision ID: 015
Revises: 014
Create Date: 2026-08-17

Prevents duplicate secrets with the same key per user.
Requires user_id or role_ids for secret retrieval (enforced in core.py).
"""

from alembic import op

revision = "015"
down_revision = "014"
branch_labels = None
depends_on = None


def upgrade():
    # Clean up existing duplicates: keep the oldest (lowest id) per (key, created_by)
    op.execute(
        """
        DELETE FROM secrets
        WHERE id NOT IN (
            SELECT MIN(id) FROM secrets
            GROUP BY key, created_by
        )
    """
    )

    # Drop the existing non-unique index
    op.drop_index("ix_secrets_key", table_name="secrets")

    # Add composite unique constraint
    op.create_unique_constraint("uq_secrets_key_created_by", "secrets", ["key", "created_by"])


def downgrade():
    op.drop_constraint("uq_secrets_key_created_by", "secrets", type_="unique")
    op.create_index("ix_secrets_key", "secrets", ["key"])
