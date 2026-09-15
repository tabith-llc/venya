# Copyright (c) 2026 Tabith LLC.
# Use of this source code is governed by the Business Source License 1.1
# included in the LICENSE file at the root of this repository. As of the
# Change Date listed there, the work is available under MPL 2.0.
# SPDX-License-Identifier: BUSL-1.1

"""fix EnrollmentToken.user_id FK to reference users.user_id (String)

Revision ID: 018
Revises: 017
Create Date: 2026-08-18

Fixes H-10: EnrollmentToken.user_id used ForeignKey("users.id") (Integer)
while all 8 other user FK references use ForeignKey("users.user_id") (String).

Changes:
1. Alters user_id column from Integer to String(64)
2. Drops old FK constraint, adds new one referencing users.user_id
"""

import sqlalchemy as sa
from alembic import op

revision = "018"
down_revision = "017"
branch_labels = None
depends_on = None


def upgrade():
    # Drop FK constraint first
    op.drop_constraint("enrollment_tokens_user_id_fkey", "enrollment_tokens", type_="foreignkey")

    # Alter column type from Integer to String(64)
    op.alter_column(
        "enrollment_tokens", "user_id", existing_type=sa.INTEGER(), type_=sa.String(64), existing_nullable=False
    )

    # Add new FK constraint referencing users.user_id
    op.create_foreign_key(
        "enrollment_tokens_user_id_fkey",
        "enrollment_tokens",
        "users",
        ["user_id"],
        ["user_id"],
    )


def downgrade():
    # Drop new FK constraint
    op.drop_constraint("enrollment_tokens_user_id_fkey", "enrollment_tokens", type_="foreignkey")

    # Alter column back to Integer
    op.alter_column(
        "enrollment_tokens", "user_id", existing_type=sa.String(64), type_=sa.INTEGER(), existing_nullable=False
    )

    # Restore old FK constraint
    op.create_foreign_key(
        "enrollment_tokens_user_id_fkey",
        "enrollment_tokens",
        "users",
        ["user_id"],
        ["id"],
    )
