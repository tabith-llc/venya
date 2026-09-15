# Copyright (c) 2026 Tabith LLC.
# Use of this source code is governed by the Business Source License 1.1
# included in the LICENSE file at the root of this repository. As of the
# Change Date listed there, the work is available under MPL 2.0.
# SPDX-License-Identifier: BUSL-1.1

"""fix elevation_tokens expires_at timezone

Revision ID: 013
Revises: 012
Create Date: 2026-08-15

The elevation_tokens table was created with a naive DateTime column
(missing timezone=True), but the ORM model declares timezone=True.
This migration fixes the column to match the model.

Without this fix, clock skew tolerance calculations could produce
incorrect results when comparing expires_at values.
"""

import sqlalchemy as sa
from alembic import op

revision = "013"
down_revision = "012"
branch_labels = None
depends_on = None


def upgrade():
    op.alter_column(
        "elevation_tokens",
        "expires_at",
        existing_type=sa.DateTime(),
        type_=sa.DateTime(timezone=True),
        existing_nullable=False,
    )


def downgrade():
    op.alter_column(
        "elevation_tokens",
        "expires_at",
        existing_type=sa.DateTime(timezone=True),
        type_=sa.DateTime(),
        existing_nullable=False,
    )
