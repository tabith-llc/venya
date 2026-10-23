# Copyright (c) 2026 Tabith LLC.
# Use of this source code is governed by the Business Source License 1.1
# included in the LICENSE file at the root of this repository. As of the
# Change Date listed there, the work is available under MPL 2.0.
# SPDX-License-Identifier: BUSL-1.1

"""Add admin_cert_revocations table.

Creates the admin_cert_revocations table for tracking revoked admin
client certificates. This enables revocation checking in the admin
mTLS middleware, ensuring that compromised admin certificates can be
revoked before their 90-day expiry.

Revision ID: 011_admin_cert_revocations
Revises: 010_remove_executor_token_binding
Create Date: 2026-08-15
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "011_admin_cert_revocations"
down_revision: str | None = "010_remove_executor_token_binding"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    """Create admin_cert_revocations table."""
    op.create_table(
        "admin_cert_revocations",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("serial_number", sa.String(64), nullable=False),
        sa.Column("revoked_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("reason", sa.String(64), nullable=True),
    )
    op.create_index(
        op.f("ix_admin_cert_revocations_serial_number"), "admin_cert_revocations", ["serial_number"], unique=False
    )


def downgrade() -> None:
    """Drop admin_cert_revocations table."""
    op.drop_index(op.f("ix_admin_cert_revocations_serial_number"), table_name="admin_cert_revocations")
    op.drop_table("admin_cert_revocations")
