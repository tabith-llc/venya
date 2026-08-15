"""Add binding_hash column to enrollment token tables.

Binding hashes cryptographically tie enrollment tokens to their
intended entity (executor_id or user_id), preventing token misuse
if the database is compromised.

Revision ID: 008_token_binding
Revises: 007_executor_enrollment_tokens
Create Date: 2026-08-14
"""

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "008_token_binding"
down_revision: Union[str, None] = "007_executor_enrollment_tokens"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Add binding_hash columns to both enrollment token tables."""
    # executor_enrollment_tokens — NOT NULL with empty default (legacy tokens rejected)
    op.add_column(
        "executor_enrollment_tokens",
        sa.Column("binding_hash", sa.String(64), nullable=False, server_default=""),
    )

    # enrollment_tokens — NOT NULL with empty default (legacy tokens rejected)
    op.add_column(
        "enrollment_tokens",
        sa.Column("binding_hash", sa.String(64), nullable=False, server_default=""),
    )


def downgrade() -> None:
    """Remove binding_hash columns."""
    op.drop_column("enrollment_tokens", "binding_hash")
    op.drop_column("executor_enrollment_tokens", "binding_hash")
