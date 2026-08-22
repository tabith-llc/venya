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
    op.drop_column("executor_enrollment_tokens", "binding_hash")


def downgrade() -> None:
    """Re-add binding_hash column."""
    op.add_column(
        "executor_enrollment_tokens",
        op.Column("binding_hash", sa.String(64), nullable=False, server_default=""),
    )
