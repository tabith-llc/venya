"""executor enrollment tokens for bootstrap registration

Revision ID: 007_executor_enrollment_tokens
Revises: 006_elevation_tokens
Create Date: 2026-08-13
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "007_executor_enrollment_tokens"
down_revision: str | None = "006_elevation_tokens"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "executor_enrollment_tokens",
        sa.Column("id", sa.Integer, primary_key=True),
        sa.Column("executor_id", sa.String(64), nullable=False),
        sa.Column("token_hash", sa.String(64), nullable=False),
        sa.Column("state", sa.String(16), nullable=False, server_default="created"),
        sa.Column("created_by", sa.String(64), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("used_at", sa.DateTime(timezone=True), nullable=True),
        sa.UniqueConstraint("token_hash", name="uq_executor_enrollment_tokens_token_hash"),
    )
    op.create_foreign_key(
        "fk_executor_enrollment_tokens_created_by", "executor_enrollment_tokens", "users", ["created_by"], ["user_id"]
    )
    op.create_index(
        "ix_executor_enrollment_tokens_token_hash",
        "executor_enrollment_tokens",
        ["token_hash"],
    )
    op.create_index(
        "ix_executor_enrollment_tokens_executor_id",
        "executor_enrollment_tokens",
        ["executor_id"],
    )
    op.create_index(
        "ix_executor_enrollment_tokens_expires_at",
        "executor_enrollment_tokens",
        ["expires_at"],
    )


def downgrade() -> None:
    op.drop_index("ix_executor_enrollment_tokens_expires_at", table_name="executor_enrollment_tokens")
    op.drop_index("ix_executor_enrollment_tokens_executor_id", table_name="executor_enrollment_tokens")
    op.drop_index("ix_executor_enrollment_tokens_token_hash", table_name="executor_enrollment_tokens")
    op.drop_table("executor_enrollment_tokens")
