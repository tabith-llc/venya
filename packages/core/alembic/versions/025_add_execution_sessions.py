"""Add execution_sessions and execution_session_secrets tables

Revision ID: 025
Revises: 024
Create Date: 2026-08-29
"""

import sqlalchemy as sa
from alembic import op

revision = "025"
down_revision = "024"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # execution_sessions table
    op.create_table(
        "execution_sessions",
        sa.Column("id", sa.String(), primary_key=True),
        sa.Column("user_id", sa.String(), sa.ForeignKey("users.user_id"), nullable=False),
        sa.Column("executor_id", sa.String(), nullable=False),
        sa.Column("command", sa.Text(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("completed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("exit_code", sa.Integer(), nullable=True),
        sa.Column("stdout", sa.Text(), nullable=True),
        sa.Column("stderr", sa.Text(), nullable=True),
    )

    # Index on expires_at for cleanup loop efficiency
    op.create_index("ix_execution_sessions_expires_at", "execution_sessions", ["expires_at"])

    # execution_session_secrets join table
    op.create_table(
        "execution_session_secrets",
        sa.Column("session_id", sa.String(), sa.ForeignKey("execution_sessions.id"), primary_key=True),
        sa.Column("secret_id", sa.Integer(), sa.ForeignKey("secrets.id"), primary_key=True),
        sa.Column("wrapped_value", sa.Text(), nullable=False),
    )


def downgrade() -> None:
    op.drop_table("execution_session_secrets")
    op.drop_table("execution_sessions")
