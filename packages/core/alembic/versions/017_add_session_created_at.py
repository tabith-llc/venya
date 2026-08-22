"""add created_at to sessions table with unique constraints and indexes

Revision ID: 017
Revises: 016
Create Date: 2026-08-18

Fixes H-08: session hard cap was computed from expires_at - session_timeout,
which shifts on every session extension and breaks if session_timeout config
changes. Stores actual creation time in created_at column.

Fixes H-11: Session.access_token had no unique constraint — duplicate tokens
could cause refresh_token() to pick an arbitrary session.

Also fixes L-23: Missing indexes on user_id and expires_at.

Session model after migration:
    id = Column(Integer, primary_key=True)
    user_id = Column(String(64), ForeignKey("users.user_id"), nullable=False, index=True)
    created_at = Column(DateTime(timezone=True), default=NOW, nullable=False)
    expires_at = Column(DateTime(timezone=True), nullable=False, index=True)
    access_token = Column(String(128), nullable=True, unique=True)
    access_token_jti = Column(String(64), nullable=True, unique=True)
"""

import sqlalchemy as sa
from alembic import op

revision = "017"
down_revision = "016"
branch_labels = None
depends_on = None


def upgrade():
    # H-08: Add created_at column
    op.add_column("sessions", sa.Column("created_at", sa.DateTime(timezone=True), nullable=True))

    # Backfill existing rows with NOW() — safe approach
    op.execute("UPDATE sessions SET created_at = NOW() WHERE created_at IS NULL")

    op.alter_column("sessions", "created_at", nullable=False)

    # H-11: Check for and resolve duplicate access_token values
    # (keep the newest by id, delete the rest)
    op.execute(
        """
        DELETE FROM sessions
        WHERE id NOT IN (
            SELECT MAX(id)
            FROM sessions
            WHERE access_token IS NOT NULL
            GROUP BY access_token
        )
        AND access_token IS NOT NULL
    """
    )

    op.execute(
        """
        DELETE FROM sessions
        WHERE id NOT IN (
            SELECT MAX(id)
            FROM sessions
            WHERE access_token_jti IS NOT NULL
            GROUP BY access_token_jti
        )
        AND access_token_jti IS NOT NULL
    """
    )

    # H-11: Unique constraints on token columns
    op.create_unique_constraint("uq_sessions_access_token", "sessions", ["access_token"])
    op.create_unique_constraint("uq_sessions_access_token_jti", "sessions", ["access_token_jti"])

    # L-23: Performance indexes
    op.create_index("ix_sessions_user_id", "sessions", ["user_id"])
    op.create_index("ix_sessions_expires_at", "sessions", ["expires_at"])


def downgrade():
    op.drop_index("ix_sessions_expires_at", table_name="sessions")
    op.drop_index("ix_sessions_user_id", table_name="sessions")
    op.drop_constraint("uq_sessions_access_token_jti", "sessions")
    op.drop_constraint("uq_sessions_access_token", "sessions")
    op.drop_column("sessions", "created_at")
