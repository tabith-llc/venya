"""add unique constraint on secrets(key, created_by)

Revision ID: 015
Revises: 014
Create Date: 2026-08-17

Prevents duplicate secrets with the same key per user.
Requires user_id or role_ids for secret retrieval (enforced in core.py).
"""

from alembic import op
import sqlalchemy as sa

revision = "015"
down_revision = "014"
branch_labels = None
depends_on = None


def upgrade():
    # Clean up existing duplicates: keep the oldest (lowest id) per (key, created_by)
    op.execute("""
        DELETE FROM secrets
        WHERE id NOT IN (
            SELECT MIN(id) FROM secrets
            GROUP BY key, created_by
        )
    """)

    # Drop the existing non-unique index
    op.drop_index("ix_secrets_key", table_name="secrets")

    # Add composite unique constraint
    op.create_unique_constraint(
        "uq_secrets_key_created_by", "secrets", ["key", "created_by"]
    )


def downgrade():
    op.drop_constraint("uq_secrets_key_created_by", "secrets", type_="unique")
    op.create_index("ix_secrets_key", "secrets", ["key"])
