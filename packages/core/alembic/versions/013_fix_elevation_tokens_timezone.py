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

from alembic import op
import sqlalchemy as sa

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
