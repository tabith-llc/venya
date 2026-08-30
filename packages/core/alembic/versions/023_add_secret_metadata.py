"""Add metadata JSONB column to secrets table

Revision ID: 023
Revises: 022
Create Date: 2026-08-29
"""

import sqlalchemy as sa
from alembic import op

revision = "023"
down_revision = "022"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # Add nullable JSONB column with empty dict default
    op.add_column(
        "secrets",
        sa.Column("metadata", sa.JSON(), nullable=True, server_default="{}"),
    )

    # GIN index for JSONB querying — makes metadata->>'executor' = 'web-server-3' fast
    op.execute("CREATE INDEX ix_secrets_metadata ON secrets USING gin (metadata)")


def downgrade() -> None:
    op.execute("DROP INDEX IF EXISTS ix_secrets_metadata")
    op.drop_column("secrets", "metadata")
