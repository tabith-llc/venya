"""elevation tokens for browser secret unmasking

Revision ID: 006_elevation_tokens
Revises: 005_browser_enrollment
Create Date: 2026-08-06
"""

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision: str = "006_elevation_tokens"
down_revision: Union[str, None] = "005_browser_enrollment"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "elevation_tokens",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("token_hash", sa.String(64), nullable=False),
        sa.Column("user_id", sa.String(64), nullable=False),
        sa.Column("expires_at", sa.DateTime(), nullable=False),
        sa.Column("used", sa.Boolean(), nullable=False, server_default="false"),
        sa.ForeignKeyConstraint(["user_id"], ["users.user_id"]),
        sa.UniqueConstraint("token_hash", name="uq_elevation_tokens_token_hash"),
    )
    op.create_index(
        "ix_elevation_tokens_token_hash",
        "elevation_tokens",
        ["token_hash"],
    )
    op.create_index(
        "ix_elevation_tokens_user_id",
        "elevation_tokens",
        ["user_id"],
    )
    op.create_index(
        "ix_elevation_tokens_expires_at",
        "elevation_tokens",
        ["expires_at"],
    )


def downgrade() -> None:
    op.drop_index("ix_elevation_tokens_expires_at", table_name="elevation_tokens")
    op.drop_index("ix_elevation_tokens_user_id", table_name="elevation_tokens")
    op.drop_index("ix_elevation_tokens_token_hash", table_name="elevation_tokens")
    op.drop_table("elevation_tokens")
