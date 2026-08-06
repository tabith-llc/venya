"""add created_at and failed_attempts to enrollment_tokens

Revision ID: 005_browser_enrollment
Revises: 004_init_fido2
Create Date: 2026-08-06
"""

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision: str = "005_browser_enrollment"
down_revision: Union[str, None] = "004_init_fido2"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column(
        "enrollment_tokens",
        sa.Column("created_at", sa.DateTime(), nullable=False, server_default=sa.text("now()")),
    )
    op.add_column(
        "enrollment_tokens",
        sa.Column("failed_attempts", sa.Integer(), nullable=False, server_default="0"),
    )


def downgrade() -> None:
    op.drop_column("enrollment_tokens", "failed_attempts")
    op.drop_column("enrollment_tokens", "created_at")
