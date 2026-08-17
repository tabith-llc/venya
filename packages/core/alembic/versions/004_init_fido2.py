"""add recovery_code_hash to users table

Revision ID: 004_init_fido2
Revises: 003_webauthn_credentials
Create Date: 2026-08-05
"""

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision: str = "004_init_fido2"
down_revision: Union[str, None] = "003_webauthn_credentials"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column(
        "users",
        sa.Column("recovery_code_hash", sa.String(64), nullable=True),
    )


def downgrade() -> None:
    op.drop_column("users", "recovery_code_hash")
