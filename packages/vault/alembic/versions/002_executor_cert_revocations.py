"""executor cert revocations table

Revision ID: 002_executor_cert_revocations
Revises: 001_initial
Create Date: 2026-08-03
"""

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision: str = "002_executor_cert_revocations"
down_revision: Union[str, None] = "001_initial"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "executor_cert_revocations",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("serial_number", sa.String(64), nullable=False),
        sa.Column("executor_id", sa.String(64), nullable=True),
        sa.Column("revoked_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("reason", sa.Text(), nullable=True),
        sa.UniqueConstraint("serial_number", name="uq_executor_cert_revocations_serial_number"),
    )
    op.create_index(
        "ix_executor_cert_revocations_serial_number",
        "executor_cert_revocations",
        ["serial_number"],
    )
    op.create_index(
        "ix_executor_cert_revocations_revoked_at",
        "executor_cert_revocations",
        ["revoked_at"],
    )


def downgrade() -> None:
    op.drop_table("executor_cert_revocations")
