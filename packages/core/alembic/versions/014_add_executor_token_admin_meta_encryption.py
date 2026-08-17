"""add executor token admin metadata encryption

Revision ID: 014
Revises: 013
Create Date: 2026-08-16

Adds encrypted admin metadata columns to executor_enrollment_tokens.
Forensic identity fields (ip, ua, sid) are encrypted as a JSON blob
using the core's DEK/KEK scheme. Columns are nullable for backward
compatibility with existing rows. Nullified after 90 days per retention
policy.
"""

from alembic import op
import sqlalchemy as sa

revision = "014"
down_revision = "013"
branch_labels = None
depends_on = None


def upgrade():
    op.add_column(
        "executor_enrollment_tokens",
        sa.Column("admin_meta_wrapped_dek", sa.LargeBinary, nullable=True),
    )
    op.add_column(
        "executor_enrollment_tokens",
        sa.Column("admin_meta_nonce", sa.LargeBinary, nullable=True),
    )
    op.add_column(
        "executor_enrollment_tokens",
        sa.Column("admin_meta_ciphertext", sa.LargeBinary, nullable=True),
    )


def downgrade():
    op.drop_column("executor_enrollment_tokens", "admin_meta_ciphertext")
    op.drop_column("executor_enrollment_tokens", "admin_meta_nonce")
    op.drop_column("executor_enrollment_tokens", "admin_meta_wrapped_dek")
