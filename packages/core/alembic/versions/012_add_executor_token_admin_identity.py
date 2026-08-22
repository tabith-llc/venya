"""add executor token admin identity fields

Revision ID: 012
Revises: 011
Create Date: 2025-01-01

Adds forensic identity fields to executor_enrollment_tokens for admin
enrollment token creation tracking. Fields are nullified after 90 days
per retention policy.
"""

import sqlalchemy as sa
from alembic import op

revision = "012"
down_revision = "011"
branch_labels = None
depends_on = None


def upgrade():
    op.add_column(
        "executor_enrollment_tokens",
        sa.Column(
            "created_by_session_id",
            sa.String(64),
            nullable=True,
            comment="Forensic trace — nullify after 90 days per retention policy",
        ),
    )
    op.add_column(
        "executor_enrollment_tokens",
        sa.Column(
            "created_from_ip",
            sa.String(45),
            nullable=True,
            comment="Forensic trace — nullify after 90 days per retention policy",
        ),
    )
    op.add_column(
        "executor_enrollment_tokens",
        sa.Column(
            "created_from_user_agent",
            sa.String(256),
            nullable=True,
            comment="Forensic trace — nullify after 90 days per retention policy",
        ),
    )


def downgrade():
    op.drop_column("executor_enrollment_tokens", "created_from_user_agent")
    op.drop_column("executor_enrollment_tokens", "created_from_ip")
    op.drop_column("executor_enrollment_tokens", "created_by_session_id")
