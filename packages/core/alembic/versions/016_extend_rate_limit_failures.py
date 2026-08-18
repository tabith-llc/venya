"""extend rate_limit_failures to general-purpose rate limit counter table

Revision ID: 016
Revises: 015
Create Date: 2026-08-18

Repurposes the unused RateLimitFailure table from per-user failure tracking
to a general-purpose fixed-window rate limit counter table.

Old schema: (user_id PK, failed_attempts, window_start)
New schema: (identifier PK, endpoint_type PK, window_start PK, count)

identifier = IP address or user_id depending on scope
endpoint_type = "generic", "auth", or "break_glass"
window_start = fixed window bucket start
count = atomic counter incremented via UPSERT

Fixed-window buckets (not sliding window). A burst at window boundary
allows up to 2x the limit — acceptable for this use case.
"""

from alembic import op
import sqlalchemy as sa

revision = "016"
down_revision = "015"
branch_labels = None
depends_on = None


def upgrade():
    # Drop existing table (H-06 notes it was unused, so no data loss concern)
    op.drop_table("rate_limit_failures")

    # Recreate with new schema: composite PK for fixed-window counters
    op.create_table(
        "rate_limit_failures",
        sa.Column("identifier", sa.String(64), nullable=False),
        sa.Column("endpoint_type", sa.String(16), nullable=False),
        sa.Column("window_start", sa.DateTime(timezone=True), nullable=False),
        sa.Column("count", sa.Integer, server_default="0", nullable=False),
        sa.PrimaryKeyConstraint(
            "identifier", "endpoint_type", "window_start",
            name="pk_rate_limit_failures",
        ),
    )

    # Index for efficient cleanup of expired windows
    op.create_index(
        "ix_rate_limit_failures_window",
        "rate_limit_failures",
        ["window_start"],
    )


def downgrade():
    # Restore original schema
    op.drop_table("rate_limit_failures")

    op.create_table(
        "rate_limit_failures",
        sa.Column("user_id", sa.String(64), primary_key=True),
        sa.Column("failed_attempts", sa.Integer, server_default="0", nullable=False),
        sa.Column("window_start", sa.DateTime(timezone=True), nullable=False),
    )
