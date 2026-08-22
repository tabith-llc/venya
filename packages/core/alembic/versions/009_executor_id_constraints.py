"""Add CHECK constraints on executor_id columns.

Enforces strict format validation at the database level:
- Lowercase alphanumeric + hyphens only (no underscores)
- 2-64 characters
- Starts and ends with alphanumeric
- DNS-label compatible (RFC 1035)

Revision ID: 009_executor_id_constraints
Revises: 008_token_binding
Create Date: 2026-08-14
"""

from collections.abc import Sequence

from alembic import op

revision: str = "009_executor_id_constraints"
down_revision: str | None = "008_token_binding"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

# Pattern enforced by CHECK constraints
EXECUTOR_ID_PATTERN = r"^[a-z0-9][a-z0-9-]{0,62}[a-z0-9]$"


def upgrade() -> None:
    """Add CHECK constraints on executor_id columns."""
    # users.user_id — executor_id becomes user_id for MTLS executors
    op.execute(f"ALTER TABLE users ADD CONSTRAINT chk_user_id_format " f"CHECK (user_id ~ '{EXECUTOR_ID_PATTERN}')")

    # executor_enrollment_tokens.executor_id
    op.execute(
        f"ALTER TABLE executor_enrollment_tokens ADD CONSTRAINT "
        f"chk_executor_enrollment_tokens_executor_id_format "
        f"CHECK (executor_id ~ '{EXECUTOR_ID_PATTERN}')"
    )

    # executor_certs.executor_id
    op.execute(
        f"ALTER TABLE executor_certs ADD CONSTRAINT "
        f"chk_executor_certs_executor_id_format "
        f"CHECK (executor_id ~ '{EXECUTOR_ID_PATTERN}')"
    )


def downgrade() -> None:
    """Remove CHECK constraints on executor_id columns."""
    op.execute("ALTER TABLE users DROP CONSTRAINT IF EXISTS chk_user_id_format")
    op.execute(
        "ALTER TABLE executor_enrollment_tokens "
        "DROP CONSTRAINT IF EXISTS chk_executor_enrollment_tokens_executor_id_format"
    )
    op.execute("ALTER TABLE executor_certs " "DROP CONSTRAINT IF EXISTS chk_executor_certs_executor_id_format")
