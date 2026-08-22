"""browser enrollment — no schema changes needed

All enrollment_tokens columns are defined in 001_initial_schema.

Revision ID: 005_browser_enrollment
Revises: 004_init_fido2
Create Date: 2026-08-06
"""

from collections.abc import Sequence

# revision identifiers, used by Alembic.
revision: str = "005_browser_enrollment"
down_revision: str | None = "004_init_fido2"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    pass


def downgrade() -> None:
    pass
