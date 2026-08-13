"""browser enrollment — no schema changes needed

All enrollment_tokens columns are defined in 001_initial_schema.

Revision ID: 005_browser_enrollment
Revises: 004_init_fido2
Create Date: 2026-08-06
"""

from typing import Sequence, Union

from alembic import op

# revision identifiers, used by Alembic.
revision: str = "005_browser_enrollment"
down_revision: Union[str, None] = "004_init_fido2"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    pass


def downgrade() -> None:
    pass
