# Copyright (c) 2026 Tabith LLC.
# Use of this source code is governed by the Business Source License 1.1
# included in the LICENSE file at the root of this repository. As of the
# Change Date listed there, the work is available under MPL 2.0.
# SPDX-License-Identifier: BUSL-1.1

"""add recovery_code_hash to users table

Revision ID: 004_init_fido2
Revises: 003_webauthn_credentials
Create Date: 2026-08-05
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision: str = "004_init_fido2"
down_revision: str | None = "003_webauthn_credentials"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column(
        "users",
        sa.Column("recovery_code_hash", sa.String(64), nullable=True),
    )


def downgrade() -> None:
    op.drop_column("users", "recovery_code_hash")
