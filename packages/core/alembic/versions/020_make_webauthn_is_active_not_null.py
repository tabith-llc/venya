# Copyright (c) 2026 Tabith LLC.
# Use of this source code is governed by the Business Source License 1.1
# included in the LICENSE file at the root of this repository. As of the
# Change Date listed there, the work is available under MPL 2.0.
# SPDX-License-Identifier: BUSL-1.1

"""Make webauthn_credentials.is_active NOT NULL

Revision ID: 020
Revises: 019
Create Date: 2026-08-18

M-02: WebAuthnCredential.is_active was nullable=True (SQLAlchemy default),
meaning == True filters silently dropped NULL rows. Two-part fix:
1. Added nullable=False to the column definition in models.py
2. Replaced all 7 occurrences of == True with .is_(True) in server code

The nullable=False migration backfills any existing NULL rows to False,
then adds the NOT NULL constraint. Semantically correct: credentials are
either active or inactive — no pending/unknown state.
"""

import sqlalchemy as sa
from alembic import op

revision = "020"
down_revision = "019"
branch_labels = None
depends_on = None


def upgrade():
    # Backfill any NULL values to False, then add NOT NULL constraint
    op.execute("UPDATE webauthn_credentials SET is_active = FALSE WHERE is_active IS NULL")
    op.alter_column("webauthn_credentials", "is_active", existing_type_=sa.BOOLEAN(), nullable=False)


def downgrade():
    op.alter_column("webauthn_credentials", "is_active", existing_type_=sa.BOOLEAN(), nullable=True)
