# Copyright (c) 2026 Tabith LLC.
# Use of this source code is governed by the Business Source License 1.1
# included in the LICENSE file at the root of this repository. As of the
# Change Date listed there, the work is available under MPL 2.0.
# SPDX-License-Identifier: BUSL-1.1

"""add access_token_expires_at to sessions table

Revision ID: 034
Revises: 033
Create Date: 2026-10-02

#342: the advertised access-token TTL is enforced at bearer validation, which
needs the expiry on the row — the in-memory AccessToken's expires_at was
never persisted. Additive nullable column; the writer sites (session
creation, refresh) fill it and the middleware gate rejects NULL or past
timestamps (fail-closed). Old rows carry NULL until their next login.
"""

import sqlalchemy as sa
from alembic import op

revision = "034"
down_revision = "033"
branch_labels = None
depends_on = None


def upgrade():
    op.add_column("sessions", sa.Column("access_token_expires_at", sa.DateTime(timezone=True), nullable=True))


def downgrade():
    op.drop_column("sessions", "access_token_expires_at")
