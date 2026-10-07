# Copyright (c) 2026 Tabith LLC.
# Use of this source code is governed by the Business Source License 1.1
# included in the LICENSE file at the root of this repository. As of the
# Change Date listed there, the work is available under MPL 2.0.
# SPDX-License-Identifier: BUSL-1.1

"""add session_id to elevation_tokens

Revision ID: 035
Revises: 034
Create Date: 2026-10-07

#527 elevation-not-session-bound: an elevation token was bound to a USER
only, so it outlived the session that earned it (logout left the row
consumable for its 60 s life). Add a nullable session_id — the session
that performed the ceremony — and SessionManager.revoke_session deletes
bound rows with the session. Nullable by design: pre-fix rows carry NULL
(no backfill — the issuing session is not reconstructable after the fact)
and stay consumable under the existing user+expiry checks; their own
60-second TTL bounds the residue at upgrade time. Indexed: the revoke
path filters on it. No DB-level FK (sessions.id referenced in code, not
schema — the bulk SQL sweeps and SQLite-permissive installs make an
engine-enforced FK behave divergently; lifecycle rule lives in
session_manager).
"""

import sqlalchemy as sa
from alembic import op

revision = "035"
down_revision = "034"
branch_labels = None
depends_on = None


def upgrade():
    op.add_column("elevation_tokens", sa.Column("session_id", sa.Integer(), nullable=True))
    op.create_index("ix_elevation_tokens_session_id", "elevation_tokens", ["session_id"])


def downgrade():
    op.drop_index("ix_elevation_tokens_session_id", table_name="elevation_tokens")
    op.drop_column("elevation_tokens", "session_id")
