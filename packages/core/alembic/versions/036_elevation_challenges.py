# Copyright (c) 2026 Tabith LLC.
# Use of this source code is governed by the Business Source License 1.1
# included in the LICENSE file at the root of this repository. As of the
# Change Date listed there, the work is available under MPL 2.0.
# SPDX-License-Identifier: BUSL-1.1

"""elevation_challenges table

Revision ID: 036
Revises: 035
Create Date: 2026-10-07

#528 elevation-challenge-state-process-memory-only: the pending elevation
ceremony's auth binding (user, session) lived in app.state — per-process.
A multi-worker core could issue on one worker and assert on another
(401 "challenge not found"), and a restart mid-ceremony lost the state;
the fix moves the binding to this table so every worker reads the same
record, and the claim is an atomic single-consume UPDATE (house pattern:
enrollment_tokens.state). session_id carries no DB-level FK — same ruling
as elevation_tokens.session_id (035): bulk sweeps and per-engine FK
behavior make the lifecycle rule an application rule. user_id does carry
the FK + CASCADE, mirroring every other credential-bearing table here.
"""

import sqlalchemy as sa
from alembic import op

revision = "036"
down_revision = "035"
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        "elevation_challenges",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("challenge_id", sa.String(64), nullable=False),
        sa.Column("user_id", sa.String(64), nullable=False),
        sa.Column("session_id", sa.Integer(), nullable=True),
        sa.Column("state", sa.String(16), nullable=False, server_default="created"),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(
            ["user_id"],
            ["users.user_id"],
            name="fk_elevation_challenges_user_id",
            ondelete="CASCADE",
        ),
        sa.UniqueConstraint("challenge_id", name="uq_elevation_challenges_challenge_id"),
    )
    op.create_index(
        "ix_elevation_challenges_challenge_id",
        "elevation_challenges",
        ["challenge_id"],
    )
    op.create_index(
        "ix_elevation_challenges_user_id",
        "elevation_challenges",
        ["user_id"],
    )
    op.create_index(
        "ix_elevation_challenges_expires_at",
        "elevation_challenges",
        ["expires_at"],
    )


def downgrade():
    op.drop_index("ix_elevation_challenges_expires_at", table_name="elevation_challenges")
    op.drop_index("ix_elevation_challenges_user_id", table_name="elevation_challenges")
    op.drop_index("ix_elevation_challenges_challenge_id", table_name="elevation_challenges")
    op.drop_table("elevation_challenges")
