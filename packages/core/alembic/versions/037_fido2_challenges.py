# Copyright (c) 2026 Tabith LLC.
# Use of this source code is governed by the Business Source License 1.1
# included in the LICENSE file at the root of this repository. As of the
# Change Date listed there, the work is available under MPL 2.0.
# SPDX-License-Identifier: BUSL-1.1

"""fido2_challenges table

Revision ID: 037
Revises: 036
Create Date: 2026-10-08

#534 fido2-challenge-store-process-memory-only: the protocol half of a
pending WebAuthn ceremony (issued challenge bytes plus ceremony metadata)
lived in a per-process Fido2Store dict. A core restart between issuance
and the verifier's response lost it — the response 401'd — and any future
multi-worker routing fails the same way the #528 elevation binding did
before its table. This migration moves that state to the DB, with the
same atomic single-consume claim vocabulary as elevation_challenges (036).
`payload` holds the ceremony dict as JSON text; bytes values are
base64-tagged rather than stringified (raw_challenge,
existing_credential_ids).

DELIBERATE DIVERGENCE from 036: user_id carries NO foreign key. A
registration challenge can be issued while the user row is still
pending-created (init flow) or not present yet at all (the
enrollment-token flow binds the id; the row lands later), and an
untargeted login start carries an empty binding — a FK would refuse live
ceremonies. Rows are short-lived (pruned at the next challenge touch) and
need no cascade, so the lifecycle rule stays an application rule. Same
ruling class as elevation_challenges.session_id above and
audit_events.user_id (022).
"""

import sqlalchemy as sa
from alembic import op

revision = "037"
down_revision = "036"
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        "fido2_challenges",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("challenge_id", sa.String(64), nullable=False),
        sa.Column("user_id", sa.String(64), nullable=False),
        sa.Column("payload", sa.Text(), nullable=False),
        sa.Column("state", sa.String(16), nullable=False, server_default="created"),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.UniqueConstraint("challenge_id", name="uq_fido2_challenges_challenge_id"),
    )
    op.create_index(
        "ix_fido2_challenges_challenge_id",
        "fido2_challenges",
        ["challenge_id"],
    )
    op.create_index(
        "ix_fido2_challenges_user_id",
        "fido2_challenges",
        ["user_id"],
    )
    op.create_index(
        "ix_fido2_challenges_expires_at",
        "fido2_challenges",
        ["expires_at"],
    )


def downgrade():
    op.drop_index("ix_fido2_challenges_expires_at", table_name="fido2_challenges")
    op.drop_index("ix_fido2_challenges_user_id", table_name="fido2_challenges")
    op.drop_index("ix_fido2_challenges_challenge_id", table_name="fido2_challenges")
    op.drop_table("fido2_challenges")
