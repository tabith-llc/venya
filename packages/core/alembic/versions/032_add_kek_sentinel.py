# Copyright (c) 2026 Tabith LLC.
# Use of this source code is governed by the Business Source License 1.1
# included in the LICENSE file at the root of this repository. As of the
# Change Date listed there, the work is available under MPL 2.0.
# SPDX-License-Identifier: BUSL-1.1

"""kek_sentinel — boot-time proof that the encryption passphrase matches stored key material

Revision ID: 032
Revises: 031
Create Date: 2026-10-01

Ticket server-silent-boot-wrong-kek-passphrase (DR-drill D-6): a restore with a
WRONG VENYA_DB__PASSPHRASE booted green because the KEK is lazy-derived from
passphrase + persisted salt — the mismatch only surfaced at the first unwrap,
after the wrong KEK had already wrapped NEW DEKs (those secrets permanently
unrecoverable). The server now unwraps this single-row sentinel at every
startup and aborts before any new wrapping can happen.

One logical row: a fixed known plaintext wrapped under the KEK with the SAME
AES-256-KW envelope as secret DEKs (40 bytes) — no new crypto format, no
passphrase or plaintext stored. Portable schema DDL: op.create_table with sa
types, identical style to 025 (PostgreSQL installer path + SQLite dev/test).
"""

import sqlalchemy as sa
from alembic import op

revision = "032"
down_revision = "031"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "kek_sentinel",
        sa.Column("key", sa.String(64), nullable=False),
        sa.Column("wrapped_sentinel", sa.LargeBinary(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("key"),
    )


def downgrade() -> None:
    # Honest full reversal: drop the table. Boot verification then degrades to
    # the legacy DEK-sampling path (up to 5 stored envelopes judged ALL-fail),
    # and the row is re-mintable at the next successful store — no stored data
    # becomes unrecoverable by downgrading this migration.
    op.drop_table("kek_sentinel")
