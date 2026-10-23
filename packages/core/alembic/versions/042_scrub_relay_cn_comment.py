# Copyright (c) 2026 Tabith LLC.
# Use of this source code is governed by the Business Source License 1.1
# included in the LICENSE file at the root of this repository. As of the
# Change Date listed there, the work is available under MPL 2.0.
# SPDX-License-Identifier: BUSL-1.1

"""Scrub a development-site hostname out of a shipped column comment — #697

Revision ID: 042
Revises: 041
Create Date: 2026-10-21

The owner ruled 2026-10-21 that the beta artifact must not carry private
operator identifiers: "beta release cannot happen with this info present! we
will scrub BEFORE tagging." ``CoreRelayCredential.common_name``
(``models.py:782``) declared its example CN as a real development host, and a
column comment IS shipped DDL — the precedent in this very chain is 012 (three
``comment=`` clauses) and 024 (one) — so the model edit lands here too.

Only the example string changes. The column's type, nullability, length and
index are untouched, so no row and no query reads differently.

``downgrade()`` clears the comment rather than restoring the previous text:
the earlier text named a development host, which is the thing this migration
exists to remove. Restoring it in a downgrade would put the identifier back
into a shipped artifact, and into a fresh install on any rollback.

Tables altered (no table created, none dropped):
  core_relay_credentials
"""

import sqlalchemy as sa
from alembic import op

revision = "042"
down_revision = "041"
branch_labels = None
depends_on = None

#: The comment the model declares. Mirrors `models.py:782` — an interlock test
#: fails if the two ever drift apart, because a comment that lives only in the
#: ORM is the drift this leg found (see the report's autogenerate section).
COLUMN_COMMENT = "Subject CN as presented, e.g. 'core-1-relay' — matched against relay_client_ids"


def upgrade() -> None:
    op.alter_column(
        "core_relay_credentials",
        "common_name",
        existing_type=sa.String(128),
        existing_nullable=False,
        comment=COLUMN_COMMENT,
    )


def downgrade() -> None:
    op.alter_column(
        "core_relay_credentials",
        "common_name",
        existing_type=sa.String(128),
        existing_nullable=False,
        comment=None,
    )
