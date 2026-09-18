# Copyright (c) 2026 Tabith LLC.
# Use of this source code is governed by the Business Source License 1.1
# included in the LICENSE file at the root of this repository. As of the
# Change Date listed there, the work is available under MPL 2.0.
# SPDX-License-Identifier: BUSL-1.1

"""Single-active key-version invariant (partial unique index)

Revision ID: 028
Revises: 027
Create Date: 2026-09-17

Key rotation is synchronous bookkeeping under single-KEK alpha semantics
(ticket key-rotation-worker-missing, option-2 ruling): rotate flips `active`
in one transaction. The at-most-one-active invariant is enforced at the DB
level so concurrent rotations cannot both commit an active row: a partial
unique index over (active) WHERE active — every row the predicate selects
carries the same indexed value, so a second active row violates uniqueness.
Portable across PostgreSQL (installer path) and SQLite (dev/test).

The pre-clean UPDATE is defensive: legacy DBs are expected to carry 0 or 1
active rows (the pre-fix rotate route never activated anything), but the
index creation must not fail on a customer install regardless — extra actives
are deactivated keeping the newest.
"""

import sqlalchemy as sa
from alembic import op

revision = "028"
down_revision = "027"
branch_labels = None
depends_on = None

INDEX_NAME = "uq_key_versions_single_active"

# Portable: boolean `active` is truthy in WHERE on both dialects; the
# `false` literal and ORDER BY/LIMIT subquery are valid on both.
DEACTIVATE_EXTRA_ACTIVE = (
    "UPDATE key_versions SET active = false WHERE active AND id NOT IN "
    "(SELECT id FROM key_versions WHERE active ORDER BY created_at DESC, id DESC LIMIT 1)"
)


def upgrade() -> None:
    op.execute(DEACTIVATE_EXTRA_ACTIVE)
    op.create_index(
        INDEX_NAME,
        "key_versions",
        ["active"],
        unique=True,
        postgresql_where=sa.text("active"),
        sqlite_where=sa.text("active"),
    )


def downgrade() -> None:
    op.drop_index(INDEX_NAME, table_name="key_versions")
