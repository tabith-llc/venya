# Copyright (c) 2026 Tabith LLC.
# Use of this source code is governed by the Business Source License 1.1
# included in the LICENSE file at the root of this repository. As of the
# Change Date listed there, the work is available under MPL 2.0.
# SPDX-License-Identifier: BUSL-1.1

"""Add the ON DELETE CASCADE clauses models.py declares but the schema never got

Revision ID: 039
Revises: 038
Create Date: 2026-10-13

Part of #591. ``models.py`` declares ``ondelete="CASCADE"`` at 10 sites; 8 of
them exist in the schema (7 created by migration 019, one minted by 036). The
two below were declared and never built, so the schema disagreed with the
ORM — a path that TRUSTS the declaration (the ops clear, an offboarding
script, a customer's own SQL) got an FK violation instead of a cascade:

  execution_sessions.user_id — 025 created the table with a plain inline
      ``sa.ForeignKey("users.user_id")``; 019 predates that table, so nothing
      ever added the clause.
  role_members.role_id — 001:57 created the FK unnamed with no ``ondelete``;
      019 repaired only the sibling ``role_members.user_id``.

Same drop-then-create shape as 019, with the constraint names those two
creations inherited. PostgreSQL names an unnamed foreign key
``{table}_{column}_fkey`` — the same rule 018, 019 and 022 already rely on for
columns created the same way (``enrollment_tokens_user_id_fkey`` from an inline
001 column FK, ``role_members_user_id_fkey`` and ``audit_events_user_id_fkey``
from unnamed 001 ``sa.ForeignKeyConstraint`` calls), and the guard in
``tests/test_dropped_fk_model_drift.py`` pins it against this tree.

The product's admin delete route already removes these rows by hand, so no
route behaviour changes here: this makes the declared clause real for every
path that does not go through the route.

Tables updated:
  execution_sessions.user_id
  role_members.role_id
"""

from alembic import op

revision = "039"
down_revision = "038"
branch_labels = None
depends_on = None

# (table, constraint_name, column, ref_table, ref_column) — 019's shape.
CASCADE_FKS = [
    ("execution_sessions", "execution_sessions_user_id_fkey", "user_id", "users", "user_id"),
    ("role_members", "role_members_role_id_fkey", "role_id", "roles", "id"),
]


def upgrade():
    for table, constraint, column, ref_table, ref_col in CASCADE_FKS:
        op.drop_constraint(constraint, table, type_="foreignkey")
        op.create_foreign_key(
            constraint,
            table,
            ref_table,
            [column],
            [ref_col],
            ondelete="CASCADE",
        )


def downgrade():
    for table, constraint, column, ref_table, ref_col in CASCADE_FKS:
        op.drop_constraint(constraint, table, type_="foreignkey")
        op.create_foreign_key(
            constraint,
            table,
            ref_table,
            [column],
            [ref_col],
        )
