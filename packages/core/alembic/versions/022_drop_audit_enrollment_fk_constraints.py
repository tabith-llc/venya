# Copyright (c) 2026 Tabith LLC.
# Use of this source code is governed by the Business Source License 1.1
# included in the LICENSE file at the root of this repository. As of the
# Change Date listed there, the work is available under MPL 2.0.
# SPDX-License-Identifier: BUSL-1.1

"""Drop FK on executor_enrollment_tokens.created_by and audit_events.user_id

mTLS admin identities (cert CN) have no row in users — the FK made
INSERT fail. Both columns are audit fields that should store the auth
principal regardless of authentication mechanism.

Revision ID: 022
Revises: 021
"""
from alembic import op

revision = "022"
down_revision = "021"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # executor_enrollment_tokens.created_by — named FK, made CASCADE in 019
    op.drop_constraint(
        "fk_executor_enrollment_tokens_created_by",
        "executor_enrollment_tokens",
        type_="foreignkey",
    )
    # audit_events.user_id — inline FK from migration 001
    # PostgreSQL convention names inline FKs {table}_{column}_fkey.
    # Verified: audit_events_user_id_fkey
    op.drop_constraint(
        "audit_events_user_id_fkey",
        "audit_events",
        type_="foreignkey",
    )


def downgrade() -> None:
    op.create_foreign_key(
        "audit_events_user_id_fkey",
        "audit_events",
        "users",
        ["user_id"],
        ["user_id"],
    )
    op.create_foreign_key(
        "fk_executor_enrollment_tokens_created_by",
        "executor_enrollment_tokens",
        "users",
        ["created_by"],
        ["user_id"],
        ondelete="CASCADE",
    )
