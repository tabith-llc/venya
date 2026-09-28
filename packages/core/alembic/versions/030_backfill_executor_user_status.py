# Copyright (c) 2026 Tabith LLC.
# Use of this source code is governed by the Business Source License 1.1
# included in the LICENSE file at the root of this repository. As of the
# Change Date listed there, the work is available under MPL 2.0.
# SPDX-License-Identifier: BUSL-1.1

"""users backfill — executor mtls identities stuck at pending_enrollment

Revision ID: 030
Revises: 029
Create Date: 2026-09-26

Registration auto-created the users-side identity row without a status, so
every executor identity inherited the human default 'pending_enrollment' and
nothing ever flipped it (the transition lives in the WebAuthn enrollment
path, which mtls identities never traverse). The route fix births new rows
active and self-heals on re-registration; this data migration repairs
EXISTING installs without requiring every executor to re-register. Scoped
WHERE auth_mode='mtls' AND status='pending_enrollment' — human rows are
never touched. Portable across PostgreSQL (installer path) and SQLite
(dev/test): UPDATE + COALESCE + CURRENT_TIMESTAMP exist in both.
"""

from alembic import op

revision = "030"
down_revision = "029"
branch_labels = None
depends_on = None

BACKFILL_MTLS_STATUS = (
    "UPDATE users SET status='active', "
    "enrolled_at=COALESCE(enrolled_at, CURRENT_TIMESTAMP) "
    "WHERE auth_mode='mtls' AND status='pending_enrollment'"
)


def upgrade() -> None:
    op.execute(BACKFILL_MTLS_STATUS)


def downgrade() -> None:
    # Data backfill is not reliably reversible: post-fix, the route itself
    # activates rows, so a reverse UPDATE cannot distinguish migrated rows
    # from legitimately-active ones. Downgrade intentionally leaves data
    # as-is (honest no-op) rather than corrupting live identities.
    pass
