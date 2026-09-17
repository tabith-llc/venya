# Copyright (c) 2026 Tabith LLC.
# Use of this source code is governed by the Business Source License 1.1
# included in the LICENSE file at the root of this repository. As of the
# Change Date listed there, the work is available under MPL 2.0.
# SPDX-License-Identifier: BUSL-1.1

"""Bootstrap the initial active key version (v1)

Revision ID: 027
Revises: 026
Create Date: 2026-09-17

Fresh installs previously had an empty key_versions table: GET
/api/v1/key-versions/active answered 503 and `venya store` required an
explicit --key-version v1 (ticket key-version-no-bootstrap). This seeds
exactly one active 'v1' row when — and only when — the table is empty;
existing installs with their own versions are untouched. The row is
bookkeeping: secret decryption never consults key_versions and labels are
stored without validation (ticket item-4c), so no key material is involved.
Rotation completion (a worker that flips active=True on rotate) remains a
separate concern — see ticket key-rotation-worker-missing.
"""

from alembic import op

revision = "027"
down_revision = "026"
branch_labels = None
depends_on = None

# Portable across PostgreSQL (installer path) and SQLite (dev/test):
# `true`/`false` literals and CURRENT_TIMESTAMP work on both; the no-FROM
# SELECT ... WHERE NOT EXISTS form is valid on both (verified empirically).
# Idempotent by construction — safe to re-run against a seeded table.
SEED_ACTIVE_V1 = (
    "INSERT INTO key_versions (version_label, created_at, active, rotation_pending) "
    "SELECT 'v1', CURRENT_TIMESTAMP, true, false "
    "WHERE NOT EXISTS (SELECT 1 FROM key_versions)"
)


def upgrade() -> None:
    op.execute(SEED_ACTIVE_V1)


def downgrade() -> None:
    # Data seed: downgrade must NOT delete key-version bookkeeping rows —
    # stored secrets may carry the 'v1' label. Deliberate no-op.
    pass
