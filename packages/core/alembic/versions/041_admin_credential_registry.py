# Copyright (c) 2026 Tabith LLC.
# Use of this source code is governed by the Business Source License 1.1
# included in the LICENSE file at the root of this repository. As of the
# Change Date listed there, the work is available under MPL 2.0.
# SPDX-License-Identifier: BUSL-1.1

"""Registry of the admin credentials this core issued or holds — the population #684 lacked

Revision ID: 041
Revises: 040
Create Date: 2026-10-20

Part of #684 (`admin-revoke-accepts-a-serial-no-credential-holds`). The defective route
validated the FORMAT of the operator's string and then blind-inserted an
`AdminCertRevocation` row, so `venya admin revoke-admin-cert --serial <any hex>` exited 0
and wrote a revocation naming a serial no credential ever held, while the live admin
credential kept transacting — measured physically by a prior worker lane at leg 232, against the
sibling relay route (`core_relay_certs.py`), which refuses the identical string with
`REFUSE_UNREGISTERED`. A membership check needs something to be a member OF, and on this
plane nothing existed: `AdminCertRevocation` (`models.py:613`) was the only
admin-certificate relation in the tree, and using it would be circular — it is what the
verb writes.

This supplies the population, in the shape #597 shipped for the relay plane
(`040_core_relay_credential_registry.py` + `server/relay_registry.py` boot ingest), with
ONE deliberate divergence: there is no `revoked_at` column here. The admin plane already
has a revocation authority (`AdminCertRevocation`) and `AdminCAManager.generate_crl`
draws from it, so a second revocation column would be a second source of truth for one
fact. This table answers exactly one question — "did this core ever vouch for a
credential with this serial" — and membership is all it answers.

`serial_number` carries the unique constraint that makes the boot ingest idempotent
(upsert by serial, `source` never rewritten), and it is stored in the ONE canonical WRITE
form (`canonical_serial`: lowercase hex, zero-padded to a 16-digit MINIMUM, never a mask)
per #481 — every lookup compares it with `serial_match_clause`, so a legacy spelling of
the same integer still matches and a re-mint that changes the serial creates a second row
rather than silently rewriting the history of the first. The old serial stays revocable,
which is the whole point of a registry.

Reversible: `downgrade()` drops the index then the table, removing exactly what this
migration added and touching no other relation.

Tables added:
  admin_credentials
"""

import sqlalchemy as sa
from alembic import op

revision = "041"
down_revision = "040"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "admin_credentials",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("serial_number", sa.String(64), nullable=False),
        sa.Column("common_name", sa.String(128), nullable=False),
        sa.Column("source", sa.String(32), nullable=False),
        sa.Column("cert_fingerprint", sa.String(64), nullable=True),
        sa.Column("public_key_hash", sa.String(64), nullable=True),
        sa.Column("issued_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("not_after", sa.DateTime(timezone=True), nullable=True),
        sa.Column("registered_at", sa.DateTime(timezone=True), nullable=False),
        sa.UniqueConstraint("serial_number", name="uq_admin_credentials_serial_number"),
    )
    # The operator-facing read: which writer put this credential in the population.
    op.create_index("ix_admin_credentials_source", "admin_credentials", ["source"])


def downgrade() -> None:
    op.drop_index("ix_admin_credentials_source", table_name="admin_credentials")
    op.drop_table("admin_credentials")
