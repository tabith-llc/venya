# Copyright (c) 2026 Tabith LLC.
# Use of this source code is governed by the Business Source License 1.1
# included in the LICENSE file at the root of this repository. As of the
# Change Date listed there, the work is available under MPL 2.0.
# SPDX-License-Identifier: BUSL-1.1

"""Registry for the core's own relay client credential presented at executor :8443

Revision ID: 040
Revises: 039
Create Date: 2026-10-17

Part of #597. The credential the CORE presents when it dials an executor relay
listener is minted outside the product — `install-venya-core.sh:1005-1023` runs
`openssl ecparam` + `openssl req` + `openssl x509 -req` straight to
`/etc/venya/relay/relay-client.crt` (CN `${CORE_HOSTNAME}-relay`, `-days 365`,
EKU clientAuth-only). It entered no table, so it had no revocation path: the only
revocation tables in the tree were `executor_cert_revocations` (001-era) and
`admin_cert_revocations`, and the CRL the same CA mints is drawn from
`ExecutorCertRevocation` alone (`server/ca.py:generate_crl`, query at :760).

Measured before this row (s134, `flash5-586-listener-door-s134-report.md`): a
`VERIFY_CRL_CHECK_LEAF` bolted to the listener door ADMITS the legitimate
:8443 peer, because that peer's serial is in no table — the gap is population,
not flag. This migration supplies the population.

Columns and their `models.py` declarations (`core.iam.models.CoreRelayCredential`)
are 1:1; `serial_number` carries the unique constraint that makes an idempotent
boot-time ingest safe (upsert by serial), and the partial index on
`revoked_at IS NOT NULL` is the read the revocation feed performs — the live
rows are the fleet's steady state and are never what the poll wants.

Reversible: `downgrade()` drops the index then the table, so a rollback of this
migration removes exactly what it added and touches no other relation.

Tables added:
  core_relay_credentials
"""

import sqlalchemy as sa
from alembic import op

revision = "040"
down_revision = "039"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "core_relay_credentials",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("serial_number", sa.String(64), nullable=False),
        sa.Column("common_name", sa.String(128), nullable=False),
        sa.Column("hostname", sa.String(128), nullable=True),
        sa.Column("cert_fingerprint", sa.String(64), nullable=True),
        sa.Column("public_key_hash", sa.String(64), nullable=True),
        sa.Column("signing_ca_subject", sa.String(255), nullable=True),
        sa.Column("signing_ca_aki", sa.String(64), nullable=True),
        sa.Column("issued_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("not_after", sa.DateTime(timezone=True), nullable=True),
        sa.Column("registered_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("revoked_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("revoke_reason", sa.Text(), nullable=True),
        sa.UniqueConstraint("serial_number", name="uq_core_relay_credentials_serial_number"),
    )
    op.create_index(
        "ix_core_relay_credentials_common_name",
        "core_relay_credentials",
        ["common_name"],
    )
    # The feed's read: revoked rows only. Partial, so the live steady state stays out of it.
    op.create_index(
        "ix_core_relay_credentials_revoked_at",
        "core_relay_credentials",
        ["revoked_at"],
        postgresql_where=sa.text("revoked_at IS NOT NULL"),
    )


def downgrade() -> None:
    op.drop_index("ix_core_relay_credentials_revoked_at", table_name="core_relay_credentials")
    op.drop_index("ix_core_relay_credentials_common_name", table_name="core_relay_credentials")
    op.drop_table("core_relay_credentials")
