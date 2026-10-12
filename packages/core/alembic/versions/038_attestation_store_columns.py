# Copyright (c) 2026 Tabith LLC.
# Use of this source code is governed by the Business Source License 1.1
# included in the LICENSE file at the root of this repository. As of the
# Change Date listed there, the work is available under MPL 2.0.
# SPDX-License-Identifier: BUSL-1.1

"""attestation store columns on webauthn_credentials (queue #2, leg 1: store, not enforce)

Revision ID: 038
Revises: 037
Create Date: 2026-10-13

Yubico's relying-party guidance says to store the raw attestation object with
the credential so attestation policy can act retroactively ("store the
verbatim response, including the attestation statement"); today the server
parsed it and discarded it. This migration adds the three record-only
columns:

- attestation_fmt      — the attestation statement format as sent ("packed",
                         "none", ...); String(32)
- aaguid               — canonical 8-4-4-4-12 hex string from the attested
                         credential data; String(36)
- attestation_object   — the verbatim CBOR bytes as received (base64url
                         decoded); LargeBinary, same blob shape as public_key

All nullable: rows predating this migration carry NULL (no backfill — the
ceremony bytes are gone), and every registration served from here on writes
all three. NO enforcement, NO chain verification, NO trust roots in this
change — those are queue #2 leg 2. add_column only, dialect-portable DDL.
"""

import sqlalchemy as sa
from alembic import op

revision = "038"
down_revision = "037"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("webauthn_credentials", sa.Column("attestation_fmt", sa.String(length=32), nullable=True))
    op.add_column("webauthn_credentials", sa.Column("aaguid", sa.String(length=36), nullable=True))
    op.add_column("webauthn_credentials", sa.Column("attestation_object", sa.LargeBinary(), nullable=True))


def downgrade() -> None:
    op.drop_column("webauthn_credentials", "attestation_object")
    op.drop_column("webauthn_credentials", "aaguid")
    op.drop_column("webauthn_credentials", "attestation_fmt")
