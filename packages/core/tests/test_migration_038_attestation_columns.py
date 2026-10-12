# Copyright (c) 2026 Tabith LLC.
# Use of this source code is governed by the Business Source License 1.1
# included in the LICENSE file at the root of this repository. As of the
# Change Date listed there, the work is available under MPL 2.0.
# SPDX-License-Identifier: BUSL-1.1

"""Migration 038 — attestation store columns on webauthn_credentials.

Kills the model-vs-schema pitfall class (UndefinedColumn on the fresh
install path): every column the leg-1 model declares must be added by this
migration, with the same name and a compatible type, and the ALTER must
actually APPLY on a scratch database carrying the pre-038 table shape.
upgrade()/downgrade() run through a real alembic Operations context against
SQLite here; the DDL is plain add_column (dialect-portable). The
PostgreSQL fresh-chain proof (alembic upgrade head on a clean PG DB) rides
the installer cell — this file pins the statement surface, the apply, and
the model parity; the 031 DCL interlock (testing pattern) is unchanged by
this migration.
"""

import importlib.util
import inspect
from pathlib import Path

import sqlalchemy as sa
from alembic.migration import MigrationContext
from alembic.operations import Operations
from core.iam.models import WebAuthnCredential
from sqlalchemy import create_engine
from sqlalchemy import inspect as sa_inspect

_MIGRATION_PATH = Path(__file__).resolve().parents[1] / "alembic" / "versions" / "038_attestation_store_columns.py"

# The pre-038 table shape: every current column EXCEPT the three the
# migration adds (kept as literal DDL so the test does not silently track
# the model — if a future column moves, this must be edited deliberately).
_PRE_038_DDL = """
CREATE TABLE webauthn_credentials (
    id INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT,
    user_id VARCHAR(64) NOT NULL,
    credential_id BLOB NOT NULL UNIQUE,
    public_key BLOB NOT NULL,
    sign_count INTEGER,
    label VARCHAR(64),
    is_active BOOLEAN,
    created_at DATETIME,
    last_used_at DATETIME
)
"""


def _load_migration():
    spec = importlib.util.spec_from_file_location("migration_038", _MIGRATION_PATH)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def test_migration_exists_and_chains_to_037():
    mod = _load_migration()
    assert mod.revision == "038"
    assert mod.down_revision == "037"


def test_migration_adds_exactly_the_model_columns():
    """Model/migration parity — the UndefinedColumn class, pinned at both ends."""
    mod = _load_migration()
    src = inspect.getsource(mod.upgrade)
    model_cols = WebAuthnCredential.__table__.c
    for name in ("attestation_fmt", "aaguid", "attestation_object"):
        assert f'"{name}"' in src, f"upgrade() must add_column {name}"
        assert name in model_cols, f"model must declare {name} (migration exists to serve it)"
    # type parity: strings sized as the migration declares them, blob like public_key
    assert model_cols["attestation_fmt"].type.length == 32
    assert model_cols["aaguid"].type.length == 36
    assert isinstance(model_cols["attestation_object"].type, sa.LargeBinary)
    # all record-only: nullable, matching the pre-038-row reality
    for name in ("attestation_fmt", "aaguid", "attestation_object"):
        assert model_cols[name].nullable is True


def test_upgrade_applies_on_scratch_db_and_downgrade_reverses(tmp_path):
    """Fresh-upgrade cell: the ALTER applies against the pre-038 shape, the
    columns come out with the right SQLite types, and downgrade removes them."""
    mod = _load_migration()
    engine = create_engine(f"sqlite:///{tmp_path}/mig.db")
    with engine.connect() as conn:
        conn.execute(sa.text(_PRE_038_DDL))
        conn.commit()

        ctx = MigrationContext.configure(conn)
        with Operations.context(ctx):
            mod.upgrade()

        cols = {c["name"]: c for c in sa_inspect(conn).get_columns("webauthn_credentials")}
        assert {"attestation_fmt", "aaguid", "attestation_object"} <= set(cols), "038 upgrade did not add all three"
        assert cols["attestation_fmt"]["type"].length == 32
        assert cols["aaguid"]["type"].length == 36
        for name in ("attestation_fmt", "aaguid", "attestation_object"):
            assert cols[name]["nullable"] is True

        # rows written before 038 read back with NULLs — no NOT-NULL surprise
        conn.execute(
            sa.text("INSERT INTO webauthn_credentials (user_id, credential_id, public_key) VALUES ('u', x'01', x'02')")
        )
        got = conn.execute(
            sa.text("SELECT attestation_fmt, aaguid, attestation_object FROM webauthn_credentials")
        ).one()
        assert got == (None, None, None)

        with Operations.context(ctx):
            mod.downgrade()
        cols = {c["name"] for c in sa_inspect(conn).get_columns("webauthn_credentials")}
        assert cols.isdisjoint({"attestation_fmt", "aaguid", "attestation_object"}), "downgrade must be a clean inverse"


def test_model_orm_write_reads_back_on_migrated_schema(tmp_path):
    """End-to-end of the pitfall itself: ORM insert through a schema produced
    by upgrade() (not create_all) flushes without UndefinedColumn."""
    mod = _load_migration()
    engine = create_engine(f"sqlite:///{tmp_path}/orm.db")
    with engine.connect() as conn:
        conn.execute(sa.text(_PRE_038_DDL))
        ctx = MigrationContext.configure(conn)
        with Operations.context(ctx):
            mod.upgrade()
        conn.commit()

    # users table must exist for the FK declaration (SQLite does not enforce
    # it by default; the raw DDL keeps this scratch schema hand-authored,
    # on purpose — see _PRE_038_DDL).
    with engine.connect() as conn:
        conn.exec_driver_sql("CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY, user_id VARCHAR(64) UNIQUE)")
        conn.commit()

    from core.iam.models import WebAuthnCredential as WC
    from sqlalchemy.orm import sessionmaker

    session = sessionmaker(bind=engine)()
    session.add(
        WC(
            user_id="u1",
            credential_id=b"c1",
            public_key=b"pk",
            sign_count=0,
            is_active=True,
            attestation_fmt="packed",
            aaguid="00010203-0405-0607-0809-0a0b0c0d0e0f",
            attestation_object=b"\xa3raw-bytes",
        )
    )
    session.commit()
    row = session.query(WC).filter_by(credential_id=b"c1").one()
    assert row.attestation_object == b"\xa3raw-bytes"
    assert row.attestation_fmt == "packed"
    session.close()
