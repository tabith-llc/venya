# Copyright (c) 2026 Tabith LLC.
# Use of this source code is governed by the Business Source License 1.1
# included in the LICENSE file at the root of this repository. As of the
# Change Date listed there, the work is available under MPL 2.0.
# SPDX-License-Identifier: BUSL-1.1

"""Migration 041 — the admin-credential registry #684 needed, proven on BOTH engines.

Kills the model-vs-schema pitfall class (UndefinedColumn on the fresh-install path),
same posture as ``test_migration_038_attestation_columns.py``: every column the
``AdminCredential`` model declares must be created by this migration, and the DDL must
actually APPLY. The #684 membership read (``admin_revoke_admin_cert`` refusing a serial
no credential holds) is only as real as this table, so its two structural guarantees —
the unique serial and the source index — are asserted against the engine the product
ships on, not only the SQLite one the unit suites use.

Coverage split, stated because the halves prove different things:
  * SQLite (always runs): ``upgrade()``/``downgrade()`` through a real alembic
    Operations context on a scratch DB stamped at 040, model parity, an ORM
    write/read-back on the migrated schema, and the unique serial enforced by the DB.
  * PostgreSQL (``VENYA_TEST_PG_URL``, skipif when unset): the PG-dialect render of
    040->041 applied into a throwaway SCHEMA — ``SERIAL`` identity, ``timestamptz``
    columns, the inline unique constraint and both indexes present, a duplicate serial
    refused by the database, and the rendered down-migration dropping index then table.

The PG half uses a scratch schema inside the database the URL names rather than a second
database: ``CREATE DATABASE`` needs a privilege the test roles are deliberately without
(the create-and-drop-ownership design in the venue notes). And the FULL
``alembic upgrade head`` chain cannot run on this venue either, by product design —
migration 031 fails loud when the installer-provisioned ``venya_audit`` role is absent.
The whole-chain fresh-install proof is therefore a separate physical cell (run once on a
cluster carrying the installer's roles); this file pins 041's own statement surface on
the shipping dialect.
"""

import datetime as dt
import importlib.util
import io
import os
import uuid
from contextlib import redirect_stdout
from pathlib import Path

import pytest
from alembic import command
from alembic.config import Config
from alembic.migration import MigrationContext
from alembic.operations import Operations
from core.iam.models import AdminCredential
from core.utils.cert_serial import serial_match_key
from sqlalchemy import create_engine
from sqlalchemy import event as sa_event
from sqlalchemy import inspect as sa_inspect
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session
from sqlalchemy.pool import NullPool

_MIGRATION_PATH = Path(__file__).resolve().parents[1] / "alembic" / "versions" / "041_admin_credential_registry.py"
_CORE_ROOT = Path(__file__).resolve().parents[1]
_PG_URL_ENV = "VENYA_TEST_PG_URL"
# One deadline, one name, shared by every PostgreSQL-gated cell (the #614 R1 posture): a
# read transaction left open would pin this cell's DDL forever.
_PG_DEADLINE = {"options": "-c lock_timeout=5000 -c statement_timeout=60000"}
_MODEL_COLUMNS = {
    "id",
    "serial_number",
    "common_name",
    "source",
    "cert_fingerprint",
    "public_key_hash",
    "issued_at",
    "not_after",
    "registered_at",
}


def _load_migration():
    spec = importlib.util.spec_from_file_location("migration_041", _MIGRATION_PATH)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def _pre_041_engine(tmp_path):
    """A scratch DB at the 040 face: the registry relation absent, version stamped 040.

    Foreign keys are switched ON at connect time (the #634 rule — a SQLite engine without
    the pragma declares constraints and enforces none, so a cell can pass on rows no real
    database would accept). 041 has no FKs itself, so the listener costs nothing here and
    keeps this file out of the #634 blind-site baseline instead of growing it.
    """
    engine = create_engine(f"sqlite:///{tmp_path / 'pre041.db'}")

    @sa_event.listens_for(engine, "connect")
    def _fk_on(dbapi_conn, _rec):
        cur = dbapi_conn.cursor()
        cur.execute("PRAGMA foreign_keys=ON")
        cur.close()

    with engine.begin() as conn:
        conn.exec_driver_sql("CREATE TABLE alembic_version (version_num VARCHAR(32) NOT NULL)")
        conn.exec_driver_sql("INSERT INTO alembic_version VALUES ('040')")
    return engine


def _apply(engine, fn):
    """Run one migration function through a real alembic Operations context (#038 shape)."""
    with engine.connect() as conn:
        ctx = MigrationContext.configure(conn)
        with Operations.context(ctx):
            fn()


# --------------------------------------------------------------------------------
# Statement surface + model parity (dialect-independent, always runs)
# --------------------------------------------------------------------------------


def test_migration_exists_and_chains_to_040():
    mod = _load_migration()
    assert mod.revision == "041"
    assert mod.down_revision == "040", "041 must chain onto the #597 relay registry, not fork the head"


def test_model_and_migration_declare_the_same_columns():
    """A column on the model that 041 does not create is an UndefinedColumn on install."""
    assert {c.name for c in AdminCredential.__table__.columns} == _MODEL_COLUMNS


# --------------------------------------------------------------------------------
# Apply + reverse on a scratch DB (SQLite; the Operations-context shape #038 set)
# --------------------------------------------------------------------------------


def test_upgrade_applies_on_scratch_db_and_downgrade_reverses(tmp_path):
    engine = _pre_041_engine(tmp_path)
    mod = _load_migration()
    _apply(engine, lambda: mod.upgrade())
    with engine.connect() as conn:
        insp = sa_inspect(conn)
        assert "admin_credentials" in insp.get_table_names(), "041 did not create the relation"
        assert {c["name"] for c in insp.get_columns("admin_credentials")} == _MODEL_COLUMNS
        assert "uq_admin_credentials_serial_number" in [
            u["name"] for u in insp.get_unique_constraints("admin_credentials")
        ]
        assert any(i["name"] == "ix_admin_credentials_source" for i in insp.get_indexes("admin_credentials"))
        assert "revoked_at" not in {
            c["name"] for c in insp.get_columns("admin_credentials")
        }, "a second revocation column would be a second source of truth — AdminCertRevocation owns that fact"

    _apply(engine, lambda: mod.downgrade())
    assert "admin_credentials" not in sa_inspect(engine).get_table_names(), "downgrade left the table behind"


def test_model_orm_write_reads_back_on_migrated_schema(tmp_path):
    """Round-trip the shipped model over the migrated schema — the UndefinedColumn check."""
    engine = _pre_041_engine(tmp_path)
    _apply(engine, lambda: _load_migration().upgrade())
    now = dt.datetime.now(dt.UTC)
    with Session(engine) as s:
        s.add(
            AdminCredential(
                serial_number="000000000000abcd",
                common_name="CN=cell",
                source="boot",
                issued_at=now,
                not_after=now,
                registered_at=now,
            )
        )
        s.commit()
        row = s.query(AdminCredential).filter_by(serial_number="000000000000abcd").one()
        assert row.source == "boot"
        # SQLite has no timezone-aware storage — the offset-aware law is proved on PG below
        # (timestamptz rendered and accepted), not here against a dialect that drops the zone.


def test_unique_serial_is_enforced_by_the_database(tmp_path):
    """Boot-ingest idempotency rests on a constraint, not on writer discipline."""
    engine = _pre_041_engine(tmp_path)
    _apply(engine, lambda: _load_migration().upgrade())
    now = dt.datetime.now(dt.UTC)
    with Session(engine) as s:
        s.add(AdminCredential(serial_number="00000000000000ff", common_name="CN=a", source="boot", registered_at=now))
        s.commit()
        s.add(
            AdminCredential(serial_number="00000000000000ff", common_name="CN=b", source="register", registered_at=now)
        )
        with pytest.raises(IntegrityError):
            s.commit()


# --------------------------------------------------------------------------------
# PostgreSQL dialect half — real PG or it skips, naming the env var in the reason
# --------------------------------------------------------------------------------


def _offline_cfg() -> Config:
    cfg = Config(str(_CORE_ROOT / "alembic.ini"))
    cfg.set_main_option("script_location", str(_CORE_ROOT / "alembic"))
    return cfg


def _render(fn, url: str, *args) -> list:
    """Offline-render one migration step on the PG dialect and return its DDL statements.

    Offline mode opens no connection — the URL is needed only to select the dialect, so
    VENYA_DB_URL is pointed at the PG URL for the duration (env.py reads that name). A
    revision RANGE requires sql=True, which is exactly the mode that binds nothing.
    """
    prev = os.environ.get("VENYA_DB_URL")
    os.environ["VENYA_DB_URL"] = url
    try:
        buf = io.StringIO()
        with redirect_stdout(buf):
            fn(_offline_cfg(), *args, sql=True)
    finally:
        if prev is None:
            os.environ.pop("VENYA_DB_URL", None)
        else:
            os.environ["VENYA_DB_URL"] = prev
    rendered = buf.getvalue()
    body = rendered.split("UPDATE alembic_version")[0]
    stmts = []
    for frag in body.split(";"):
        s = "\n".join(line for line in frag.splitlines() if not line.strip().startswith("--")).strip()
        if s and not s.upper().startswith(("BEGIN", "COMMIT")):
            stmts.append(s)
    return stmts


def _scalar(conn, sql, *params):
    return conn.exec_driver_sql(sql, params).scalar()


@pytest.mark.skipif(
    not os.environ.get(_PG_URL_ENV),
    reason=f"needs a scratch PostgreSQL in {_PG_URL_ENV} (not available on this venue)",
)
class TestAdminCredentialRegistry041Postgresql:
    """PostgreSQL half of migration 041 — the dialect a real install runs.

    Class-named per the #614 R1 interlock: every file that names VENYA_TEST_PG_URL must
    declare a *Postgresql class, because that is what the scan walks.
    """

    def test_pg_render_of_041_applies_and_reverses_on_the_real_engine(self):
        """The DDL a real install executes is the PG render — so render it, apply it, reverse it."""
        url = os.environ[_PG_URL_ENV]
        # NullPool: every block below gets its own connection, so the scratch search_path set
        # inside one cannot leak into the next (a pooled re-use would inherit it silently).
        engine = create_engine(url, connect_args=_PG_DEADLINE, poolclass=NullPool)
        schema = f"t684_{uuid.uuid4().hex[:10]}"

        def scoped(begin=False):
            """A connection whose session search_path is the scratch schema (bound, not spliced)."""
            cm = engine.begin() if begin else engine.connect()
            conn = cm.__enter__()
            conn.exec_driver_sql("select set_config('search_path', %s, false)", (schema,))
            return cm, conn

        up_ddl = _render(command.upgrade, url, "040:041")
        down_ddl = _render(command.downgrade, url, "041:040")
        assert any("CREATE TABLE admin_credentials" in s for s in up_ddl), "040:041 rendered no table"
        assert any("DROP TABLE admin_credentials" in s for s in down_ddl), "041:040 rendered no drop"
        try:
            cm, conn = scoped()
            try:
                conn.exec_driver_sql(f"CREATE SCHEMA {schema}")
                for stmt in up_ddl:
                    conn.exec_driver_sql(stmt)
                assert (
                    _scalar(conn, "select to_regclass('admin_credentials')") is not None
                ), "PG rejected the rendered 041 DDL"
                cols = {
                    r[0]: r[1]
                    for r in conn.exec_driver_sql(
                        "select column_name, data_type from information_schema.columns "
                        "where table_schema=current_schema() and table_name='admin_credentials'"
                    )
                }
                assert set(cols) == _MODEL_COLUMNS, "PG schema disagrees with the model"
                assert cols["id"] == "integer", "041 did not render SERIAL identity on PostgreSQL"
                for ts in ("issued_at", "not_after", "registered_at"):
                    assert cols[ts] == "timestamp with time zone", f"{ts} reached PG without a timezone"
                cons = {
                    r[0]
                    for r in conn.exec_driver_sql(
                        "select con.conname from pg_constraint con join pg_namespace n on n.oid=con.connamespace "
                        "where n.nspname=current_schema() and con.conrelid='admin_credentials'::regclass"
                    )
                }
                assert "uq_admin_credentials_serial_number" in cons
                idx = {
                    r[0]
                    for r in conn.exec_driver_sql(
                        "select indexname from pg_indexes where schemaname=current_schema() and tablename='admin_credentials'"
                    )
                }
                assert {"ix_admin_credentials_source", "uq_admin_credentials_serial_number"} <= idx
                conn.commit()
            finally:
                cm.__exit__(None, None, None)

            # the database, not a writer, refuses a duplicate serial
            ins = "INSERT INTO admin_credentials (serial_number, common_name, source, registered_at) VALUES (%s, 'CN=pg-cell', 'boot', now())"
            cm, conn = scoped(begin=True)
            try:
                conn.exec_driver_sql(ins, ("00000000000000ff",))
                with pytest.raises(IntegrityError):
                    conn.exec_driver_sql(ins, ("00000000000000ff",))
            finally:
                cm.__exit__(None, None, None)

            # and the membership read the fix depends on matches legacy spellings ON PG.
            # The key comes from the SHIPPED matcher, never a hand-rolled normalisation.
            cm, conn = scoped(begin=True)
            try:
                conn.exec_driver_sql(ins, ("100A",))
                for probe, expected in (("100A", 1), ("000000000000100a", 1), ("0x100A", 1), (4106, 1), ("1002", 0)):
                    n = conn.exec_driver_sql(
                        "select count(*) from admin_credentials where ltrim(upper(serial_number),'0') = %s",
                        (serial_match_key(probe),),
                    ).scalar()
                    assert n == expected, f"serial spelling {probe!r} matched {n}, expected {expected}"
                conn.rollback()  # probe rows are this cell's, not the venue's
            finally:
                cm.__exit__(None, None, None)

            # the rendered down-migration reverses the rendered up-migration
            cm, conn = scoped(begin=True)
            try:
                for stmt in down_ddl:
                    conn.exec_driver_sql(stmt)
                assert (
                    _scalar(conn, "select to_regclass('admin_credentials')") is None
                ), "041's downgrade did not drop the table on PostgreSQL"
                conn.rollback()  # leave the venue's public schema and data exactly as found
            finally:
                cm.__exit__(None, None, None)
        finally:
            cm, conn = scoped()
            try:
                conn.exec_driver_sql(f"DROP SCHEMA IF EXISTS {schema} CASCADE")
                conn.exec_driver_sql("select set_config('search_path', 'public', false)")
                conn.commit()
            finally:
                cm.__exit__(None, None, None)
            engine.dispose()
