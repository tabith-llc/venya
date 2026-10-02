# Copyright (c) 2026 Tabith LLC.
# Use of this source code is governed by the Business Source License 1.1
# included in the LICENSE file at the root of this repository. As of the
# Change Date listed there, the work is available under MPL 2.0.
# SPDX-License-Identifier: BUSL-1.1

"""Migration 034 — sessions.access_token_expires_at (#342, owner ruling A).

Follows the 033-test pattern: the real upgrade()/downgrade() run through
alembic Operations on a live SQLite connection seeded with the pre-034
sessions schema, plus the model interlock — an ORM INSERT/FLUSH/READ of the
new field against the MIGRATED schema (never create_all): the
model-without-migration UndefinedColumn class guard from AGENTS pitfalls.
Old rows stay NULL: fail-closed rejection is the middleware's job, not a
backfill's.
"""

import importlib.util
from datetime import UTC, datetime
from pathlib import Path

from alembic.migration import MigrationContext
from alembic.operations import Operations
from core.iam.models import Session
from sqlalchemy import create_engine, inspect
from sqlalchemy.orm import Session as OrmSession

_MIGRATION_PATH = Path(__file__).resolve().parents[1] / "alembic" / "versions" / "034_add_access_token_expiry.py"

_OLD_SCHEMA = """
CREATE TABLE sessions (
    id INTEGER NOT NULL PRIMARY KEY,
    user_id VARCHAR(64) NOT NULL,
    created_at TIMESTAMP,
    expires_at TIMESTAMP,
    access_token VARCHAR(128),
    access_token_jti VARCHAR(64)
)
"""


def _load_migration():
    spec = importlib.util.spec_from_file_location("migration_034", _MIGRATION_PATH)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def _run(engine, fn) -> None:
    mod = _load_migration()
    with engine.begin() as conn:
        ctx = MigrationContext.configure(conn)
        mod.op = Operations(ctx)
        fn(mod)


def _old_engine(tmp_path):
    engine = create_engine(f"sqlite:///{tmp_path / 'mig.db'}")
    with engine.begin() as conn:
        conn.exec_driver_sql(_OLD_SCHEMA)
        conn.exec_driver_sql(
            "INSERT INTO sessions (id, user_id, created_at, expires_at, access_token, access_token_jti) "
            "VALUES (1, 'u1', '2026-10-01 00:00:00', '2026-10-01 04:00:00', 'tok-old', 'jti-old')"
        )
    return engine


def test_revision_chain():
    mod = _load_migration()
    assert mod.revision == "034"
    assert mod.down_revision == "033"


def test_upgrade_adds_nullable_column_and_old_rows_stay_null(tmp_path):
    engine = _old_engine(tmp_path)
    _run(engine, lambda mod: mod.upgrade())
    cols = {c["name"]: c for c in inspect(engine).get_columns("sessions")}
    assert "access_token_expires_at" in cols
    assert cols["access_token_expires_at"]["nullable"] is True
    with engine.connect() as conn:
        assert conn.exec_driver_sql("SELECT access_token_expires_at FROM sessions WHERE id=1").scalar() is None


def test_downgrade_drops_the_column(tmp_path):
    engine = _old_engine(tmp_path)
    _run(engine, lambda mod: mod.upgrade())
    _run(engine, lambda mod: mod.downgrade())
    cols = {c["name"] for c in inspect(engine).get_columns("sessions")}
    assert "access_token_expires_at" not in cols
    assert "access_token" in cols  # siblings untouched


def test_migrated_schema_round_trips_the_new_field_through_the_orm(tmp_path):
    engine = _old_engine(tmp_path)
    _run(engine, lambda mod: mod.upgrade())
    now = datetime.now(UTC)
    expiry = datetime(2026, 10, 2, 12, 0, 0, tzinfo=UTC)
    with OrmSession(engine) as s:
        s.add(
            Session(
                user_id="u2",
                created_at=now,
                expires_at=now,
                access_token="tok-new",
                access_token_jti="jti-new",
                access_token_expires_at=expiry,
            )
        )
        s.flush()  # UndefinedColumn class guard: fails if the migration lacks the model column
        row = s.query(Session).filter(Session.access_token == "tok-new").one()
        assert row.access_token_expires_at is not None
