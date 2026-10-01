# Copyright (c) 2026 Tabith LLC.
# Use of this source code is governed by the Business Source License 1.1
# included in the LICENSE file at the root of this repository. As of the
# Change Date listed there, the work is available under MPL 2.0.
# SPDX-License-Identifier: BUSL-1.1

"""Migration 033 — execution_sessions.command_argv (#322, ruling Q4=D2).

Follows the 032-test pattern (op.add_column: the real upgrade()/downgrade()
run through alembic Operations on a live SQLite connection seeded with the
pre-033 schema) plus the 029-test interlock (the ORM model carries the same
nullable column — a model column without the migration kills fresh installs
with UndefinedColumn, and vice versa). Old rows must stay NULL: there is
nothing to backfill — the pre-#322 string wire never carried true argv.
"""

import importlib.util
from datetime import UTC, datetime
from pathlib import Path

from alembic.migration import MigrationContext
from alembic.operations import Operations
from core.iam.models import ExecutionSession
from sqlalchemy import create_engine, inspect
from sqlalchemy.orm import Session

_MIGRATION_PATH = (
    Path(__file__).resolve().parents[1] / "alembic" / "versions" / "033_add_execution_session_command_argv.py"
)

_OLD_SCHEMA = """
CREATE TABLE execution_sessions (
    id VARCHAR NOT NULL PRIMARY KEY,
    user_id VARCHAR(64) NOT NULL,
    executor_id VARCHAR NOT NULL,
    command TEXT,
    created_at TIMESTAMP,
    expires_at TIMESTAMP,
    completed_at TIMESTAMP,
    exit_code INTEGER,
    stdout TEXT,
    stderr TEXT
)
"""


def _load_migration():
    spec = importlib.util.spec_from_file_location("migration_033", _MIGRATION_PATH)
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
            "INSERT INTO execution_sessions (id, user_id, executor_id, command, created_at, expires_at) "
            "VALUES ('old-1', 'u1', 'e1', 'echo hi', '2026-10-01 00:00:00', '2026-10-01 00:10:00')"
        )
    return engine


def test_revision_chain():
    mod = _load_migration()
    assert mod.revision == "033"
    assert mod.down_revision == "032"


def test_upgrade_adds_nullable_column_and_old_rows_stay_null(tmp_path):
    engine = _old_engine(tmp_path)
    _run(engine, lambda mod: mod.upgrade())
    cols = {c["name"]: c for c in inspect(engine).get_columns("execution_sessions")}
    assert "command_argv" in cols
    assert cols["command_argv"]["nullable"] is True
    # pre-change row: NULL (no backfill — the string wire never carried argv)
    with engine.connect() as conn:
        assert conn.exec_driver_sql("SELECT command_argv FROM execution_sessions WHERE id='old-1'").scalar() is None


def test_upgraded_schema_reads_writes_true_argv_through_the_orm(tmp_path):
    """Model-vs-migration interlock: ORM write/read against the MIGRATED
    schema (not create_all) — exact token round trip incl. an arg with a space."""
    engine = _old_engine(tmp_path)
    _run(engine, lambda mod: mod.upgrade())
    argv = ["grep", "error message", "app.log"]
    with Session(engine) as s:
        now = datetime.now(UTC)
        s.add(
            ExecutionSession(
                id="new-1",
                user_id="u1",
                executor_id="e1",
                command="grep 'error message' app.log",
                command_argv=argv,
                created_at=now,
                expires_at=now,
            )
        )
        s.commit()
        row = s.query(ExecutionSession).filter(ExecutionSession.id == "new-1").one()
        assert row.command_argv == argv
        assert s.query(ExecutionSession).filter(ExecutionSession.id == "old-1").one().command_argv is None


def test_downgrade_drops_the_column(tmp_path):
    engine = _old_engine(tmp_path)
    _run(engine, lambda mod: mod.upgrade())
    _run(engine, lambda mod: mod.downgrade())
    cols = {c["name"] for c in inspect(engine).get_columns("execution_sessions")}
    assert "command_argv" not in cols


def test_model_migration_interlock():
    """The ORM model carries the same column — model and migration land together."""
    assert "command_argv" in ExecutionSession.__table__.columns
    col = ExecutionSession.__table__.columns["command_argv"]
    assert col.nullable is True
