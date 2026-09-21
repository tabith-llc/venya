# Copyright (c) 2026 Tabith LLC.
# Use of this source code is governed by the Business Source License 1.1
# included in the LICENSE file at the root of this repository. As of the
# Change Date listed there, the work is available under MPL 2.0.
# SPDX-License-Identifier: BUSL-1.1

"""Migration 029 — executors.version (nullable, no backfill).

Follows the 027/028-test pattern: the migration's exact SQL constant runs
against a real old-schema SQLite table. Plus the model/migration interlock
(AGENTS common-pitfall: a model column without the migration kills the
heartbeat hot path with UndefinedColumn on fresh installs).
"""

import importlib.util
import sqlite3
from pathlib import Path

from core.iam.models import Executor

_MIGRATION_PATH = Path(__file__).resolve().parents[1] / "alembic" / "versions" / "029_add_executor_version.py"

_OLD_SCHEMA = """
CREATE TABLE executors (
    id VARCHAR NOT NULL PRIMARY KEY,
    hostname VARCHAR NOT NULL,
    enrolled_at TIMESTAMP,
    revoked_at TIMESTAMP,
    last_heartbeat TIMESTAMP,
    status VARCHAR NOT NULL DEFAULT 'pending'
)
"""


def _load_migration():
    spec = importlib.util.spec_from_file_location("migration_029", _MIGRATION_PATH)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def test_migration_file_exists_and_is_chained():
    mod = _load_migration()
    assert mod.revision == "029"
    assert mod.down_revision == "028"


def test_add_column_sql_runs_on_old_schema_and_is_nullable():
    mod = _load_migration()
    conn = sqlite3.connect(":memory:")
    conn.executescript(_OLD_SCHEMA)
    conn.execute("INSERT INTO executors (id, hostname) VALUES ('e1', 'h1')")
    conn.execute(mod.ADD_VERSION_COLUMN)
    # pre-existing row reads back NULL — no backfill (ruling condition 4)
    row = conn.execute("SELECT version FROM executors WHERE id='e1'").fetchone()
    assert row[0] is None
    # new rows may omit it
    conn.execute("INSERT INTO executors (id, hostname) VALUES ('e2', 'h2')")
    assert conn.execute("SELECT version FROM executors WHERE id='e2'").fetchone()[0] is None
    # and accept a value
    conn.execute("UPDATE executors SET version='1.2.3' WHERE id='e2'")
    assert conn.execute("SELECT version FROM executors WHERE id='e2'").fetchone()[0] == "1.2.3"


def test_no_backfill_statements_in_migration():
    """ADD COLUMN only — the migration must not touch data (condition 4)."""
    mod = _load_migration()
    assert mod.ADD_VERSION_COLUMN.strip().upper().startswith("ALTER TABLE EXECUTORS ADD COLUMN VERSION")
    assert "UPDATE" not in mod.ADD_VERSION_COLUMN.upper()
    assert "INSERT" not in mod.ADD_VERSION_COLUMN.upper()


def test_model_migration_interlock():
    """The ORM model carries the same column — model and migration land together."""
    assert "version" in Executor.__table__.columns
    col = Executor.__table__.columns["version"]
    assert col.nullable is True
