# Copyright (c) 2026 Tabith LLC.
# Use of this source code is governed by the Business Source License 1.1
# included in the LICENSE file at the root of this repository. As of the
# Change Date listed there, the work is available under MPL 2.0.
# SPDX-License-Identifier: BUSL-1.1

"""Migration 030 — users backfill for stranded executor (mtls) identities.

Follows the 029-test pattern: the migration's exact SQL constant runs
against a real old-schema SQLite fixture. The paired negative IS the point:
the WHERE clause must touch mtls rows ONLY — a human 'pending_enrollment'
row is a live enrollment invite and flipping it would fabricate an account.
"""

import importlib.util
import sqlite3
from pathlib import Path

_MIGRATION_PATH = Path(__file__).resolve().parents[1] / "alembic" / "versions" / "030_backfill_executor_user_status.py"

_OLD_SCHEMA = """
CREATE TABLE users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id VARCHAR NOT NULL,
    display_name VARCHAR,
    status VARCHAR NOT NULL DEFAULT 'pending_enrollment',
    auth_mode VARCHAR NOT NULL DEFAULT 'security-key',
    enrolled_at TIMESTAMP,
    session_timeout INTEGER NOT NULL DEFAULT 900,
    recovery_code_hash VARCHAR
)
"""


def _load_migration():
    spec = importlib.util.spec_from_file_location("migration_030", _MIGRATION_PATH)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def test_migration_file_exists_and_is_chained():
    mod = _load_migration()
    assert mod.revision == "030"
    assert mod.down_revision == "029"


def test_backfill_flips_only_stranded_mtls_rows():
    mod = _load_migration()
    conn = sqlite3.connect(":memory:")
    conn.executescript(_OLD_SCHEMA)
    rows = [
        # (user_id, status, auth_mode, enrolled_at)
        ("exec-1", "pending_enrollment", "mtls", None),  # stranded executor → FLIP + backfill enrolled_at
        ("human-1", "pending_enrollment", "webauthn", None),  # live human invite → UNTOUCHED (paired negative)
        ("human-2", "active", "webauthn", "2026-09-25 20:00:14"),  # enrolled human → UNTOUCHED
        ("exec-2", "active", "mtls", "2026-09-20 10:00:00"),  # already-active executor → UNTOUCHED (idempotent)
    ]
    conn.executemany(
        "INSERT INTO users (user_id, status, auth_mode, enrolled_at) VALUES (?,?,?,?)",
        rows,
    )
    conn.execute(mod.BACKFILL_MTLS_STATUS)
    after = {
        r[0]: (r[1], r[2], r[3]) for r in conn.execute("SELECT user_id, status, auth_mode, enrolled_at FROM users")
    }
    assert after["exec-1"][0] == "active"
    assert after["exec-1"][2] is not None  # enrolled_at backfilled
    assert after["human-1"] == ("pending_enrollment", "webauthn", None)
    assert after["human-2"] == ("active", "webauthn", "2026-09-25 20:00:14")
    assert after["exec-2"] == ("active", "mtls", "2026-09-20 10:00:00")  # enrolled_at NOT overwritten


def test_backfill_sql_is_scoped_and_data_only():
    mod = _load_migration()
    sql = mod.BACKFILL_MTLS_STATUS.upper()
    assert sql.startswith("UPDATE USERS SET")
    assert "AUTH_MODE='MTLS'" in sql
    assert "STATUS='PENDING_ENROLLMENT'" in sql
    assert "INSERT" not in sql and "DELETE" not in sql and "ALTER" not in sql
