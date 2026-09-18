# Copyright (c) 2026 Tabith LLC.
# Use of this source code is governed by the Business Source License 1.1
# included in the LICENSE file at the root of this repository. As of the
# Change Date listed there, the work is available under MPL 2.0.
# SPDX-License-Identifier: BUSL-1.1

"""Migration 028 single-active invariant — SQL semantics on real SQLite.

Follows the 027-test pattern: the migration's exact SQL constants are
executed against real tables. The headline test is the RACE (user directive:
sequential proves the index exists; the race proves the invariant) — two
barrier-synchronized threads insert active rows concurrently and exactly one
may win. Ticket: key-rotation-worker-missing (option-2 ruling).
"""

import importlib.util
import sqlite3
import threading
from pathlib import Path

import pytest
from core.iam.models import KeyVersion
from sqlalchemy import create_engine, text
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

_MIGRATION_PATH = (
    Path(__file__).resolve().parents[1] / "alembic" / "versions" / "028_key_version_single_active_index.py"
)


def _load_migration():
    spec = importlib.util.spec_from_file_location("migration_028", _MIGRATION_PATH)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def _engine_with_table():
    engine = create_engine("sqlite://")
    KeyVersion.__table__.create(engine)
    return engine


def _insert_version(engine, label, active):
    with Session(engine) as s:
        s.add(KeyVersion(version_label=label, active=active, rotation_pending=False))
        s.commit()


def test_revision_chain():
    mod = _load_migration()
    assert mod.revision == "028"
    assert mod.down_revision == "027"


def test_model_creates_partial_unique_index():
    """The model's __table_args__ index matches the migration's contract."""
    engine = _engine_with_table()
    with engine.begin() as conn:
        row = conn.execute(
            text("SELECT sql FROM sqlite_master WHERE type='index' AND name='uq_key_versions_single_active'")
        ).fetchone()
    assert row is not None, "partial unique index missing from model metadata"
    assert "UNIQUE" in row[0].upper()
    assert "WHERE" in row[0].upper() and "active" in row[0]


def test_second_active_insert_rejected():
    """Baseline constraint check (paired with the race test below)."""
    engine = _engine_with_table()
    _insert_version(engine, "v1", active=True)
    with pytest.raises(IntegrityError):
        _insert_version(engine, "v2", active=True)


def test_inactive_rows_unlimited():
    """Negative half of the predicate: the index scopes to active rows only."""
    engine = _engine_with_table()
    _insert_version(engine, "v1", active=True)
    for label in ("old-1", "old-2", "old-3"):
        _insert_version(engine, label, active=False)
    with Session(engine) as s:
        assert s.query(KeyVersion).count() == 4


def test_concurrent_active_inserts_exactly_one_wins(tmp_path):
    """RACE: two threads insert active rows simultaneously — exactly one
    commits, the loser gets IntegrityError, final state has ONE active row.

    Both connections carry a busy timeout, so the loser's INSERT executes
    after the winner's commit and hits the unique partial index — the same
    unique-violation a loser sees on PostgreSQL. (SQLite serializes writers;
    the index decides the outcome, not the lock.)
    """
    db_path = tmp_path / "race.db"
    engine = create_engine(f"sqlite:///{db_path}")
    KeyVersion.__table__.create(engine)
    engine.dispose()

    barrier = threading.Barrier(2)
    results: list[tuple[str, str]] = []
    lock = threading.Lock()

    def racer(label: str) -> None:
        try:
            barrier.wait(timeout=10)
            conn = sqlite3.connect(db_path, timeout=5)
            try:
                conn.execute(
                    "INSERT INTO key_versions (version_label, created_at, active, rotation_pending) "
                    "VALUES (?, CURRENT_TIMESTAMP, 1, 0)",
                    (label,),
                )
                conn.commit()
                outcome = ("ok", label)
            finally:
                conn.close()
        except Exception as e:
            outcome = (type(e).__name__, str(e))
        with lock:
            results.append(outcome)

    threads = [threading.Thread(target=racer, args=(f"r{i}",)) for i in range(2)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=30)

    kinds = sorted(kind for kind, _ in results)
    assert kinds == ["IntegrityError", "ok"], f"expected exactly one winner and one unique violation, got {results}"

    conn = sqlite3.connect(db_path)
    try:
        active = conn.execute("SELECT COUNT(*) FROM key_versions WHERE active").fetchone()[0]
        total = conn.execute("SELECT COUNT(*) FROM key_versions").fetchone()[0]
    finally:
        conn.close()
    assert active == 1, "invariant violated: more than one active row after the race"
    assert total == 1, "loser's row must not persist"


def test_preclean_deactivates_extra_active_keeping_newest():
    """Migration pre-clean on a legacy-shaped table (no index yet)."""
    mod = _load_migration()
    engine = create_engine("sqlite://")
    with engine.begin() as conn:
        conn.execute(
            text(
                "CREATE TABLE key_versions ("
                "id INTEGER PRIMARY KEY, version_label VARCHAR(64) NOT NULL UNIQUE, "
                "created_at TIMESTAMP NOT NULL, active BOOLEAN NOT NULL, "
                "rotation_pending BOOLEAN NOT NULL, encrypted_kek_hash VARCHAR(64))"
            )
        )
        conn.execute(
            text(
                "INSERT INTO key_versions (version_label, created_at, active, rotation_pending) VALUES "
                "('v-old', '2026-01-01 00:00:00', 1, 0), "
                "('v-new', '2026-06-01 00:00:00', 1, 0), "
                "('v-off', '2026-03-01 00:00:00', 0, 0)"
            )
        )
        conn.execute(text(mod.DEACTIVATE_EXTRA_ACTIVE))
        rows = conn.execute(text("SELECT version_label, active FROM key_versions ORDER BY id")).fetchall()
    assert rows == [("v-old", 0), ("v-new", 1), ("v-off", 0)]
    # Index creation now succeeds on the cleaned data (SQLite-emitted form):
    with engine.begin() as conn:
        conn.execute(text(f"CREATE UNIQUE INDEX {mod.INDEX_NAME} ON key_versions (active) WHERE active"))


def test_seed_027_remains_idempotent_under_index():
    """Chain compatibility: the 027 bootstrap seed still works with the index."""
    m027 = importlib.util.spec_from_file_location(
        "migration_027",
        Path(__file__).resolve().parents[1] / "alembic" / "versions" / "027_bootstrap_active_key_version.py",
    )
    mod027 = importlib.util.module_from_spec(m027)
    m027.loader.exec_module(mod027)

    engine = _engine_with_table()
    with engine.begin() as conn:
        conn.execute(text(mod027.SEED_ACTIVE_V1))
        conn.execute(text(mod027.SEED_ACTIVE_V1))
    with Session(engine) as s:
        rows = s.query(KeyVersion).all()
        assert len(rows) == 1
        assert rows[0].version_label == "v1"
        assert rows[0].active is True
