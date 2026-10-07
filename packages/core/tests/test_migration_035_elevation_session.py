# Copyright (c) 2026 Tabith LLC.
# Use of this source code is governed by the Business Source License 1.1
# included in the LICENSE file at the root of this repository. As of the
# Change Date listed there, the work is available under MPL 2.0.
# SPDX-License-Identifier: BUSL-1.1

"""Migration 035 — elevation_tokens.session_id (#527 elevation-not-session-bound).

Follows the 034-test pattern: the real upgrade()/downgrade() run through
alembic Operations on a live SQLite connection seeded with the pre-035
elevation_tokens schema, plus the model interlock — an ORM INSERT/FLUSH/READ
of the new field against the MIGRATED schema (never create_all at startup):
the model-without-migration UndefinedColumn class guard from AGENTS pitfalls.
Old rows stay NULL by ruling: no backfill (the earning session is not
reconstructable after the fact); the row's own TTL bounds the residue.
"""

import importlib.util
from datetime import UTC, datetime, timedelta
from pathlib import Path

from alembic.migration import MigrationContext
from alembic.operations import Operations
from core.iam.models import ElevationToken
from sqlalchemy import create_engine, inspect
from sqlalchemy.orm import Session as OrmSession

_MIGRATION_PATH = Path(__file__).resolve().parents[1] / "alembic" / "versions" / "035_add_elevation_token_session_id.py"

_OLD_SCHEMA = """
CREATE TABLE elevation_tokens (
    id INTEGER NOT NULL PRIMARY KEY,
    token_hash VARCHAR(64) NOT NULL,
    user_id VARCHAR(64) NOT NULL,
    expires_at TIMESTAMP NOT NULL,
    used BOOLEAN NOT NULL DEFAULT false,
    CONSTRAINT uq_elevation_tokens_token_hash UNIQUE (token_hash)
)
"""


def _load_migration():
    spec = importlib.util.spec_from_file_location("migration_035", _MIGRATION_PATH)
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
            "INSERT INTO elevation_tokens (id, token_hash, user_id, expires_at, used) "
            "VALUES (1, 'h-old', 'u1', '2026-10-07 00:00:00', false)"
        )
    return engine


def test_revision_chain():
    mod = _load_migration()
    assert mod.revision == "035"
    assert mod.down_revision == "034"


def test_upgrade_adds_nullable_session_id_and_old_rows_stay_null(tmp_path):
    engine = _old_engine(tmp_path)
    _run(engine, lambda mod: mod.upgrade())
    cols = {c["name"]: c for c in inspect(engine).get_columns("elevation_tokens")}
    assert "session_id" in cols
    assert cols["session_id"]["nullable"] is True
    with engine.connect() as conn:
        assert conn.exec_driver_sql("SELECT session_id FROM elevation_tokens WHERE id=1").scalar() is None


def test_upgrade_adds_the_session_id_index(tmp_path):
    engine = _old_engine(tmp_path)
    _run(engine, lambda mod: mod.upgrade())
    idx = {i["name"] for i in inspect(engine).get_indexes("elevation_tokens")}
    assert "ix_elevation_tokens_session_id" in idx


def test_downgrade_drops_column_and_index(tmp_path):
    engine = _old_engine(tmp_path)
    _run(engine, lambda mod: mod.upgrade())
    _run(engine, lambda mod: mod.downgrade())
    cols = {c["name"] for c in inspect(engine).get_columns("elevation_tokens")}
    assert "session_id" not in cols
    assert "token_hash" in cols  # siblings untouched
    idx = {i["name"] for i in inspect(engine).get_indexes("elevation_tokens")}
    assert "ix_elevation_tokens_session_id" not in idx


def test_migrated_schema_round_trips_the_new_field_through_the_orm(tmp_path):
    engine = _old_engine(tmp_path)
    _run(engine, lambda mod: mod.upgrade())
    now = datetime.now(UTC)
    with OrmSession(engine) as s:
        s.add(
            ElevationToken(
                token_hash="h-new",
                user_id="u2",
                session_id=7,
                expires_at=now + timedelta(seconds=60),
                used=False,
            )
        )
        s.flush()  # UndefinedColumn class guard: fails if the migration lacks the model column
        row = s.query(ElevationToken).filter(ElevationToken.token_hash == "h-new").one()
        assert row.session_id == 7


def test_model_has_the_column_the_migration_creates():
    """Drift pin: the model and migration 035 describe the same field."""
    col = ElevationToken.__table__.c.session_id
    assert col.nullable is True
    assert col.primary_key is False
