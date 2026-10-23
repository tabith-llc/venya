# Copyright (c) 2026 Tabith LLC.
# Use of this source code is governed by the Business Source License 1.1
# included in the LICENSE file at the root of this repository. As of the
# Change Date listed there, the work is available under MPL 2.0.
# SPDX-License-Identifier: BUSL-1.1

"""Migration 036 — elevation_challenges table (#528).

Same tested shape as 034/035: the real upgrade()/downgrade() run through
alembic Operations on a live SQLite connection (a fresh database, no prior
table — this migration CREATES), plus the model interlock (ORM
INSERT/FLUSH/READ against the MIGRATED schema) and the server_default pin:
state lands 'created' without the ORM saying so (raw-SQL inserts stay
correct).
"""

import importlib.util
from datetime import UTC, datetime, timedelta
from pathlib import Path

from alembic.migration import MigrationContext
from alembic.operations import Operations
from core.iam.models import ElevationChallenge
from sqlalchemy import create_engine, inspect
from sqlalchemy.orm import Session as OrmSession

_MIGRATION_PATH = Path(__file__).resolve().parents[1] / "alembic" / "versions" / "036_elevation_challenges.py"


def _load_migration():
    spec = importlib.util.spec_from_file_location("migration_036", _MIGRATION_PATH)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def _run(engine, fn) -> None:
    mod = _load_migration()
    with engine.begin() as conn:
        ctx = MigrationContext.configure(conn)
        mod.op = Operations(ctx)
        fn(mod)


def _bare_engine(tmp_path):
    return create_engine(f"sqlite:///{tmp_path / 'mig.db'}")


def test_revision_chain():
    mod = _load_migration()
    assert mod.revision == "036"
    assert mod.down_revision == "035"


def test_upgrade_creates_table_and_indexes(tmp_path):
    engine = _bare_engine(tmp_path)
    _run(engine, lambda mod: mod.upgrade())
    insp = inspect(engine)
    assert "elevation_challenges" in insp.get_table_names()
    cols = {c["name"]: c for c in insp.get_columns("elevation_challenges")}
    for name in ("challenge_id", "user_id", "session_id", "state", "created_at", "expires_at"):
        assert name in cols
    assert cols["session_id"]["nullable"] is True
    assert cols["user_id"]["nullable"] is False
    idx = {i["name"] for i in insp.get_indexes("elevation_challenges")}
    assert {
        "ix_elevation_challenges_challenge_id",
        "ix_elevation_challenges_user_id",
        "ix_elevation_challenges_expires_at",
    } <= idx


def test_state_has_created_server_default(tmp_path):
    engine = _bare_engine(tmp_path)
    _run(engine, lambda mod: mod.upgrade())
    with engine.begin() as conn:
        conn.exec_driver_sql(
            "INSERT INTO elevation_challenges (challenge_id, user_id, created_at, expires_at) "
            "VALUES ('c1', 'u1', '2026-10-07 00:00:00', '2026-10-07 00:05:00')"
        )
        state = conn.exec_driver_sql("SELECT state FROM elevation_challenges WHERE challenge_id='c1'").scalar()
    assert state == "created"


def test_downgrade_drops_the_table(tmp_path):
    engine = _bare_engine(tmp_path)
    _run(engine, lambda mod: mod.upgrade())
    _run(engine, lambda mod: mod.downgrade())
    assert "elevation_challenges" not in inspect(engine).get_table_names()


def test_migrated_schema_round_trips_through_the_orm(tmp_path):
    engine = _bare_engine(tmp_path)
    _run(engine, lambda mod: mod.upgrade())
    now = datetime.now(UTC)
    with OrmSession(engine) as s:
        s.add(
            ElevationChallenge(
                challenge_id="c2",
                user_id="u2",
                session_id=9,
                state="created",
                created_at=now,
                expires_at=now + timedelta(seconds=300),
            )
        )
        s.flush()  # UndefinedColumn class guard: fails if the migration lacks a model column
        row = s.query(ElevationChallenge).filter_by(challenge_id="c2").one()
        assert row.session_id == 9
        assert row.state == "created"


def test_model_matches_the_migration_columns():
    """Drift pin: model and migration 036 describe the same fields."""
    table = ElevationChallenge.__table__
    assert {c.name for c in table.columns} == {
        "id",
        "challenge_id",
        "user_id",
        "session_id",
        "state",
        "created_at",
        "expires_at",
    }
    assert table.c.challenge_id.unique is True
