# Copyright (c) 2026 Tabith LLC.
# Use of this source code is governed by the Business Source License 1.1
# included in the LICENSE file at the root of this repository. As of the
# Change Date listed there, the work is available under MPL 2.0.
# SPDX-License-Identifier: BUSL-1.1

"""Migration 032 — kek_sentinel table (upgrade/downgrade cells, #304).

The migration is op.create_table, so the test executes the module's real
upgrade()/downgrade() through an alembic Operations bound to a live SQLite
connection: upgrade must produce a schema the ORM model can write/read with
(the model-vs-migration interlock from AGENTS "Common Pitfalls" — a missing
column would kill fresh installs with UndefinedColumn), downgrade must remove
it cleanly.
"""

import importlib.util
from datetime import UTC, datetime
from pathlib import Path

from alembic.migration import MigrationContext
from alembic.operations import Operations
from core.iam.models import KekSentinel
from sqlalchemy import create_engine, inspect
from sqlalchemy.orm import Session

_MIGRATION_PATH = Path(__file__).resolve().parents[1] / "alembic" / "versions" / "032_add_kek_sentinel.py"


def _load_migration():
    spec = importlib.util.spec_from_file_location("migration_032", _MIGRATION_PATH)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def _run(engine, fn) -> None:
    """Execute the migration module's upgrade()/downgrade() against the engine."""
    mod = _load_migration()
    with engine.begin() as conn:
        ctx = MigrationContext.configure(conn)
        mod.op = Operations(ctx)
        fn(mod)


def test_revision_chain():
    mod = _load_migration()
    assert mod.revision == "032"
    assert mod.down_revision == "031"


def test_upgrade_creates_model_compatible_table(tmp_path):
    engine = create_engine(f"sqlite:///{tmp_path / 'mig.db'}")
    _run(engine, lambda mod: mod.upgrade())
    assert "kek_sentinel" in inspect(engine).get_table_names()
    # ORM write/read against the MIGRATED schema (not create_all): the exact
    # interlock that catches model-vs-migration drift.
    with Session(engine) as s:
        s.add(KekSentinel(key="kek_sentinel", wrapped_sentinel=b"\x00" * 40, created_at=datetime.now(UTC)))
        s.commit()
        assert len(s.query(KekSentinel).one().wrapped_sentinel) == 40


def test_downgrade_drops_the_table(tmp_path):
    engine = create_engine(f"sqlite:///{tmp_path / 'mig.db'}")
    _run(engine, lambda mod: mod.upgrade())
    _run(engine, lambda mod: mod.downgrade())
    assert "kek_sentinel" not in inspect(engine).get_table_names()


def test_model_columns_match_migration_columns(tmp_path):
    engine = create_engine(f"sqlite:///{tmp_path / 'mig.db'}")
    _run(engine, lambda mod: mod.upgrade())
    assert {c["name"] for c in inspect(engine).get_columns("kek_sentinel")} == {
        c.key for c in KekSentinel.__table__.columns
    }
