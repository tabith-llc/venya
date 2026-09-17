# Copyright (c) 2026 Tabith LLC.
# Use of this source code is governed by the Business Source License 1.1
# included in the LICENSE file at the root of this repository. As of the
# Change Date listed there, the work is available under MPL 2.0.
# SPDX-License-Identifier: BUSL-1.1

"""Migration 027 bootstrap seed — SQL semantics on a real SQLite table.

The migration is one portable INSERT…SELECT…WHERE NOT EXISTS statement; these
tests execute its exact text (imported from the migration module) against a
real key_versions table: fresh-seed positive, idempotency and
leave-existing-installs-untouched negatives, plus the revision chain.
Ticket: key-version-no-bootstrap.
"""

import importlib.util
from pathlib import Path

from core.iam.models import KeyVersion
from sqlalchemy import create_engine, text
from sqlalchemy.orm import Session

_MIGRATION_PATH = Path(__file__).resolve().parents[1] / "alembic" / "versions" / "027_bootstrap_active_key_version.py"


def _load_migration():
    spec = importlib.util.spec_from_file_location("migration_027", _MIGRATION_PATH)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def _engine_with_table():
    engine = create_engine("sqlite://")
    KeyVersion.__table__.create(engine)
    return engine


def test_revision_chain():
    mod = _load_migration()
    assert mod.revision == "027"
    assert mod.down_revision == "026"


def test_seeds_single_active_v1_on_fresh_table():
    mod = _load_migration()
    engine = _engine_with_table()
    with engine.begin() as conn:
        conn.execute(text(mod.SEED_ACTIVE_V1))
    with Session(engine) as s:
        rows = s.query(KeyVersion).all()
        assert len(rows) == 1
        assert rows[0].version_label == "v1"
        assert rows[0].active is True
        assert rows[0].rotation_pending is False


def test_seed_is_idempotent():
    mod = _load_migration()
    engine = _engine_with_table()
    with engine.begin() as conn:
        conn.execute(text(mod.SEED_ACTIVE_V1))
        conn.execute(text(mod.SEED_ACTIVE_V1))
    with Session(engine) as s:
        assert s.query(KeyVersion).count() == 1


def test_existing_install_untouched():
    """Negative: an install with its own versions gets no injected v1."""
    mod = _load_migration()
    engine = _engine_with_table()
    with Session(engine) as s:
        s.add(KeyVersion(version_label="v0-custom", active=True, rotation_pending=False))
        s.commit()
    with engine.begin() as conn:
        conn.execute(text(mod.SEED_ACTIVE_V1))
    with Session(engine) as s:
        rows = s.query(KeyVersion).all()
        assert [r.version_label for r in rows] == ["v0-custom"]
