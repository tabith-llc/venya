# Copyright (c) 2026 Tabith LLC.
# Use of this source code is governed by the Business Source License 1.1
# included in the LICENSE file at the root of this repository. As of the
# Change Date listed there, the work is available under MPL 2.0.
# SPDX-License-Identifier: BUSL-1.1

"""SessionManager.cleanup_expired aligned to the hard-cap predicate (#529).

The live production sweep is server.maintenance.cleanup_expired_sessions;
this core method currently has NO production callers (verified by grep in
the #529 leg). It carried the same missing-cap bug PLUS a worse idle leg:
it deleted any row whose sliding expires_at had passed, including rows
still refreshable inside the cap — which the ruled refresh design (Option
A, mcp-refresh-path-unreachable) treats as LIVE. These cells pin the
aligned two-leg predicate so a future caller inherits the correct sweep,
not the dormant bug.

Truth-table pairs: past-cap extended row DELETED / in-cap live row KEPT /
idle-expired-in-cap (recoverable) row KEPT / long-dead row DELETED.
"""

from datetime import UTC, datetime, timedelta

import pytest
from core.iam.models import Base, Session
from core.iam.session_manager import SessionConfig, SessionManager
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker


@pytest.fixture()
def db():
    engine = create_engine("sqlite://")
    Base.metadata.create_all(engine)
    session = sessionmaker(bind=engine)()
    try:
        yield session
    finally:
        session.close()


def _mk(db, token, created_delta, expires_delta):
    now = datetime.now(UTC)
    row = Session(
        user_id="u1",
        created_at=now + timedelta(seconds=created_delta),
        expires_at=now + timedelta(seconds=expires_delta),
        access_token=token,
    )
    db.add(row)
    db.commit()
    return row


def _tokens(db):
    db.expire_all()
    return {r.access_token for r in db.query(Session).all()}


def test_past_cap_extended_row_deleted(db):
    """PAIRED (cap leg): refreshed forever, but the cap is blown — sweep
    takes it (HEAD's expires_at-only predicate never saw it)."""
    _mk(db, "zombie-refresh", -5 * 3600, +600)
    n = SessionManager(db, SessionConfig()).cleanup_expired()
    db.commit()
    assert n == 1
    assert _tokens(db) == set()


def test_idle_expired_in_cap_survives(db):
    """PAIRED (the dormant extra bug): an idle-expired row INSIDE the cap is
    refresh-recoverable (Option A) — the old bare-expires_at leg deleted
    exactly this class; the aligned predicate keeps it."""
    _mk(db, "recoverable", -2 * 3600, -3600)
    n = SessionManager(db, SessionConfig()).cleanup_expired()
    db.commit()
    assert n == 0
    assert _tokens(db) == {"recoverable"}


def test_live_in_cap_row_survives(db):
    _mk(db, "live", -3 * 3600, +600)
    n = SessionManager(db, SessionConfig()).cleanup_expired()
    db.commit()
    assert n == 0
    assert _tokens(db) == {"live"}


def test_long_dead_row_deleted_by_idle_leg(db):
    """Original intent preserved: idle-dead so long the cap is certainly
    blown — the idle leg takes it even without a created_at match...
    (and the cap leg would too; belt and suspenders, same set)."""
    _mk(db, "gone", -6 * 3600, -5 * 3600)
    n = SessionManager(db, SessionConfig()).cleanup_expired()
    db.commit()
    assert n == 1
    assert _tokens(db) == set()


def test_cap_boundary_tolerant_side_kept(db):
    """Tolerance pin: created exactly at the cap is still refreshable
    (check_refresh_window uses >=) — cleanup must not delete first."""
    _mk(db, "at-cap", -4 * 3600, +600)
    n = SessionManager(db, SessionConfig()).cleanup_expired()
    db.commit()
    assert n == 0
    assert _tokens(db) == {"at-cap"}
