# Copyright (c) 2026 Tabith LLC.
# Use of this source code is governed by the Business Source License 1.1
# included in the LICENSE file at the root of this repository. As of the
# Change Date listed there, the work is available under MPL 2.0.
# SPDX-License-Identifier: BUSL-1.1

"""revoke_session deletes the session's elevation tokens (#527, half 2):
an unconsumed elevation token bound to a logged-out session must not stay
consumable. Real SQLite (house precedent: test_session_manager_gate.py) —
the delete is the mechanism, so row presence/absence is the assertion.

Truth-table pairs: bound row DELETED / legacy NULL-session row KEPT (not
attributable to any session — its own TTL is the bound) / another session's
bound row KEPT.
"""

from datetime import UTC, datetime, timedelta

import pytest
from core.iam.models import Base, ElevationToken, Session, User
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


def _mk(db, user_id="u1", status="active"):
    db.add(User(user_id=user_id, status=status))
    now = datetime.now(UTC)
    s1 = Session(user_id=user_id, created_at=now, expires_at=now + timedelta(minutes=15), access_token="tok-1")
    s2 = Session(user_id=user_id, created_at=now, expires_at=now + timedelta(minutes=15), access_token="tok-2")
    db.add_all([s1, s2])
    db.commit()
    return s1, s2


def _tok(db, hash_, session_id):
    t = ElevationToken(
        token_hash=hash_,
        user_id="u1",
        session_id=session_id,
        expires_at=datetime.now(UTC) + timedelta(seconds=60),
        used=False,
    )
    db.add(t)
    db.commit()
    return t


def test_revoke_deletes_bound_unconsumed_token(db):
    """PAIRED: the session's elevation-token row is gone with the session."""
    s1, _s2 = _mk(db)
    _tok(db, "h-bound", s1.id)
    mgr = SessionManager(db, SessionConfig())
    assert mgr.revoke_session(s1.id) is True
    assert db.query(ElevationToken).filter(ElevationToken.token_hash == "h-bound").first() is None


def test_revoke_keeps_other_sessions_token(db):
    s1, s2 = _mk(db)
    t2 = _tok(db, "h-other", s2.id)
    mgr = SessionManager(db, SessionConfig())
    mgr.revoke_session(s1.id)
    db.commit()
    assert db.query(ElevationToken).filter(ElevationToken.id == t2.id).first() is not None


def test_revoke_keeps_legacy_null_session_token(db):
    """Back-compatible half: pre-#527 rows carry NULL session_id and are not
    attributable — revoke of ANY session must not silently eat them."""
    s1, _s2 = _mk(db)
    legacy = _tok(db, "h-legacy", None)
    mgr = SessionManager(db, SessionConfig())
    mgr.revoke_session(s1.id)
    db.commit()
    assert db.query(ElevationToken).filter(ElevationToken.id == legacy.id).first() is not None
