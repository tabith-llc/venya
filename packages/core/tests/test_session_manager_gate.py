# Copyright (c) 2026 Tabith LLC.
# Use of this source code is governed by the Business Source License 1.1
# included in the LICENSE file at the root of this repository. As of the
# Change Date listed there, the work is available under MPL 2.0.
# SPDX-License-Identifier: BUSL-1.1

"""Active-user gate on session issuance (ticket
sec-unauth-webauthn-registration-takeover, B1 core-choke-point ruling, user
2026-09-20): SessionManager.create_session refuses missing / disabled /
pending_enrollment users with UserNotActiveError. Every login path (webauthn
login/complete, browser assert, enroll auto-session) issues through this one
guard.

Real SQLite, not mocks: the gate is a SELECT against the users table and the
enroll-ordering pin below depends on REAL autoflush semantics — mock dbs model
neither (house precedent: test_secret_delete_fk.py).
"""

import pytest
from core.iam.models import Base, User
from core.iam.session_manager import SessionConfig, SessionManager, UserNotActiveError
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


def _mk_user(db, user_id="u1", status="active"):
    user = User(user_id=user_id, status=status)
    db.add(user)
    db.commit()
    return user


def test_active_user_gets_session(db):
    """Positive half: an active user is issued a session + token."""
    _mk_user(db)
    session, token = SessionManager(db, SessionConfig()).create_session("u1")
    assert session.user_id == "u1"
    assert token.token
    assert token.user_id == "u1"


def test_disabled_user_refused(db):
    """Negative half: status='disabled' (set by admin PUT /admin/users/{id})
    cannot be issued a session."""
    _mk_user(db, status="disabled")
    with pytest.raises(UserNotActiveError) as exc:
        SessionManager(db, SessionConfig()).create_session("u1")
    assert exc.value.status == "disabled"


def test_pending_enrollment_user_refused(db):
    """Negative half: the DEFAULT status (pending_enrollment, models.py:50)
    cannot be issued a session — an unenrolled user_id has no live identity."""
    _mk_user(db, status="pending_enrollment")
    with pytest.raises(UserNotActiveError) as exc:
        SessionManager(db, SessionConfig()).create_session("u1")
    assert exc.value.status == "pending_enrollment"


def test_missing_user_refused(db):
    """Negative half: no users row at all (e.g. the removed public
    registration flow's phantom user_ids) → refused, status None."""
    with pytest.raises(UserNotActiveError) as exc:
        SessionManager(db, SessionConfig()).create_session("ghost")
    assert exc.value.status is None


def test_enroll_ordering_active_set_in_same_transaction(db):
    """ORDERING PIN (user ruling 2026-09-20): enroll.py sets
    user.status='active' (:280) and calls create_session (:289) in the SAME
    uncommitted transaction — the gate's SELECT must see the pending
    activation via SQLAlchemy autoflush. A future refactor that reorders the
    writes or disables autoflush FAILS HERE loudly, instead of silently
    locking new enrollees out of their own auto-session."""
    user = _mk_user(db, status="pending_enrollment")
    user.status = "active"  # dirty, uncommitted — exactly the enroll pattern
    session, _token = SessionManager(db, SessionConfig()).create_session("u1")
    assert session.user_id == "u1"


def test_is_user_active_predicate():
    """The central predicate behind the gate — single semantic source consumed
    by create_session (issuance) AND the server middleware _validate_token
    (surviving sessions, sec-auth-elevation-authz-hardening #9)."""
    from core.iam.session_manager import is_user_active

    assert is_user_active(User(user_id="x", status="active")) is True
    assert is_user_active(User(user_id="x", status="disabled")) is False
    assert is_user_active(User(user_id="x", status="pending_enrollment")) is False
    assert is_user_active(None) is False
