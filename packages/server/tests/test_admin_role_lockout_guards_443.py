# Copyright (c) 2026 Tabith LLC.
# Use of this source code is governed by the Business Source License 1.1
# included in the LICENSE file at the root of this repository. As of the
# Change Date listed there, the work will be available under MPL 2.0.
# SPDX-License-Identifier: BUSL-1.1

"""Route-level truth-table cells for the #443 admin-lockout guards.

Both destructive routes used to delete without asking whether an administrator
survived:

- ``DELETE /admin/users/{user_id}`` (routes/admin.py::admin_remove) bulk-deleted
  the target's ``role_members`` rows with it;
- ``DELETE /roles/{role_id}/members/{user_id}`` (routes/roles.py::
  role_member_remove) deleted whichever membership it found.

Either could leave a deployment with zero members in the ``admin`` role — no
enrollment, no key rotation, no policy changes — and neither had a self-removal
answer. Both now refuse with 409 (the same-file precedent: the SoD refusal here
in roles.py, and admin_remove_executor's refused-while-history-retained 409)
and land an ``admin_lockout_denied`` row.

Prior route tests used MagicMock sessions, and a mock can never answer a roster
question honestly — these cells bind the REAL routes to a REAL SQLite session
(harness copied from test_admin_delete_dependencies_425.py), so every assertion
about "the row is still there" reads the database, not a call list.
"""

from datetime import UTC, datetime

import pytest
from core.iam.models import (
    AuditEvent,
    Base,
    Role,
    RoleMember,
    User,
    WebAuthnCredential,
)
from core.iam.models import (
    Session as SessionModel,
)
from fastapi import FastAPI
from server.dependencies import get_current_user, get_db, require_admin
from server.routes import admin as admin_routes
from server.routes import roles as roles_routes
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool
from starlette.testclient import TestClient

SECOND_ADMIN = "admin2"


@pytest.fixture()
def session():
    engine = create_engine(
        "sqlite://",
        poolclass=StaticPool,
        connect_args={"check_same_thread": False},
    )
    Base.metadata.create_all(engine)
    factory = sessionmaker(bind=engine)

    s = factory()
    s.add_all(
        [
            User(user_id="admin1", status="active"),
            User(user_id=SECOND_ADMIN, status="active"),
            User(user_id="plainjane", status="active"),
            Role(name="admin", permissions="read-write"),
            Role(name="operator", permissions="read"),
        ]
    )
    s.commit()
    yield s
    s.close()
    engine.dispose()


def _client(session, caller_id):
    """Real admin + roles routers, require_admin pinned to one caller."""
    app = FastAPI()
    app.include_router(admin_routes.router, prefix="/api/v1")
    app.include_router(roles_routes.router, prefix="/api/v1")
    auth = {"user_id": caller_id}
    app.dependency_overrides[get_current_user] = lambda: auth
    app.dependency_overrides[require_admin] = lambda: auth
    app.dependency_overrides[get_db] = lambda: session
    return TestClient(app, raise_server_exceptions=False)


def _admin_role_id(session):
    return session.query(Role).filter(Role.name == "admin").one().id


def _join(session, user_id, role_name="admin"):
    session.add(RoleMember(user_id=user_id, role_id=_role_id(session, role_name)))
    session.commit()


def _role_id(session, name):
    return session.query(Role).filter(Role.name == name).one().id


def _holds(session, user_id, role_name="admin"):
    return (
        session.query(RoleMember)
        .filter(RoleMember.user_id == user_id, RoleMember.role_id == _role_id(session, role_name))
        .first()
        is not None
    )


def _user_exists(session, user_id):
    return session.query(User).filter(User.user_id == user_id).count() == 1


def _denials(session):
    return session.query(AuditEvent).filter(AuditEvent.event_type == "admin_lockout_denied").all()


def _fields(row):
    """AuditEvent.fields round-trips as JSON text off a real DB read."""
    import json as _json

    return _json.loads(row.fields) if isinstance(row.fields, str) else row.fields


def _success_rows(session, event_type):
    return session.query(AuditEvent).filter(AuditEvent.event_type == event_type).all()


class TestRoleMemberRemoveLockoutGuard:
    """DELETE /roles/{admin}/members/{user_id} — both halves."""

    def test_removing_the_last_admin_is_refused(self, session):
        """(a) refused, and the membership row is STILL in the database."""
        _join(session, "admin1")
        client = _client(session, caller_id=SECOND_ADMIN)

        resp = client.delete(f"/api/v1/roles/{_admin_role_id(session)}/members/admin1")

        assert resp.status_code == 409, resp.text
        assert "last admin" in resp.json()["detail"]
        assert _holds(session, "admin1"), "refusal must not delete the membership"
        assert not _success_rows(session, "member_removed")

    def test_removing_a_non_last_admin_succeeds(self, session):
        """(b) the negative half: two admins, one leaves, the roster stands."""
        _join(session, "admin1")
        _join(session, SECOND_ADMIN)
        client = _client(session, caller_id="admin1")

        resp = client.delete(f"/api/v1/roles/{_admin_role_id(session)}/members/{SECOND_ADMIN}")

        assert resp.status_code == 200, resp.text
        assert resp.json()["removed"] is True
        assert not _holds(session, SECOND_ADMIN)
        assert _holds(session, "admin1")
        assert len(_success_rows(session, "member_removed")) == 1

    def test_self_removal_from_the_admin_role_is_refused(self, session):
        """(c) caller == target, another admin stands by: still refused, with a
        reason naming why, and the row survives."""
        _join(session, "admin1")
        _join(session, SECOND_ADMIN)
        client = _client(session, caller_id="admin1")

        resp = client.delete(f"/api/v1/roles/{_admin_role_id(session)}/members/admin1")

        assert resp.status_code == 409, resp.text
        assert "your own admin membership" in resp.json()["detail"]
        assert _holds(session, "admin1")

    def test_non_admin_role_membership_removal_untouched(self, session):
        """Negative (posture): the guard is admin-role scoped — a caller leaving
        a NON-admin role is the ordinary operation it always was."""
        _join(session, "admin1")
        _join(session, "admin1", role_name="operator")
        client = _client(session, caller_id="admin1")

        resp = client.delete(f"/api/v1/roles/{_role_id(session, 'operator')}/members/admin1")

        assert resp.status_code == 200, resp.text
        assert not _holds(session, "admin1", role_name="operator")
        assert _holds(session, "admin1")

    def test_absent_membership_still_404s(self, session):
        """Regression: the 404 half of the route is not eaten by the guard."""
        _join(session, "admin1")
        client = _client(session, caller_id="admin1")

        resp = client.delete(f"/api/v1/roles/{_admin_role_id(session)}/members/plainjane")

        assert resp.status_code == 404, resp.text


class TestAdminRemoveLockoutGuard:
    """DELETE /admin/users/{user_id} — both halves."""

    def test_removing_the_last_admin_user_is_refused(self, session):
        """(d) first half: the only admin-role holder cannot be deleted, and the
        USER row plus its membership both survive."""
        _join(session, "admin1")
        client = _client(session, caller_id=SECOND_ADMIN)

        resp = client.delete("/api/v1/admin/users/admin1")

        assert resp.status_code == 409, resp.text
        assert "last admin" in resp.json()["detail"]
        assert _user_exists(session, "admin1")
        assert _holds(session, "admin1")
        assert not _success_rows(session, "user_deleted")

    def test_self_account_removal_is_refused(self, session):
        """(d) self half: a caller cannot delete the account they are calling
        from, even with a second admin present."""
        _join(session, "admin1")
        _join(session, SECOND_ADMIN)
        client = _client(session, caller_id="admin1")

        resp = client.delete("/api/v1/admin/users/admin1")

        assert resp.status_code == 409, resp.text
        assert "your own user account" in resp.json()["detail"]
        assert _user_exists(session, "admin1")

    def test_removing_a_non_admin_user_still_works(self, session):
        """(d) NEGATIVE HALF / regression lock on the bulk-delete path: a plain
        user is removed exactly as before, dependents and all — the cascade the
        #425 fix paid for is not disturbed."""
        _join(session, "admin1")
        _join(session, "plainjane", role_name="operator")
        now = datetime.now(UTC)
        session.add(
            WebAuthnCredential(
                user_id="plainjane",
                credential_id=b"KEY_J",
                public_key=b"pk",
                label="key",
                created_at=now,
            )
        )
        session.add(SessionModel(user_id="plainjane", created_at=now, expires_at=now))
        session.commit()
        client = _client(session, caller_id="admin1")

        resp = client.delete("/api/v1/admin/users/plainjane")

        assert resp.status_code == 200, resp.text
        assert resp.json()["removed"] is True
        assert not _user_exists(session, "plainjane")
        assert session.query(RoleMember).filter(RoleMember.user_id == "plainjane").count() == 0
        assert session.query(WebAuthnCredential).filter(WebAuthnCredential.user_id == "plainjane").count() == 0
        assert session.query(SessionModel).filter(SessionModel.user_id == "plainjane").count() == 0
        assert len(_success_rows(session, "user_deleted")) == 1

    def test_removing_an_admin_with_another_admin_standing_by_works(self, session):
        """(b) shape, user route: deleting a NON-last admin who is not the
        caller stays allowed."""
        _join(session, "admin1")
        _join(session, SECOND_ADMIN)
        client = _client(session, caller_id="admin1")

        resp = client.delete(f"/api/v1/admin/users/{SECOND_ADMIN}")

        assert resp.status_code == 200, resp.text
        assert not _user_exists(session, SECOND_ADMIN)
        assert _holds(session, "admin1")

    def test_unknown_user_still_404s(self, session):
        """Regression: the guard answers after the 404, not instead of it."""
        _join(session, "admin1")
        client = _client(session, caller_id="admin1")

        assert client.delete("/api/v1/admin/users/ghost").status_code == 404


class TestRefusalAuditAndDisclosurePosture:
    """The refusal is audited (same-transaction shape as the success path,
    commit-before-raise like the other denial rows) and discloses nothing."""

    def test_last_admin_refusal_lands_one_value_free_denial_row(self, session):
        _join(session, "admin1")
        _join(session, "plainjane", role_name="operator")
        client = _client(session, caller_id=SECOND_ADMIN)

        resp = client.delete("/api/v1/admin/users/admin1")

        assert resp.status_code == 409, resp.text
        rows = _denials(session)
        assert len(rows) == 1, "a refusal must be recorded, and recorded once"
        assert rows[0].user_id == SECOND_ADMIN  # the actor, per migration-022 convention
        fields = _fields(rows[0])
        assert fields["outcome"] == "denied"
        assert fields["reason"] == "last_admin"
        assert fields["action"] == "remove_user"
        assert fields["target_user_id"] == "admin1"

    def test_role_member_refusal_lands_a_denial_row(self, session):
        _join(session, "admin1")
        client = _client(session, caller_id=SECOND_ADMIN)

        resp = client.delete(f"/api/v1/roles/{_admin_role_id(session)}/members/admin1")

        assert resp.status_code == 409, resp.text
        rows = _denials(session)
        assert len(rows) == 1
        assert _fields(rows[0])["action"] == "remove_member"

    def test_denial_rows_and_details_disclose_no_other_user(self, session):
        """(e) enumeration posture: neither the 409 body nor the audit fields
        may name anyone besides the id the caller already typed."""
        _join(session, "admin1")
        for name in ("carol", "dave", "eve"):
            session.add(User(user_id=name, status="active"))
        session.commit()
        client = _client(session, caller_id="carol")

        bodies = [
            client.delete("/api/v1/admin/users/admin1").json()["detail"],
            client.delete(f"/api/v1/roles/{_admin_role_id(session)}/members/admin1").json()["detail"],
            client.delete("/api/v1/admin/users/carol").json()["detail"],
        ]

        for name in ("dave", "eve"):
            assert all(name not in body for body in bodies), bodies
        for row in _denials(session):
            blob = str(_fields(row))
            assert "dave" not in blob and "eve" not in blob

    def test_successful_removals_write_no_denial_row(self, session):
        """Negative half of the audit surface: a permitted removal is not
        recorded as a refusal."""
        _join(session, "admin1")
        _join(session, SECOND_ADMIN)
        client = _client(session, caller_id="admin1")

        assert client.delete(f"/api/v1/admin/users/{SECOND_ADMIN}").status_code == 200
        assert _denials(session) == []


class TestConfigureUserStatusGuard:
    """PUT /admin/users/{user_id} — the #486 deactivation half of the same
    rule. ``status`` is a different field from the roster, so the removal
    guards stay silent while the login path dies: is_user_active refuses every
    session for a disabled account, and recovery-code reissue needs an account
    that can still sign in."""

    def _configure(self, client, user_id, payload):
        return client.put(f"/api/v1/admin/users/{user_id}", json=payload)

    def test_disabling_the_only_active_admin_is_refused(self, session):
        """The headline: one active admin, zero others usable -> 409 and the
        account is STILL active in the database."""
        _join(session, "admin1")
        client = _client(session, caller_id=SECOND_ADMIN)

        resp = self._configure(client, "admin1", {"status": "disabled"})

        assert resp.status_code == 409, resp.text
        assert "usable admin" in resp.json()["detail"]
        assert _status(session, "admin1") == "active", "a refusal must not write the status"
        assert not _success_rows(session, "user_updated")

    def test_disabling_an_admin_while_another_active_admin_stands_is_allowed(self, session):
        """(b) shape, status route: the refusal is only for a zero-usable
        after-state, so the ordinary disable of a co-admin still works."""
        _join(session, "admin1")
        _join(session, SECOND_ADMIN)
        client = _client(session, caller_id="admin1")

        resp = self._configure(client, SECOND_ADMIN, {"status": "disabled"})

        assert resp.status_code == 200, resp.text
        assert resp.json()["configured"] is True
        assert _status(session, SECOND_ADMIN) == "disabled"
        assert _status(session, "admin1") == "active"

    def test_disabling_a_non_admin_user_is_allowed_and_guard_silent(self, session):
        """Negative: the guard is admin-role scoped — a plain account is
        disabled exactly as before, with no denial row."""
        _join(session, "admin1")
        _join(session, "plainjane", role_name="operator")
        client = _client(session, caller_id="admin1")

        resp = self._configure(client, "plainjane", {"status": "disabled"})

        assert resp.status_code == 200, resp.text
        assert _status(session, "plainjane") == "disabled"
        assert _denials(session) == []

    def test_activating_the_last_admin_is_allowed(self, session):
        """Recovery path: the guarded direction is deactivation only, so
        re-activating the only admin is never refused."""
        _join(session, "admin1")
        _set_status(session, "admin1", "disabled")
        client = _client(session, caller_id="cert-only-admin")

        resp = self._configure(client, "admin1", {"status": "active"})

        assert resp.status_code == 200, resp.text
        assert _status(session, "admin1") == "active"

    def test_non_status_fields_on_the_last_admin_are_allowed(self, session):
        """Regression: the guard answers the status write only — display name and
        auth mode on the last admin stay the ordinary operation (no req.status,
        no guard call). #625 dropped `session_timeout` from this payload: the
        field no longer exists on the request model, so sending it would be a
        422 by #357's extra=forbid, not a pass-through."""
        _join(session, "admin1")
        client = _client(session, caller_id="admin1")

        resp = self._configure(client, "admin1", {"display_name": "Ops", "auth_mode": "security-key"})

        assert resp.status_code == 200, resp.text
        assert _status(session, "admin1") == "active"

    def test_one_active_one_disabled_roster_refuses_deactivating_the_active_one(self, session):
        """The #486 outage exactly: TWO admin rows on the roster, ONE usable.
        A roster-only check would wave this through."""
        _join(session, "admin1")
        _join(session, SECOND_ADMIN)
        _set_status(session, SECOND_ADMIN, "disabled")
        client = _client(session, caller_id="admin1")

        resp = self._configure(client, "admin1", {"status": "disabled"})

        assert resp.status_code == 409, resp.text
        assert _status(session, "admin1") == "active"

    def test_pending_enrollment_write_on_the_last_admin_is_refused(self, session):
        """Scope pinned: is_user_active gates on "active", so
        pending_enrollment takes the login away too — guarding only the
        "disabled" literal would reopen the outage through the other value."""
        _join(session, "admin1")
        client = _client(session, caller_id=SECOND_ADMIN)

        resp = self._configure(client, "admin1", {"status": "pending_enrollment"})

        assert resp.status_code == 409, resp.text
        assert _status(session, "admin1") == "active"

    def test_refusal_lands_one_denial_row_naming_the_configure_action(self, session):
        """AC1: the SAME event and shape as the removal refusals — no new
        audit vocabulary, one row, commit-before-raise."""
        _join(session, "admin1")
        _join(session, "plainjane", role_name="operator")
        client = _client(session, caller_id=SECOND_ADMIN)

        resp = self._configure(client, "admin1", {"status": "disabled"})

        assert resp.status_code == 409, resp.text
        rows = _denials(session)
        assert len(rows) == 1, "a refusal must be recorded, and recorded once"
        assert rows[0].user_id == SECOND_ADMIN  # the actor, migration-022 convention
        fields = _fields(rows[0])
        assert fields["outcome"] == "denied"
        assert fields["reason"] == "last_usable_admin_deactivated"
        assert fields["action"] == "configure_user"
        assert fields["target_user_id"] == "admin1"

    def test_refusal_discloses_no_other_user(self, session):
        """(e) enumeration posture on the new route: neither the 409 body nor
        the audit row may name anyone besides the id the caller typed."""
        _join(session, "admin1")
        for name in ("dave", "eve"):
            session.add(User(user_id=name, status="active"))
        session.commit()
        client = _client(session, caller_id="dave")

        resp = self._configure(client, "admin1", {"status": "disabled"})

        assert resp.status_code == 409, resp.text
        body = resp.json()["detail"]
        for name in ("dave", "eve"):
            assert name not in body, body
        for row in _denials(session):
            blob = str(_fields(row))
            assert "eve" not in blob

    def test_successful_configure_writes_no_denial_row(self, session):
        """Negative half of the audit surface: a permitted status write is not
        recorded as a refusal, and still writes its user_updated row."""
        _join(session, "admin1")
        _join(session, SECOND_ADMIN)
        client = _client(session, caller_id="admin1")

        assert self._configure(client, SECOND_ADMIN, {"status": "disabled"}).status_code == 200
        assert _denials(session) == []
        assert len(_success_rows(session, "user_updated")) == 1

    def test_unknown_user_still_404s(self, session):
        """Regression: the guard answers after the 404, not instead of it."""
        _join(session, "admin1")
        client = _client(session, caller_id="admin1")

        assert self._configure(client, "ghost", {"status": "disabled"}).status_code == 404


def _status(session, user_id):
    session.expire_all()
    return session.query(User).filter(User.user_id == user_id).one().status


def _set_status(session, user_id, value):
    session.query(User).filter(User.user_id == user_id).update({"status": value})
    session.commit()
