# Copyright (c) 2026 Tabith LLC.
# Use of this source code is governed by the Business Source License 1.1
# included in the LICENSE file at the root of this repository. As of the
# Change Date listed there, the work will be available under MPL 2.0.
# SPDX-License-Identifier: BUSL-1.1

"""Truth-table tests for the #443 admin-lockout guard (RoleManager).

The guard is the ONE enforcement point behind both destructive routes
(``DELETE /admin/users/{user_id}`` and ``DELETE /roles/{role_id}/members/
{user_id}``): a removal that would leave the ``admin`` role with zero members,
or that would let a caller strip their own admin access, is refused BEFORE any
delete. #443 shipped because neither route had either check, so a deployment
could lock itself out of enrollment, key rotation and policy work.

Bound to a REAL SQLite session (house pattern from
test_role_manager_delete_dependency_425.py) — the guard reads the roster, and a
mock can answer a roster question with anything.

Every cell is paired with the half that must STILL WORK: a guard that refuses
everything is not a pass.
"""

import pytest
from core.iam.models import Base, Role, RoleMember, User
from core.iam.role_manager import AdminLockoutError, RoleManager
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

OTHER_ADMIN = "admin2"  # the second admin, used by the no-disclosure cells


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
            User(user_id=OTHER_ADMIN, status="active"),
            User(user_id="plainjane", status="active"),
            Role(name="admin", permissions="read-write"),
            Role(name="operator", permissions="read"),
        ]
    )
    s.commit()
    yield s
    s.close()
    engine.dispose()


def _role_id(session, name):
    return session.query(Role).filter(Role.name == name).one().id


def _admin_id(session):
    return _role_id(session, "admin")


def _join(session, user_id, role_name):
    session.add(RoleMember(user_id=user_id, role_id=_role_id(session, role_name)))
    session.commit()


def _holds(session, user_id, role_name):
    return (
        session.query(RoleMember)
        .filter(RoleMember.user_id == user_id, RoleMember.role_id == _role_id(session, role_name))
        .first()
        is not None
    )


class TestMembershipScopedGuard:
    """DELETE /roles/{role_id}/members/{user_id} shape: role_id is always set."""

    def test_last_admin_membership_removal_refused(self, session):
        """(a) ONE admin member: the removal is refused and the row SURVIVES."""
        _join(session, "admin1", "admin")

        with pytest.raises(AdminLockoutError) as excinfo:
            RoleManager(session).remove_member("admin1", _admin_id(session), caller_user_id="someone-else")

        assert excinfo.value.reason == AdminLockoutError.LAST_ADMIN
        session.rollback()
        assert _holds(session, "admin1", "admin")

    def test_non_last_admin_membership_removal_succeeds(self, session):
        """(b) negative half: with TWO admin members, one leaves and the roster
        keeps an admin — the operation is NOT refused."""
        _join(session, "admin1", "admin")
        _join(session, OTHER_ADMIN, "admin")

        assert RoleManager(session).remove_member(OTHER_ADMIN, _admin_id(session), caller_user_id="admin1") is True
        session.commit()
        assert not _holds(session, OTHER_ADMIN, "admin")
        assert _holds(session, "admin1", "admin")

    def test_self_removal_of_own_admin_membership_refused(self, session):
        """(c) the caller IS the target: refused even though another admin
        remains — the refusal is the 'are you sure' a remote call cannot
        answer, so reason is self_removal, not last_admin."""
        _join(session, "admin1", "admin")
        _join(session, OTHER_ADMIN, "admin")

        with pytest.raises(AdminLockoutError) as excinfo:
            RoleManager(session).remove_member("admin1", _admin_id(session), caller_user_id="admin1")

        assert excinfo.value.reason == AdminLockoutError.SELF_REMOVAL
        session.rollback()
        assert _holds(session, "admin1", "admin")

    def test_non_admin_role_membership_removal_untouched(self, session):
        """Negative (posture): a role other than 'admin' cannot empty the admin
        roster, so removing someone from it stays the ordinary operation."""
        _join(session, "admin1", "admin")
        _join(session, "admin1", "operator")

        assert (
            RoleManager(session).remove_member("admin1", _role_id(session, "operator"), caller_user_id="admin1") is True
        )
        session.commit()
        assert _holds(session, "admin1", "admin")
        assert not _holds(session, "admin1", "operator")

    def test_absent_membership_still_returns_false(self, session):
        """Negative: the 404 half of the route (remove_member -> False) is not
        swallowed by the guard — a caller removing themself from a role they
        never held gets the same answer as before."""
        _join(session, "admin1", "admin")
        _join(session, OTHER_ADMIN, "admin")

        assert RoleManager(session).remove_member("plainjane", _admin_id(session), caller_user_id="plainjane") is False

    def test_no_caller_identity_still_enforces_last_admin(self, session):
        """A certificate-only caller carries no user_id: the self-removal half
        cannot fire, but the last-admin half MUST still refuse."""
        _join(session, "admin1", "admin")

        with pytest.raises(AdminLockoutError) as excinfo:
            RoleManager(session).remove_member("admin1", _admin_id(session))

        assert excinfo.value.reason == AdminLockoutError.LAST_ADMIN

    def test_guard_answers_before_the_delete(self, session):
        """A refusal stages nothing: the raise precedes db.delete(), so the
        route's commit has no membership deletion to land."""
        _join(session, "admin1", "admin")

        rm = RoleManager(session)
        with pytest.raises(AdminLockoutError):
            rm.remove_member("admin1", _admin_id(session), caller_user_id="cert-only-identity")

        assert len(session.deleted) == 0
        assert _holds(session, "admin1", "admin")


class TestUserScopedGuard:
    """DELETE /admin/users/{user_id} shape: role_id is None (the whole user goes)."""

    def test_last_admin_user_removal_refused(self, session):
        """(d) first half: the only admin-role holder cannot be deleted."""
        _join(session, "admin1", "admin")

        with pytest.raises(AdminLockoutError) as excinfo:
            RoleManager(session).assert_removal_keeps_admin("admin1", caller_user_id="cert-only-identity")

        assert excinfo.value.reason == AdminLockoutError.LAST_ADMIN

    def test_self_account_removal_refused(self, session):
        """(d) self half: a caller cannot delete their own account, even with
        another admin standing by."""
        _join(session, "admin1", "admin")
        _join(session, OTHER_ADMIN, "admin")

        with pytest.raises(AdminLockoutError) as excinfo:
            RoleManager(session).assert_removal_keeps_admin("admin1", caller_user_id="admin1")

        assert excinfo.value.reason == AdminLockoutError.SELF_REMOVAL

    def test_non_admin_user_removal_allowed(self, session):
        """(d) negative half / regression lock on the bulk-delete path: a plain
        user — even one holding a NON-admin role — removes exactly as before."""
        _join(session, "admin1", "admin")
        _join(session, "plainjane", "operator")

        # No raise: admin_remove proceeds to its own dependent-row cascade.
        RoleManager(session).assert_removal_keeps_admin("plainjane", caller_user_id="admin1")

    def test_admin_user_with_another_admin_standing_by_allowed(self, session):
        """(d) negative half: deleting an admin who is NOT the last one and is
        NOT the caller is allowed — the roster keeps an administrator."""
        _join(session, "admin1", "admin")
        _join(session, OTHER_ADMIN, "admin")

        RoleManager(session).assert_removal_keeps_admin(OTHER_ADMIN, caller_user_id="admin1")

    def test_self_account_removal_refused_without_admin_role(self, session):
        """Posture: 'do not delete the account you are logged in as' does not
        depend on the target holding the admin role."""
        with pytest.raises(AdminLockoutError) as excinfo:
            RoleManager(session).assert_removal_keeps_admin("plainjane", caller_user_id="plainjane")

        assert excinfo.value.reason == AdminLockoutError.SELF_REMOVAL


class TestUnseededAdminRole:
    """A pre-init core has no 'admin' role row: there is no roster to empty."""

    def test_membership_scoped_call_passes_through(self, session):
        session.query(RoleMember).delete()
        session.query(Role).filter(Role.name == "admin").delete()
        session.commit()

        RoleManager(session).assert_removal_keeps_admin("admin1", role_id=999, caller_user_id="someone-else")

    def test_whole_user_self_removal_still_refused(self, session):
        session.query(Role).filter(Role.name == "admin").delete()
        session.query(RoleMember).delete()
        session.commit()

        with pytest.raises(AdminLockoutError) as excinfo:
            RoleManager(session).assert_removal_keeps_admin("admin1", caller_user_id="admin1")

        assert excinfo.value.reason == AdminLockoutError.SELF_REMOVAL


class TestNoEnumerationOracle:
    """(e) Neither the message nor the structured fields may name another
    user: the refusal says WHO CANNOT GO, never who else could."""

    def _refused(self, session):
        _join(session, "admin1", "admin")
        with pytest.raises(AdminLockoutError) as excinfo:
            RoleManager(session).assert_removal_keeps_admin("admin1", caller_user_id="cert-only-identity")
        return excinfo.value

    def test_last_admin_detail_names_no_other_user(self, session):
        # Seed a SECOND user id that must never surface, then refuse by
        # deleting the first while... actually: keep one admin and another
        # plain user present, so any roster dump would leak 'plainjane'.
        _join(session, "plainjane", "operator")
        error = self._refused(session)

        assert "plainjane" not in str(error)
        assert OTHER_ADMIN not in str(error)
        assert error.user_id == "admin1"  # the target the caller already named

    def test_structured_fields_carry_only_the_target_and_role(self, session):
        _join(session, "plainjane", "operator")
        error = self._refused(session)

        assert error.reason == AdminLockoutError.LAST_ADMIN
        assert error.user_id == "admin1"
        assert isinstance(error.role_id, int)
