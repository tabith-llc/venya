# Copyright (c) 2026 Tabith LLC.
# Use of this source code is governed by the Business Source License 1.1
# included in the LICENSE file at the root of this repository. As of the
# Change Date listed there, the work will be available under MPL 2.0.
# SPDX-License-Identifier: BUSL-1.1

import os
import threading

"""Truth-table tests for the admin-lockout guard (RoleManager) — #443 removals,
#486 deactivations.

The guard is the ONE enforcement point behind the destructive routes
(``DELETE /admin/users/{user_id}`` and ``DELETE /roles/{role_id}/members/
{user_id}``): a removal that would leave the ``admin`` role with zero members,
or that would let a caller strip their own admin access, is refused BEFORE any
delete. #443 shipped because neither route had either check, so a deployment
could lock itself out of enrollment, key rotation and policy work.

#486 adds the other half of the same rule: ``PUT /admin/users/{user_id}`` can
write ``users.status``, which leaves the roster intact but takes the account
out of the login path — a disabled account cannot authenticate
(``session_manager.is_user_active``), and recovery-code reissue needs an
account that can still sign in. So the count these cells check is the set of
USABLE admins: active status AND an ``admin`` membership.

Bound to a REAL SQLite session (house pattern from
test_role_manager_delete_dependency_425.py) — the guard reads the roster and
the account statuses, and a mock can answer either question with anything.

Every cell is paired with the half that must STILL WORK: a guard that refuses
everything is not a pass.
"""

import pytest
from core.iam.models import Base, Role, RoleMember, User
from core.iam.role_manager import AdminLockoutError, RoleManager
from sqlalchemy import create_engine, event
from sqlalchemy.dialects import postgresql
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


def _set_status(session, user_id, status_value):
    session.query(User).filter(User.user_id == user_id).update({"status": status_value})
    session.commit()


class TestUsableAdminSet:
    """#486 AC3: the definition of "usable admin" — active status AND an
    ``admin`` membership. Both absence classes count as zero."""

    def test_active_admin_counts(self, session):
        _join(session, "admin1", "admin")
        assert RoleManager(session).usable_admin_ids() == {"admin1"}

    def test_disabled_admin_does_not_count(self, session):
        _join(session, "admin1", "admin")
        _set_status(session, "admin1", "disabled")

        assert RoleManager(session).usable_admin_ids() == set()

    def test_active_user_without_admin_membership_does_not_count(self, session):
        _join(session, "admin1", "operator")

        assert RoleManager(session).usable_admin_ids() == set()

    def test_pending_enrollment_admin_does_not_count(self, session):
        """A freshly created account that has not enrolled yet is not usable
        either — ``is_user_active`` is the login gate, not a string check on
        "disabled" only."""
        _join(session, "admin1", "admin")
        _set_status(session, "admin1", "pending_enrollment")

        assert RoleManager(session).usable_admin_ids() == set()

    def test_no_admin_role_seeded_yet_counts_zero(self, session):
        session.query(RoleMember).delete()
        session.query(Role).filter(Role.name == "admin").delete()
        session.commit()

        assert RoleManager(session).usable_admin_ids() == set()


class TestStatusChangeKeepsAdmin:
    """#486: the deactivation half of the lockout rule, same enforcement point
    as the removal guards — asserted at the core, where the count lives."""

    def test_disabling_the_only_active_admin_refused(self, session):
        """The headline: one active admin, no other usable admin -> refuse."""
        _join(session, "admin1", "admin")

        with pytest.raises(AdminLockoutError) as excinfo:
            RoleManager(session).assert_status_change_keeps_admin("admin1", "disabled")

        assert excinfo.value.reason == AdminLockoutError.LAST_USABLE_ADMIN_DEACTIVATED
        assert excinfo.value.user_id == "admin1"
        session.rollback()
        assert _user_status(session, "admin1") == "active"

    def test_disabling_an_admin_while_another_active_admin_stands_allowed(self, session):
        """Paired negative (AC1): the refusal is only for ZERO usable admins."""
        _join(session, "admin1", "admin")
        _join(session, OTHER_ADMIN, "admin")

        RoleManager(session).assert_status_change_keeps_admin(OTHER_ADMIN, "disabled")

    def test_disabling_a_non_admin_user_allowed_and_guard_silent(self, session):
        """Negative: the ordinary administrative write on a plain account is
        untouched — no raise, no reason, nothing to answer."""
        _join(session, "admin1", "admin")
        _join(session, "plainjane", "operator")

        RoleManager(session).assert_status_change_keeps_admin("plainjane", "disabled")

    def test_activation_of_the_last_admin_allowed(self, session):
        """Pinning the scope: ONLY deactivation is guarded. Re-activating the
        last admin must stay possible — that is the recovery path."""
        _join(session, "admin1", "admin")
        _set_status(session, "admin1", "disabled")

        RoleManager(session).assert_status_change_keeps_admin("admin1", "active")

    def test_pending_enrollment_write_on_the_last_admin_refused(self, session):
        """A ruled-scope cell the spec matrix asks about: ``pending_enrollment``
        is not an activation — ``is_user_active`` refuses login for it exactly
        as it does for ``disabled`` — so the design rule (refuse when the write
        leaves ZERO usable admins) covers it. Reported as a spec-vs-design
        discrepancy for the lead; this cell states which way the code went."""
        _join(session, "admin1", "admin")

        with pytest.raises(AdminLockoutError) as excinfo:
            RoleManager(session).assert_status_change_keeps_admin("admin1", "pending_enrollment")

        assert excinfo.value.reason == AdminLockoutError.LAST_USABLE_ADMIN_DEACTIVATED

    def test_pending_enrollment_write_allowed_when_another_active_admin_stands(self, session):
        """Paired negative of the cell above: the rule counts usable admins, it
        does not blacklist a status value."""
        _join(session, "admin1", "admin")
        _join(session, OTHER_ADMIN, "admin")

        RoleManager(session).assert_status_change_keeps_admin(OTHER_ADMIN, "pending_enrollment")

    def test_one_active_one_disabled_roster_refuses_deactivating_the_active_one(self, session):
        """The roster has two admins on paper, ONE usable: the removal guards
        see a healthy roster and stay silent, which is exactly the #486
        outage — the status write must be the one that answers."""
        _join(session, "admin1", "admin")
        _join(session, OTHER_ADMIN, "admin")
        _set_status(session, OTHER_ADMIN, "disabled")

        with pytest.raises(AdminLockoutError) as excinfo:
            RoleManager(session).assert_status_change_keeps_admin("admin1", "disabled")

        assert excinfo.value.reason == AdminLockoutError.LAST_USABLE_ADMIN_DEACTIVATED

    def test_disabling_an_already_disabled_admin_allowed(self, session):
        """Negative: a no-op disable on the last admin changes nothing, so it
        changes nothing to refuse — the usable count is already zero and this
        write does not lower it."""
        _join(session, "admin1", "admin")
        _set_status(session, "admin1", "disabled")

        RoleManager(session).assert_status_change_keeps_admin("admin1", "disabled")

    def test_unseeded_admin_role_passes_through(self, session):
        """Pre-init posture, matching the removal half: no admin role means no
        roster to strand."""
        session.query(RoleMember).delete()
        session.query(Role).filter(Role.name == "admin").delete()
        session.commit()

        RoleManager(session).assert_status_change_keeps_admin("admin1", "disabled")

    def test_guard_answers_before_any_status_write(self, session):
        """The refusal stages nothing: the route's commit has no pending UPDATE
        to land, so the account keeps signing in."""
        _join(session, "admin1", "admin")
        target = session.query(User).filter(User.user_id == "admin1").one()

        rm = RoleManager(session)
        with pytest.raises(AdminLockoutError):
            rm.assert_status_change_keeps_admin("admin1", "disabled")

        assert len(session.deleted) == 0
        assert len(session.new) == 0
        assert not session.is_modified(target), "the guard must not stage a status UPDATE"
        assert target.status == "active"
        session.expire_all()
        assert _user_status(session, "admin1") == "active"

    def test_unknown_status_value_is_treated_as_deactivating(self, session):
        """Fail-closed posture: the guard guards on "not active", so an
        unrecognised status value cannot slip past it as if it were an
        activation."""
        _join(session, "admin1", "admin")

        with pytest.raises(AdminLockoutError) as excinfo:
            RoleManager(session).assert_status_change_keeps_admin("admin1", "suspended")

        assert excinfo.value.reason == AdminLockoutError.LAST_USABLE_ADMIN_DEACTIVATED

    def test_refusal_message_states_the_usable_admin_definition(self, session):
        """AC3: the operator reading the 409 learns WHAT counts as usable, not
        just that something is wrong — and the message names no other member."""
        _join(session, "admin1", "admin")
        _join(session, OTHER_ADMIN, "operator")

        with pytest.raises(AdminLockoutError) as excinfo:
            RoleManager(session).assert_status_change_keeps_admin("admin1", "disabled")

        message = str(excinfo.value)
        assert "active" in message and "admin role" in message
        assert OTHER_ADMIN not in message
        assert "plainjane" not in message


def _user_status(session, user_id):
    return session.query(User).filter(User.user_id == user_id).one().status


# ---------------------------------------------------------------------------
# #487 — the roster COUNT must be taken under a row lock (option (i): atomic)
# ---------------------------------------------------------------------------


def _role_member_reads_locked(session, run):
    """Run ``run()`` and record, for every ORM SELECT issued against
    ``role_members``, whether the statement REQUESTS a row lock.

    The lock check renders the captured statement through the PRODUCTION
    dialect (PostgreSQL), because SQLite — the test-harness backend —
    silently drops ``FOR UPDATE`` (verified: the locked read executes and
    the clause is omitted). A ``True`` entry therefore means "this read asks
    PostgreSQL to lock the roster rows it returns", which is the idiom
    :func:`credentials.py`' last-active-credential guard and
    ``EnrollmentToken`` minting already use (``with_for_update()``).

    What this DOES prove: the guard's roster read requests the lock, in
    statement order. What this does NOT prove: the wait/serialization
    semantics of that lock — no PostgreSQL runs on this venue; that half is
    the gated ``TestConcurrentRemovalsPostgresql`` cell below, which skipped
    here and must be run against a scratch PostgreSQL before anyone claims
    the race is physically closed.
    """
    outcomes = []

    def hook(state):
        if not state.is_select:
            return
        statement = state.statement
        if "role_members" not in str(statement):
            return
        pg_text = " ".join(str(statement.compile(dialect=postgresql.dialect())).split()).upper()
        outcomes.append("FOR UPDATE" in pg_text)

    event.listen(session, "do_orm_execute", hook)
    try:
        run()
    finally:
        event.remove(session, "do_orm_execute", hook)
    return outcomes


class TestGuardLocksTheRosterRead487:
    """AC1/AC2 (atomic option): both enforcement points — the removal guard
    (#443) and the status guard (#486) — count the admin roster under
    ``FOR UPDATE``, so two concurrent removals of the last two admins cannot
    both read a roster of two. Same posture on both surfaces, AC2."""

    def test_removal_guard_roster_read_is_locked(self, session):
        """RED at HEAD: the guard counts the roster with no lock."""
        _join(session, "admin1", "admin")
        _join(session, OTHER_ADMIN, "admin")

        outcomes = _role_member_reads_locked(
            session,
            lambda: RoleManager(session).assert_removal_keeps_admin(
                OTHER_ADMIN, role_id=_admin_id(session), caller_user_id="admin1"
            ),
        )

        assert outcomes, "the guard must read the roster at all"
        assert outcomes[0] is True, f"first roster read must FOR UPDATE, saw {outcomes}"

    def test_status_guard_roster_read_is_locked(self, session):
        """The #486 half answers with the SAME posture (AC2: the surfaces
        must not diverge)."""
        _join(session, "admin1", "admin")
        _join(session, OTHER_ADMIN, "admin")

        outcomes = _role_member_reads_locked(
            session,
            lambda: RoleManager(session).assert_status_change_keeps_admin(OTHER_ADMIN, "disabled"),
        )

        assert outcomes, "the guard must read the roster at all"
        assert outcomes[0] is True, f"first roster read must FOR UPDATE, saw {outcomes}"

    def test_removal_lock_precedes_the_membership_delete_read(self, session):
        """Ordering: in ``remove_member`` the LOCKED guard read runs before
        the (unlocked, same-transaction) lookup the delete uses — the lock is
        taken before anything the rule protects is touched."""
        _join(session, "admin1", "admin")
        _join(session, OTHER_ADMIN, "admin")

        outcomes = _role_member_reads_locked(
            session,
            lambda: RoleManager(session).remove_member(OTHER_ADMIN, _admin_id(session), caller_user_id="admin1"),
        )

        assert outcomes[0] is True, f"guard read must come first and be locked, saw {outcomes}"
        session.commit()

    def test_non_admin_role_removal_still_succeeds_under_the_locked_guard_read(self, session):
        """Paired negative on posture: removing a membership of a role other
        than 'admin' still answers through the guard's locked roster read
        (the guard cannot know which role is at stake until it looks), and
        the operation stays ALLOWED — the lock must not refuse what the rule
        permits."""
        _join(session, "admin1", "admin")
        _join(session, "admin1", "operator")

        outcomes = _role_member_reads_locked(
            session,
            lambda: RoleManager(session).remove_member(
                "admin1", _role_id(session, "operator"), caller_user_id="admin1"
            ),
        )

        assert outcomes[0] is True, f"roster read under lock, then fall-through, saw {outcomes}"
        session.commit()
        assert _holds(session, "admin1", "admin")
        assert not _holds(session, "admin1", "operator")


class TestRemovalsSucceedWhileThirdAdminStands:
    """AC2's paired negative, behavioral half: with THREE admins on the
    roster, two removals (the race's two threads, run sequentially here)
    both succeed and one admin survives. The lock must not over-refuse — a
    race test that only proves refusal is untested.

    Plain sequential, so this cell does not pretend to be the concurrent
    case; the concurrent negative lives in the PostgreSQL-gated class."""

    def test_two_removals_pass_when_a_third_admin_stands(self, session):
        session.add(User(user_id="admin3", status="active"))
        session.commit()
        _join(session, "admin1", "admin")
        _join(session, OTHER_ADMIN, "admin")
        _join(session, "admin3", "admin")

        assert RoleManager(session).remove_member(OTHER_ADMIN, _admin_id(session), caller_user_id="admin1") is True
        session.commit()
        assert RoleManager(session).remove_member("admin3", _admin_id(session), caller_user_id="admin1") is True
        session.commit()

        assert _holds(session, "admin1", "admin")
        assert RoleManager(session).usable_admin_ids() == {"admin1"}


_PG_URL_ENV = "VENYA_TEST_PG_URL"


@pytest.mark.skipif(
    not os.environ.get(_PG_URL_ENV),
    reason=f"real-concurrency cell needs a scratch PostgreSQL in {_PG_URL_ENV} (not available on this venue)",
)
class TestConcurrentRemovalsPostgresql:
    """The #487 race, physically: two threads each remove a DIFFERENT one of
    the last two admins, released together by a barrier so both guard reads
    aim at the same roster. Under the row lock, exactly one succeeds and one
    answers ``AdminLockoutError(LAST_ADMIN)`` — the second guard waits on the
    locked read, re-scans after the first commits (READ COMMITTED re-evaluates
    the locking scan), and sees the survivor already gone.

    DESIGN NOTE FROM THIS LEG: this class is the ticket's physical cell
    rendered as code. It has NOT RUN on the #487 leg — no PostgreSQL exists
    at that venue (spec: no fleet/VM) — so it skipped. Point
    ``VENYA_TEST_PG_URL`` at a SCRATCH database (it drops and recreates the
    IAM tables) before trusting it; do not run it against anything live.

    "Exactly one succeeds" is deterministic AFTER the lock lands; before the
    fix the outcome is timing-dependent (that is the race itself), so this
    cell is the concurrency proof for the fix, not a repro for the bug.
    """

    def _engine_and_factory(self):
        engine = create_engine(os.environ[_PG_URL_ENV])
        Base.metadata.drop_all(engine)
        Base.metadata.create_all(engine)
        return engine, sessionmaker(bind=engine)

    def _seed(self, factory, admin_ids):
        s = factory()
        try:
            for uid in admin_ids:
                s.add(User(user_id=uid, status="active"))
            s.add(Role(name="admin", permissions="read-write"))
            s.commit()
            admin_role = s.query(Role).filter(Role.name == "admin").one()
            for uid in admin_ids:
                s.add(RoleMember(user_id=uid, role_id=admin_role.id))
            s.commit()
            return admin_role.id
        finally:
            s.close()

    def _race(self, admin_ids, targets):
        engine, factory = self._engine_and_factory()
        try:
            admin_role_id = self._seed(factory, admin_ids)
            results = []
            barrier = threading.Barrier(len(targets))

            def worker(target):
                s = factory()
                try:
                    # Start the transaction BEFORE the release, so both
                    # threads' guard reads race for the same roster snapshot.
                    s.query(User).filter(User.user_id == target).first()
                    barrier.wait()
                    try:
                        removed = RoleManager(s).remove_member(target, admin_role_id, caller_user_id="cert-only")
                        s.commit()
                        results.append((target, "removed" if removed else "not-found"))
                    except AdminLockoutError as exc:
                        s.rollback()
                        results.append((target, f"refused:{exc.reason}"))
                finally:
                    s.close()

            threads = [threading.Thread(target=worker, args=(t,)) for t in targets]
            for t in threads:
                t.start()
            for t in threads:
                t.join(timeout=30)
            survivors = self._roster(factory)
            return sorted(results), survivors
        finally:
            Base.metadata.drop_all(engine)
            engine.dispose()

    def _roster(self, factory):
        s = factory()
        try:
            return RoleManager(s).usable_admin_ids()
        finally:
            s.close()

    def test_last_two_admins_two_threads_exactly_one_passes(self):
        outcomes, survivors = self._race(["admin1", "admin2"], ["admin1", "admin2"])
        statuses = [status for _, status in outcomes]
        assert sorted(statuses) == ["refused:last_admin", "removed"], outcomes
        assert len(survivors) == 1, survivors

    def test_two_threads_with_third_admin_both_pass(self):
        outcomes, survivors = self._race(["admin1", "admin2", "admin3"], ["admin1", "admin2"])
        assert sorted(status for _, status in outcomes) == ["removed", "removed"], outcomes
        assert survivors == {"admin3"}, survivors
