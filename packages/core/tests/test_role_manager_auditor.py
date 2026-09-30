# Copyright (c) 2026 Tabith LLC.
# Use of this source code is governed by the Business Source License 1.1
# included in the LICENSE file at the root of this repository. As of the
# Change Date listed there, the work is available under MPL 2.0.
# SPDX-License-Identifier: BUSL-1.1

"""Auditor permission tier in RoleManager (ticket auditor-role).

Truth table with paired negatives, real SQLite (house precedent:
test_session_manager_gate.py — mocks model neither autoflush nor the
relationship-loaded role.permissions).

Tier semantics under test:
- create/update accept "auditor" (and STILL reject anything else).
- has_permission("auditor"): auditor role passes; read-write EXCEEDS (the
  ticket's post-change table grants audit viewing to read-write/admin —
  admin roles are seeded permissions="read-write"); plain read FAILS.
- has_permission("read-write"): auditor does NOT satisfy it — the auditor
  tier never implies write (the ticket's explicit narrowing).
- has_permission("read"): any membership passes, auditor included.
"""

import pytest
from core.iam.models import Base, RoleMember, User
from core.iam.role_manager import RoleManager, RoleManagerError, SeparationOfDutiesError
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


def _mk_member(db, user_id, permissions):
    """Create a role with the given tier and bind user_id to it."""
    rm = RoleManager(db)
    role = rm.create_role(name=f"r-{permissions}-{user_id}", permissions=permissions)
    db.add(RoleMember(user_id=user_id, role_id=role.id))
    db.commit()
    return role


class TestAuditorRoleLifecycle:
    def test_create_role_auditor_succeeds(self, db):
        rm = RoleManager(db)
        role = rm.create_role(name="auditor", permissions="auditor")
        assert role.permissions == "auditor"

    def test_create_role_invalid_permission_still_rejected(self, db):
        """Paired negative: the widened set did not become accept-anything."""
        rm = RoleManager(db)
        with pytest.raises(RoleManagerError) as exc:
            rm.create_role(name="superuser", permissions="admin")
        assert "auditor" in str(exc.value)

    def test_update_role_to_auditor(self, db):
        rm = RoleManager(db)
        role = rm.create_role(name="flip", permissions="read")
        updated = rm.update_role(role.id, permissions="auditor")
        assert updated.permissions == "auditor"

    def test_update_role_invalid_permission_still_rejected(self, db):
        """Paired negative on the update path."""
        rm = RoleManager(db)
        role = rm.create_role(name="flip2", permissions="read")
        with pytest.raises(RoleManagerError):
            rm.update_role(role.id, permissions="root")


class TestHasPermissionAuditorTier:
    def test_auditor_role_passes_auditor(self, db):
        role = _mk_member(db, "aud1", "auditor")
        assert RoleManager(db).has_permission("aud1", role.id, "auditor") is True

    def test_read_role_fails_auditor(self, db):
        """Paired negative (acceptance: read users CANNOT query audit logs)."""
        role = _mk_member(db, "rd1", "read")
        assert RoleManager(db).has_permission("rd1", role.id, "auditor") is False

    def test_read_write_role_passes_auditor(self, db):
        """Regression pin: read-write EXCEEDS auditor — admin (seeded
        read-write) must not lose audit-log access."""
        role = _mk_member(db, "rw1", "read-write")
        assert RoleManager(db).has_permission("rw1", role.id, "auditor") is True

    def test_auditor_role_fails_read_write(self, db):
        """KEY paired negative: auditor does NOT imply write (acceptance:
        auditor cannot create secrets / execute commands)."""
        role = _mk_member(db, "aud2", "auditor")
        assert RoleManager(db).has_permission("aud2", role.id, "read-write") is False

    def test_auditor_role_passes_read(self, db):
        """Auditor keeps the read-tier listings (roles/executors/secrets
        metadata are require_role("read") routes)."""
        role = _mk_member(db, "aud3", "auditor")
        assert RoleManager(db).has_permission("aud3", role.id, "read") is True

    def test_non_member_fails_auditor(self, db):
        """Paired negative: no membership at all → False (not just wrong tier)."""
        role = _mk_member(db, "aud4", "auditor")
        assert RoleManager(db).has_permission("ghost", role.id, "auditor") is False


class TestSeparationOfDutiesGrant:
    """Ruling 2' (NIST SP 800-53 Rev 5 AC-5 preventive, "we need federal
    acceptance!"): the auditor+other-tier mixture is IMPOSSIBLE by
    construction — refused at grant time (add_member) and at tier flips
    (update_role). The union permission MATH (1b) is untouched: the guard
    prevents states, it computes NO permissions."""

    def _user(self, db, user_id):
        db.add(User(user_id=user_id))
        db.commit()

    def test_grant_auditor_to_no_memberships_allowed(self, db):
        """P1: clean slate + auditor → legal grant."""
        self._user(db, "sod-p1")
        rm = RoleManager(db)
        aud = rm.create_role(name="sod-aud-p1", permissions="auditor")
        membership = rm.add_member("sod-p1", aud.id)
        assert membership.role_id == aud.id

    def test_second_auditor_role_allowed(self, db):
        """P2 paired positive: auditor+auditor stays {auditor} — legal.
        (Two auditor roles for one compliance team, e.g. firm + firm.)"""
        self._user(db, "sod-p2")
        rm = RoleManager(db)
        a1 = rm.create_role(name="sod-aud-a", permissions="auditor")
        a2 = rm.create_role(name="sod-aud-b", permissions="auditor")
        rm.add_member("sod-p2", a1.id)
        rm.add_member("sod-p2", a2.id)
        assert set(rm.get_user_permissions("sod-p2").values()) == {"auditor"}

    def test_grant_auditor_to_read_holder_refused(self, db):
        """N1: read-tier holder + auditor grant → SeparationOfDutiesError;
        re-query proves the membership was NOT created."""
        self._user(db, "sod-n1")
        rm = RoleManager(db)
        rd = rm.create_role(name="sod-read-n1", permissions="read")
        aud = rm.create_role(name="sod-aud-n1", permissions="auditor")
        rm.add_member("sod-n1", rd.id)
        db.commit()
        with pytest.raises(SeparationOfDutiesError) as exc:
            rm.add_member("sod-n1", aud.id)
        assert exc.value.tiers == ["auditor", "read"]
        assert exc.value.user_id == "sod-n1"
        db.rollback()
        assert [m.role_id for m in rm.get_user_roles("sod-n1")] == [rd.id]

    def test_grant_read_to_auditor_refused(self, db):
        """N2 paired negative: direction does not matter — granting the
        NON-auditor tier onto an auditor is the same mixed state."""
        self._user(db, "sod-n2")
        rm = RoleManager(db)
        aud = rm.create_role(name="sod-aud-n2", permissions="auditor")
        rd = rm.create_role(name="sod-read-n2", permissions="read")
        rm.add_member("sod-n2", aud.id)
        db.commit()
        with pytest.raises(SeparationOfDutiesError):
            rm.add_member("sod-n2", rd.id)
        db.rollback()
        assert [m.role_id for m in rm.get_user_roles("sod-n2")] == [aud.id]

    def test_tier_flip_onto_member_with_other_tiers_refused(self, db):
        """N3: flip a POPULATED read role to auditor while its member also
        holds read-write → mixed {auditor, read-write} outcome → refused;
        re-query proves the role tier is UNCHANGED (guard runs before any
        mutation)."""
        self._user(db, "sod-n3")
        rm = RoleManager(db)
        b = rm.create_role(name="sod-flip-n3", permissions="read")
        c = rm.create_role(name="sod-rw-n3", permissions="read-write")
        rm.add_member("sod-n3", b.id)
        rm.add_member("sod-n3", c.id)
        db.commit()
        with pytest.raises(SeparationOfDutiesError) as exc:
            rm.update_role(b.id, permissions="auditor")
        assert exc.value.tiers == ["auditor", "read-write"]
        db.commit()
        assert rm.get_role(b.id).permissions == "read"

    def test_tier_flip_memberless_role_allowed(self, db):
        """N4 paired positive: memberless role flips freely — the guard
        only refuses flips that WOULD mix a state for an existing member."""
        rm = RoleManager(db)
        b = rm.create_role(name="sod-flip-n4", permissions="read")
        updated = rm.update_role(b.id, permissions="auditor")
        assert updated.permissions == "auditor"
