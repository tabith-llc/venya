# Copyright (c) 2026 Tabith LLC.
# Use of this source code is governed by the Business Source License 1.1
# included in the LICENSE file at the root of this repository. As of the
# Change Date listed there, the work is available under MPL 2.0.
# SPDX-License-Identifier: BUSL-1.1

"""Role CRUD + membership + permissions."""

from dataclasses import dataclass

from sqlalchemy import func
from sqlalchemy.orm import Session

from .models import Role, RoleMember, SecretRole, User
from .session_manager import is_user_active


class RoleManagerError(Exception):
    """Role manager error."""


class SeparationOfDutiesError(RoleManagerError):
    """Grant-time separation-of-duties refusal (auditor-role ruling 2',
    NIST SP 800-53 Rev 5 AC-5 preventive: an auditor+other-tier mixture
    must be IMPOSSIBLE by construction, not merely inadvisable).

    Subclasses RoleManagerError so every existing catch keeps working;
    carries the structured grant context (target user, role, resulting
    tier-set) so the server layer writes the auditor_sod_denied audit
    event without re-querying or string-matching the message.
    """

    def __init__(self, message: str, *, user_id: str, role_id: int, tiers: set[str]) -> None:
        super().__init__(message)
        self.user_id = user_id
        self.role_id = role_id
        self.tiers = sorted(tiers)


class AdminLockoutError(RoleManagerError):
    """Admin-lockout refusal (#443, #486).

    Raised before any write by the two halves of the shared lockout rule —
    :meth:`RoleManager.assert_removal_keeps_admin` (destructive removals) and
    :meth:`RoleManager.assert_status_change_keeps_admin` (account
    deactivation): the operation would leave the ``admin`` role with nobody in
    it who can actually sign in, or it would let a caller strip their own
    access. A deployment with zero usable administrators cannot enroll, rotate
    keys or change policy, so the refusal is the safe outcome.

    Subclasses RoleManagerError so every existing catch keeps working; carries
    the structured refusal context (target user, role, machine-readable
    reason) so the server layer writes the admin_lockout_denied audit event
    without re-querying or string-matching the message. Messages are
    enumeration-safe by construction: they name no other member.
    """

    LAST_ADMIN = "last_admin"
    SELF_REMOVAL = "self_removal"
    #: #486: the account-status write would take the last usable admin's login
    #: out of service. The roster still shows an admin, so the removal guard
    #: stays silent — the outage arrives through ``users.status`` instead.
    LAST_USABLE_ADMIN_DEACTIVATED = "last_usable_admin_deactivated"

    def __init__(
        self,
        message: str,
        *,
        reason: str,
        user_id: str,
        role_id: int | None = None,
    ) -> None:
        super().__init__(message)
        self.reason = reason
        self.user_id = user_id
        self.role_id = role_id


def _mixed_auditor_tiers(tiers: set[str]) -> bool:
    """True iff 'auditor' coexists with ANY non-auditor tier (ruling 2').

    Two auditor-tier memberships are legal — the resulting set is still
    {auditor}; len() == 1.
    """
    return "auditor" in tiers and len(tiers) > 1


@dataclass
class RoleInfo:
    """Role information."""

    id: int
    name: str
    permissions: str
    description: str | None = None
    member_count: int = 0
    secret_count: int = 0


class RoleManager:
    """Manages roles, memberships, and permissions."""

    #: The role whose non-empty roster is the lockout boundary (#443). The
    #: literal is the one require_admin resolves too (server/dependencies.py) —
    #: a named constant, not a second source of the admin role id.
    ADMIN_ROLE_NAME = "admin"

    #: The one account status that keeps a login usable. Compared only through
    #: :func:`core.iam.session_manager.is_user_active` — this constant names
    #: the value, the predicate owns the semantics (#486: a second
    #: status-literal comparison would be the divergence bug that file warns
    #: about).
    USER_STATUS_ACTIVE = "active"

    def __init__(self, db: Session) -> None:
        self.db = db

    def create_role(
        self,
        name: str,
        permissions: str = "read",
        description: str | None = None,
    ) -> Role:
        """Create a new role.

        Args:
            name: Role name (unique).
            permissions: Permission tier — "read", "read-write", or "auditor".
            description: Optional description.

        Returns:
            The created Role.

        Raises:
            RoleManagerError: If role name already exists or permissions are invalid.
        """
        if permissions not in ("read", "read-write", "auditor"):
            raise RoleManagerError(f"Invalid permissions: {permissions}. Must be 'read', 'read-write', or 'auditor'")

        existing = self.db.query(Role).filter(func.lower(Role.name) == name.lower()).first()
        if existing:
            raise RoleManagerError(f"Role '{name}' already exists")

        role = Role(name=name.lower(), permissions=permissions, description=description)
        self.db.add(role)
        self.db.flush()
        return role

    def update_role(
        self,
        role_id: int,
        *,
        name: str | None = None,
        permissions: str | None = None,
        description: str | None = None,
    ) -> Role:
        """Update a role.

        Args:
            role_id: Role ID to update.
            name: New role name.
            permissions: New permission tier.
            description: New description.

        Returns:
            The updated Role.

        Raises:
            RoleManagerError: If role not found, name already exists, or permissions invalid.
        """
        role = self.get_role(role_id)
        if role is None:
            raise RoleManagerError(f"Role {role_id} not found")

        if name is not None:
            if name == role.name:
                name = None
            else:
                existing = self.db.query(Role).filter(func.lower(Role.name) == name.lower(), Role.id != role_id).first()
                if existing:
                    raise RoleManagerError(f"Role '{name}' already exists")

        if permissions is not None:
            if permissions not in ("read", "read-write", "auditor"):
                raise RoleManagerError(
                    f"Invalid permissions: {permissions}. Must be 'read', 'read-write', or 'auditor'"
                )
            if permissions == role.permissions:
                permissions = None

        # Separation of duties (auditor-role ruling 2', applied BEFORE any
        # mutation): a tier flip must not mix {auditor, non-auditor} for ANY
        # current member — each member's RESULTING tier-set is evaluated with
        # this role already carrying the new tier (a role whose members all
        # hold only auditor, or a role with no members, is always allowed).
        if permissions is not None:
            for member in self.get_role_members(role_id):
                resulting = {
                    permissions if m.role_id == role_id else m.role.permissions
                    for m in self.get_user_roles(member.user_id)
                }
                if _mixed_auditor_tiers(resulting):
                    raise SeparationOfDutiesError(
                        f"Separation of duties: setting role {role_id} to '{permissions}' would mix "
                        f"tiers {sorted(resulting)} for user '{member.user_id}'",
                        user_id=member.user_id,
                        role_id=role_id,
                        tiers=resulting,
                    )

        if name is not None:
            role.name = name.lower()
        if permissions is not None:
            role.permissions = permissions
        if description is not None:
            role.description = description

        self.db.flush()
        return role

    def get_role(self, role_id: int) -> Role | None:
        """Get a role by ID."""
        return self.db.query(Role).filter(Role.id == role_id).first()

    def get_role_by_name(self, name: str) -> Role | None:
        """Get a role by name."""
        return self.db.query(Role).filter(func.lower(Role.name) == name.lower()).first()

    def list_roles(self) -> list[Role]:
        """List all roles."""
        return self.db.query(Role).order_by(Role.name).all()

    def delete_role(self, role_id: int) -> bool:
        """Delete an EMPTY role.

        A role that still has members or secret scopes is refused with a
        dependency message: the ORM delete-dependency machinery cannot
        blank-out the RoleMember/SecretRole primary-key columns, and today
        raises an internal AssertionError instead (#425 DEFECT A).

        Returns:
            True if deleted, False if not found.

        Raises:
            RoleManagerError: if the role still has members or secret scopes.
        """
        role = self.get_role(role_id)
        if role is None:
            return False

        member_count = self.db.query(RoleMember).filter(RoleMember.role_id == role_id).count()
        if member_count:
            raise RoleManagerError(f"Role '{role.name}' still has {member_count} member(s); remove members first")
        scope_count = self.db.query(SecretRole).filter(SecretRole.role_id == role_id).count()
        if scope_count:
            raise RoleManagerError(f"Role '{role.name}' still scopes {scope_count} secret(s); unscope secrets first")

        self.db.delete(role)
        self.db.flush()
        return True

    def add_member(self, user_id: str, role_id: int) -> RoleMember:
        """Add a user to a role.

        Args:
            user_id: User ID.
            role_id: Role ID.

        Returns:
            The created RoleMember.

        Raises:
            RoleManagerError: If user or role doesn't exist, or membership already exists.
        """
        # Check existence
        if not self.db.query(User).filter(User.user_id == user_id).first():
            raise RoleManagerError(f"User '{user_id}' not found")
        role = self.get_role(role_id)
        if role is None:
            raise RoleManagerError(f"Role ID {role_id} not found")

        # Check for duplicate
        existing = (
            self.db.query(RoleMember).filter(RoleMember.user_id == user_id, RoleMember.role_id == role_id).first()
        )
        if existing:
            raise RoleManagerError(f"User '{user_id}' is already a member of role {role_id}")

        # Separation of duties (auditor-role ruling 2'): the add may not
        # produce a mixed {auditor, non-auditor} tier-set. Computed on the
        # RESULTING set — auditor+auditor stays legal, auditor+anything
        # else is refused. No legacy-state migration is needed: the
        # auditor tier ships for the first time WITH this guard, so no
        # mixed state can pre-exist.
        resulting = {m.role.permissions for m in self.get_user_roles(user_id)} | {role.permissions}
        if _mixed_auditor_tiers(resulting):
            raise SeparationOfDutiesError(
                f"Separation of duties: user '{user_id}' cannot hold the auditor tier together "
                f"with other tiers — resulting tiers {sorted(resulting)}",
                user_id=user_id,
                role_id=role_id,
                tiers=resulting,
            )

        membership = RoleMember(user_id=user_id, role_id=role_id)
        self.db.add(membership)
        self.db.flush()
        return membership

    def remove_member(self, user_id: str, role_id: int, *, caller_user_id: str | None = None) -> bool:
        """Remove a user from a role.

        Args:
            user_id: User to remove.
            role_id: Role to remove the membership from.
            caller_user_id: Authenticated caller's user id, when it has one.
                It carries the #443 self-removal half of the guard; pass None
                only where no user principal exists (a certificate-only
                caller), which disables that half and NOT the last-admin half.

        Returns:
            True if removed, False if not found.

        Raises:
            AdminLockoutError: Refused before any write because the removal
                would leave the admin roster empty, or would strip the caller's
                own admin membership (#443).
        """
        # ONE enforcement point: the rule runs here, so no caller can reach the
        # delete without having answered it.
        self.assert_removal_keeps_admin(
            user_id,
            role_id=role_id,
            caller_user_id=caller_user_id,
        )
        membership = (
            self.db.query(RoleMember).filter(RoleMember.user_id == user_id, RoleMember.role_id == role_id).first()
        )
        if membership is None:
            return False

        self.db.delete(membership)
        self.db.flush()
        return True

    def assert_removal_keeps_admin(
        self,
        target_user_id: str,
        *,
        role_id: int | None = None,
        caller_user_id: str | None = None,
    ) -> None:
        """Refuse a destructive removal that would leave this core without an admin.

        ONE enforcement point for both destructive surfaces (#443 acceptance
        criterion 3), so a future route cannot ship without it — each caller
        invokes it BEFORE any write:

        - ``role_id=None`` — the whole user is going away, and with it every
          membership it holds (``DELETE /admin/users/{user_id}``). Removing
          one's own account over the API is refused outright.
        - ``role_id`` set — only that one membership is at stake
          (``DELETE /roles/{role_id}/members/{user_id}``); a role other than
          the admin role cannot empty the admin roster, and a target that
          holds no admin membership keeps its existing 404 — so both fall
          through untouched.

        Refusals, in this order (the last-admin fact outranks the self-removal
        fact when both apply, because it is the one telling the operator to
        seed a second admin first):

        1. last admin — the target holds the only admin membership, so the
           removal would leave the roster empty.
        2. self-removal — the caller is the target: the "are you sure" a
           remote call cannot answer.

        Concurrency posture (#487): the count is taken under a row lock
        (:meth:`_locked_admin_roster`), held until the caller's transaction
        ends, so this guard plus the delete it answers for is one atomic
        step — concurrent removals of the last two admins cannot both pass.

        Args:
            target_user_id: User whose membership (or whole account) is being
                removed.
            role_id: Role of the single membership being removed, or None when
                the entire user is being removed.
            caller_user_id: Authenticated caller's user id, when it has one.
                ``None`` (a certificate-only caller with no user row) simply
                disables the self-removal half; the last-admin half still
                applies.

        Raises:
            AdminLockoutError: On either refusal. Messages are enumeration-
            safe: they name no member other than the caller's own target.
        """
        # Same lookup require_admin uses (server/dependencies.py) — never a
        # re-derived id or a name guess. The read is the LOCKED variant (#487):
        # the roster rows are FOR UPDATE until this transaction ends, so the
        # count-and-write below is atomic — two concurrent removals of the
        # last two admins cannot both read a roster of two. The idiom is the
        # existing one in this tree: credentials.py's last-active-credential
        # guard and enrollment_manager.py's token cap do the same thing.
        roles = self._locked_admin_roster()
        if roles is None:
            # No admin role seeded yet (a pre-init core): there is no roster to
            # empty, so only the self-removal half of the rule can apply.
            if role_id is None and caller_user_id is not None and target_user_id == caller_user_id:
                raise AdminLockoutError(
                    "Cannot remove your own user account",
                    reason=AdminLockoutError.SELF_REMOVAL,
                    user_id=target_user_id,
                )
            return
        admin_role, members = roles
        if role_id is not None and role_id != admin_role.id:
            return
        target_holds_admin = any(member.user_id == target_user_id for member in members)

        if target_holds_admin and len(members) <= 1:
            raise AdminLockoutError(
                "Cannot remove the last admin",
                reason=AdminLockoutError.LAST_ADMIN,
                user_id=target_user_id,
                role_id=admin_role.id,
            )

        if caller_user_id is None or target_user_id != caller_user_id:
            return
        if role_id is not None and not target_holds_admin:
            # Membership-scoped route, caller is the target, but the target
            # holds no admin membership: nothing is taken away here, so the
            # route's existing 404 stays the answer.
            return
        raise AdminLockoutError(
            "Cannot remove your own user account" if role_id is None else "Cannot remove your own admin membership",
            reason=AdminLockoutError.SELF_REMOVAL,
            user_id=target_user_id,
            role_id=None if role_id is None else admin_role.id,
        )

    def _admin_role_and_members(self) -> tuple[Role, list[RoleMember]] | None:
        """The ``admin`` role row and its roster, or None when no admin role is
        seeded yet.

        The unlocked read — correct for enumeration callers such as
        :meth:`usable_admin_ids` re-reads inside an already-locked
        transaction. The lockout GUARDS use :meth:`_locked_admin_roster`,
        which shares this helper's role lookup and adds the row lock (#487).
        """
        admin_role = self.get_role_by_name(self.ADMIN_ROLE_NAME)
        if admin_role is None:
            return None
        return admin_role, self.get_role_members(admin_role.id)

    def _locked_admin_roster(self) -> tuple[Role, list[RoleMember]] | None:
        """The ``admin`` role row and its roster read ``FOR UPDATE`` (#487).

        Same role lookup as :meth:`_admin_role_and_members` (one
        ``get_role_by_name``, the same require_admin resolves), but the
        member rows carry a row lock held until the caller's transaction
        commits or rolls back. That makes "count the roster, then act" a
        single atomic step against a concurrent removal or status write
        racing for the same roster: the second transaction blocks on this
        read, re-evaluates after the first commits (READ COMMITTED), and
        sees the roster the first transaction left behind — so exactly one
        of two concurrent removals of the last two admins can pass.
        PostgreSQL locks; SQLite, the test backend, ignores the clause —
        the same posture the credential-deactivation guard (#credentials.py
        ``with_for_update``) and the enrollment token cap (#enrollment_manager.py)
        already ship. Raises nothing; mirrors the unlocked helper's
        ``None`` answer when no admin role is seeded.
        """
        admin_role = self.get_role_by_name(self.ADMIN_ROLE_NAME)
        if admin_role is None:
            return None
        members = self.db.query(RoleMember).filter(RoleMember.role_id == admin_role.id).with_for_update().all()
        return admin_role, members

    def usable_admin_ids(self) -> set[str]:
        """User ids that count as usable administrators right now (#486).

        "Usable admin" = ``is_user_active(user)`` (the single login-status
        gate, the same predicate ``create_session`` and the auth middleware
        use) AND an ``admin``-role membership. An account that is disabled, or
        one that is active but no longer holds the membership, counts as
        absent: the roster alone is not the boundary — the roster of
        SIGNABLE-IN members is.
        """
        roles = self._admin_role_and_members()
        if roles is None:
            return set()
        return {
            member.user_id
            for member in roles[1]
            if is_user_active(self.db.query(User).filter(User.user_id == member.user_id).first())
        }

    def assert_status_change_keeps_admin(self, target_user_id: str, new_status: str | None) -> None:
        """Refuse an account-status write that would strand the last usable admin (#486).

        The deactivation half of the ONE lockout rule. The removal guards
        (:meth:`assert_removal_keeps_admin`) answer whether an ``admin``
        membership survives; this answers whether a surviving membership is
        still SIGNABLE-IN, because a disabled account keeps its roster row
        while :func:`is_user_active` refuses every login for it — and
        recovery-code reissue is conditioned on an account that can still sign
        in. Two different fields, one outage class.

        The count is the CURRENT usable-admin set, so the rule reads the way
        an operator would: after this write, can anyone still administer this
        core? A write is refused when it would take the set to zero AND the
        target is in it today (causation — a status write on an account that
        already cannot sign in strands nobody new). The roster read below is
        the LOCKED variant (#487), the same posture as the removal guard, so
        the two surfaces do not diverge and a concurrent deactivation of the
        other last admin cannot slip both writes through.

        Args:
            target_user_id: Account whose status is being written.
            new_status: The status value the write would store. Only
                ``USER_STATUS_ACTIVE`` preserves login, so every other value —
                ``disabled``, ``pending_enrollment``, or an unexpected one —
                counts as taking that account out of the usable set
                (fail-closed, and the same test ``is_user_active`` applies at
                login: ``pending_enrollment`` cannot sign in either, so
                treating it as safe would reopen the outage through the other
                literal).

        Raises:
            AdminLockoutError: ``reason=LAST_USABLE_ADMIN_DEACTIVATED`` when
                the write would leave the ``admin`` role with zero usable
                admins. Enumeration-safe: the message names no member other
                than the target the caller already typed.
        """
        if new_status == self.USER_STATUS_ACTIVE:
            # An activation cannot strand anybody — only deactivation is guarded.
            return

        roles = self._locked_admin_roster()
        if roles is None:
            # No admin role seeded yet (a pre-init core): no roster to strand.
            return
        admin_role, members = roles
        if not any(member.user_id == target_user_id for member in members):
            # A status write on a NON-admin account cannot shrink the
            # usable-admin set, so it stays the ordinary operation.
            return

        # The target is under the CANDIDATE status now, which is not
        # USER_STATUS_ACTIVE (handled above), so it is not usable in the
        # after-state. A target that is NOT usable today cannot be made less
        # usable by this write, so the count only drops when the target is in
        # the set right now (causation, not merely a post-state of zero).
        usable = self.usable_admin_ids()
        if target_user_id not in usable:
            return
        if usable - {target_user_id}:
            return

        raise AdminLockoutError(
            "Cannot deactivate the only usable admin — a usable admin is an active "
            "account that also holds the admin role, and this write would leave "
            "zero. Seed or activate another admin first.",
            reason=AdminLockoutError.LAST_USABLE_ADMIN_DEACTIVATED,
            user_id=target_user_id,
            role_id=admin_role.id,
        )

    def get_role_members(self, role_id: int) -> list[RoleMember]:
        """Get all members of a role."""
        return self.db.query(RoleMember).filter(RoleMember.role_id == role_id).all()

    def get_user_roles(self, user_id: str) -> list[RoleMember]:
        """Get all roles a user belongs to."""
        return self.db.query(RoleMember).filter(RoleMember.user_id == user_id).all()

    def has_permission(self, user_id: str, role_id: int, required_permission: str) -> bool:
        """Check if a user has a required permission in a role.

        Args:
            user_id: User ID.
            role_id: Role ID.
            required_permission: "read", "read-write", or "auditor".

        Returns:
            True if the user's role permission meets or exceeds the required level.
        """
        membership = (
            self.db.query(RoleMember)
            .filter(
                RoleMember.user_id == user_id,
                RoleMember.role_id == role_id,
            )
            .first()
        )
        if membership is None:
            return False

        role = membership.role
        if required_permission == "read-write":
            return role.permissions == "read-write"
        if required_permission == "auditor":
            # Audit-visibility tier (ticket auditor-role): the auditor role
            # passes, and read-write EXCEEDS it — the ticket's post-change
            # permission table grants audit-log viewing to read-write/admin
            # (admin roles are seeded permissions="read-write"), so an
            # auditor-only check here would lock admins out of the audit log.
            return role.permissions in ("auditor", "read-write")
        return True  # "read" is always granted if membership exists

    def get_user_permissions(self, user_id: str) -> dict[int, str]:
        """Get all roles and their permissions for a user.

        Returns:
            Dict mapping role_id to permission level.
        """
        memberships = self.get_user_roles(user_id)
        return {m.role_id: m.role.permissions for m in memberships}
