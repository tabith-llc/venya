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

    def remove_member(self, user_id: str, role_id: int) -> bool:
        """Remove a user from a role.

        Returns:
            True if removed, False if not found.
        """
        membership = (
            self.db.query(RoleMember).filter(RoleMember.user_id == user_id, RoleMember.role_id == role_id).first()
        )
        if membership is None:
            return False

        self.db.delete(membership)
        self.db.flush()
        return True

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
