"""Role CRUD + membership + permissions."""


from dataclasses import dataclass, field
from typing import Any

from sqlalchemy import func
from sqlalchemy.orm import Session

from .models import Role, RoleMember, User


class RoleManagerError(Exception):
    """Role manager error."""


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
            permissions: Permission tier — "read" or "read-write".
            description: Optional description.

        Returns:
            The created Role.

        Raises:
            RoleManagerError: If role name already exists or permissions are invalid.
        """
        if permissions not in ("read", "read-write"):
            raise RoleManagerError(
                f"Invalid permissions: {permissions}. Must be 'read' or 'read-write'"
            )

        existing = (
            self.db.query(Role).filter(func.lower(Role.name) == name.lower()).first()
        )
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
                existing = (
                    self.db.query(Role)
                    .filter(func.lower(Role.name) == name.lower(), Role.id != role_id)
                    .first()
                )
                if existing:
                    raise RoleManagerError(f"Role '{name}' already exists")

        if permissions is not None:
            if permissions not in ("read", "read-write"):
                raise RoleManagerError(
                    f"Invalid permissions: {permissions}. Must be 'read' or 'read-write'"
                )
            if permissions == role.permissions:
                permissions = None

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
        return (
            self.db.query(Role).filter(func.lower(Role.name) == name.lower()).first()
        )

    def list_roles(self) -> list[Role]:
        """List all roles."""
        return self.db.query(Role).order_by(Role.name).all()

    def delete_role(self, role_id: int) -> bool:
        """Delete a role.

        Returns:
            True if deleted, False if not found.
        """
        role = self.get_role(role_id)
        if role is None:
            return False

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
        if not self.get_role(role_id):
            raise RoleManagerError(f"Role ID {role_id} not found")

        # Check for duplicate
        existing = (
            self.db.query(RoleMember)
            .filter(RoleMember.user_id == user_id, RoleMember.role_id == role_id)
            .first()
        )
        if existing:
            raise RoleManagerError(f"User '{user_id}' is already a member of role {role_id}")

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
            self.db.query(RoleMember)
            .filter(RoleMember.user_id == user_id, RoleMember.role_id == role_id)
            .first()
        )
        if membership is None:
            return False

        self.db.delete(membership)
        self.db.flush()
        return True

    def get_role_members(self, role_id: int) -> list[RoleMember]:
        """Get all members of a role."""
        return (
            self.db.query(RoleMember)
            .filter(RoleMember.role_id == role_id)
            .all()
        )

    def get_user_roles(self, user_id: str) -> list[RoleMember]:
        """Get all roles a user belongs to."""
        return (
            self.db.query(RoleMember)
            .filter(RoleMember.user_id == user_id)
            .all()
        )

    def has_permission(
        self, user_id: str, role_id: int, required_permission: str
    ) -> bool:
        """Check if a user has a required permission in a role.

        Args:
            user_id: User ID.
            role_id: Role ID.
            required_permission: "read" or "read-write".

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
        return True  # "read" is always granted if membership exists

    def get_user_permissions(self, user_id: str) -> dict[int, str]:
        """Get all roles and their permissions for a user.

        Returns:
            Dict mapping role_id to permission level.
        """
        memberships = self.get_user_roles(user_id)
        return {m.role_id: m.role.permissions for m in memberships}
