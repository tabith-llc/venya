# Copyright (c) 2026 Tabith LLC.
# Use of this source code is governed by the Business Source License 1.1
# included in the LICENSE file at the root of this repository. As of the
# Change Date listed there, the work is available under MPL 2.0.
# SPDX-License-Identifier: BUSL-1.1

"""Role CRUD endpoints."""

import logging
from datetime import UTC, datetime
from typing import Literal

from core.iam.role_manager import RoleManagerError, SeparationOfDutiesError
from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from ..audit_lifecycle import (
    MEMBER_ADDED,
    MEMBER_REMOVED,
    ROLE_CREATED,
    ROLE_DELETED,
    ROLE_UPDATED,
    audit_lifecycle,
)
from ..dependencies import get_db, require_admin, require_role

router = APIRouter()
logger = logging.getLogger("venya.server")


def _audit_sod_denied(db: Session, actor: dict, action: str, error: SeparationOfDutiesError) -> None:
    """Write the auditor_sod_denied compliance event on a SoD refusal
    (auditor-role ruling 2'). COMMIT BEFORE the raise — get_db rolls back
    any exception escaping the route, so an add-then-raise without commit
    would evaporate the event. Fail-closed: an audit-write failure never
    upgrades the refusal (logged loudly, still 4xx). Value-free fields:
    ids, tiers, outcome — no role descriptions or user data beyond ids.
    """
    from core.iam.models import AuditEvent

    try:
        db.add(
            AuditEvent(
                event_type="auditor_sod_denied",
                user_id=(actor or {}).get("user_id"),
                fields={
                    "outcome": "denied",
                    "reason": "separation of duties: auditor tier is exclusive",
                    "action": action,
                    "target_user_id": error.user_id,
                    "role_id": error.role_id,
                    "attempted_tiers": error.tiers,
                },
                timestamp=datetime.now(UTC),
            )
        )
        db.commit()
    except Exception:
        logger.exception("Audit write failed on auditor SoD deny (still denying)")


# --- Request/Response models ---


class RoleCreateRequest(BaseModel):
    model_config = {"extra": "forbid"}  # #357 sweep: silent-drop dies here (repo-wide extra=forbid ruling)

    name: str = Field(..., min_length=1, pattern=r"^[a-zA-Z0-9_-]+$", description="Role name (unique)")
    permissions: Literal["read", "read-write", "auditor"] = Field(
        "read", description='Permission tier: "read", "read-write", or "auditor"'
    )
    description: str | None = Field(None, description="Optional description")


class RoleUpdateRequest(BaseModel):
    model_config = {"extra": "forbid"}  # #357 sweep: silent-drop dies here (repo-wide extra=forbid ruling)

    name: str | None = Field(None, min_length=1, pattern=r"^[a-zA-Z0-9_-]+$", description="New role name")
    permissions: Literal["read", "read-write", "auditor"] | None = Field(
        None, description='New permission tier: "read", "read-write", or "auditor"'
    )
    description: str | None = Field(None, description="New description")


class RoleCreateResponse(BaseModel):
    id: int
    name: str
    permissions: str
    description: str | None


class RoleGetResponse(BaseModel):
    id: int
    name: str
    permissions: str
    description: str | None
    member_count: int = 0


class RoleListResponse(BaseModel):
    roles: list[RoleGetResponse]


class RoleDeleteResponse(BaseModel):
    deleted: bool
    name: str


class RoleMemberAddRequest(BaseModel):
    model_config = {"extra": "forbid"}  # #357 sweep: silent-drop dies here (repo-wide extra=forbid ruling)

    user_id: str = Field(..., description="User ID to add")


class RoleMemberAddResponse(BaseModel):
    user_id: str
    role_id: int
    added: bool = True


class RoleMemberListResponse(BaseModel):
    members: list[dict]


class RoleMemberRemoveResponse(BaseModel):
    removed: bool
    user_id: str


# --- Endpoints ---


@router.post(
    "/roles",
    response_model=RoleCreateResponse,
    status_code=status.HTTP_201_CREATED,
)
async def roles_create(
    req: RoleCreateRequest,
    auth_user: dict = Depends(require_admin),
    db: Session = Depends(get_db),
) -> RoleCreateResponse:
    """Create a new role.

    Requires admin permission.
    """
    from core.iam.role_manager import RoleManager

    role_manager = RoleManager(db)
    try:
        role = role_manager.create_role(
            name=req.name,
            permissions=req.permissions,
            description=req.description,
        )
        audit_lifecycle(
            db,
            ROLE_CREATED,
            auth_user.get("user_id"),
            {"role_id": role.id, "role_name": role.name, "permissions": role.permissions},
        )
        db.commit()
    except RoleManagerError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e),
        )
    except Exception:
        logger.exception("Role creation failed")
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Role creation failed",
        )

    return RoleCreateResponse(
        id=role.id,
        name=role.name,
        permissions=role.permissions,
        description=role.description,
    )


@router.get(
    "/roles",
    response_model=RoleListResponse,
)
async def roles_list(
    _: dict = Depends(require_role("read")),
    db: Session = Depends(get_db),
) -> RoleListResponse:
    """List all roles."""
    from core.iam.role_manager import RoleManager

    role_manager = RoleManager(db)
    roles = role_manager.list_roles()
    result = []
    for role in roles:
        members = role_manager.get_role_members(role.id)
        result.append(
            RoleGetResponse(
                id=role.id,
                name=role.name,
                permissions=role.permissions,
                description=role.description,
                member_count=len(members),
            )
        )
    return RoleListResponse(roles=result)


@router.get(
    "/roles/{role_id}",
    response_model=RoleGetResponse,
)
async def roles_get(
    role_id: int,
    _: dict = Depends(require_role("read")),
    db: Session = Depends(get_db),
) -> RoleGetResponse:
    """Get a role by ID."""
    from core.iam.role_manager import RoleManager

    role_manager = RoleManager(db)
    role = role_manager.get_role(role_id)
    if role is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Role {role_id} not found",
        )
    members = role_manager.get_role_members(role_id)
    return RoleGetResponse(
        id=role.id,
        name=role.name,
        permissions=role.permissions,
        description=role.description,
        member_count=len(members),
    )


@router.put(
    "/roles/{role_id}",
    response_model=RoleGetResponse,
)
async def roles_update(
    role_id: int,
    req: RoleUpdateRequest,
    auth_user: dict = Depends(require_admin),
    db: Session = Depends(get_db),
) -> RoleGetResponse:
    """Update a role.

    Requires admin permission.
    """
    from core.iam.role_manager import RoleManager

    role_manager = RoleManager(db)
    try:
        role = role_manager.update_role(
            role_id,
            name=req.name,
            permissions=req.permissions,
            description=req.description,
        )
        audit_lifecycle(
            db,
            ROLE_UPDATED,
            auth_user.get("user_id"),
            {
                "role_id": role.id,
                "role_name": role.name,
                "changed_fields": [f for f in ("name", "permissions", "description") if getattr(req, f) is not None],
            },
        )
        db.commit()
        members = role_manager.get_role_members(role_id)
        return RoleGetResponse(
            id=role.id,
            name=role.name,
            permissions=role.permissions,
            description=role.description,
            member_count=len(members),
        )
    except HTTPException:
        raise
    except SeparationOfDutiesError as e:
        _audit_sod_denied(db, auth_user, action="role_tier_change", error=e)
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=str(e),
        )
    except RoleManagerError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e),
        )
    except Exception:
        logger.exception("Role update failed")
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Role update failed",
        )


@router.delete(
    "/roles/{role_id}",
    response_model=RoleDeleteResponse,
    status_code=status.HTTP_200_OK,
)
async def roles_delete(
    role_id: int,
    auth_user: dict = Depends(require_admin),
    db: Session = Depends(get_db),
) -> RoleDeleteResponse:
    """Delete a role.

    Requires admin permission.
    """
    from core.iam.role_manager import RoleManager

    role_manager = RoleManager(db)
    try:
        role = role_manager.get_role(role_id)
        if role is None:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Role {role_id} not found",
            )
        name = role.name
        members_affected = len(role_manager.get_role_members(role_id))
        deleted = role_manager.delete_role(role_id)
        if not deleted:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Role {role_id} not found",
            )
        audit_lifecycle(
            db,
            ROLE_DELETED,
            auth_user.get("user_id"),
            {"role_id": role_id, "role_name": name, "members_affected": members_affected},
        )
        db.commit()
        return RoleDeleteResponse(deleted=True, name=name)
    except HTTPException:
        raise
    except RoleManagerError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e),
        )
    except Exception:
        logger.exception("Role deletion failed")
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Role deletion failed",
        )


@router.get(
    "/roles/{role_id}/members",
    response_model=RoleMemberListResponse,
)
async def role_members_list(
    role_id: int,
    user_info: dict = Depends(require_role("read")),
    db: Session = Depends(get_db),
) -> RoleMemberListResponse:
    """List all members of a role.

    Roster scoping (role-read-surface-enumeration-oracle #448): the roster names
    every human identity inside a group, which is identity STRUCTURE, not a group
    name — so it is answered only about groups the caller actually holds, or for
    callers in an OVERSIGHT tier (``auditor`` / ``read-write``), the same tier set
    the audit GET surface was deliberately raised to. Everyone else gets a 404 in
    the exact shape ``roles_get`` above uses for an unknown role id: a 403 would
    confirm "that group exists and you are outside it", which is half the
    exposure being closed.

    ``GET /roles`` and ``GET /roles/{role_id}`` are deliberately UNCHANGED — group
    names, tiers and member COUNTS stay visible to every tier (RULING 4).

    No new query and no parallel role lookup: the caller's own ``role_id -> tier``
    map rides the ``require_role("read")`` gate's per-request fetch — ``_checker``
    attaches it as ``user_info["_role_permissions"]`` (``dependencies.py``), the
    same reuse pattern ``routes/audit.py`` and ``secrets_get`` already use. Both
    halves of this decision read that one request-scoped map.

    Fail-closed note: the executor early-return in ``_checker`` attaches no role
    map, so a caller arriving without one is denied. Executor mTLS identity is
    only granted on ``/api/v1/sessions/...`` paths, so no live caller is
    affected — and a missing map must never widen a gate.
    """
    from core.iam.role_manager import RoleManager

    # Both halves read the map the gate already fetched (role_id -> tier).
    caller_permissions: dict = user_info.get("_role_permissions") or {}
    member_of_this_role = role_id in caller_permissions
    oversight_tier = any(tier in ("auditor", "read-write") for tier in caller_permissions.values())

    if not (member_of_this_role or oversight_tier):
        # DENIED BEFORE ANY ROLE/MEMBERSHIP READ: this branch touches no table, so
        # a group the caller is outside of and an id that does not exist produce
        # the same status and the same detail template — indistinguishable, and
        # with no existence signal to extract. Same wording as ``roles_get``'s
        # unknown-role 404; deliberately no distinguishing detail, no extra body.
        logger.warning(
            "Role roster refused: caller %s holds no tier over role %s",
            user_info.get("user_id"),
            role_id,
        )
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Role {role_id} not found",
        )

    role_manager = RoleManager(db)
    members = role_manager.get_role_members(role_id)
    result = [{"user_id": m.user_id, "role_id": m.role_id} for m in members]
    return RoleMemberListResponse(members=result)


@router.post(
    "/roles/{role_id}/members",
    response_model=RoleMemberAddResponse,
    status_code=status.HTTP_201_CREATED,
)
async def role_member_add(
    role_id: int,
    req: RoleMemberAddRequest,
    auth_user: dict = Depends(require_admin),
    db: Session = Depends(get_db),
) -> RoleMemberAddResponse:
    """Add a user to a role.

    Requires admin permission.
    """
    from core.iam.role_manager import RoleManager

    role_manager = RoleManager(db)
    try:
        membership = role_manager.add_member(
            user_id=req.user_id,
            role_id=role_id,
        )
        audit_lifecycle(
            db,
            MEMBER_ADDED,
            auth_user.get("user_id"),
            {"role_id": role_id, "target_user_id": membership.user_id},
        )
        db.commit()
        return RoleMemberAddResponse(
            user_id=membership.user_id,
            role_id=membership.role_id,
            added=True,
        )
    except HTTPException:
        raise
    except SeparationOfDutiesError as e:
        _audit_sod_denied(db, auth_user, action="add_member", error=e)
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=str(e),
        )
    except RoleManagerError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e),
        )
    except Exception:
        logger.exception("Role member add failed")
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Role member add failed",
        )


@router.delete(
    "/roles/{role_id}/members/{user_id}",
    response_model=RoleMemberRemoveResponse,
    status_code=status.HTTP_200_OK,
)
async def role_member_remove(
    role_id: int,
    user_id: str,
    auth_user: dict = Depends(require_admin),
    db: Session = Depends(get_db),
) -> RoleMemberRemoveResponse:
    """Remove a user from a role.

    Requires admin permission.
    """
    from core.iam.role_manager import RoleManager

    role_manager = RoleManager(db)
    try:
        removed = role_manager.remove_member(
            user_id=user_id,
            role_id=role_id,
        )
        if not removed:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"User '{user_id}' not found in role {role_id}",
            )
        audit_lifecycle(
            db,
            MEMBER_REMOVED,
            auth_user.get("user_id"),
            {"role_id": role_id, "target_user_id": user_id},
        )
        db.commit()
        return RoleMemberRemoveResponse(removed=True, user_id=user_id)
    except HTTPException:
        raise
    except RoleManagerError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e),
        )
    except Exception:
        logger.exception("Role member removal failed")
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Role member removal failed",
        )
