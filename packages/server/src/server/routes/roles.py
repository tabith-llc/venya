"""Role CRUD endpoints."""

import logging
from typing import Literal

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from ..dependencies import get_db, require_admin, require_role

router = APIRouter()
logger = logging.getLogger("venya.server")


# --- Request/Response models ---


class RoleCreateRequest(BaseModel):
    name: str = Field(..., min_length=1, pattern=r"^[a-zA-Z0-9_-]+$", description="Role name (unique)")
    permissions: Literal["read", "read-write"] = Field(
        "read", description='Permission tier: "read" or "read-write"'
    )
    description: str | None = Field(None, description="Optional description")


class RoleUpdateRequest(BaseModel):
    name: str | None = Field(None, min_length=1, pattern=r"^[a-zA-Z0-9_-]+$", description="New role name")
    permissions: Literal["read", "read-write"] | None = Field(
        None, description='New permission tier: "read" or "read-write"'
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
    _: dict = Depends(require_admin),
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
        db.commit()
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e),
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
        result.append(RoleGetResponse(
            id=role.id,
            name=role.name,
            permissions=role.permissions,
            description=role.description,
            member_count=len(members),
        ))
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
    _: dict = Depends(require_admin),
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
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e),
        )


@router.delete(
    "/roles/{role_id}",
    response_model=RoleDeleteResponse,
    status_code=status.HTTP_200_OK,
)
async def roles_delete(
    role_id: int,
    _: dict = Depends(require_admin),
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
        deleted = role_manager.delete_role(role_id)
        if not deleted:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Role {role_id} not found",
            )
        db.commit()
        return RoleDeleteResponse(deleted=True, name=name)
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e),
        )


@router.get(
    "/roles/{role_id}/members",
    response_model=RoleMemberListResponse,
)
async def role_members_list(
    role_id: int,
    _: dict = Depends(require_role("read")),
    db: Session = Depends(get_db),
) -> RoleMemberListResponse:
    """List all members of a role."""
    from core.iam.role_manager import RoleManager

    role_manager = RoleManager(db)
    members = role_manager.get_role_members(role_id)
    result = [
        {"user_id": m.user_id, "role_id": m.role_id}
        for m in members
    ]
    return RoleMemberListResponse(members=result)


@router.post(
    "/roles/{role_id}/members",
    response_model=RoleMemberAddResponse,
    status_code=status.HTTP_201_CREATED,
)
async def role_member_add(
    role_id: int,
    req: RoleMemberAddRequest,
    _: dict = Depends(require_admin),
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
        db.commit()
        return RoleMemberAddResponse(
            user_id=membership.user_id,
            role_id=membership.role_id,
            added=True,
        )
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e),
        )


@router.delete(
    "/roles/{role_id}/members/{user_id}",
    response_model=RoleMemberRemoveResponse,
    status_code=status.HTTP_200_OK,
)
async def role_member_remove(
    role_id: int,
    user_id: str,
    _: dict = Depends(require_admin),
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
        db.commit()
        return RoleMemberRemoveResponse(removed=True, user_id=user_id)
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e),
        )
