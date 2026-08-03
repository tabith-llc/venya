"""Role CRUD endpoints."""

import logging

from fastapi import APIRouter, HTTPException, Request, status
from pydantic import BaseModel, Field

router = APIRouter()
logger = logging.getLogger("venya.server")


# --- Request/Response models ---


class RoleCreateRequest(BaseModel):
    name: str = Field(..., description="Role name (unique)")
    permissions: str = Field(
        "read", description='Permission tier: "read" or "read-write"'
    )
    description: str | None = Field(None, description="Optional description")


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
    request: Request,
) -> RoleCreateResponse:
    """Create a new role.

    Requires admin permission.
    """
    # TODO: Implement role creation via role_manager
    return RoleCreateResponse(
        id=0,
        name=req.name,
        permissions=req.permissions,
        description=req.description,
    )


@router.get(
    "/roles",
    response_model=RoleListResponse,
)
async def roles_list(
    request: Request,
) -> RoleListResponse:
    """List all roles."""
    # TODO: Query roles from DB
    return RoleListResponse(roles=[])


@router.get(
    "/roles/{role_id}",
    response_model=RoleGetResponse,
)
async def roles_get(
    role_id: int,
    request: Request,
) -> RoleGetResponse:
    """Get a role by ID."""
    # TODO: Query role from DB
    return RoleGetResponse(id=role_id, name="example", permissions="read")


@router.delete(
    "/roles/{role_id}",
    response_model=RoleDeleteResponse,
    status_code=status.HTTP_200_OK,
)
async def roles_delete(
    role_id: int,
    request: Request,
) -> RoleDeleteResponse:
    """Delete a role.

    Requires admin permission.
    """
    # TODO: Delete role via role_manager
    return RoleDeleteResponse(deleted=True, name="example")


@router.get(
    "/roles/{role_id}/members",
    response_model=RoleMemberListResponse,
)
async def role_members_list(
    role_id: int,
    request: Request,
) -> RoleMemberListResponse:
    """List all members of a role."""
    # TODO: Query members from DB
    return RoleMemberListResponse(members=[])


@router.post(
    "/roles/{role_id}/members",
    status_code=status.HTTP_201_CREATED,
)
async def role_member_add(
    role_id: int,
    req: RoleMemberAddRequest,
    request: Request,
) -> dict:
    """Add a user to a role.

    Requires admin permission.
    """
    # TODO: Add member via role_manager
    return {"user_id": req.user_id, "role_id": role_id, "added": True}


@router.delete(
    "/roles/{role_id}/members/{user_id}",
    response_model=RoleMemberRemoveResponse,
    status_code=status.HTTP_200_OK,
)
async def role_member_remove(
    role_id: int,
    user_id: str,
    request: Request,
) -> RoleMemberRemoveResponse:
    """Remove a user from a role.

    Requires admin permission.
    """
    # TODO: Remove member via role_manager
    return RoleMemberRemoveResponse(removed=True, user_id=user_id)
