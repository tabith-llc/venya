"""Enrollment flow endpoints."""

import logging

from fastapi import APIRouter, HTTPException, Request, status
from pydantic import BaseModel, Field

router = APIRouter()
logger = logging.getLogger("venya.server")


# --- Request/Response models ---


class EnrollmentTokenCreateRequest(BaseModel):
    user_id: str = Field(..., description="User ID to enroll")
    auth_mode: str = Field(
        "security-key", description="Auth mode: security-key or platform"
    )


class EnrollmentTokenCreateResponse(BaseModel):
    token: str
    expires_at: str
    enrollment_url: str


class EnrollmentTokenConsumeRequest(BaseModel):
    token: str = Field(..., description="Enrollment token")
    user_id: str = Field(..., description="User ID being enrolled")


class EnrollmentTokenConsumeResponse(BaseModel):
    enrolled: bool
    user_id: str
    auth_mode: str


class EnrollmentTokenListResponse(BaseModel):
    tokens: list[dict]


# --- Endpoints ---


@router.post(
    "/enrollment/tokens",
    response_model=EnrollmentTokenCreateResponse,
    status_code=status.HTTP_201_CREATED,
)
async def enrollment_create_token(
    req: EnrollmentTokenCreateRequest,
    request: Request,
) -> EnrollmentTokenCreateResponse:
    """Create an enrollment token for a new user.

    Requires admin permission.
    The token is used in the enrollment URL for the user to complete setup.
    """
    # TODO: Generate enrollment token, store in DB
    import secrets
    from datetime import datetime, timedelta, timezone

    token = secrets.token_urlsafe(32)
    expires_at = datetime.now(timezone.utc) + timedelta(hours=24)

    return EnrollmentTokenCreateResponse(
        token=token,
        expires_at=expires_at.isoformat(),
        enrollment_url=f"/api/v1/enrollment/confirm?token={token}&user_id={req.user_id}",
    )


@router.get(
    "/enrollment/tokens",
    response_model=EnrollmentTokenListResponse,
)
async def enrollment_list_tokens(
    request: Request,
) -> EnrollmentTokenListResponse:
    """List active enrollment tokens.

    Requires admin permission.
    """
    # TODO: Query tokens from DB
    return EnrollmentTokenListResponse(tokens=[])


@router.post(
    "/enrollment/confirm",
    response_model=EnrollmentTokenConsumeResponse,
    status_code=status.HTTP_200_OK,
)
async def enrollment_confirm(
    req: EnrollmentTokenConsumeRequest,
    request: Request,
) -> EnrollmentTokenConsumeResponse:
    """Complete enrollment using a token.

    Called after the user has completed WebAuthn registration.
    """
    # TODO: Validate token, create user, link WebAuthn credentials
    return EnrollmentTokenConsumeResponse(
        enrolled=True,
        user_id=req.user_id,
        auth_mode="security-key",
    )
