"""Enrollment flow endpoints.

Admin endpoints for managing enrollment tokens (old flow, superseded by
Phase 1 admin users endpoint).
"""

import logging

from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from ..dependencies import get_db, require_admin
from ..utils.time import effective_expiry_check_time

router = APIRouter()
logger = logging.getLogger("venya.server")


# --- Request/Response models ---


class EnrollmentTokenCreateRequest(BaseModel):
    user_id: str = Field(..., description="User ID that already exists")


class EnrollmentTokenCreateResponse(BaseModel):
    token: str
    expires_in_seconds: int = 900


class EnrollmentTokenListResponse(BaseModel):
    tokens: list[dict]


class EnrollmentTokenRevokeRequest(BaseModel):
    token_id: int


class EnrollmentTokenRevokeResponse(BaseModel):
    revoked: bool


# --- Endpoints ---


@router.post(
    "/enrollment/tokens",
    response_model=EnrollmentTokenCreateResponse,
    status_code=status.HTTP_201_CREATED,
)
async def enrollment_create_token(
    req: EnrollmentTokenCreateRequest,
    _: dict = Depends(require_admin),
    db: Session = Depends(get_db),
) -> EnrollmentTokenCreateResponse:
    """Create an enrollment token for an existing user.

    Requires admin permission.
    """
    try:
        from datetime import timezone as tz

        from core.iam.enrollment_manager import EnrollmentError, EnrollmentManager
        from core.iam.models import User

        em = EnrollmentManager(db)

        # Find user by user_id string
        user = db.query(User).filter(User.user_id == req.user_id).first()
        if not user:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"User '{req.user_id}' not found",
            )

        token, plaintext = em.create_enrollment_token(user.user_id)
        db.commit()
        return EnrollmentTokenCreateResponse(
            token=plaintext,
            expires_in_seconds=900,
        )
    except HTTPException:
        raise
    except EnrollmentError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e),
        )
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e),
        )


@router.get(
    "/enrollment/tokens",
    response_model=EnrollmentTokenListResponse,
)
async def enrollment_list_tokens(
    request: Request,
    _: dict = Depends(require_admin),
    db: Session = Depends(get_db),
) -> EnrollmentTokenListResponse:
    """List active enrollment tokens.

    Requires admin permission.
    """
    from datetime import timezone as tz

    from core.iam.models import EnrollmentToken

    server_config = getattr(request.app.state, "config", None)
    tolerance = (
        server_config.clock_skew.token_tolerance_seconds
        if server_config and hasattr(server_config, "clock_skew")
        else 60
    )
    now_minus_tolerance = effective_expiry_check_time(tolerance)
    tokens = (
        db.query(EnrollmentToken)
        .filter(
            EnrollmentToken.state.in_(["created", "in_progress"]),
            EnrollmentToken.expires_at > now_minus_tolerance,
        )
        .order_by(EnrollmentToken.created_at.desc())
        .all()
    )
    result = [
        {
            "id": t.id,
            "user_id": t.user_id,
            "state": t.state,
            "created_at": t.created_at.isoformat(),
            "expires_at": t.expires_at.isoformat(),
        }
        for t in tokens
    ]
    return EnrollmentTokenListResponse(tokens=result)


@router.post(
    "/enrollment/tokens/{token_id}/revoke",
    response_model=EnrollmentTokenRevokeResponse,
    status_code=status.HTTP_200_OK,
)
async def enrollment_revoke_token(
    token_id: int,
    _: dict = Depends(require_admin),
    db: Session = Depends(get_db),
) -> EnrollmentTokenRevokeResponse:
    """Revoke an enrollment token.

    Requires admin permission.
    """
    from core.iam.enrollment_manager import EnrollmentManager

    try:
        em = EnrollmentManager(db)
        revoked = em.revoke_token(token_id)
        db.commit()
        return EnrollmentTokenRevokeResponse(revoked=revoked)
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e),
        )
