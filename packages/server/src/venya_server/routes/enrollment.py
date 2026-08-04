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


# --- Helper functions ---


def _get_db(request: Request):
    """Get a database session from the backend on app state."""
    backend = getattr(request.app.state, "backend", None)
    if backend is None:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Backend not initialized",
        )
    return backend.get_session()


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
    db = _get_db(request)
    try:
        from venya.iam.enrollment_manager import EnrollmentManager

        em = EnrollmentManager(db)
        token = em.create_enrollment_token(
            user_id=req.user_id,
            auth_mode=req.auth_mode,
        )
        db.commit()
        return EnrollmentTokenCreateResponse(
            token=token.token,
            expires_at=token.expires_at.isoformat(),
            enrollment_url=f"/api/v1/enrollment/confirm?token={token.token}&user_id={req.user_id}",
        )
    except Exception as e:
        db.rollback()
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e),
        )
    finally:
        db.close()


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
    db = _get_db(request)
    try:
        from venya.iam.models import EnrollmentToken

        now = __import__("datetime").datetime.now(__import__("datetime").timezone.utc)
        tokens = (
            db.query(EnrollmentToken)
            .filter(
                EnrollmentToken.consumed == False,  # noqa: E712
                EnrollmentToken.expires_at > now,
            )
            .order_by(EnrollmentToken.expires_at.desc())
            .all()
        )
        result = [
            {
                "token": t.token,
                "user_id": t.user_id,
                "expires_at": t.expires_at.isoformat(),
            }
            for t in tokens
        ]
        return EnrollmentTokenListResponse(tokens=result)
    finally:
        db.close()


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
    db = _get_db(request)
    try:
        from venya.iam.enrollment_manager import EnrollmentManager

        em = EnrollmentManager(db)
        user = em.consume_enrollment_token(
            token_value=req.token,
            auth_mode="security-key",
        )
        db.commit()
        return EnrollmentTokenConsumeResponse(
            enrolled=True,
            user_id=user.user_id,
            auth_mode=user.auth_mode,
        )
    except Exception as e:
        db.rollback()
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e),
        )
    finally:
        db.close()
