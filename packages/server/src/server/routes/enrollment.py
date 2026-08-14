"""Enrollment flow endpoints.

Admin endpoints for managing enrollment tokens (old flow, superseded by
Phase 1 admin users endpoint).
"""

import logging

from fastapi import APIRouter, HTTPException, Request, status
from pydantic import BaseModel, Field

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
    """Create an enrollment token for an existing user.

    Requires admin permission.
    """
    db = _get_db(request)
    try:
        from datetime import timezone as tz

        from vault.iam.enrollment_manager import EnrollmentError, EnrollmentManager
        from vault.iam.models import User

        em = EnrollmentManager(db)

        # Find user by user_id string
        user = db.query(User).filter(User.user_id == req.user_id).first()
        if not user:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"User '{req.user_id}' not found",
            )

        token, plaintext = em.create_enrollment_token(user.id)
        db.commit()
        return EnrollmentTokenCreateResponse(
            token=plaintext,
            expires_in_seconds=900,
        )
    except HTTPException:
        raise
    except EnrollmentError as e:
        db.rollback()
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e),
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
        from datetime import timezone as tz

        from vault.iam.models import EnrollmentToken

        tokens = (
            db.query(EnrollmentToken)
            .filter(
                EnrollmentToken.state.in_(["created", "in_progress"]),
                EnrollmentToken.expires_at > __import__("datetime").datetime.now(tz.utc),
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
    finally:
        db.close()


@router.post(
    "/enrollment/tokens/{token_id}/revoke",
    response_model=EnrollmentTokenRevokeResponse,
    status_code=status.HTTP_200_OK,
)
async def enrollment_revoke_token(
    token_id: int,
    request: Request,
) -> EnrollmentTokenRevokeResponse:
    """Revoke an enrollment token.

    Requires admin permission.
    """
    db = _get_db(request)
    try:
        from vault.iam.enrollment_manager import EnrollmentManager

        em = EnrollmentManager(db)
        revoked = em.revoke_token(token_id)
        db.commit()
        return EnrollmentTokenRevokeResponse(revoked=revoked)
    except Exception as e:
        db.rollback()
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e),
        )
    finally:
        db.close()
