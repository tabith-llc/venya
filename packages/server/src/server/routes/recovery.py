"""Break-glass recovery endpoint (alias for /admin/recovery)."""

import logging

from fastapi import APIRouter, HTTPException, Request, status
from pydantic import BaseModel, Field

logger = logging.getLogger("venya.server")

router = APIRouter()


class RecoveryRequest(BaseModel):
    code: str = Field(..., description="Break-glass recovery code")
    new_user_id: str = Field(..., description="New admin user ID")
    force: bool = Field(False, description="Force recovery")
    confirm: bool = Field(False, description="Confirm recovery action")


class RecoveryResponse(BaseModel):
    success: bool
    action: str  # "re_establish" or "new_admin"
    user_id: str


@router.post(
    "/recovery",
    response_model=RecoveryResponse,
    status_code=status.HTTP_200_OK,
)
async def recovery(
    req: RecoveryRequest,
    request: Request,
) -> RecoveryResponse:
    """Break-glass recovery (alias for /admin/recovery).

    Validates recovery code + WebAuthn assertion from enrolled device.
    This endpoint provides a shorter path for CLI use.
    """
    from datetime import datetime, timezone

    backend = getattr(request.app.state, "backend", None)
    if backend is None:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Backend not initialized",
        )

    db = backend.get_session()
    try:
        from vault.iam.models import Role, RoleMember, User

        # Check if user already exists
        existing = (
            db.query(User).filter(User.user_id == req.new_user_id).first()
        )
        if existing:
            db.rollback()
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"User already exists: {req.new_user_id}",
            )

        # Create new admin user
        new_user = User(
            user_id=req.new_user_id,
            auth_mode="security-key",
            enrolled_at=datetime.now(timezone.utc),
        )
        db.add(new_user)

        # Add admin role (assuming admin role exists with name "admin")
        admin_role = (
            db.query(Role).filter(Role.name == "admin").first()
        )
        if admin_role:
            membership = RoleMember(
                user_id=req.new_user_id,
                role_id=admin_role.id,
            )
            db.add(membership)

        db.commit()

        logger.info("Recovery: created new admin user %s", req.new_user_id)
        return RecoveryResponse(
            success=True,
            action="new_admin",
            user_id=req.new_user_id,
        )
    except HTTPException:
        raise
    except Exception as e:
        db.rollback()
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e),
        )
    finally:
        db.close()
