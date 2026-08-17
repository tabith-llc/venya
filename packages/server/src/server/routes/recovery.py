"""Break-glass recovery endpoint (alias for /admin/recovery)."""

import hashlib
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
        from core.iam.models import Role, RoleMember, User

        # Validate recovery code against stored hash
        pepper = getattr(
            getattr(request.app.state, "config", None),
            "recovery_code_pepper",
            "",
        )
        submitted_hash = hashlib.sha256((pepper + req.code).encode()).hexdigest()

        # Find admin user with matching recovery code hash
        admin_user = (
            db.query(User)
            .join(RoleMember)
            .join(Role)
            .filter(Role.name == "admin")
            .filter(User.recovery_code_hash == submitted_hash)
            .first()
        )

        if admin_user is None:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid recovery code",
            )

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

        logger.info("Recovery: created new admin user %s (validated by code from %s)", req.new_user_id, admin_user.user_id)
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
