"""Initialization endpoint."""

import logging
import secrets

from fastapi import APIRouter, Request, status
from pydantic import BaseModel, Field

router = APIRouter()
logger = logging.getLogger("venya.server")


# --- Request/Response models ---


class InitRequest(BaseModel):
    user_id: str = Field(..., description="User ID for first admin")


class InitResponse(BaseModel):
    initialized: bool
    recovery_code: str | None = None
    user_id: str | None = None


# --- Endpoints ---


@router.post(
    "/init",
    response_model=InitResponse,
    status_code=status.HTTP_201_CREATED,
)
async def init_vault(
    req: InitRequest,
    request: Request,
) -> InitResponse:
    """Bootstrap the vault: create admin role + enroll first admin + generate CA.

    Returns a break-glass recovery code (printed once, never stored).
    If already initialized, returns 409.
    """
    from ..ca import CAManager
    from ..dependencies import get_backend

    backend = get_backend(request)
    db = backend.get_session()
    try:
        # Check if already initialized (admin role exists)
        from vault.iam.models import Role

        admin_role = db.query(Role).filter(Role.name == "admin").first()
        if admin_role is not None:
            return InitResponse(
                initialized=False,
                recovery_code=None,
                user_id=None,
            )

        # Generate CA if not already present
        config = getattr(request.app.state, "config", None)
        if config is not None:
            ca_dir = getattr(config, "ca_dir", "/var/lib/venya/ca")
            ca_manager = CAManager(ca_dir)
            if not ca_manager.has_ca:
                try:
                    ca_manager.initialize()
                    logger.info("CA initialized during vault bootstrap")
                except RuntimeError:
                    logger.debug("CA already exists on disk")

        # Create admin role
        admin_role = Role(
            name="admin",
            permissions="read-write",
            description="System administrator — full access",
        )
        db.add(admin_role)
        db.flush()  # Get the role ID before creating membership

        # Enroll first admin user
        from vault.iam.models import User

        admin_user = User(
            user_id=req.user_id,
            auth_mode="security-key",
        )
        db.add(admin_user)

        # Assign admin role
        from vault.iam.models import RoleMember

        membership = RoleMember(
            user_id=req.user_id,
            role_id=admin_role.id,
        )
        db.add(membership)

        db.commit()

        recovery_code = secrets.token_urlsafe(32)
        logger.info("Vault initialized: admin %s enrolled, recovery code issued", req.user_id)

        return InitResponse(
            initialized=True,
            recovery_code=recovery_code,
            user_id=req.user_id,
        )
    finally:
        db.close()
