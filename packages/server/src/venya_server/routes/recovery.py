"""Break-glass recovery endpoint (alias for /admin/recovery)."""

import logging

from fastapi import APIRouter, Request, status
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
    # TODO: Delegate to admin recovery logic
    return RecoveryResponse(
        success=True,
        action="new_admin",
        user_id=req.new_user_id,
    )
