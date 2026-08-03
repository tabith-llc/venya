"""Admin operation endpoints."""

import logging

from fastapi import APIRouter, HTTPException, Request, status
from pydantic import BaseModel, Field

router = APIRouter()
logger = logging.getLogger("venya.server")


# --- Request/Response models ---


class AdminEnrollRequest(BaseModel):
    user_id: str = Field(..., description="User ID to enroll")
    auth_mode: str = Field("security-key", description="Auth mode")


class AdminEnrollResponse(BaseModel):
    enrolled: bool
    user_id: str
    auth_mode: str


class AdminRemoveRequest(BaseModel):
    user_id: str = Field(..., description="User ID to remove")


class AdminRemoveResponse(BaseModel):
    removed: bool
    user_id: str


class AdminUserListResponse(BaseModel):
    users: list[dict]


class AdminConfigureUserRequest(BaseModel):
    auth_mode: str | None = None
    session_timeout: int | None = None


class AdminConfigureUserResponse(BaseModel):
    configured: bool
    user_id: str


class AdminKeyVersionListResponse(BaseModel):
    versions: list[dict]


class AdminKeyVersionRotateRequest(BaseModel):
    new_key: str | None = Field(
        None, description="Path to new key file (hex-encoded 32 bytes)"
    )


class AdminKeyVersionRotateResponse(BaseModel):
    job_id: int
    status: str
    old_key_version_id: int | None
    new_key_version_id: int | None


class AdminKeyVersionRollbackRequest(BaseModel):
    job_id: int


class AdminKeyVersionRollbackResponse(BaseModel):
    rolled_back: bool
    job_id: int
    restored_secrets_count: int


class AdminSetCommandPolicyRequest(BaseModel):
    preset: str = Field(
        "balanced", description="Policy preset: strict, balanced, permissive"
    )
    custom_allowed_commands: list[str] | None = None
    custom_dangerous_patterns: list[str] | None = None


class AdminSetCommandPolicyResponse(BaseModel):
    policy_name: str
    preset: str
    updated: bool


class AdminRecoveryRequest(BaseModel):
    recovery_code: str = Field(..., description="Break-glass recovery code")
    new_user_id: str = Field(..., description="New admin user ID")
    webauthn_assertion: dict = Field(
        ..., description="WebAuthn assertion from enrolled device"
    )


class AdminRecoveryResponse(BaseModel):
    success: bool
    action: str  # "re_establish" or "new_admin"
    user_id: str


class AdminAddAllowedCommandRequest(BaseModel):
    command_path: str = Field(..., description="Absolute path to allowed command")


class AdminAddAllowedCommandResponse(BaseModel):
    added: bool
    command_path: str


class AdminKeyVersionDeactivateResponse(BaseModel):
    deactivated: bool
    version_id: int
    version_label: str


class AdminKeyVersionRevokeResponse(BaseModel):
    revoked: bool
    version_id: int
    version_label: str


class AdminKeyRotationStatusResponse(BaseModel):
    jobs: list[dict]


class AdminKeyRotationJobRollbackRequest(BaseModel):
    job_id: int


class AdminKeyRotationJobRollbackResponse(BaseModel):
    rolled_back: bool
    job_id: int
    restored_secrets_count: int


class AdminRevokeExecutorResponse(BaseModel):
    revoked: bool
    executor_id: str


# --- Endpoints ---


@router.post(
    "/admin/enroll",
    response_model=AdminEnrollResponse,
    status_code=status.HTTP_201_CREATED,
)
async def admin_enroll(
    req: AdminEnrollRequest,
    request: Request,
) -> AdminEnrollResponse:
    """Enroll a new user (admin only)."""
    # TODO: Implement via enrollment_manager
    return AdminEnrollResponse(
        enrolled=True, user_id=req.user_id, auth_mode=req.auth_mode
    )


@router.delete(
    "/admin/users/{user_id}",
    response_model=AdminRemoveResponse,
    status_code=status.HTTP_200_OK,
)
async def admin_remove(
    user_id: str,
    request: Request,
) -> AdminRemoveResponse:
    """Remove a user (admin only)."""
    # TODO: Implement
    return AdminRemoveResponse(removed=True, user_id=user_id)


@router.get(
    "/admin/users",
    response_model=AdminUserListResponse,
)
async def admin_list_users(
    request: Request,
) -> AdminUserListResponse:
    """List all registered users (admin only)."""
    # TODO: Query users from DB
    return AdminUserListResponse(users=[])


@router.put(
    "/admin/users/{user_id}",
    response_model=AdminConfigureUserResponse,
)
async def admin_configure_user(
    user_id: str,
    req: AdminConfigureUserRequest,
    request: Request,
) -> AdminConfigureUserResponse:
    """Configure user settings (admin only)."""
    # TODO: Update user settings
    return AdminConfigureUserResponse(configured=True, user_id=user_id)


@router.get(
    "/admin/key-versions",
    response_model=AdminKeyVersionListResponse,
)
async def admin_key_version_list(
    request: Request,
) -> AdminKeyVersionListResponse:
    """List all key versions (admin only)."""
    # TODO: Query key versions from DB
    return AdminKeyVersionListResponse(versions=[])


@router.post(
    "/admin/key-versions/rotate",
    response_model=AdminKeyVersionRotateResponse,
    status_code=status.HTTP_202_ACCEPTED,
)
async def admin_key_version_rotate(
    req: AdminKeyVersionRotateRequest,
    request: Request,
) -> AdminKeyVersionRotateResponse:
    """Start key rotation (admin only).

    Creates a new key version and begins re-wrapping all secrets.
    """
    # TODO: Implement key rotation
    return AdminKeyVersionRotateResponse(
        job_id=0,
        status="pending",
        old_key_version_id=None,
        new_key_version_id=None,
    )


@router.post(
    "/admin/key-versions/rollback",
    response_model=AdminKeyVersionRollbackResponse,
    status_code=status.HTTP_200_OK,
)
async def admin_key_version_rollback(
    req: AdminKeyVersionRollbackRequest,
    request: Request,
) -> AdminKeyVersionRollbackResponse:
    """Roll back a failed rotation job (admin only)."""
    # TODO: Implement rollback
    return AdminKeyVersionRollbackResponse(
        rolled_back=True, job_id=req.job_id, restored_secrets_count=0
    )


@router.post(
    "/admin/command-policy",
    response_model=AdminSetCommandPolicyResponse,
    status_code=status.HTTP_200_OK,
)
async def admin_set_command_policy(
    req: AdminSetCommandPolicyRequest,
    request: Request,
) -> AdminSetCommandPolicyResponse:
    """Set executor command policy (admin only)."""
    # TODO: Update command_policies table
    return AdminSetCommandPolicyResponse(
        policy_name="default",
        preset=req.preset,
        updated=True,
    )


@router.post(
    "/admin/recovery",
    response_model=AdminRecoveryResponse,
    status_code=status.HTTP_200_OK,
)
async def admin_recovery(
    req: AdminRecoveryRequest,
    request: Request,
) -> AdminRecoveryResponse:
    """Break-glass recovery (admin only).

    Validates recovery code + WebAuthn assertion from enrolled device.
    """
    # TODO: Validate recovery code, verify WebAuthn assertion
    return AdminRecoveryResponse(
        success=True,
        action="new_admin",
        user_id=req.new_user_id,
    )


@router.post(
    "/admin/command-policy/allowed",
    response_model=AdminAddAllowedCommandResponse,
    status_code=status.HTTP_200_OK,
)
async def admin_add_allowed_command(
    req: AdminAddAllowedCommandRequest,
    request: Request,
) -> AdminAddAllowedCommandResponse:
    """Add a command to the allowlist (admin only)."""
    # TODO: Update command_policies table
    return AdminAddAllowedCommandResponse(added=True, command_path=req.command_path)


@router.post(
    "/admin/key-versions/{version_id}/deactivate",
    response_model=AdminKeyVersionDeactivateResponse,
    status_code=status.HTTP_200_OK,
)
async def admin_key_version_deactivate(
    version_id: int,
    request: Request,
) -> AdminKeyVersionDeactivateResponse:
    """Deactivate a key version (admin only).

    Marks the version as inactive — no longer used for new encryption.
    """
    # TODO: Mark key version as inactive
    return AdminKeyVersionDeactivateResponse(
        deactivated=True,
        version_id=version_id,
        version_label=f"v{version_id}",
    )


@router.post(
    "/admin/key-versions/{version_id}/revoke",
    response_model=AdminKeyVersionRevokeResponse,
    status_code=status.HTTP_200_OK,
)
async def admin_key_version_revoke(
    version_id: int,
    request: Request,
) -> AdminKeyVersionRevokeResponse:
    """Revoke a key version (admin only).

    Permanently removes the version. All secrets must have been
    re-wrapped to a newer version first.
    """
    # TODO: Verify no secrets reference this version, then revoke
    return AdminKeyVersionRevokeResponse(
        revoked=True,
        version_id=version_id,
        version_label=f"v{version_id}",
    )


@router.get(
    "/admin/key-rotation/status",
    response_model=AdminKeyRotationStatusResponse,
    status_code=status.HTTP_200_OK,
)
async def admin_key_rotation_status(
    request: Request,
) -> AdminKeyRotationStatusResponse:
    """Show progress of active rotation jobs (admin only)."""
    # TODO: Query key_rotation_jobs from DB
    return AdminKeyRotationStatusResponse(jobs=[])


@router.post(
    "/admin/key-rotation/{job_id}/rollback",
    response_model=AdminKeyRotationJobRollbackResponse,
    status_code=status.HTTP_200_OK,
)
async def admin_key_rotation_job_rollback(
    job_id: int,
    request: Request,
) -> AdminKeyRotationJobRollbackResponse:
    """Roll back a failed or interrupted rotation job (admin only)."""
    # TODO: Restore partially re-wrapped secrets, mark job as rolled_back
    return AdminKeyRotationJobRollbackResponse(
        rolled_back=True,
        job_id=job_id,
        restored_secrets_count=0,
    )


@router.post(
    "/admin/executors/{executor_id}/revoke",
    response_model=AdminRevokeExecutorResponse,
    status_code=status.HTTP_200_OK,
)
async def admin_revoke_executor(
    executor_id: str,
    request: Request,
) -> AdminRevokeExecutorResponse:
    """Revoke an executor certificate (admin only).

    Adds the executor's certificate serial number to the revocation list.
    The executor will be rejected on next revocation check (polls every 60s).
    """
    from datetime import datetime, timezone

    from ..dependencies import get_backend
    from ..iam.models import ExecutorCert, ExecutorCertRevocation

    backend = get_backend(request)
    db = backend.get_session()
    try:
        # Look up the executor's current certificate
        cert = (
            db.query(ExecutorCert)
            .filter(ExecutorCert.executor_id == executor_id)
            .first()
        )

        if cert is None:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Executor not found: {executor_id}",
            )

        # Check if already revoked
        existing_revocation = (
            db.query(ExecutorCertRevocation)
            .filter(ExecutorCertRevocation.serial_number == cert.serial_number)
            .first()
        )

        if existing_revocation is not None:
            return AdminRevokeExecutorResponse(revoked=False, executor_id=executor_id)

        # Add to revocation list
        revocation = ExecutorCertRevocation(
            serial_number=cert.serial_number,
            executor_id=executor_id,
            revoked_at=datetime.now(timezone.utc),
            reason="Admin revocation",
        )
        db.add(revocation)
        db.commit()

        logger.info("Revoked executor certificate: %s (serial: %s)", executor_id, cert.serial_number)
        return AdminRevokeExecutorResponse(revoked=True, executor_id=executor_id)
    finally:
        db.close()


@router.post(
    "/admin/key-rotation",
    response_model=AdminKeyVersionRotateResponse,
    status_code=status.HTTP_202_ACCEPTED,
)
async def admin_key_rotation(
    req: AdminKeyVersionRotateRequest,
    request: Request,
) -> AdminKeyVersionRotateResponse:
    """Start key rotation (alias for /admin/key-versions/rotate).

    Admin only. Creates a new key version and begins re-wrapping all secrets.
    """
    # TODO: Implement key rotation
    return AdminKeyVersionRotateResponse(
        job_id=0,
        status="pending",
        old_key_version_id=None,
        new_key_version_id=None,
    )
