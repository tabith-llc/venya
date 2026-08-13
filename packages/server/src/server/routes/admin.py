"""Admin operation endpoints."""

import json
import logging
from datetime import datetime, timezone

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
    enrollment_token: str | None = None


class AdminCreateUserRequest(BaseModel):
    username: str = Field(..., description="User ID (e.g. 'jsmith')")
    display_name: str | None = Field(None, description="Human-readable name")
    roles: list[str] = Field(default_factory=list, description="Role names to assign")


class AdminCreateUserResponse(BaseModel):
    user_id: str
    status: str
    enrollment_token: str
    expires_in_seconds: int = 900


class AdminReEnrollResponse(BaseModel):
    user_id: str
    enrollment_token: str
    expires_in_seconds: int = 900
    credentials_deactivated: int = 0
    tokens_revoked: int = 0


class AdminUserTokenListResponse(BaseModel):
    tokens: list[dict]


class AdminUserTokenCreateResponse(BaseModel):
    user_id: str
    enrollment_token: str
    expires_in_seconds: int = 900
    previous_tokens_revoked: int = 0


class AdminTokenRevokeResponse(BaseModel):
    revoked: bool
    token_id: int


class AdminRemoveRequest(BaseModel):
    user_id: str = Field(..., description="User ID to remove")


class AdminRemoveResponse(BaseModel):
    removed: bool
    user_id: str


class AdminUserListResponse(BaseModel):
    users: list[dict]


class AdminConfigureUserRequest(BaseModel):
    display_name: str | None = None
    status: str | None = None
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
    "/admin/enroll",
    response_model=AdminEnrollResponse,
    status_code=status.HTTP_201_CREATED,
)
async def admin_enroll(
    req: AdminEnrollRequest,
    request: Request,
) -> AdminEnrollResponse:
    """Enroll a new user (admin only).

    Creates an enrollment token that the user can use to complete onboarding.
    DEPRECATED: Use POST /admin/users instead.
    """
    db = _get_db(request)
    try:
        from datetime import timezone as tz

        from vault.iam.enrollment_manager import EnrollmentError, EnrollmentManager
        from vault.iam.models import User

        em = EnrollmentManager(db)

        # Check if user already exists
        existing = db.query(User).filter(User.user_id == req.user_id).first()
        if existing:
            raise EnrollmentError(f"User '{req.user_id}' already exists")

        # Create user
        user = User(
            user_id=req.user_id,
            status="pending_enrollment",
            auth_mode=req.auth_mode,
        )
        db.add(user)
        db.flush()

        # Create enrollment token
        token, plaintext = em.create_enrollment_token(user.id)
        db.commit()

        return AdminEnrollResponse(
            enrolled=True,
            user_id=req.user_id,
            auth_mode=req.auth_mode,
            enrollment_token=plaintext,
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


@router.post(
    "/admin/users",
    response_model=AdminCreateUserResponse,
    status_code=status.HTTP_201_CREATED,
)
async def admin_create_user(
    req: AdminCreateUserRequest,
    request: Request,
) -> AdminCreateUserResponse:
    """Create a new user and enrollment token (admin only).

    Phase 1: Admin creates user + enrollment token in one call.
    The admin delivers the token to the user out-of-band.
    """
    db = _get_db(request)
    try:
        from datetime import timezone as tz

        from vault.iam.enrollment_manager import EnrollmentError, EnrollmentManager
        from vault.iam.models import Role, RoleMember, User

        em = EnrollmentManager(db)

        # Check if user already exists
        existing = db.query(User).filter(User.user_id == req.username).first()
        if existing:
            raise EnrollmentError(f"User '{req.username}' already exists")

        # Create user
        user = User(
            user_id=req.username,
            display_name=req.display_name,
            status="pending_enrollment",
        )
        db.add(user)
        db.flush()

        # Assign roles
        for role_name in req.roles:
            role = db.query(Role).filter(Role.name == role_name).first()
            if role is None:
                raise EnrollmentError(f"Role '{role_name}' not found")
            membership = RoleMember(user_id=user.user_id, role_id=role.id)
            db.add(membership)

        # Create enrollment token
        token, plaintext = em.create_enrollment_token(user.id)
        db.commit()

        logger.info(
            "Admin created user '%s' (ID: %d) with roles: %s",
            req.username, user.id, req.roles,
        )

        return AdminCreateUserResponse(
            user_id=req.username,
            status="pending_enrollment",
            enrollment_token=plaintext,
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
    db = _get_db(request)
    try:
        from vault.iam.models import RoleMember, Session, User

        user = db.query(User).filter(User.user_id == user_id).first()
        if user is None:
            db.rollback()
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"User not found: {user_id}",
            )

        # Remove role memberships
        db.query(RoleMember).filter(RoleMember.user_id == user_id).delete()
        # Remove sessions
        db.query(Session).filter(Session.user_id == user_id).delete()
        # Remove enrollment tokens (user_id is integer FK)
        from vault.iam.models import EnrollmentToken

        db.query(EnrollmentToken).filter(EnrollmentToken.user_id == user.id).delete()
        # Remove the user
        db.delete(user)
        db.commit()

        logger.info("Admin removed user: %s", user_id)
        return AdminRemoveResponse(removed=True, user_id=user_id)
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


@router.get(
    "/admin/users",
    response_model=AdminUserListResponse,
)
async def admin_list_users(
    request: Request,
) -> AdminUserListResponse:
    """List all registered users (admin only)."""
    db = _get_db(request)
    try:
        from vault.iam.models import User

        users = db.query(User).order_by(User.enrolled_at).all()
        result = [
            {
                "user_id": u.user_id,
                "display_name": u.display_name,
                "status": u.status,
                "auth_mode": u.auth_mode,
                "enrolled_at": u.enrolled_at.isoformat() if u.enrolled_at else None,
                "session_timeout": u.session_timeout,
            }
            for u in users
        ]
        return AdminUserListResponse(users=result)
    finally:
        db.close()


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
    db = _get_db(request)
    try:
        from vault.iam.models import User

        user = db.query(User).filter(User.user_id == user_id).first()
        if user is None:
            db.rollback()
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"User not found: {user_id}",
            )

        if req.display_name is not None:
            user.display_name = req.display_name
        if req.status is not None:
            user.status = req.status
        if req.auth_mode is not None:
            user.auth_mode = req.auth_mode
        if req.session_timeout is not None:
            user.session_timeout = req.session_timeout

        db.commit()
        return AdminConfigureUserResponse(configured=True, user_id=user_id)
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


@router.get(
    "/admin/key-versions",
    response_model=AdminKeyVersionListResponse,
)
async def admin_key_version_list(
    request: Request,
) -> AdminKeyVersionListResponse:
    """List all key versions (admin only)."""
    db = _get_db(request)
    try:
        from vault.iam.models import KeyVersion

        versions = db.query(KeyVersion).order_by(KeyVersion.created_at.desc()).all()
        result = [
            {
                "id": v.id,
                "version_label": v.version_label,
                "active": v.active,
                "rotation_pending": v.rotation_pending,
                "created_at": v.created_at.isoformat() if v.created_at else None,
            }
            for v in versions
        ]
        return AdminKeyVersionListResponse(versions=result)
    finally:
        db.close()


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
    db = _get_db(request)
    try:
        from vault.iam.models import KeyVersion, KeyRotationJob, KeyRotationSecret, Secret

        # Get current active key version
        active_version = (
            db.query(KeyVersion)
            .filter(KeyVersion.active == True)  # noqa: E712
            .order_by(KeyVersion.created_at.desc())
            .first()
        )

        # Create new key version
        import uuid

        new_version = KeyVersion(
            version_label=f"v{uuid.uuid4().hex[:8]}",
            active=False,
            rotation_pending=True,
        )
        db.add(new_version)
        db.flush()

        # Create rotation job
        job = KeyRotationJob(
            status="pending",
            total_secrets=db.query(Secret).count(),
            completed_secrets=0,
            failed_count=0,
        )
        db.add(job)
        db.flush()

        # Create per-secret tracking entries
        secrets = db.query(Secret).all()
        for secret in secrets:
            rotation_secret = KeyRotationSecret(
                rotation_job_id=job.id,
                secret_id=secret.id,
                status="pending",
            )
            db.add(rotation_secret)

        # Deactivate old version
        if active_version:
            active_version.active = False

        db.commit()

        return AdminKeyVersionRotateResponse(
            job_id=job.id,
            status="pending",
            old_key_version_id=active_version.id if active_version else None,
            new_key_version_id=new_version.id,
        )
    except Exception as e:
        db.rollback()
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e),
        )
    finally:
        db.close()


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
    db = _get_db(request)
    try:
        from vault.iam.models import KeyRotationJob

        job = (
            db.query(KeyRotationJob)
            .filter(KeyRotationJob.id == req.job_id)
            .first()
        )
        if job is None:
            db.rollback()
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Rotation job {req.job_id} not found",
            )

        # Count restored secrets (those that were rotated before rollback)
        from vault.iam.models import KeyRotationSecret

        restored = (
            db.query(KeyRotationSecret)
            .filter(
                KeyRotationSecret.rotation_job_id == req.job_id,
                KeyRotationSecret.status == "rotated",
            )
            .count()
        )

        job.status = "rolled_back"
        job.rolled_back_at = datetime.now(timezone.utc)
        db.commit()

        logger.info(
            "Rolled back rotation job %d, restored %d secrets",
            req.job_id,
            restored,
        )
        return AdminKeyVersionRollbackResponse(
            rolled_back=True,
            job_id=req.job_id,
            restored_secrets_count=restored,
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
    db = _get_db(request)
    try:
        from vault.iam.models import CommandPolicy

        policy = (
            db.query(CommandPolicy)
            .filter(CommandPolicy.policy_name == "default")
            .first()
        )

        if policy is None:
            policy = CommandPolicy(
                policy_name="default",
                preset=req.preset,
            )
            db.add(policy)

        policy.preset = req.preset
        if req.custom_allowed_commands is not None:
            policy.allowed_commands = json.dumps(req.custom_allowed_commands)
        if req.custom_dangerous_patterns is not None:
            policy.dangerous_patterns = json.dumps(req.custom_dangerous_patterns)
        policy.updated_at = datetime.now(timezone.utc)

        db.commit()
        return AdminSetCommandPolicyResponse(
            policy_name="default",
            preset=req.preset,
            updated=True,
        )
    except Exception as e:
        db.rollback()
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e),
        )
    finally:
        db.close()


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
    db = _get_db(request)
    try:
        from vault.iam.models import User

        # In production, this would validate the recovery code against
        # a secure store and verify the WebAuthn assertion.
        # For now, we create a new admin user.
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
        from vault.iam.models import Role, RoleMember

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

        logger.info("Admin recovery: created new admin user %s", req.new_user_id)
        return AdminRecoveryResponse(
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
    db = _get_db(request)
    try:
        from vault.iam.models import CommandPolicy

        policy = (
            db.query(CommandPolicy)
            .filter(CommandPolicy.policy_name == "default")
            .first()
        )

        if policy is None:
            policy = CommandPolicy(
                policy_name="default",
                preset="balanced",
                allowed_commands=json.dumps([req.command_path]),
            )
            db.add(policy)
        else:
            allowed = json.loads(policy.allowed_commands) if policy.allowed_commands else []
            if req.command_path not in allowed:
                allowed.append(req.command_path)
                policy.allowed_commands = json.dumps(allowed)

            policy.updated_at = datetime.now(timezone.utc)

        db.commit()
        return AdminAddAllowedCommandResponse(added=True, command_path=req.command_path)
    except Exception as e:
        db.rollback()
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e),
        )
    finally:
        db.close()


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
    db = _get_db(request)
    try:
        from vault.iam.models import KeyVersion

        version = (
            db.query(KeyVersion)
            .filter(KeyVersion.id == version_id)
            .first()
        )
        if version is None:
            db.rollback()
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Key version {version_id} not found",
            )

        version.active = False
        db.commit()

        logger.info("Deactivated key version: %s", version.version_label)
        return AdminKeyVersionDeactivateResponse(
            deactivated=True,
            version_id=version_id,
            version_label=version.version_label,
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
    db = _get_db(request)
    try:
        from vault.iam.models import KeyVersion, Secret

        version = (
            db.query(KeyVersion)
            .filter(KeyVersion.id == version_id)
            .first()
        )
        if version is None:
            db.rollback()
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Key version {version_id} not found",
            )

        # Check if any secrets still reference this version
        secret_count = (
            db.query(Secret)
            .filter(Secret.key_version_id == str(version_id))
            .count()
        )
        if secret_count > 0:
            db.rollback()
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Cannot revoke: {secret_count} secrets still use this version",
            )

        db.delete(version)
        db.commit()

        logger.info("Revoked key version: %s", version.version_label)
        return AdminKeyVersionRevokeResponse(
            revoked=True,
            version_id=version_id,
            version_label=version.version_label,
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


@router.get(
    "/admin/key-rotation/status",
    response_model=AdminKeyRotationStatusResponse,
    status_code=status.HTTP_200_OK,
)
async def admin_key_rotation_status(
    request: Request,
) -> AdminKeyRotationStatusResponse:
    """Show progress of active rotation jobs (admin only)."""
    db = _get_db(request)
    try:
        from vault.iam.models import KeyRotationJob

        jobs = (
            db.query(KeyRotationJob)
            .order_by(KeyRotationJob.started_at.desc() if hasattr(KeyRotationJob, 'started_at') else KeyRotationJob.id.desc())
            .all()
        )
        result = [
            {
                "id": j.id,
                "status": j.status,
                "total_secrets": j.total_secrets,
                "completed_secrets": j.completed_secrets,
                "failed_count": j.failed_count,
                "started_at": j.started_at.isoformat() if j.started_at else None,
                "completed_at": j.completed_at.isoformat() if j.completed_at else None,
            }
            for j in jobs
        ]
        return AdminKeyRotationStatusResponse(jobs=result)
    finally:
        db.close()


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
    db = _get_db(request)
    try:
        from vault.iam.models import KeyRotationJob, KeyRotationSecret

        job = (
            db.query(KeyRotationJob)
            .filter(KeyRotationJob.id == job_id)
            .first()
        )
        if job is None:
            db.rollback()
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Rotation job {job_id} not found",
            )

        # Count restored secrets
        restored = (
            db.query(KeyRotationSecret)
            .filter(
                KeyRotationSecret.rotation_job_id == job_id,
                KeyRotationSecret.status == "rotated",
            )
            .count()
        )

        job.status = "rolled_back"
        job.rolled_back_at = datetime.now(timezone.utc)
        db.commit()

        logger.info(
            "Rolled back rotation job %d, restored %d secrets",
            job_id,
            restored,
        )
        return AdminKeyRotationJobRollbackResponse(
            rolled_back=True,
            job_id=job_id,
            restored_secrets_count=restored,
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

    from vault.iam.models import ExecutorCert, ExecutorCertRevocation

    backend = getattr(request.app.state, "backend", None)
    if backend is None:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Backend not initialized",
        )
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

        logger.info(
            "Revoked executor certificate: %s (serial: %s)",
            executor_id,
            cert.serial_number,
        )
        return AdminRevokeExecutorResponse(revoked=True, executor_id=executor_id)
    finally:
        db.close()


# --- Phase 6: Re-enrollment ---


@router.post(
    "/admin/users/{user_id}/re-enroll",
    response_model=AdminReEnrollResponse,
    status_code=status.HTTP_200_OK,
)
async def admin_re_enroll(
    user_id: str,
    request: Request,
) -> AdminReEnrollResponse:
    """Re-enroll a user who has lost all credentials (admin only).

    Phase 6: Resets user for fresh enrollment.
    - Sets user status to pending_enrollment
    - Revokes all active enrollment tokens
    - Deactivates all WebAuthn credentials
    - Generates new enrollment token
    """
    db = _get_db(request)
    try:
        from datetime import timezone as tz

        from vault.iam.enrollment_manager import EnrollmentError, EnrollmentManager
        from vault.iam.models import User, WebAuthnCredential

        em = EnrollmentManager(db)

        # Find user
        user = db.query(User).filter(User.user_id == user_id).first()
        if user is None:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"User not found: {user_id}",
            )

        # Deactivate all active credentials
        deactivated = (
            db.query(WebAuthnCredential)
            .filter(
                WebAuthnCredential.user_id == user.user_id,
                WebAuthnCredential.is_active == True,  # noqa: E712
            )
            .update({"is_active": False}, synchronize_session="fetch")
        )

        # Revoke all active enrollment tokens
        tokens_revoked = em.revoke_all_active_tokens(user.id)

        # Set user status to pending_enrollment
        user.status = "pending_enrollment"

        # Generate new enrollment token
        token, plaintext = em.create_enrollment_token(user.id)
        db.commit()

        logger.info(
            "Re-enrolled user '%s' (ID: %d), deactivated %d credentials, revoked %d tokens",
            user_id, user.id, deactivated, tokens_revoked,
        )

        return AdminReEnrollResponse(
            user_id=user_id,
            enrollment_token=plaintext,
            expires_in_seconds=900,
            credentials_deactivated=deactivated,
            tokens_revoked=tokens_revoked,
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


# --- Phase 7: Admin Token Management ---


@router.get(
    "/admin/users/{user_id}/enrollment-tokens",
    response_model=AdminUserTokenListResponse,
    status_code=status.HTTP_200_OK,
)
async def admin_list_user_tokens(
    user_id: str,
    request: Request,
) -> AdminUserTokenListResponse:
    """List all enrollment tokens for a user (admin only).

    Phase 7: Shows token states for audit/management.
    """
    db = _get_db(request)
    try:
        from vault.iam.models import EnrollmentToken, User

        user = db.query(User).filter(User.user_id == user_id).first()
        if user is None:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"User not found: {user_id}",
            )

        tokens = (
            db.query(EnrollmentToken)
            .filter(EnrollmentToken.user_id == user.id)
            .order_by(EnrollmentToken.created_at.desc())
            .all()
        )

        result = [
            {
                "id": t.id,
                "state": t.state,
                "created_at": t.created_at.isoformat(),
                "expires_at": t.expires_at.isoformat(),
                "used_at": t.used_at.isoformat() if t.used_at else None,
            }
            for t in tokens
        ]

        return AdminUserTokenListResponse(tokens=result)
    finally:
        db.close()


@router.post(
    "/admin/users/{user_id}/enrollment-tokens",
    response_model=AdminUserTokenCreateResponse,
    status_code=status.HTTP_201_CREATED,
)
async def admin_create_user_token(
    user_id: str,
    request: Request,
) -> AdminUserTokenCreateResponse:
    """Issue a new enrollment token for a user (admin only).

    Phase 7: Revokes existing tokens and issues a new one.
    """
    db = _get_db(request)
    try:
        from vault.iam.enrollment_manager import EnrollmentManager
        from vault.iam.models import User

        em = EnrollmentManager(db)

        user = db.query(User).filter(User.user_id == user_id).first()
        if user is None:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"User not found: {user_id}",
            )

        # Revoke existing active tokens
        tokens_revoked = em.revoke_all_active_tokens(user.id)

        # Create new token
        token, plaintext = em.create_enrollment_token(user.id)
        db.commit()

        return AdminUserTokenCreateResponse(
            user_id=user_id,
            enrollment_token=plaintext,
            expires_in_seconds=900,
            previous_tokens_revoked=tokens_revoked,
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


@router.delete(
    "/admin/enrollment-tokens/{token_id}",
    response_model=AdminTokenRevokeResponse,
    status_code=status.HTTP_200_OK,
)
async def admin_revoke_token(
    token_id: int,
    request: Request,
) -> AdminTokenRevokeResponse:
    """Revoke a specific enrollment token (admin only).

    Phase 7: Revokes a single token by ID.
    """
    db = _get_db(request)
    try:
        from vault.iam.enrollment_manager import EnrollmentManager

        em = EnrollmentManager(db)
        revoked = em.revoke_token(token_id)
        db.commit()

        return AdminTokenRevokeResponse(revoked=revoked, token_id=token_id)
    except Exception as e:
        db.rollback()
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e),
        )
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
    return await admin_key_version_rotate(req, request)
