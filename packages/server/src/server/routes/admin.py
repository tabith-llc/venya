# Copyright (c) 2026 Tabith LLC.
# Use of this source code is governed by the Business Source License 1.1
# included in the LICENSE file at the root of this repository. As of the
# Change Date listed there, the work is available under MPL 2.0.
# SPDX-License-Identifier: BUSL-1.1

"""Admin operation endpoints."""

import hashlib
import hmac
import json
import logging
from datetime import UTC, datetime, timedelta

from core.utils.entropy import get_secure_token
from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel, Field
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from .. import metrics
from ..dependencies import enrollment_manager, get_db, require_admin
from ..rate_limit import rate_limit_admin_token_gen
from ..utils.executor_id import validate_executor_id
from ..utils.token_binding import compute_binding_hash

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
    """Rotation takes no parameters under single-KEK bookkeeping semantics.

    The former ``new_key`` field advertised per-version key material that
    never existed (the KEK derives from the install passphrase); removed
    with the option-2 ruling — zero callers existed.
    """


class AdminKeyVersionRotateResponse(BaseModel):
    job_id: int
    status: str
    old_key_version_id: int | None
    new_key_version_id: int | None
    note: str = Field("", description="Rotation semantics note (single-KEK: no secret re-wrap)")


class AdminKeyVersionRollbackRequest(BaseModel):
    job_id: int


class AdminKeyVersionRollbackResponse(BaseModel):
    rolled_back: bool
    job_id: int
    restored_secrets_count: int


class AdminSetCommandPolicyRequest(BaseModel):
    preset: str = Field("balanced", description="Policy preset: strict, balanced, permissive")
    custom_allowed_commands: list[str] | None = None
    custom_dangerous_patterns: list[str] | None = None


class AdminSetCommandPolicyResponse(BaseModel):
    policy_name: str
    preset: str
    updated: bool


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


class AdminEnrollExecutorResponse(BaseModel):
    executor_id: str
    enrollment_token: str
    expires_in_seconds: int
    expires_at: str


class AdminExecutorInfo(BaseModel):
    executor_id: str
    serial_number: str
    fingerprint: str
    not_before: datetime
    not_after: datetime


class AdminExecutorListResponse(BaseModel):
    executors: list[AdminExecutorInfo]


# --- Helper functions ---


# --- Endpoints ---


@router.post(
    "/admin/enroll",
    response_model=AdminEnrollResponse,
    status_code=status.HTTP_201_CREATED,
)
async def admin_enroll(
    req: AdminEnrollRequest,
    request: Request,
    _: dict = Depends(require_admin),
    db: Session = Depends(get_db),
) -> AdminEnrollResponse:
    """Enroll a new user (admin only).

    Creates an enrollment token that the user can use to complete onboarding.
    DEPRECATED: Use POST /admin/users instead.
    """
    try:

        from core.iam.enrollment_manager import EnrollmentError
        from core.iam.models import User

        em = enrollment_manager(db, request)

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
        token, plaintext = em.create_enrollment_token(user.user_id)
        config = getattr(request.app.state, "config", None)
        if config and config.recovery_code_pepper:
            token.binding_hash = compute_binding_hash(req.user_id, plaintext, config.recovery_code_pepper)
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
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e),
        )
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e),
        )


@router.post(
    "/admin/users",
    response_model=AdminCreateUserResponse,
    status_code=status.HTTP_201_CREATED,
)
async def admin_create_user(
    req: AdminCreateUserRequest,
    request: Request,
    _: dict = Depends(require_admin),
    db: Session = Depends(get_db),
) -> AdminCreateUserResponse:
    """Create a new user and enrollment token (admin only).

    Phase 1: Admin creates user + enrollment token in one call.
    The admin delivers the token to the user out-of-band.
    """
    try:

        from core.iam.enrollment_manager import EnrollmentError
        from core.iam.models import Role, RoleMember, User

        em = enrollment_manager(db, request)

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
        token, plaintext = em.create_enrollment_token(user.user_id)
        config = getattr(request.app.state, "config", None)
        if config and config.recovery_code_pepper:
            token.binding_hash = compute_binding_hash(req.username, plaintext, config.recovery_code_pepper)
        db.commit()
        metrics.TOKEN_CREATED.labels(type="user").inc()

        logger.info(
            "Admin created user '%s' (ID: %d) with roles: %s",
            req.username,
            user.id,
            req.roles,
        )

        return AdminCreateUserResponse(
            user_id=req.username,
            status="pending_enrollment",
            enrollment_token=plaintext,
            expires_in_seconds=int(em.config.token_expiry.total_seconds()),
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


@router.delete(
    "/admin/users/{user_id}",
    response_model=AdminRemoveResponse,
    status_code=status.HTTP_200_OK,
)
async def admin_remove(
    user_id: str,
    _: dict = Depends(require_admin),
    db: Session = Depends(get_db),
) -> AdminRemoveResponse:
    """Remove a user (admin only)."""
    try:
        from core.iam.models import RoleMember, Session, User

        user = db.query(User).filter(User.user_id == user_id).first()
        if user is None:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"User not found: {user_id}",
            )

        # Remove role memberships
        db.query(RoleMember).filter(RoleMember.user_id == user_id).delete()
        # Remove sessions
        db.query(Session).filter(Session.user_id == user_id).delete()
        # Remove enrollment tokens (user_id is String FK to users.user_id)
        from core.iam.models import EnrollmentToken

        db.query(EnrollmentToken).filter(EnrollmentToken.user_id == user.user_id).delete()
        # Remove the user
        db.delete(user)
        db.commit()

        logger.info("Admin removed user: %s", user_id)
        return AdminRemoveResponse(removed=True, user_id=user_id)
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e),
        )


@router.get(
    "/admin/users",
    response_model=AdminUserListResponse,
)
async def admin_list_users(
    _: dict = Depends(require_admin),
    db: Session = Depends(get_db),
) -> AdminUserListResponse:
    """List all registered users (admin only)."""
    from core.iam.models import User

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


@router.put(
    "/admin/users/{user_id}",
    response_model=AdminConfigureUserResponse,
)
async def admin_configure_user(
    user_id: str,
    req: AdminConfigureUserRequest,
    request: Request,
    _: dict = Depends(require_admin),
    db: Session = Depends(get_db),
) -> AdminConfigureUserResponse:
    """Configure user settings (admin only)."""
    try:
        from core.iam.models import User

        user = db.query(User).filter(User.user_id == user_id).first()
        if user is None:
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
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e),
        )


@router.get(
    "/admin/key-versions",
    response_model=AdminKeyVersionListResponse,
)
async def admin_key_version_list(
    _: dict = Depends(require_admin),
    db: Session = Depends(get_db),
) -> AdminKeyVersionListResponse:
    """List all key versions (admin only)."""
    from core.iam.models import KeyVersion

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


NO_REWRAP_NOTE = "no re-wrap: single-KEK alpha semantics"


@router.post(
    "/admin/key-versions/rotate",
    response_model=AdminKeyVersionRotateResponse,
)
async def admin_key_version_rotate(
    req: AdminKeyVersionRotateRequest,
    _: dict = Depends(require_admin),
    db: Session = Depends(get_db),
) -> AdminKeyVersionRotateResponse:
    """Rotate the active key version synchronously (admin only).

    Label-boundary rotation under single-KEK alpha semantics: there is no
    per-version key material (the KEK derives from the install passphrase)
    and secret decryption never consults key_versions, so NO secrets are
    re-wrapped. Existing secrets keep their stored label and remain
    decryptable; new secrets receive the new label via
    GET /key-versions/active. The rotation job is terminal ("completed")
    when this request returns. The at-most-one-active invariant is enforced
    by the uq_key_versions_single_active partial unique index (migration
    028) — a lost concurrency race surfaces as 409, never a second active
    version.
    """
    import uuid

    from core.iam.models import KeyRotationJob, KeyVersion, Secret

    now = datetime.now(UTC)
    try:
        active_version = (
            db.query(KeyVersion).filter(KeyVersion.active.is_(True)).order_by(KeyVersion.created_at.desc()).first()
        )
        old_id = active_version.id if active_version else None

        # Deactivate ALL active versions (normally exactly one; the partial
        # unique index makes more unreachable on migrated databases).
        db.query(KeyVersion).filter(KeyVersion.active.is_(True)).update(
            {KeyVersion.active: False}, synchronize_session=False
        )

        new_version = KeyVersion(
            version_label=f"v{uuid.uuid4().hex[:8]}",
            active=True,
            rotation_pending=False,
        )
        db.add(new_version)
        db.flush()

        job = KeyRotationJob(
            status="completed",
            old_key_version_id=old_id,
            new_key_version_id=new_version.id,
            total_secrets=db.query(Secret).count(),
            completed_secrets=0,  # truthful: nothing is re-wrapped (single KEK)
            failed_count=0,
            started_at=now,
            completed_at=now,
        )
        db.add(job)
        db.commit()
    except IntegrityError:
        # Lost a concurrent-rotation race — the partial unique index caught
        # it. get_db rolls the session back when this HTTPException escapes
        # (routes must not touch rollback/close themselves).
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Concurrent rotation committed first; re-check GET /key-versions/active",
        )
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e),
        )

    logger.info(
        "Rotated key version %s -> %s (job %d; %s)",
        old_id,
        new_version.version_label,
        job.id,
        NO_REWRAP_NOTE,
    )
    return AdminKeyVersionRotateResponse(
        job_id=job.id,
        status="completed",
        old_key_version_id=old_id,
        new_key_version_id=new_version.id,
        note=NO_REWRAP_NOTE,
    )


def _rollback_key_rotation(db: Session, job_id: int) -> int:
    """Flip the active key version back for a completed rotation job.

    Shared by both rollback routes. Under single-KEK semantics no secrets
    were ever re-wrapped, so there is nothing to restore at the secret
    level — rollback reactivates the job's OLD key version, deactivates the
    new one, and marks the job rolled_back. Only the MOST RECENT job can be
    rolled back: flipping under a newer rotation would silently undo it.

    Returns the legacy re-wrap count (structurally 0 post-fix; counted for
    pre-fix job rows whose KeyRotationSecret entries may exist).
    """
    from core.iam.models import KeyRotationJob, KeyRotationSecret, KeyVersion

    job = db.query(KeyRotationJob).filter(KeyRotationJob.id == job_id).first()
    if job is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Rotation job {job_id} not found",
        )
    if job.status != "completed":
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"Rotation job {job_id} has status {job.status!r}; only 'completed' rotations can be rolled back",
        )
    latest = db.query(KeyRotationJob).order_by(KeyRotationJob.id.desc()).first()
    if latest is not None and latest.id != job.id:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=(
                f"Rotation job {job_id} is not the most recent rotation (job {latest.id} is); "
                "roll that one back first"
            ),
        )
    if job.old_key_version_id is None:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"Rotation job {job_id} created the first key version; there is no prior version to reactivate",
        )
    old_version = db.query(KeyVersion).filter(KeyVersion.id == job.old_key_version_id).first()
    if old_version is None:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"Prior key version {job.old_key_version_id} no longer exists",
        )

    restored = (
        db.query(KeyRotationSecret)
        .filter(
            KeyRotationSecret.rotation_job_id == job_id,
            KeyRotationSecret.status == "rotated",
        )
        .count()
    )

    db.query(KeyVersion).filter(KeyVersion.active.is_(True)).update(
        {KeyVersion.active: False}, synchronize_session=False
    )
    old_version.active = True
    job.status = "rolled_back"
    job.rolled_back_at = datetime.now(UTC)
    db.commit()

    logger.info(
        "Rolled back rotation job %d: reactivated key version %d "
        "(%d re-wrapped secrets restored — none are re-wrapped under single-KEK semantics)",
        job_id,
        old_version.id,
        restored,
    )
    return restored


@router.post(
    "/admin/key-versions/rollback",
    response_model=AdminKeyVersionRollbackResponse,
    status_code=status.HTTP_200_OK,
)
async def admin_key_version_rollback(
    req: AdminKeyVersionRollbackRequest,
    _: dict = Depends(require_admin),
    db: Session = Depends(get_db),
) -> AdminKeyVersionRollbackResponse:
    """Roll back the most recent completed rotation (admin only).

    Reactivates the prior key version and marks the job rolled_back.
    restored_secrets_count is 0 under single-KEK semantics (no secret was
    ever re-wrapped). 404 for a missing job; 409 for non-completed,
    non-latest, or first-ever rotations.
    """
    try:
        restored = _rollback_key_rotation(db, req.job_id)
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e),
        )
    return AdminKeyVersionRollbackResponse(
        rolled_back=True,
        job_id=req.job_id,
        restored_secrets_count=restored,
    )


@router.post(
    "/admin/command-policy",
    response_model=AdminSetCommandPolicyResponse,
    status_code=status.HTTP_200_OK,
)
async def admin_set_command_policy(
    req: AdminSetCommandPolicyRequest,
    _: dict = Depends(require_admin),
    db: Session = Depends(get_db),
) -> AdminSetCommandPolicyResponse:
    """Set executor command policy (admin only)."""
    try:
        from core.iam.models import CommandPolicy

        policy = db.query(CommandPolicy).filter(CommandPolicy.policy_name == "default").first()

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
        policy.updated_at = datetime.now(UTC)

        db.commit()
        return AdminSetCommandPolicyResponse(
            policy_name="default",
            preset=req.preset,
            updated=True,
        )
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e),
        )


@router.post(
    "/admin/command-policy/allowed",
    response_model=AdminAddAllowedCommandResponse,
    status_code=status.HTTP_200_OK,
)
async def admin_add_allowed_command(
    req: AdminAddAllowedCommandRequest,
    _: dict = Depends(require_admin),
    db: Session = Depends(get_db),
) -> AdminAddAllowedCommandResponse:
    """Add a command to the allowlist (admin only)."""
    try:
        from core.iam.models import CommandPolicy

        policy = db.query(CommandPolicy).filter(CommandPolicy.policy_name == "default").first()

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

            policy.updated_at = datetime.now(UTC)

        db.commit()
        return AdminAddAllowedCommandResponse(added=True, command_path=req.command_path)
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e),
        )


@router.post(
    "/admin/key-versions/{version_id}/deactivate",
    response_model=AdminKeyVersionDeactivateResponse,
    status_code=status.HTTP_200_OK,
)
async def admin_key_version_deactivate(
    version_id: int,
    _: dict = Depends(require_admin),
    db: Session = Depends(get_db),
) -> AdminKeyVersionDeactivateResponse:
    """Deactivate a key version (admin only).

    Marks the version as inactive — no longer used for new encryption.
    """
    try:
        from core.iam.models import KeyVersion

        version = db.query(KeyVersion).filter(KeyVersion.id == version_id).first()
        if version is None:
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
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e),
        )


@router.post(
    "/admin/key-versions/{version_id}/revoke",
    response_model=AdminKeyVersionRevokeResponse,
    status_code=status.HTTP_200_OK,
)
async def admin_key_version_revoke(
    version_id: int,
    _: dict = Depends(require_admin),
    db: Session = Depends(get_db),
) -> AdminKeyVersionRevokeResponse:
    """Revoke a key version (admin only).

    Permanently removes the version. All secrets must have been
    re-wrapped to a newer version first.
    """
    try:
        from core.iam.models import KeyVersion, Secret

        version = db.query(KeyVersion).filter(KeyVersion.id == version_id).first()
        if version is None:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Key version {version_id} not found",
            )

        # Check if any secrets still reference this version
        secret_count = db.query(Secret).filter(Secret.key_version_id == str(version_id)).count()
        if secret_count > 0:
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
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e),
        )


@router.get(
    "/admin/key-rotation/status",
    response_model=AdminKeyRotationStatusResponse,
    status_code=status.HTTP_200_OK,
)
async def admin_key_rotation_status(
    _: dict = Depends(require_admin),
    db: Session = Depends(get_db),
) -> AdminKeyRotationStatusResponse:
    """Show progress of active rotation jobs (admin only)."""
    from core.iam.models import KeyRotationJob

    jobs = (
        db.query(KeyRotationJob)
        .order_by(
            KeyRotationJob.started_at.desc() if hasattr(KeyRotationJob, "started_at") else KeyRotationJob.id.desc()
        )
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


@router.post(
    "/admin/key-rotation/{job_id}/rollback",
    response_model=AdminKeyRotationJobRollbackResponse,
    status_code=status.HTTP_200_OK,
)
async def admin_key_rotation_job_rollback(
    job_id: int,
    _: dict = Depends(require_admin),
    db: Session = Depends(get_db),
) -> AdminKeyRotationJobRollbackResponse:
    """Roll back a completed rotation by job id (admin only).

    Same semantics as POST /admin/key-versions/rollback: reactivates the
    prior key version, marks the job rolled_back, restored_secrets_count 0
    under single-KEK semantics. 404 missing; 409 non-completed / non-latest /
    first-ever rotation.
    """
    try:
        restored = _rollback_key_rotation(db, job_id)
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e),
        )
    return AdminKeyRotationJobRollbackResponse(
        rolled_back=True,
        job_id=job_id,
        restored_secrets_count=restored,
    )


@router.get(
    "/admin/executors",
    response_model=AdminExecutorListResponse,
)
async def admin_list_executors(
    _: dict = Depends(require_admin),
    db: Session = Depends(get_db),
) -> AdminExecutorListResponse:
    """List all registered executors with their current certificates (admin only).

    Returns the latest non-revoked certificate for each executor.
    Executors are deduplicated by executor_id — only the most recent
    active cert per executor is returned.
    """
    from core.iam.models import ExecutorCert, ExecutorCertRevocation

    revoked_serials = {r.serial_number for r in db.query(ExecutorCertRevocation.serial_number).all()}

    certs = (
        db.query(ExecutorCert)
        .filter(~ExecutorCert.serial_number.in_(revoked_serials))
        .order_by(ExecutorCert.created_at.desc())
        .all()
    )

    # Deduplicate: keep latest cert per executor_id
    latest: dict[str, ExecutorCert] = {}
    for cert in certs:
        if cert.executor_id not in latest:
            latest[cert.executor_id] = cert

    result = [
        {
            "executor_id": c.executor_id,
            "serial_number": c.serial_number,
            "fingerprint": c.fingerprint,
            "not_before": c.not_before,
            "not_after": c.not_after,
        }
        for c in latest.values()
    ]

    return AdminExecutorListResponse(executors=result)


@router.post(
    "/admin/executors/{executor_id}/revoke",
    response_model=AdminRevokeExecutorResponse,
    status_code=status.HTTP_200_OK,
)
async def admin_revoke_executor(
    executor_id: str,
    _: dict = Depends(require_admin),
    db: Session = Depends(get_db),
) -> AdminRevokeExecutorResponse:
    """Revoke an executor certificate (admin only).

    Adds the executor's certificate serial number to the revocation list.
    The executor will be rejected on next revocation check (polls every 60s).
    """
    from datetime import datetime

    from core.iam.models import ExecutorCert, ExecutorCertRevocation

    # Look up the executor's current certificate
    cert = db.query(ExecutorCert).filter(ExecutorCert.executor_id == executor_id).first()

    if cert is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Executor not found: {executor_id}",
        )

    # Check if already revoked
    existing_revocation = (
        db.query(ExecutorCertRevocation).filter(ExecutorCertRevocation.serial_number == cert.serial_number).first()
    )

    if existing_revocation is not None:
        return AdminRevokeExecutorResponse(revoked=False, executor_id=executor_id)

    # Add to revocation list
    revocation = ExecutorCertRevocation(
        serial_number=cert.serial_number,
        executor_id=executor_id,
        revoked_at=datetime.now(UTC),
        reason="Admin revocation",
    )
    db.add(revocation)
    db.commit()
    metrics.TOKEN_REVOKED.labels(reason="executor_revoked").inc()

    logger.info(
        "Revoked executor cert: executor_id=%s, serial=%s",
        executor_id,
        cert.serial_number,
    )
    return AdminRevokeExecutorResponse(revoked=True, executor_id=executor_id)


@router.post(
    "/admin/executors/{executor_id}/enroll",
    response_model=AdminEnrollExecutorResponse,
    status_code=status.HTTP_201_CREATED,
)
async def admin_enroll_executor(
    executor_id: str,
    request: Request,
    _rl: None = Depends(rate_limit_admin_token_gen),
    _: dict = Depends(require_admin),
    db: Session = Depends(get_db),
) -> AdminEnrollExecutorResponse:
    """Generate an enrollment token for executor bootstrap registration (admin only).

    Creates a token in the format `enrl_exec_{base64url}` with configurable expiry.
    The token is hashed and stored in the database. The plaintext token is
    returned only once.

    The admin delivers the token to the executor operator out-of-band.
    The executor includes it in the registration request.
    """
    # Validate executor_id format before any DB or CA operations
    try:
        executor_id = validate_executor_id(executor_id)
    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e),
        )

    from core.iam.models import AuditEvent, ExecutorEnrollmentToken

    try:
        config = getattr(request.app.state, "config", None)
        ttl_seconds = config.executor_enrollment.token_ttl_seconds if config else 1800

        caller = getattr(request.state, "auth_user", {})
        admin_user_id = caller.get("user_id", "unknown")
        session_id = caller.get("session_id")
        client_ip = request.client.host if request.client else None
        user_agent = request.headers.get("user-agent")

        plaintext = "enrl_exec_" + get_secure_token(32)
        pepper = config.recovery_code_pepper if config else ""
        token_hash = hmac.new(
            pepper.encode("utf-8"),
            plaintext.encode("utf-8"),
            hashlib.sha256,
        ).hexdigest()
        now = datetime.now(UTC)
        expires_at = now + timedelta(seconds=ttl_seconds)

        token = ExecutorEnrollmentToken(
            executor_id=executor_id,
            token_hash=token_hash,
            state="created",
            created_by=admin_user_id,
            created_by_session_id=str(session_id) if session_id else None,
            created_from_ip=client_ip,
            created_from_user_agent=user_agent,
            expires_at=expires_at,
        )
        db.add(token)

        # Encrypt forensic identity fields into JSON blob before flush
        meta_dict = {
            "ip": client_ip,
            "ua": user_agent,
            "sid": str(session_id) if session_id else None,
        }
        core = getattr(request.app.state, "core", None)
        if core is None:
            raise RuntimeError("Core not initialized — cannot encrypt admin metadata")
        wrapped_dek, nonce, ciphertext = core.encrypt(json.dumps(meta_dict).encode("utf-8"))
        token.admin_meta_wrapped_dek = wrapped_dek
        token.admin_meta_nonce = nonce
        token.admin_meta_ciphertext = ciphertext

        db.flush()

        audit_event = AuditEvent(
            event_type="executor_enrollment_token_created",
            user_id=admin_user_id,
            fields={
                "executor_id": executor_id,
                "token_id": token.id,
                "token_hash_preview": token_hash[:8],
                "expires_at": expires_at.isoformat(),
                "created_by_session_id": str(session_id) if session_id else None,
                "created_from_ip": client_ip,
                "created_from_user_agent": user_agent,
                "token_created_at": now.isoformat(),
            },
            timestamp=now,
        )
        db.add(audit_event)
        db.commit()
        metrics.TOKEN_CREATED.labels(type="executor").inc()

        logger.info(
            "Admin created executor enrollment token for %s (by %s, ttl=%ds)",
            executor_id,
            admin_user_id,
            ttl_seconds,
        )

        return AdminEnrollExecutorResponse(
            executor_id=executor_id,
            enrollment_token=plaintext,
            expires_in_seconds=ttl_seconds,
            expires_at=expires_at.isoformat(),
        )
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e),
        )


# --- Phase 6: Re-enrollment ---


@router.post(
    "/admin/users/{user_id}/re-enroll",
    response_model=AdminReEnrollResponse,
    status_code=status.HTTP_200_OK,
)
async def admin_re_enroll(
    user_id: str,
    request: Request,
    _: dict = Depends(require_admin),
    db: Session = Depends(get_db),
) -> AdminReEnrollResponse:
    """Re-enroll a user who has lost all credentials (admin only).

    Phase 6: Resets user for fresh enrollment.
    - Sets user status to pending_enrollment
    - Revokes all active enrollment tokens
    - Deactivates all WebAuthn credentials
    - Generates new enrollment token
    """
    try:

        from core.iam.enrollment_manager import EnrollmentError
        from core.iam.models import User, WebAuthnCredential

        em = enrollment_manager(db, request)

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
                WebAuthnCredential.is_active.is_(True),
            )
            .update({"is_active": False}, synchronize_session="fetch")
        )

        # Revoke all active enrollment tokens
        tokens_revoked = em.revoke_all_active_tokens(user.user_id)

        # Set user status to pending_enrollment
        user.status = "pending_enrollment"

        # Generate new enrollment token
        token, plaintext = em.create_enrollment_token(user.user_id)
        config = getattr(request.app.state, "config", None)
        if config and config.recovery_code_pepper:
            token.binding_hash = compute_binding_hash(user_id, plaintext, config.recovery_code_pepper)
        db.commit()

        logger.info(
            "Re-enrolled user '%s' (ID: %d), deactivated %d credentials, revoked %d tokens",
            user_id,
            user.id,
            deactivated,
            tokens_revoked,
        )

        return AdminReEnrollResponse(
            user_id=user_id,
            enrollment_token=plaintext,
            expires_in_seconds=int(em.config.token_expiry.total_seconds()),
            credentials_deactivated=deactivated,
            tokens_revoked=tokens_revoked,
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


# --- Phase 7: Admin Token Management ---


@router.get(
    "/admin/users/{user_id}/enrollment-tokens",
    response_model=AdminUserTokenListResponse,
    status_code=status.HTTP_200_OK,
)
async def admin_list_user_tokens(
    user_id: str,
    _: dict = Depends(require_admin),
    db: Session = Depends(get_db),
) -> AdminUserTokenListResponse:
    """List all enrollment tokens for a user (admin only).

    Phase 7: Shows token states for audit/management.
    """
    from core.iam.models import EnrollmentToken, User

    user = db.query(User).filter(User.user_id == user_id).first()
    if user is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"User not found: {user_id}",
        )

    tokens = (
        db.query(EnrollmentToken)
        .filter(EnrollmentToken.user_id == user.user_id)
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


@router.post(
    "/admin/users/{user_id}/enrollment-tokens",
    response_model=AdminUserTokenCreateResponse,
    status_code=status.HTTP_201_CREATED,
)
async def admin_create_user_token(
    user_id: str,
    request: Request,
    _: dict = Depends(require_admin),
    db: Session = Depends(get_db),
) -> AdminUserTokenCreateResponse:
    """Issue a new enrollment token for a user (admin only).

    Phase 7: Revokes existing tokens and issues a new one.
    """
    try:
        from core.iam.models import User

        em = enrollment_manager(db, request)

        user = db.query(User).filter(User.user_id == user_id).first()
        if user is None:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"User not found: {user_id}",
            )

        # Revoke existing active tokens
        tokens_revoked = em.revoke_all_active_tokens(user.user_id)

        # Create new token
        token, plaintext = em.create_enrollment_token(user.user_id)
        config = getattr(request.app.state, "config", None)
        if config and config.recovery_code_pepper:
            token.binding_hash = compute_binding_hash(user_id, plaintext, config.recovery_code_pepper)
        db.commit()

        return AdminUserTokenCreateResponse(
            user_id=user_id,
            enrollment_token=plaintext,
            expires_in_seconds=int(em.config.token_expiry.total_seconds()),
            previous_tokens_revoked=tokens_revoked,
        )
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e),
        )


@router.delete(
    "/admin/enrollment-tokens/{token_id}",
    response_model=AdminTokenRevokeResponse,
    status_code=status.HTTP_200_OK,
)
async def admin_revoke_token(
    token_id: int,
    request: Request,
    _: dict = Depends(require_admin),
    db: Session = Depends(get_db),
) -> AdminTokenRevokeResponse:
    """Revoke a specific enrollment token (admin only).

    Phase 7: Revokes a single token by ID.
    """
    try:
        em = enrollment_manager(db, request)
        revoked = em.revoke_token(token_id)
        db.commit()
        if revoked:
            metrics.TOKEN_REVOKED.labels(reason="admin_revoked").inc()

        return AdminTokenRevokeResponse(revoked=revoked, token_id=token_id)
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e),
        )


@router.post(
    "/admin/key-rotation",
    response_model=AdminKeyVersionRotateResponse,
)
async def admin_key_rotation(
    req: AdminKeyVersionRotateRequest,
    _: dict = Depends(require_admin),
    db: Session = Depends(get_db),
) -> AdminKeyVersionRotateResponse:
    """Rotate the active key version (alias for /admin/key-versions/rotate).

    Admin only. Synchronous label-boundary rotation; no secrets are
    re-wrapped (single-KEK alpha semantics).
    """
    return await admin_key_version_rotate(req, _, db)


# --- Admin mTLS Certificate Revocation ---


class AdminRevokeCertRequest(BaseModel):
    serial: str = Field(..., description="Hex serial number of certificate to revoke")
    reason: str = Field(default="unspecified", description="Revocation reason")


class AdminRevokeCertResponse(BaseModel):
    serial: str
    revoked: bool
    reason: str
    already_revoked: bool = False


@router.post("/admin/certs/revoke")
async def admin_revoke_admin_cert(
    req: AdminRevokeCertRequest,
    _: dict = Depends(require_admin),
    db: Session = Depends(get_db),
) -> AdminRevokeCertResponse:
    """Revoke an admin certificate by serial number.

    Admin only. Idempotent — revoking the same serial twice returns success.
    """
    # Validate serial format
    serial = req.serial.strip()
    try:
        int(serial, 16)
        if len(serial) > 16:
            raise ValueError("too long")
    except ValueError:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid serial format — must be hex string (up to 16 chars)",
        )

    # Check if already revoked (idempotent)
    from core.iam.models import AdminCertRevocation

    existing = db.query(AdminCertRevocation).filter(AdminCertRevocation.serial_number == serial).first()

    if existing:
        logger.info("Admin cert %s already revoked (reason: %s)", serial, existing.reason)
        return AdminRevokeCertResponse(serial=serial, revoked=True, reason=existing.reason, already_revoked=True)

    # Insert new revocation
    now = datetime.now(UTC)
    revocation = AdminCertRevocation(serial_number=serial, reason=req.reason, revoked_at=now)
    db.add(revocation)
    db.commit()

    logger.info("Admin cert %s revoked (reason: %s)", serial, req.reason)
    return AdminRevokeCertResponse(serial=serial, revoked=True, reason=req.reason)
