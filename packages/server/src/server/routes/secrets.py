"""Secret CRUD endpoints."""

import base64
import hashlib
import logging
import types
from datetime import UTC, datetime, timedelta
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from server.dependencies import get_db, require_role

router = APIRouter()
logger = logging.getLogger("venya.server")


# --- Request/Response models ---


class SecretCreateRequest(BaseModel):
    key: str = Field(..., description="Secret key")
    value: str = Field(..., description="Secret value (plaintext)")
    roles: list[str] = Field(..., description="Role names to scope the secret to")
    key_version_id: str = Field(..., description="Key version ID for encryption")
    metadata: SecretMetadata | None = Field(
        default=None,
        description="Structured metadata for discovery (executor, purpose, username, description)",
    )


class SecretCreateResponse(BaseModel):
    id: int
    key: str
    role_names: list[str]
    metadata: dict[str, Any] | None = None


class SecretMetadata(BaseModel):
    """Structured metadata for a secret. All fields optional.

    Common fields are documented for LLM discovery. Additional
    fields are accepted for operator-specific context.
    """

    executor: str | None = Field(
        default=None,
        description="Executor ID this secret is intended for",
        examples=["web-server-3"],
    )
    purpose: str | None = Field(
        default=None,
        description="What this secret is used for",
        examples=["ssh_login", "api_key", "db_connection", "sudo_password"],
    )
    username: str | None = Field(
        default=None,
        description="Associated username for this credential",
        examples=["bot", "deploy", "postgres"],
    )
    description: str | None = Field(
        default=None,
        description="Human-readable context",
        examples=["Bot account SSH password for web-server-3"],
    )

    model_config = {"extra": "allow"}


class SecretUpdateRequest(BaseModel):
    value: str | None = None
    roles: list[str] | None = None
    metadata: SecretMetadata | None = None


class SecretGetResponse(BaseModel):
    key: str
    value: str
    masked: bool


class SecretListResponse(BaseModel):
    secrets: list[dict[str, Any]]


class SecretDeleteResponse(BaseModel):
    deleted: bool
    key: str


class SentinelWrappedResponse(BaseModel):
    """Sentinel-wrapped secret for executor injection."""

    secret_id: str
    wrapped_value: str  # [VENYA:{hash}]base64_data[/VENYA]
    detection_hashes: list[str]  # SHA-256 hex digests in multiple encodings


class RevokeSecretsRequest(BaseModel):
    """Request body for secret credential revocation."""

    secret_ids: list[str] = Field(
        ...,
        description="List of secret IDs whose scoped credentials should be revoked",
        min_length=1,
    )


class RevokeSecretsResponse(BaseModel):
    """Response for secret credential revocation."""

    revoked: bool
    count: int
    session_id: str


class ActiveKeyVersionResponse(BaseModel):
    """Response for the active key version."""

    key_version_id: str
    created_at: str


# --- Helper functions ---


def wrap_with_sentinel(secret_id: str, secret_value: bytes) -> str:
    """Wrap a secret value with sentinels for executor injection.

    Format: [VENYA:{8-char-hex-hash}]base64_data[/VENYA]

    Args:
        secret_id: The secret identifier.
        secret_value: The plaintext secret value.

    Returns:
        Sentinel-wrapped string.
    """
    hash_prefix = hashlib.sha256(secret_id.encode()).hexdigest()[:8]
    encoded = base64.b64encode(secret_value).decode("ascii")
    return f"[VENYA:{hash_prefix}]{encoded}[/VENYA]"


def compute_detection_hashes(value: bytes) -> list[str]:
    """Compute SHA-256 hashes for secret value in multiple encodings.

    Returns list of hex digests for: raw, base64, hex, trimmed.

    Args:
        value: The secret value bytes.

    Returns:
        List of SHA-256 hex digest strings.
    """
    import base64 as b64
    import hashlib

    hashes = []
    hashes.append(hashlib.sha256(value).hexdigest())  # raw bytes
    hashes.append(hashlib.sha256(b64.b64encode(value)).hexdigest())  # base64 encoding
    hashes.append(hashlib.sha256(value.hex().encode()).hexdigest())  # hex encoding
    trimmed = value.strip()
    if trimmed != value:
        hashes.append(hashlib.sha256(trimmed).hexdigest())  # whitespace-stripped
    return hashes


# --- Endpoints ---


@router.post(
    "/secrets",
    response_model=SecretCreateResponse,
    status_code=status.HTTP_201_CREATED,
)
async def secrets_create(
    req: SecretCreateRequest,
    request: Request,
    user_info: dict = Depends(require_role("read-write")),
) -> SecretCreateResponse:
    """Store a new secret.

    Requires read-write permission on all specified roles.
    """
    core = getattr(request.app.state, "core", None)
    if core is None:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Core not initialized",
        )

    try:
        meta = req.metadata.model_dump(exclude_none=True) if req.metadata else {}
        record = core.put(
            key=req.key,
            value=req.value.encode("utf-8"),
            user_id=user_info["user_id"],
            role_names=req.roles,
            key_version_id=req.key_version_id,
            meta=meta,
        )
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e),
        )

    return SecretCreateResponse(
        id=int(record.id),
        key=req.key,
        role_names=req.roles,
        metadata=meta if meta else None,
    )


@router.get(
    "/secrets/{key}",
    response_model=SecretGetResponse,
)
async def secrets_get(
    key: str,
    request: Request,
    unmask: bool = False,
    caller: str = "human",
    elevation_token: str | None = None,
    user_info: dict = Depends(require_role("read")),
    db: Session = Depends(get_db),
) -> SecretGetResponse:
    """Retrieve a secret value.

    Returns masked value by default for humans.
    Executor (mTLS) gets plaintext.
    Browser users need a valid elevation token to unmask.
    """
    core = getattr(request.app.state, "core", None)
    if core is None:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Core not initialized",
        )

    # For browser users requesting unmask, validate elevation token
    if caller == "human" and unmask and elevation_token:
        try:
            from core.iam.models import ElevationToken
            from sqlalchemy import update

            token_hash = hashlib.sha256(elevation_token.encode()).hexdigest()

            # Atomic conditional update: consume token only if still unused and not expired
            now = datetime.now(UTC)
            server_config = getattr(request.app.state, "config", None)
            tolerance = (
                server_config.clock_skew.token_tolerance_seconds
                if server_config and hasattr(server_config, "clock_skew")
                else 60
            )

            # Apply clock skew tolerance to expiry check
            expiry_cutoff = now - timedelta(seconds=tolerance)
            result = db.execute(
                update(ElevationToken)
                .where(
                    ElevationToken.token_hash == token_hash,
                    ElevationToken.user_id == user_info["user_id"],
                    ElevationToken.used.is_(False),
                    ElevationToken.expires_at > expiry_cutoff,
                )
                .values(used=True)
            )
            db.flush()

            if result.rowcount == 0:
                # Token already consumed by another request, expired, or not found
                value = core.get(
                    secret_key=key,
                    caller=caller,
                    unmask=False,
                    user_id=user_info.get("user_id"),
                )
                return SecretGetResponse(key=key, value=value, masked=True)

            # Token consumed atomically — now fetch plaintext
            try:
                value = core.get(
                    secret_key=key,
                    caller=caller,
                    unmask=True,
                    user_id=user_info.get("user_id"),
                )
                db.commit()
                return SecretGetResponse(key=key, value=value, masked=False)
            except HTTPException:
                raise
            except Exception as e:
                raise HTTPException(
                    status_code=status.HTTP_404_NOT_FOUND,
                    detail=str(e),
                )

        except HTTPException:
            raise
        except Exception:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Elevation token validation failed",
            )

    try:
        value = core.get(
            secret_key=key,
            caller=caller,
            unmask=unmask,
            user_id=user_info.get("user_id"),
        )
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=str(e),
        )

    return SecretGetResponse(key=key, value=value, masked=caller == "human" and not unmask)


@router.get(
    "/secrets/{key}/executor",
    response_model=SentinelWrappedResponse,
)
async def secrets_get_executor(
    key: str,
    request: Request,
    user_info: dict = Depends(require_role("read")),
) -> SentinelWrappedResponse:
    """Retrieve a secret for executor injection.

    Returns sentinel-wrapped plaintext with detection hashes.
    This endpoint is for executor (mTLS) use only.
    """
    # Verify caller is executor (mTLS)
    if user_info.get("caller") != "executor":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Executor mTLS authentication required",
        )

    core = getattr(request.app.state, "core", None)
    if core is None:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Core not initialized",
        )

    try:
        plaintext = core.get(
            secret_key=key,
            caller="executor",
        )
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=str(e),
        )

    secret_value = plaintext.encode("utf-8")
    return SentinelWrappedResponse(
        secret_id=key,
        wrapped_value=wrap_with_sentinel(key, secret_value),
        detection_hashes=compute_detection_hashes(secret_value),
    )


@router.get(
    "/secrets",
    response_model=SecretListResponse,
)
async def secrets_list(
    request: Request,
    prefix: str | None = None,
    executor: str | None = None,
    purpose: str | None = None,
    username: str | None = None,
    user_info: dict = Depends(require_role("read")),
) -> SecretListResponse:
    """List secrets, optionally filtered by key prefix or metadata.

    Metadata filters:
      ?executor=web-server-3    -> secrets tagged for that executor
      ?purpose=ssh_login         -> secrets used for SSH login
      ?username=bot              -> secrets associated with username 'bot'

    Combinable: ?executor=web-server-3&purpose=ssh_login

    No filter params -> returns all secrets (unchanged from current behavior).
    """
    backend = getattr(request.app.state, "backend", None)
    has_metadata_filter = executor is not None or purpose is not None or username is not None

    if has_metadata_filter and backend is not None:
        # Use database query for metadata filtering (does not require core)
        from core.iam.models import Secret

        db = backend.get_session()
        try:
            query = db.query(Secret)

            if executor:
                query = query.filter(Secret.meta["executor"].as_string() == executor)
            if purpose:
                query = query.filter(Secret.meta["purpose"].as_string() == purpose)
            if username:
                query = query.filter(Secret.meta["username"].as_string() == username)

            if prefix:
                query = query.filter(Secret.key.like(f"{prefix}%"))

            orm_records = query.all()
            records = []
            for r in orm_records:
                records.append(
                    types.SimpleNamespace(
                        id=r.id,
                        key=r.key,
                        key_version_id=r.key_version_id,
                        created_by=r.created_by,
                        created_at=r.created_at,
                        role_names=[sr.role.name for sr in r.roles] if r.roles else [],
                        meta=r.meta,
                    )
                )
        finally:
            db.close()
    else:
        # Use core.list for non-metadata filtering (requires core)
        core = getattr(request.app.state, "core", None)
        if core is None:
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="Core not initialized",
            )

        records = core.list(
            prefix=prefix,
        )

    secrets = []
    for r in records:
        secret_dict = {
            "id": int(r.id),
            "key": r.key,
            "key_version_id": r.key_version_id,
            "created_by": r.created_by,
            "created_at": r.created_at.isoformat() if r.created_at else None,
            "role_names": r.role_names,
        }
        if hasattr(r, "meta") and r.meta is not None:
            secret_dict["metadata"] = r.meta
        secrets.append(secret_dict)

    return SecretListResponse(secrets=secrets)


@router.delete(
    "/secrets/{key}",
    response_model=SecretDeleteResponse,
    status_code=status.HTTP_200_OK,
)
async def secrets_delete(
    key: str,
    request: Request,
    user_info: dict = Depends(require_role("read-write")),
) -> SecretDeleteResponse:
    """Delete a secret.

    Only the creator may delete a secret. Read-write permission
    is required to reach this endpoint, but deletion is gated by
    ownership in core.delete().
    """
    core = getattr(request.app.state, "core", None)
    if core is None:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Core not initialized",
        )

    deleted = core.delete(
        key=key,
        user_id=user_info["user_id"],
    )
    if not deleted:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Secret '{key}' not found or not owned by you",
        )

    return SecretDeleteResponse(deleted=deleted, key=key)


@router.patch(
    "/secrets/{key}/metadata",
    response_model=SecretCreateResponse,
    status_code=status.HTTP_200_OK,
)
async def update_secret_metadata(
    key: str,
    req: SecretUpdateRequest,
    request: Request,
    user_info: dict = Depends(require_role("read-write")),
) -> SecretCreateResponse:
    """Update only the metadata for a secret. Does not touch the value.

    Merge semantics: existing fields are preserved, new fields overwrite/add.
    """
    if not req.metadata:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Metadata field is required",
        )

    core = getattr(request.app.state, "core", None)
    if core is None:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Core not initialized",
        )

    backend = getattr(request.app.state, "backend", None)
    if backend is None:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Backend not initialized",
        )

    db = backend.get_session()
    try:
        from core.iam.models import Secret

        secret = db.query(Secret).filter(Secret.key == key).first()
        if secret is None:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Secret not found")

        # Merge: existing fields preserved, new fields overwrite
        existing_meta = secret.meta or {}
        new_meta = req.metadata.model_dump(exclude_none=True) if req.metadata else {}
        merged_meta = {**existing_meta, **new_meta}

        secret.meta = merged_meta
        db.commit()

        return SecretCreateResponse(
            id=int(secret.id),
            key=secret.key,
            role_names=[r.role.name for r in secret.roles] if secret.roles else [],
            metadata=merged_meta,
        )
    finally:
        db.close()


@router.post(
    "/sessions/{session_id}/secrets/revoke",
    response_model=RevokeSecretsResponse,
    status_code=status.HTTP_200_OK,
)
async def revoke_session_secrets(
    session_id: str,
    req: RevokeSecretsRequest,
    request: Request,
    db: Session = Depends(get_db),
) -> RevokeSecretsResponse:
    """Revoke scoped credentials for secrets injected during this session.

    Called automatically by the executor after command execution completes.
    Uses mTLS auth (executor identity), not bearer token auth.

    Args:
        session_id: The executor session ID.
        req: List of secret IDs to revoke.
        request: The FastAPI request (mTLS cert info).

    Returns:
        Confirmation of revocation with count.
    """
    from datetime import datetime

    from core.iam.models import AuditEvent

    # Verify caller is executor (mTLS)
    caller = getattr(request.state, "auth_user", {})
    if caller.get("caller") != "executor":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Executor mTLS authentication required",
        )

    # Log audit event for each revoked secret
    for secret_id in req.secret_ids:
        audit_event = AuditEvent(
            event_type="credential_revoked",
            user_id=caller.get("executor_id"),
            fields={
                "session_id": session_id,
                "secret_id": secret_id,
            },
            timestamp=datetime.now(UTC),
        )
        db.add(audit_event)

    db.commit()
    logger.info(
        "Revoked %d secret credentials for session %s",
        len(req.secret_ids),
        session_id,
    )

    return RevokeSecretsResponse(
        revoked=True,
        count=len(req.secret_ids),
        session_id=session_id,
    )


@router.get(
    "/key-versions/active",
    response_model=ActiveKeyVersionResponse,
)
async def get_active_key_version(
    user_info: dict = Depends(require_role("read")),
    db: Session = Depends(get_db),
) -> ActiveKeyVersionResponse:
    """Return the currently active key version ID.

    Used by the frontend to validate key_version_id before
    encrypting secrets. Now protected by read-level auth.
    """
    from core.iam.models import KeyVersion

    active_version = db.query(KeyVersion).filter(KeyVersion.active.is_(True)).first()
    if active_version is None:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="No active key version configured",
        )
    return ActiveKeyVersionResponse(
        key_version_id=active_version.version_label,
        created_at=active_version.created_at.isoformat() if active_version.created_at else "",
    )
