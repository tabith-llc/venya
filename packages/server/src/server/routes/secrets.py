"""Secret CRUD endpoints."""

import base64
import hashlib
import logging
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel, Field

router = APIRouter()
logger = logging.getLogger("venya.server")


# --- Request/Response models ---


class SecretCreateRequest(BaseModel):
    key: str = Field(..., description="Secret key")
    value: str = Field(..., description="Secret value (plaintext)")
    roles: list[str] = Field(..., description="Role IDs to scope the secret to")
    key_version_id: str = Field(
        ..., description="Key version ID for encryption"
    )


class SecretCreateResponse(BaseModel):
    id: int
    key: str
    role_ids: list[str]


class SecretGetRequest(BaseModel):
    unmask: bool = Field(False, description="Return plaintext instead of masked")
    caller: str = Field("human", description="Caller type: human or executor")
    elevation_token: str | None = Field(
        None, description="Elevation token for unmasking via browser",
    )


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
    import hashlib
    import base64 as b64

    hashes = []
    hashes.append(hashlib.sha256(value).hexdigest())  # raw bytes
    hashes.append(
        hashlib.sha256(b64.b64encode(value)).hexdigest()
    )  # base64 encoding
    hashes.append(
        hashlib.sha256(value.hex().encode()).hexdigest()
    )  # hex encoding
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
) -> SecretCreateResponse:
    """Store a new secret.

    Requires read-write permission on all specified roles.
    """
    user_info = await _get_user_info(request)
    vault = getattr(request.app.state, "vault", None)
    if vault is None:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Vault not initialized",
        )

    try:
        record = vault.put(
            key=req.key,
            value=req.value.encode("utf-8"),
            user_id=user_info["user_id"],
            role_ids=req.roles,
            key_version_id=req.key_version_id,
        )
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e),
        )

    return SecretCreateResponse(
        id=int(record.id),
        key=req.key,
        role_ids=req.roles,
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
) -> SecretGetResponse:
    """Retrieve a secret value.

    Returns masked value by default for humans.
    Executor (mTLS) gets plaintext.
    Browser users need a valid elevation token to unmask.
    """
    user_info = await _get_user_info(request)
    vault = getattr(request.app.state, "vault", None)
    if vault is None:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Vault not initialized",
        )

    # For browser users requesting unmask, validate elevation token
    if caller == "human" and unmask and elevation_token:
        backend = getattr(request.app.state, "backend", None)
        if backend is None:
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="Backend not initialized",
            )

        db = backend.get_session()
        try:
            import hashlib
            from datetime import datetime, timezone
            from vault.iam.models import ElevationToken

            from ..utils.time import is_expired

            token_hash = hashlib.sha256(elevation_token.encode()).hexdigest()
            elevation = (
                db.query(ElevationToken)
                .filter(
                    ElevationToken.token_hash == token_hash,
                    ElevationToken.user_id == user_info["user_id"],
                    ElevationToken.used == False,
                )
                .first()
            )

            if elevation is None:
                # No valid elevation token - return masked
                value = vault.get(
                    secret_key=key,
                    caller=caller,
                    unmask=False,
                    user_id=user_info.get("user_id"),
                )
                return SecretGetResponse(key=key, value=value, masked=True)

            server_config = getattr(request.app.state, "config", None)
            tolerance = (
                server_config.clock_skew.token_tolerance_seconds
                if server_config and hasattr(server_config, "clock_skew")
                else 60
            )
            if is_expired(elevation.expires_at, tolerance):
                # Expired token - return masked
                value = vault.get(
                    secret_key=key,
                    caller=caller,
                    unmask=False,
                    user_id=user_info.get("user_id"),
                )
                return SecretGetResponse(key=key, value=value, masked=True)

            # Mark token as used
            elevation.used = True
            db.commit()

            # Elevation valid - return plaintext
            try:
                value = vault.get(
                    secret_key=key,
                    caller=caller,
                    unmask=True,
                    user_id=user_info.get("user_id"),
                )
                return SecretGetResponse(key=key, value=value, masked=False)
            except Exception as e:
                raise HTTPException(
                    status_code=status.HTTP_404_NOT_FOUND,
                    detail=str(e),
                )

        except HTTPException:
            raise
        except Exception as e:
            try:
                db.rollback()
            except Exception:  # nosec B110 — rollback best-effort before raising HTTPException
                pass
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Elevation token validation failed",
            )
        finally:
            db.close()

    try:
        value = vault.get(
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
) -> SentinelWrappedResponse:
    """Retrieve a secret for executor injection.

    Returns sentinel-wrapped plaintext with detection hashes.
    This endpoint is for executor (mTLS) use only.
    """
    vault = getattr(request.app.state, "vault", None)
    if vault is None:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Vault not initialized",
        )

    try:
        plaintext = vault.get(
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
) -> SecretListResponse:
    """List secrets, optionally filtered by key prefix.

    Only shows secrets the authenticated user has read access to.
    """
    user_info = await _get_user_info(request)
    vault = getattr(request.app.state, "vault", None)
    if vault is None:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Vault not initialized",
        )

    records = vault.list(
        prefix=prefix,
        user_id=user_info.get("user_id"),
    )

    secrets = [
        {
            "id": int(r.id),
            "key": r.key,
            "key_version_id": r.key_version_id,
            "created_by": r.created_by,
            "created_at": r.created_at.isoformat() if r.created_at else None,
            "role_ids": r.role_ids,
        }
        for r in records
    ]

    return SecretListResponse(secrets=secrets)


@router.delete(
    "/secrets/{key}",
    response_model=SecretDeleteResponse,
    status_code=status.HTTP_200_OK,
)
async def secrets_delete(
    key: str,
    request: Request,
) -> SecretDeleteResponse:
    """Delete a secret.

    Requires read-write permission on the secret's role(s).
    """
    user_info = await _get_user_info(request)
    vault = getattr(request.app.state, "vault", None)
    if vault is None:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Vault not initialized",
        )

    deleted = vault.delete(
        key=key,
        user_id=user_info["user_id"],
    )

    return SecretDeleteResponse(deleted=deleted, key=key)


async def _get_user_info(request: Request) -> dict:
    """Extract user info from request (auth middleware sets this)."""
    user_info = getattr(request.state, "auth_user", None)
    if user_info is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Not authenticated",
        )
    return user_info


def _get_db(request: Request):
    """Get a database session from the backend on app state."""
    backend = getattr(request.app.state, "backend", None)
    if backend is None:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Backend not initialized",
        )
    return backend.get_session()


@router.post(
    "/sessions/{session_id}/secrets/revoke",
    response_model=RevokeSecretsResponse,
    status_code=status.HTTP_200_OK,
)
async def revoke_session_secrets(
    session_id: str,
    req: RevokeSecretsRequest,
    request: Request,
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
    from datetime import datetime, timezone

    from vault.iam.models import AuditEvent

    # Verify caller is executor (mTLS)
    caller = getattr(request.state, "auth_user", {})
    if caller.get("caller") != "executor":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Executor mTLS authentication required",
        )

    db = _get_db(request)
    try:
        # Log audit event for each revoked secret
        for secret_id in req.secret_ids:
            audit_event = AuditEvent(
                event_type="credential_revoked",
                user_id=caller.get("executor_id"),
                fields={
                    "session_id": session_id,
                    "secret_id": secret_id,
                },
                timestamp=datetime.now(timezone.utc),
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
    except Exception:
        db.rollback()
        raise
    finally:
        db.close()
