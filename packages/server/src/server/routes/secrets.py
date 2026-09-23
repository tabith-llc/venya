# Copyright (c) 2026 Tabith LLC.
# Use of this source code is governed by the Business Source License 1.1
# included in the LICENSE file at the root of this repository. As of the
# Change Date listed there, the work is available under MPL 2.0.
# SPDX-License-Identifier: BUSL-1.1

"""Secret CRUD endpoints."""

import base64
import hashlib
import logging
import re
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
    replaced: bool = False  # True when the store replaced a visible existing row (upsert)
    metadata_warnings: list[str] = Field(default_factory=list)  # loud-not-fatal shape-convention warnings


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


# --- Shape metadata (ticket secret-shape-metadata) -------------------------
# A "shape" = how a secret is consumed (which tool, which flag, which file
# format). Shapes are a CONVENTION over the free-form metadata column
# (SecretMetadata extra="allow") — zero schema change. The taxonomy below is
# the blessed set; unknown names are CUSTOM shapes (warn-not-fail, forward
# compatible). Usage templates reference the injected sandbox file via
# {secret_path} (= /run/secrets/venya/<id>) and NEVER the value: a value in
# command text persists UNMASKED in the audit log and /proc (the operator
# rule from architecture.md §Secret lifecycle, enforced here at authoring
# time — institutionalization rule: never bless a bypass shape).

BUILTIN_SHAPES = frozenset(
    {
        "ssh-password",
        "ssh-key",
        "http-netrc",
        "http-header-file",
        "mysql-defaults",
        "ipmi-passfile",
        "askpass",
        "sudo-stdin",
    }
)
ENV_SHAPE_PREFIX = "env:"
USAGE_PLACEHOLDERS = frozenset({"secret_path", "secret_id", "host", "user"})

# Shapes whose consumption MECHANISM has not shipped yet — declaring one is
# allowed (forward-compat ruling) but must WARN: a label implying capability
# the product lacks is a user-friendliness defect and a support-ticket
# generator. Currently EMPTY: env:NAME + askpass shipped in the env-shape
# train, sudo-stdin shipped via the narrow redirect allowance (ticket
# secret-shape-sudo-remote option (a)). Re-add here ONLY with a ruling.
# File-arg shapes are NOT here: file injection ships today, and tool
# availability inside the sandbox template is a deployment property the
# server cannot know (documented per-shape).
MECHANISM_PENDING_SHAPES: frozenset[str] = frozenset()

_VALUE_PLACEHOLDER_RE = re.compile(
    r"\{\s*(value|secret_value|secret|plaintext|password|pass|token|credential)\s*\}",
    re.IGNORECASE,
)
_PLACEHOLDER_RE = re.compile(r"\{([A-Za-z_][A-Za-z0-9_]*)\}")


def _validate_shape_metadata(meta: dict[str, Any]) -> list[str]:
    """Validate the shape/usage convention keys. Returns user-facing warnings.

    Warnings are loud, never fatal (forward-compat ruling). The security half
    RAISES 400 with an actionable message: usage templates interpolating the
    secret value, or non-string shape/usage.
    """
    warnings: list[str] = []

    shape = meta.get("shape")
    if shape is not None:
        if not isinstance(shape, str) or not shape.strip():
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="'shape' metadata must be a non-empty string (e.g. shape=ssh-key).",
            )
        if not (shape in BUILTIN_SHAPES or shape.startswith(ENV_SHAPE_PREFIX)):
            hint = (
                ""
                if meta.get("usage")
                else " Add 'usage' metadata — a command template with {secret_path} — so agents know how to consume it."
            )
            warnings.append(
                f"shape '{shape}' is not built-in; treating it as a CUSTOM shape (allowed).{hint}"
                f" Built-ins: {', '.join(sorted(BUILTIN_SHAPES))}, and env:NAME."
            )
        if shape in MECHANISM_PENDING_SHAPES:
            warnings.append(
                f"shape '{shape}' is DECLARATIVE-ONLY in this release — its consumption mechanism"
                " has not shipped yet (sudo-stdin awaits the secret-shape-sudo-remote work)."
                " The secret IS still injected as a file at /run/secrets/venya/<id>, and any tool"
                " that reads it from a file works today."
            )

    usage = meta.get("usage")
    if usage is not None:
        if not isinstance(usage, str) or not usage.strip():
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="'usage' metadata must be a non-empty command-template string.",
            )
        m = _VALUE_PLACEHOLDER_RE.search(usage)
        if m:
            allowed = ", ".join("{" + p + "}" for p in sorted(USAGE_PLACEHOLDERS))
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=(
                    f"usage template interpolates the secret value ('{m.group(0)}') — rejected."
                    " Reference the secret only by path: {secret_path} (the injected sandbox"
                    " file /run/secrets/venya/<id>). A value in command text persists UNMASKED"
                    f" in the audit log and /proc. Allowed placeholders: {allowed}."
                ),
            )
        for name in _PLACEHOLDER_RE.findall(usage):
            if name not in USAGE_PLACEHOLDERS:
                warnings.append(
                    f"usage template has unknown placeholder '{{{name}}}' — agents may not know"
                    " how to substitute it. Canonical: {secret_path} = /run/secrets/venya/<id>."
                )

    return warnings


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
    db: Session = Depends(get_db),
) -> SecretCreateResponse:
    """Store a secret (upsert on a visible existing key).

    Requires read-write permission on all specified roles. Re-storing a key
    the caller can see (role in scope OR creator — the same visibility
    primitive as get/inject/list) REPLACES that row in place: id preserved,
    created_by immutable, response carries replaced=true. A scoped-out
    caller gets a plain insert (second row) — no existence leak, no
    cross-role clobber (ticket cli-store-force-field-ignored option-2).
    """
    core = getattr(request.app.state, "core", None)
    if core is None:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Core not initialized",
        )

    # Shape-metadata build + validation BEFORE the try: the validator's
    # actionable 400 must not be swallowed by the generic except below.
    meta = req.metadata.model_dump(exclude_none=True) if req.metadata else {}
    meta_warnings = _validate_shape_metadata(meta)
    # env shapes ride the line-based sandbox env-file format — catch multi-line
    # values at authoring time (loudest, earliest point) instead of at execute.
    shape_val = meta.get("shape")
    if (
        isinstance(shape_val, str)
        and shape_val.startswith(ENV_SHAPE_PREFIX)
        and ("\n" in req.value or "\r" in req.value)
    ):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=(
                "env-shape secrets must be single-line (the sandbox env-file format is line-based). "
                "Store the value without embedded newlines, or use a file-based shape."
            ),
        )

    try:
        # Caller's ACTUAL role names, fresh from the DB (NOT user_info["roles"]
        # — that carries role IDs; same wiring as the injection path in
        # executors.py). Visibility context for the upsert resolve.
        from core.engine.core import CoreAccessError
        from core.iam.role_manager import RoleManager

        rm = RoleManager(db)
        caller_roles = [m.role.name for m in rm.get_user_roles(user_info["user_id"])]

        record = core.put(
            key=req.key,
            value=req.value.encode("utf-8"),
            user_id=user_info["user_id"],
            role_names=req.roles,
            key_version_id=req.key_version_id,
            meta=meta,
            caller_roles=caller_roles,
        )
    except CoreAccessError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e),
        )
    except Exception:
        logger.exception("Secret creation failed")
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Secret creation failed",
        )

    return SecretCreateResponse(
        id=int(record.id),
        key=req.key,
        role_names=req.roles,
        metadata=meta if meta else {},
        replaced=record.replaced,
        metadata_warnings=meta_warnings,
    )


@router.get(
    "/secrets/{key}",
    response_model=SecretGetResponse,
)
async def secrets_get(
    key: str,
    request: Request,
    unmask: bool = False,
    user_info: dict = Depends(require_role("read")),
    db: Session = Depends(get_db),
) -> SecretGetResponse:
    """Retrieve a secret value (HUMAN-ONLY route).

    Masked by default; unmask requires a valid, single-use elevation token
    (WebAuthn re-auth) and is a loud 403 without one. The token rides the
    X-Elevation-Token HEADER (sec-auth-elevation-authz-hardening #13: the
    former query param persisted tokens in nginx + uvicorn access logs;
    uvicorn.access has its own handler, so RedactingFormatter never saw it).
    Header transport is the established convention (credentials routes, CLI).

    Ticket sec-secret-caller-param-plaintext-bypass: the former
    client-controlled `caller` query param (`?caller=executor` → plaintext)
    and the tokenless `?unmask=true` fall-through were both plaintext
    bypasses of the elevation gate. The route is now human-only BY
    CONSTRUCTION — no identity branch to derive, forward, or hide in.
    Executors cannot reach it (the middleware grants caller=executor only on
    session paths after a real cert check — `_validate_executor_mtls`,
    ticket sec-executor-session-path-no-auth) and consume secrets via
    session injection (`core.get_for_injection`), never this endpoint.
    """
    elevation_token = request.headers.get("X-Elevation-Token")
    core = getattr(request.app.state, "core", None)
    if core is None:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Core not initialized",
        )

    from core.engine.core import Caller, CoreAccessError

    # Unmask is ALWAYS elevation-gated (ticket
    # sec-secret-caller-param-plaintext-bypass): tokenless unmask is a loud
    # 403, never a silent fall-through to plaintext.
    if unmask:
        if not elevation_token:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Elevation token required to unmask",
            )
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
                    caller=Caller.HUMAN,
                    unmask=False,
                    user_id=user_info.get("user_id"),
                )
                return SecretGetResponse(key=key, value=value, masked=True)

            # Token consumed atomically — now fetch plaintext
            try:
                value = core.get(
                    secret_key=key,
                    caller=Caller.HUMAN,
                    unmask=True,
                    user_id=user_info.get("user_id"),
                )
                db.commit()
                return SecretGetResponse(key=key, value=value, masked=False)
            except HTTPException:
                raise
            except CoreAccessError as e:
                raise HTTPException(
                    status_code=status.HTTP_404_NOT_FOUND,
                    detail=str(e),
                )
            except Exception:
                logger.exception("Secret retrieval failed (elevated)")
                raise HTTPException(
                    status_code=status.HTTP_404_NOT_FOUND,
                    detail="Secret retrieval failed",
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
            caller=Caller.HUMAN,
            unmask=False,
            user_id=user_info.get("user_id"),
        )
    except CoreAccessError as e:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=str(e),
        )
    except Exception:
        logger.exception("Secret retrieval failed")
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Secret retrieval failed",
        )

    return SecretGetResponse(key=key, value=value, masked=True)


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
    db: Session = Depends(get_db),
) -> SecretListResponse:
    """List secrets visible to the caller, optionally filtered by prefix/metadata.

    Visibility is enforced in core.list (single enforcement point): a secret
    is listed iff one of the caller's roles is in its scope OR the caller
    created it. Scoped-out secrets are indistinguishable from nonexistent
    ones. Executor (mTLS) callers carry no user_id — trusted injection plane,
    they see all secrets (they already receive plaintext at execute time).

    Metadata filters:
      ?executor=web-server-3    -> secrets tagged for that executor
      ?purpose=ssh_login         -> secrets used for SSH login
      ?username=bot              -> secrets associated with username 'bot'

    Combinable: ?executor=web-server-3&purpose=ssh_login
    """
    core = getattr(request.app.state, "core", None)
    if core is None:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Core not initialized",
        )

    user_id = user_info.get("user_id")
    role_names: list[str] | None = None
    if user_id is not None:
        from core.iam.role_manager import RoleManager

        rm = RoleManager(db)
        role_names = [m.role.name for m in rm.get_user_roles(user_id)]

    records = core.list(
        prefix=prefix,
        role_names=role_names,
        user_id=user_id,
        executor=executor,
        purpose=purpose,
        username=username,
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
        secret_dict["metadata"] = r.meta if r.meta is not None else {}
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
        # Visibility enforcement FIRST (sec-auth-elevation-authz-hardening #5,
        # interlock 3): route through the core single enforcement point
        # (_resolve_secret_in: visible iff caller-role in scope OR creator) so
        # a scoped-out secret is 404-INDISTINGUISHABLE from a nonexistent one
        # and the metadata writer below is NEVER touched — no existence leak,
        # no mutation. Pre-fix this route queried bare Secret.key: any
        # read-write member could rewrite metadata on ANY secret (IDOR).
        from core.engine.core import CoreAccessError
        from core.iam.models import Secret
        from core.iam.role_manager import RoleManager

        rm = RoleManager(db)
        caller_roles = [m.role.name for m in rm.get_user_roles(user_info["user_id"])]
        try:
            core.get(
                secret_key=key,
                caller="human",
                unmask=False,
                user_id=user_info["user_id"],
                role_names=caller_roles,
            )
        except CoreAccessError:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Secret not found",
            ) from None

        secret = db.query(Secret).filter(Secret.key == key).first()
        if secret is None:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Secret not found")

        # Merge: existing fields preserved, new fields overwrite
        existing_meta = secret.meta or {}
        new_meta = req.metadata.model_dump(exclude_none=True) if req.metadata else {}
        # Enforce-before-mutate (same ordering principle as the IDOR fix above):
        # a rejected usage template must not touch the row.
        meta_warnings = _validate_shape_metadata(new_meta)
        merged_meta = {**existing_meta, **new_meta}

        secret.meta = merged_meta
        db.commit()

        return SecretCreateResponse(
            id=int(secret.id),
            key=secret.key,
            role_names=[r.role.name for r in secret.roles] if secret.roles else [],
            metadata=merged_meta,
            metadata_warnings=meta_warnings,
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
