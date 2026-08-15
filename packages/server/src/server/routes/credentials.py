"""Credential management endpoints (Phases 3, 4, 5).

- POST /credentials/add/browser/start — begin adding credential (elevated)
- POST /credentials/add/browser/complete — finish adding credential (elevated)
- DELETE /credentials/{id} — remove credential (elevated, last-key guard)
- GET /credentials — list own credentials
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Any

from fastapi import APIRouter, HTTPException, Request, status
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field

from ..fido2.browser_adapter import (
    challenge_to_browser_registration_options,
    browser_registration_to_fido2,
)
from ..utils.time import effective_expiry_check_time

logger = logging.getLogger("venya.server")
router = APIRouter()


# --- Request/Response models ---


class CredentialAddStartRequest(BaseModel):
    label: str = Field(..., description="Credential label (e.g. 'Backup key')")


class CredentialAddStartResponse(BaseModel):
    challenge_id: str
    options: dict[str, Any]


class CredentialAddCompleteRequest(BaseModel):
    challenge_id: str = Field(..., description="Challenge ID from start response")
    response: dict[str, Any] = Field(..., description="WebAuthn attestation response")
    label: str = Field(..., description="Credential label")


class CredentialRemoveResponse(BaseModel):
    removed: bool
    credential_id: int


class CredentialInfo(BaseModel):
    id: int
    label: str | None
    created_at: str
    last_used_at: str | None


class CredentialListResponse(BaseModel):
    credentials: list[CredentialInfo]


# --- Helpers ---


def _get_db(request: Request):
    """Get a database session from app state."""
    backend = getattr(request.app.state, "backend", None)
    if backend is None:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Backend not initialized",
        )
    return backend.get_session()


def _get_current_user_id(request: Request) -> str:
    """Extract the current user ID from the request."""
    user_info = getattr(request.state, "auth_user", None)
    if user_info is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Not authenticated",
        )
    if isinstance(user_info, dict):
        return user_info["user_id"]
    return user_info


def _get_elevation_token(request: Request) -> str | None:
    """Extract elevation token from headers."""
    return request.headers.get("X-Elevation-Token")


def _verify_elevation(request: Request, db) -> bool:
    """Verify elevation token is valid.

    Returns True if elevation is valid, raises HTTPException otherwise.
    """
    token = _get_elevation_token(request)
    if not token:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Elevation token required. Touch your authenticator to proceed.",
        )

    from vault.iam.models import ElevationToken

    token_hash = __import__("hashlib").sha256(token.encode()).hexdigest()
    server_config = getattr(request.app.state, "config", None)
    tolerance = (
        server_config.clock_skew.token_tolerance_seconds
        if server_config and hasattr(server_config, "clock_skew")
        else 60
    )
    now_minus_tolerance = effective_expiry_check_time(tolerance)
    elevation = (
        db.query(ElevationToken)
        .filter(
            ElevationToken.token_hash == token_hash,
            ElevationToken.used == False,  # noqa: E712
            ElevationToken.expires_at > now_minus_tolerance,
        )
        .first()
    )

    if elevation is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired elevation token",
        )

    return True


# --- Endpoints ---


@router.post(
    "/credentials/add/browser/start",
    response_model=CredentialAddStartResponse,
    status_code=status.HTTP_200_OK,
)
async def credentials_add_start(
    req: CredentialAddStartRequest,
    request: Request,
) -> CredentialAddStartResponse:
    """Begin adding a new credential (requires active session + elevation).

    Phase 3, Step 2: Verify elevation, start WebAuthn registration.
    """
    db = _get_db(request)
    try:
        user_id = _get_current_user_id(request)
        _verify_elevation(request, db)

        fido2_manager = getattr(request.app.state, "fido2_manager", None)
        if fido2_manager is None:
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="FIDO2 manager not initialized",
            )

        # Get existing credential IDs to exclude
        from vault.iam.models import WebAuthnCredential

        existing = (
            db.query(WebAuthnCredential.credential_id)
            .filter(
                WebAuthnCredential.user_id == user_id,
                WebAuthnCredential.is_active == True,  # noqa: E712
            )
            .all()
        )
        existing_ids = [c[0] for c in existing]

        challenge_id, options = fido2_manager.start_registration(
            user_id=user_id,
            username=user_id,
            existing_credential_ids=existing_ids,
        )

        browser_options = challenge_to_browser_registration_options(
            challenge_id, options
        )

        return CredentialAddStartResponse(
            challenge_id=challenge_id,
            options=browser_options,
        )
    except HTTPException:
        raise
    except Exception as e:
        logger.error("Credential add start failed: %s", e)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Credential add failed",
        )
    finally:
        db.close()


@router.post(
    "/credentials/add/browser/complete",
    status_code=status.HTTP_200_OK,
)
async def credentials_add_complete(
    req: CredentialAddCompleteRequest,
    request: Request,
) -> dict[str, str]:
    """Complete adding a new credential (requires active session + elevation).

    Phase 3, Step 3: Verify elevation, complete WebAuthn registration, store credential.
    """
    db = _get_db(request)
    try:
        user_id = _get_current_user_id(request)
        _verify_elevation(request, db)

        fido2_manager = getattr(request.app.state, "fido2_manager", None)
        if fido2_manager is None:
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="FIDO2 manager not initialized",
            )

        # Complete WebAuthn registration
        try:
            fido2_response = browser_registration_to_fido2(req.response)
            cred = fido2_manager.finish_registration(
                req.challenge_id,
                fido2_response,
            )
        except ValueError as e:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=str(e),
            ) from e

        # Store WebAuthn credential
        from vault.iam.models import WebAuthnCredential

        webauthn_cred = WebAuthnCredential(
            user_id=user_id,
            credential_id=cred.credential_id,
            public_key=cred.public_key,
            sign_count=cred.sign_count,
            label=req.label,
            is_active=True,
        )
        db.add(webauthn_cred)
        db.commit()

        logger.info(
            "User %s added credential '%s'",
            user_id, req.label,
        )

        return {"status": "ok", "credential_label": req.label}
    except HTTPException:
        raise
    except Exception as e:
        try:
            db.rollback()
        except Exception:
            pass
        logger.error("Credential add complete failed: %s", e)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Credential add failed",
        ) from e
    finally:
        db.close()


@router.delete(
    "/credentials/{credential_id}",
    response_model=CredentialRemoveResponse,
    status_code=status.HTTP_200_OK,
)
async def credentials_remove(
    credential_id: int,
    request: Request,
) -> CredentialRemoveResponse:
    """Remove a credential (requires active session + elevation).

    Phase 4: Verifies elevation, checks credential belongs to user,
    prevents lockout by rejecting if this is the last active credential.
    """
    db = _get_db(request)
    try:
        user_id = _get_current_user_id(request)
        _verify_elevation(request, db)

        from vault.iam.models import WebAuthnCredential

        # Find credential
        cred = (
            db.query(WebAuthnCredential)
            .filter(
                WebAuthnCredential.id == credential_id,
                WebAuthnCredential.user_id == user_id,
            )
            .first()
        )

        if cred is None:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Credential not found",
            )

        # Guard: reject if this is the last active credential
        active_count = (
            db.query(WebAuthnCredential)
            .filter(
                WebAuthnCredential.user_id == user_id,
                WebAuthnCredential.is_active == True,  # noqa: E712
            )
            .count()
        )

        if active_count <= 1:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Cannot remove the last active credential",
            )

        # Soft-delete
        cred.is_active = False
        db.commit()

        logger.info("User %s removed credential ID %d", user_id, credential_id)

        return CredentialRemoveResponse(removed=True, credential_id=credential_id)
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
    "/credentials",
    response_model=CredentialListResponse,
    status_code=status.HTTP_200_OK,
)
async def credentials_list(
    request: Request,
) -> CredentialListResponse:
    """List own credentials (requires active session).

    Phase 5: Returns list of active credentials for the current user.
    """
    db = _get_db(request)
    try:
        user_id = _get_current_user_id(request)

        from vault.iam.models import WebAuthnCredential

        credentials = (
            db.query(WebAuthnCredential)
            .filter(
                WebAuthnCredential.user_id == user_id,
                WebAuthnCredential.is_active == True,  # noqa: E712
            )
            .order_by(WebAuthnCredential.created_at.desc())
            .all()
        )

        result = [
            CredentialInfo(
                id=c.id,
                label=c.label,
                created_at=c.created_at.isoformat(),
                last_used_at=c.last_used_at.isoformat() if c.last_used_at else None,
            )
            for c in credentials
        ]

        return CredentialListResponse(credentials=result)
    finally:
        db.close()
