# Copyright (c) 2026 Tabith LLC.
# Use of this source code is governed by the Business Source License 1.1
# included in the LICENSE file at the root of this repository. As of the
# Change Date listed there, the work is available under MPL 2.0.
# SPDX-License-Identifier: BUSL-1.1

"""Credential management endpoints (Phases 3, 4, 5).

- POST /credentials/add/browser/start — begin adding credential (elevated)
- POST /credentials/add/browser/complete — finish adding credential (elevated)
- DELETE /credentials/{id} — remove credential (elevated, last-key guard)
- GET /credentials — list own credentials
"""

import logging
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from ..dependencies import get_db
from ..fido2.browser_adapter import (
    browser_registration_to_fido2,
    challenge_to_browser_registration_options,
)
from ..fido2.manager import WebAuthnError
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


class CredentialAddCompleteResponse(BaseModel):
    status: str
    credential_label: str


class CredentialInfo(BaseModel):
    id: int
    label: str | None
    created_at: str
    last_used_at: str | None


class CredentialListResponse(BaseModel):
    credentials: list[CredentialInfo]


# --- Helpers ---


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


def _verify_elevation(request: Request, db, user_id: str) -> None:
    """Verify AND CONSUME the caller's elevation token (single-use).

    sec-auth-elevation-authz-hardening #6 (option (a) ruling: burn on every
    verify — 1 assertion = 1 token, matching the issuance design). Atomic
    conditional UPDATE mirrors the proven consume path in routes/secrets.py:
    WHERE token_hash AND user_id == caller AND NOT used AND within expiry ->
    SET used=True; rowcount 0 -> 401. Cross-user tokens and replays die
    here. The burn COMMITS immediately so a later ceremony failure cannot
    resurrect the token (a failed flow needs a fresh touch — deliberate;
    idempotent: a replay of a burned token is a clean 401, never a 500).
    """
    token = _get_elevation_token(request)
    if not token:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Elevation token required. Touch your authenticator to proceed.",
        )

    import hashlib

    from core.iam.models import ElevationToken
    from sqlalchemy import update

    token_hash = hashlib.sha256(token.encode()).hexdigest()
    server_config = getattr(request.app.state, "config", None)
    tolerance = (
        server_config.clock_skew.token_tolerance_seconds
        if server_config and hasattr(server_config, "clock_skew")
        else 60
    )
    now_minus_tolerance = effective_expiry_check_time(tolerance)
    result = db.execute(
        update(ElevationToken)
        .where(
            ElevationToken.token_hash == token_hash,
            ElevationToken.user_id == user_id,
            ElevationToken.used.is_(False),
            ElevationToken.expires_at > now_minus_tolerance,
        )
        .values(used=True)
    )
    db.commit()

    if result.rowcount == 0:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired elevation token",
        )


# --- Endpoints ---


@router.post(
    "/credentials/add/browser/start",
    response_model=CredentialAddStartResponse,
    status_code=status.HTTP_200_OK,
)
async def credentials_add_start(
    req: CredentialAddStartRequest,
    request: Request,
    db: Session = Depends(get_db),
) -> CredentialAddStartResponse:
    """Begin adding a new credential (requires active session + elevation).

    Phase 3, Step 2: Verify elevation, start WebAuthn registration.
    """
    try:
        user_id = _get_current_user_id(request)
        _verify_elevation(request, db, user_id)

        fido2_manager = getattr(request.app.state, "fido2_manager", None)
        if fido2_manager is None:
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="FIDO2 manager not initialized",
            )

        # Get existing credential IDs to exclude
        from core.iam.models import WebAuthnCredential

        existing = (
            db.query(WebAuthnCredential.credential_id)
            .filter(
                WebAuthnCredential.user_id == user_id,
                WebAuthnCredential.is_active.is_(True),
            )
            .all()
        )
        existing_ids = [c[0] for c in existing]

        challenge_id, options = fido2_manager.start_registration(
            user_id=user_id,
            username=user_id,
            existing_credential_ids=existing_ids,
        )

        browser_options = challenge_to_browser_registration_options(challenge_id, options)

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


@router.post(
    "/credentials/add/browser/complete",
    status_code=status.HTTP_200_OK,
)
async def credentials_add_complete(
    req: CredentialAddCompleteRequest,
    request: Request,
    db: Session = Depends(get_db),
) -> CredentialAddCompleteResponse:
    """Complete adding a new credential (requires active session + elevation).

    Phase 3, Step 3: Verify elevation, complete WebAuthn registration, store credential.
    """
    try:
        user_id = _get_current_user_id(request)
        _verify_elevation(request, db, user_id)

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
            # Challenge<->user binding (sec-auth-elevation-authz-hardening #4):
            # add_start bound the challenge to this session's user; refuse a
            # credential minted from another user's challenge (identity split
            # between the in-memory store and the DB row).
            if cred.user_id != user_id:
                raise WebAuthnError("Registration challenge was issued for a different user")
        except WebAuthnError as e:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=str(e),
            ) from e
        except ValueError:
            logger.exception("Credential registration verification failed (internal)")
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Credential registration verification failed",
            ) from None

        # Store WebAuthn credential
        from core.iam.models import WebAuthnCredential

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
            user_id,
            req.label,
        )

        return CredentialAddCompleteResponse(status="ok", credential_label=req.label)
    except HTTPException:
        raise
    except Exception as e:
        logger.error("Credential add complete failed: %s", e)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Credential add failed",
        ) from e


@router.delete(
    "/credentials/{credential_id}",
    response_model=CredentialRemoveResponse,
    status_code=status.HTTP_200_OK,
)
async def credentials_remove(
    credential_id: int,
    request: Request,
    db: Session = Depends(get_db),
) -> CredentialRemoveResponse:
    """Remove a credential (requires active session + elevation).

    Phase 4: Verifies elevation, checks credential belongs to user,
    prevents lockout by rejecting if this is the last active credential.
    """
    try:
        user_id = _get_current_user_id(request)
        _verify_elevation(request, db, user_id)

        from core.iam.models import WebAuthnCredential

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
        # with_for_update() locks all active credentials, preventing concurrent deactivation
        active_credentials = (
            db.query(WebAuthnCredential)
            .filter(
                WebAuthnCredential.user_id == user_id,
                WebAuthnCredential.is_active.is_(True),
            )
            .with_for_update()
            .all()
        )

        if len(active_credentials) <= 1:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Cannot remove the last active credential",
            )

        # Soft-delete (under lock)
        cred_bytes = cred.credential_id  # capture before commit (expire_on_commit refresh)
        cred.is_active = False
        db.commit()

        # Evict from the in-memory auth store so the credential stops working
        # IMMEDIATELY. finish_authentication reads the per-process store (loaded
        # once at startup), not the DB, so a soft-delete alone leaves the removed
        # credential valid until a restart. remove_credential is keyed on raw bytes.
        fido2_manager = getattr(request.app.state, "fido2_manager", None)
        if fido2_manager is not None and cred_bytes is not None:
            fido2_manager.remove_credential(cred_bytes)

        logger.info("User %s removed credential ID %d", user_id, credential_id)

        return CredentialRemoveResponse(removed=True, credential_id=credential_id)
    except HTTPException:
        raise
    except Exception:
        logger.exception("Credential removal failed")
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Credential removal failed",
        )


@router.get(
    "/credentials",
    response_model=CredentialListResponse,
    status_code=status.HTTP_200_OK,
)
async def credentials_list(
    request: Request,
    db: Session = Depends(get_db),
) -> CredentialListResponse:
    """List own credentials (requires active session).

    Phase 5: Returns list of active credentials for the current user.
    """
    user_id = _get_current_user_id(request)

    from core.iam.models import WebAuthnCredential

    credentials = (
        db.query(WebAuthnCredential)
        .filter(
            WebAuthnCredential.user_id == user_id,
            WebAuthnCredential.is_active.is_(True),
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
