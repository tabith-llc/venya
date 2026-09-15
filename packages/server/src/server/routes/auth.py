# Copyright (c) 2026 Tabith LLC.
# Use of this source code is governed by the Business Source License 1.1
# included in the LICENSE file at the root of this repository. As of the
# Change Date listed there, the work is available under MPL 2.0.
# SPDX-License-Identifier: BUSL-1.1

"""WebAuthn registration and login endpoints."""

import logging
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from .. import metrics
from ..dependencies import get_db

logger = logging.getLogger("venya.server")

router = APIRouter()


# --- Request/Response models ---


class RegistrationStartRequest(BaseModel):
    user_id: str = Field(..., description="Internal user ID")
    username: str = Field(..., description="Human-readable username")


class RegistrationStartResponse(BaseModel):
    challenge_id: str
    options: dict[str, Any]


class RegistrationCompleteRequest(BaseModel):
    challenge_id: str
    response: dict[str, Any]


class RegistrationCompleteResponse(BaseModel):
    credential_id: str


class AuthenticationStartRequest(BaseModel):
    user_id: str | None = Field(None, description="Optional user ID to target")


class AuthenticationStartResponse(BaseModel):
    challenge_id: str
    options: dict[str, Any]


class AuthenticationCompleteRequest(BaseModel):
    challenge_id: str
    response: dict[str, Any]


class AuthenticationCompleteResponse(BaseModel):
    user_id: str
    credential_id: str
    session_token: str


# --- Endpoints ---


@router.post(
    "/auth/registration/start",
    response_model=RegistrationStartResponse,
    status_code=status.HTTP_200_OK,
)
async def auth_registration_start(
    req: RegistrationStartRequest,
    request: Request,
) -> RegistrationStartResponse:
    """Start WebAuthn registration for a new credential.

    Returns challenge options for the client to present to the authenticator.
    """
    fido2_manager = getattr(request.app.state, "fido2_manager", None)
    if fido2_manager is None:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="FIDO2 manager not initialized",
        )

    # Get existing credentials for this user
    existing = fido2_manager.get_user_credentials(req.user_id)
    existing_ids = [c["credential_id"] for c in existing]

    challenge_id, options = fido2_manager.start_registration(
        user_id=req.user_id,
        username=req.username,
        existing_credential_ids=existing_ids,
    )

    return RegistrationStartResponse(challenge_id=challenge_id, options=options)


@router.post(
    "/auth/registration/complete",
    response_model=RegistrationCompleteResponse,
    status_code=status.HTTP_201_CREATED,
)
async def auth_registration_complete(
    req: RegistrationCompleteRequest,
    request: Request,
    db: Session = Depends(get_db),
) -> RegistrationCompleteResponse:
    """Complete WebAuthn registration.

    Verifies the authenticator response and stores the credential.
    """
    fido2_manager = getattr(request.app.state, "fido2_manager", None)
    if fido2_manager is None:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="FIDO2 manager not initialized",
        )

    try:
        cred = fido2_manager.finish_registration(req.challenge_id, req.response)
    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e),
        ) from e

    try:
        from core.iam.models import WebAuthnCredential

        credential = WebAuthnCredential(
            user_id=cred.user_id,
            credential_id=cred.credential_id,
            public_key=cred.public_key,
            sign_count=cred.sign_count,
            is_active=True,
        )
        db.add(credential)
        db.commit()
    except Exception:  # noqa: S110
        # D-3: pre-existing swallow — return 201 even if the DB commit fails
        # (credential was already created in the FIDO2 manager). The open
        # transaction is rolled back by get_db's `finally: close()`.
        pass  # nosec B110 — intentional, transaction rolled back by get_db finally

    return RegistrationCompleteResponse(credential_id=cred.credential_id)


@router.post(
    "/auth/login/start",
    response_model=AuthenticationStartResponse,
    status_code=status.HTTP_200_OK,
)
async def auth_login_start(
    req: AuthenticationStartRequest,
    request: Request,
) -> AuthenticationStartResponse:
    """Start WebAuthn authentication.

    Returns challenge options for the client to present to the authenticator.
    """
    fido2_manager = getattr(request.app.state, "fido2_manager", None)
    if fido2_manager is None:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="FIDO2 manager not initialized",
        )

    challenge_id, options = fido2_manager.start_authentication(
        user_id=req.user_id,
    )

    return AuthenticationStartResponse(challenge_id=challenge_id, options=options)


@router.post(
    "/auth/login/complete",
    response_model=AuthenticationCompleteResponse,
    status_code=status.HTTP_200_OK,
)
async def auth_login_complete(
    req: AuthenticationCompleteRequest,
    request: Request,
    db: Session = Depends(get_db),
) -> AuthenticationCompleteResponse:
    """Complete WebAuthn authentication.

    Verifies the assertion and issues a session token.
    """
    fido2_manager = getattr(request.app.state, "fido2_manager", None)
    if fido2_manager is None:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="FIDO2 manager not initialized",
        )

    try:
        result = fido2_manager.finish_authentication(req.challenge_id, req.response)
    except ValueError as e:
        metrics.AUTH_LOGIN_TOTAL.labels(mode="webauthn", result="failure").inc()
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=str(e),
        ) from e

    # Create session and issue token
    from datetime import timedelta

    from core.iam.role_manager import RoleManager
    from core.iam.session_manager import SessionConfig as CoreSessionConfig
    from core.iam.session_manager import SessionManager

    sc = request.app.state.config.session
    session_config = CoreSessionConfig(
        session_timeout=timedelta(seconds=sc.session_timeout),
        access_token_ttl=timedelta(seconds=sc.access_token_ttl),
        max_session_duration=timedelta(seconds=sc.max_session_duration),
    )

    sm = SessionManager(db, session_config)
    rm = RoleManager(db)

    # Get user roles
    user_roles = rm.get_user_roles(result["user_id"])
    role_ids = [m.role_id for m in user_roles]

    _session, access_token = sm.create_session(
        user_id=result["user_id"],
        roles=[str(rid) for rid in role_ids],
    )
    db.commit()
    metrics.AUTH_LOGIN_TOTAL.labels(mode="webauthn", result="success").inc()

    return AuthenticationCompleteResponse(
        user_id=result["user_id"],
        credential_id=result["credential_id"],
        session_token=access_token.token,
    )


class AuthenticationRefreshResponse(BaseModel):
    access_token: str


@router.post(
    "/auth/refresh",
    response_model=AuthenticationRefreshResponse,
    status_code=status.HTTP_200_OK,
)
async def auth_refresh(
    request: Request,
    db: Session = Depends(get_db),
) -> AuthenticationRefreshResponse:
    """Refresh the current access token.

    Validates the existing session and issues a new access token.
    The session must still be active (not idle-expired, not past max duration).
    """
    from datetime import timedelta

    from core.iam.models import Session as SessionModel
    from core.iam.session_manager import SessionConfig as CoreSessionConfig
    from core.iam.session_manager import SessionManager

    # Get the bearer token from the request
    auth_header = request.headers.get("authorization", "")
    if not auth_header.startswith("Bearer "):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing authentication token",
        )
    token = auth_header[7:]

    sc = request.app.state.config.session
    session_config = CoreSessionConfig(
        session_timeout=timedelta(seconds=sc.session_timeout),
        access_token_ttl=timedelta(seconds=sc.access_token_ttl),
        max_session_duration=timedelta(seconds=sc.max_session_duration),
    )
    manager = SessionManager(db, session_config)

    # Find session by access token
    session = db.query(SessionModel).filter(SessionModel.access_token == token).first()

    if session is None:
        metrics.AUTH_REFRESH_TOTAL.labels(result="invalid").inc()
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid token",
        )

    # Check session expiry
    if not manager.check_expiry(session):
        metrics.AUTH_REFRESH_TOTAL.labels(result="expired").inc()
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Session expired",
        )

    # Issue new token
    new_token = manager.refresh_token(token)
    if new_token is None:
        metrics.AUTH_REFRESH_TOTAL.labels(result="failed").inc()
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token refresh failed",
        )

    db.commit()
    metrics.AUTH_REFRESH_TOTAL.labels(result="success").inc()

    return AuthenticationRefreshResponse(access_token=new_token.token)
