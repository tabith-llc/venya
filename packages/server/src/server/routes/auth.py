"""WebAuthn registration and login endpoints."""

import logging
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel, Field

from ..dependencies import get_current_user
from .. import metrics

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

    # Store credential in database
    backend = getattr(request.app.state, "backend", None)
    if backend is not None:
        db = backend.get_session()
        try:
            from vault.iam.models import WebAuthnCredential

            credential = WebAuthnCredential(
                user_id=cred.user_id,
                credential_id=cred.credential_id,
                public_key=cred.public_key,
                sign_count=cred.sign_count,
                is_active=True,
            )
            db.add(credential)
            db.commit()
        except Exception:
            db.rollback()
        finally:
            db.close()

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

    from vault.iam.role_manager import RoleManager
    from vault.iam.session_manager import SessionConfig as VaultSessionConfig
    from vault.iam.session_manager import SessionManager

    backend = getattr(request.app.state, "backend", None)
    if backend is None:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Backend not initialized",
        )

    db = backend.get_session()
    try:
        session_config = VaultSessionConfig(
            session_timeout=timedelta(minutes=15),
            access_token_ttl=timedelta(minutes=5),
            max_session_duration=timedelta(hours=4),
        )

        sm = SessionManager(db, session_config)
        rm = RoleManager(db)

        # Get user roles
        user_roles = rm.get_user_roles(result["user_id"])
        role_ids = [m.role_id for m in user_roles]

        session, access_token = sm.create_session(
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
    finally:
        db.close()


class AuthenticationRefreshResponse(BaseModel):
    access_token: str


@router.post(
    "/auth/refresh",
    response_model=AuthenticationRefreshResponse,
    status_code=status.HTTP_200_OK,
)
async def auth_refresh(
    request: Request,
) -> AuthenticationRefreshResponse:
    """Refresh the current access token.

    Validates the existing session and issues a new access token.
    The session must still be active (not idle-expired, not past max duration).
    """
    from datetime import timedelta

    from vault.iam.models import Session as SessionModel
    from vault.iam.session_manager import SessionConfig as VaultSessionConfig
    from vault.iam.session_manager import SessionManager

    backend = getattr(request.app.state, "backend", None)
    if backend is None:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Backend not initialized",
        )

    # Get the bearer token from the request
    auth_header = request.headers.get("authorization", "")
    if not auth_header.startswith("Bearer "):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing authentication token",
        )
    token = auth_header[7:]

    db = backend.get_session()
    try:
        session_config = VaultSessionConfig(
            session_timeout=timedelta(minutes=15),
            access_token_ttl=timedelta(minutes=5),
            max_session_duration=timedelta(hours=4),
        )
        manager = SessionManager(db, session_config)

        # Find session by access token JTI
        session = (
            db.query(SessionModel)
            .filter(SessionModel.access_token_jti == token)
            .first()
        )

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
    finally:
        db.close()
