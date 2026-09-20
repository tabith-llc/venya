# Copyright (c) 2026 Tabith LLC.
# Use of this source code is governed by the Business Source License 1.1
# included in the LICENSE file at the root of this repository. As of the
# Change Date listed there, the work is available under MPL 2.0.
# SPDX-License-Identifier: BUSL-1.1

"""WebAuthn login endpoints.

The legacy public registration endpoints (/auth/registration/start|complete)
were REMOVED (ticket sec-unauth-webauthn-registration-takeover): they bound an
active credential to a client-supplied user_id with no authorization — an
account-takeover chain. Credential issuance goes exclusively through the
token-bound flows: routes/enroll.py (users), routes/init.py (bootstrap admin),
routes/credentials.py (authenticated add).
"""

import logging
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from .. import metrics
from ..dependencies import get_db
from ..fido2.manager import WebAuthnError

logger = logging.getLogger("venya.server")

router = APIRouter()


# --- Request/Response models ---


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
    except WebAuthnError as e:
        metrics.AUTH_LOGIN_TOTAL.labels(mode="webauthn", result="failure").inc()
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=str(e),
        ) from e
    except ValueError:
        metrics.AUTH_LOGIN_TOTAL.labels(mode="webauthn", result="failure").inc()
        logger.exception("Login verification failed (internal)")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Login verification failed",
        ) from None

    # Create session and issue token
    from datetime import timedelta

    from core.iam.role_manager import RoleManager
    from core.iam.session_manager import SessionConfig as CoreSessionConfig
    from core.iam.session_manager import SessionManager, UserNotActiveError

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

    try:
        _session, access_token = sm.create_session(
            user_id=result["user_id"],
            roles=[str(rid) for rid in role_ids],
        )
    except UserNotActiveError:
        # Status gate refused (ticket sec-unauth-webauthn-registration-takeover).
        # Uniform 401 — account state is not disclosed to the caller; the true
        # reason is logged server-side only.
        metrics.AUTH_LOGIN_TOTAL.labels(mode="webauthn", result="failure").inc()
        logger.warning("Login refused for user_id=%s: session gate (user missing or not active)", result["user_id"])
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Login verification failed",
        ) from None
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

    Gate: HARD CAP only (mcp-refresh-path-unreachable Option A, user ruling
    2026-09-20) — idle-expired sessions are revived within
    max_session_duration; past the hard cap this 401s and re-auth (FIDO2) is
    required. The distinction: API calls still 401 at idle expiry (middleware
    check_expiry unchanged); that 401 is what makes this route reachable.
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

    # Check the refresh window (hard cap only — idle-expired revives; Option A)
    if not manager.check_refresh_window(session):
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
