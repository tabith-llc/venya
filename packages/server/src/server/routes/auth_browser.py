"""Browser WebAuthn authentication endpoints.

Parallel auth endpoints that use Fido2Manager but serialize for browser
consumption via the browser adapter. Tokens are stored in HttpOnly cookies.
"""

from __future__ import annotations

import logging
from datetime import datetime, timedelta, timezone
from typing import Any

from fastapi import APIRouter, HTTPException, Request, Response, status
from pydantic import BaseModel, Field

from ..fido2.browser_adapter import (
    challenge_to_browser_options,
    browser_assertion_to_fido2,
)

logger = logging.getLogger("venya.server")

router = APIRouter()

COOKIE_NAME = "venya_access_token"
COOKIE_MAX_AGE = 300  # 5 minutes


# --- Request/Response models ---


class BrowserChallengeRequest(BaseModel):
    user_id: str | None = Field(
        None, description="Optional user ID to target specific credentials",
    )


class BrowserChallengeResponse(BaseModel):
    challenge_id: str
    options: dict[str, Any]


class BrowserAssertionRequest(BaseModel):
    challenge_id: str
    response: dict[str, Any]


class BrowserRefreshRequest(BaseModel):
    pass


class BrowserLogoutRequest(BaseModel):
    pass


# --- Helpers ---


def _set_session_cookie(response: Response, access_token: str) -> None:
    """Set the session access token cookie.

    Args:
        response: FastAPI Response object.
        access_token: The access token string.
    """
    response.set_cookie(
        key=COOKIE_NAME,
        value=access_token,
        httponly=True,
        secure=True,
        samesite="strict",
        max_age=COOKIE_MAX_AGE,
    )


def _get_session_from_cookie(
    request: Request,
) -> tuple[Any, Any, Any] | None:
    """Validate the session cookie and return session info.

    Args:
        request: FastAPI request.

    Returns:
        Tuple of (db, session, user_info) or None if invalid.
    """
    from server.dependencies import get_backend

    backend = get_backend(request)
    token = request.cookies.get(COOKIE_NAME)
    if not token:
        return None

    db = backend.get_session()
    try:
        from vault.iam.models import Session as SessionModel
        from vault.iam.role_manager import RoleManager
        from vault.iam.session_manager import SessionConfig, SessionManager

        session_config = SessionConfig(
            session_timeout=timedelta(minutes=15),
            access_token_ttl=timedelta(minutes=5),
            max_session_duration=timedelta(hours=4),
        )
        manager = SessionManager(db, session_config)

        session = (
            db.query(SessionModel)
            .filter(SessionModel.access_token_jti == token)
            .first()
        )

        if session is None:
            return None

        if not manager.check_expiry(session):
            return None

        user = session.user
        rm = RoleManager(db)
        user_roles = rm.get_user_roles(user.user_id)
        user_info = {
            "user_id": user.user_id,
            "session_id": session.id,
            "roles": [str(m.role_id) for m in user_roles],
            "exp": int(session.expires_at.timestamp()),
        }

        return db, session, user_info
    finally:
        db.close()


# --- Endpoints ---


@router.post(
    "/auth/login/browser/challenge",
    response_model=BrowserChallengeResponse,
    status_code=status.HTTP_200_OK,
)
async def browser_login_challenge(
    req: BrowserChallengeRequest,
    request: Request,
) -> BrowserChallengeResponse:
    """Issue a browser-formatted WebAuthn login challenge.

    Returns challenge options for the browser client to present
    to the authenticator via @simplewebauthn/browser.
    """
    fido2_manager = getattr(
        request.app.state, "fido2_manager", None
    )
    if fido2_manager is None:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="FIDO2 manager not initialized",
        )

    challenge_id, options = fido2_manager.start_authentication(
        user_id=req.user_id,
    )

    browser_options = challenge_to_browser_options(challenge_id, options)

    return BrowserChallengeResponse(
        challenge_id=challenge_id,
        options=browser_options,
    )


@router.post(
    "/auth/login/browser/assert",
    status_code=status.HTTP_200_OK,
)
async def browser_login_assert(
    req: BrowserAssertionRequest,
    request: Request,
) -> Response:
    """Verify browser WebAuthn assertion and set session cookie.

    Verifies the assertion via Fido2Manager, creates a session,
    and sets an HttpOnly cookie with the access token.
    """
    fido2_manager = getattr(
        request.app.state, "fido2_manager", None
    )
    if fido2_manager is None:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="FIDO2 manager not initialized",
        )

    try:
        fido2_response = browser_assertion_to_fido2(req.response)
        result = fido2_manager.finish_authentication(
            req.challenge_id, fido2_response,
        )
    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=str(e),
        ) from e

    backend = getattr(request.app.state, "backend", None)
    if backend is None:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Backend not initialized",
        )

    db = backend.get_session()
    try:
        from vault.iam.models import Session as SessionModel
        from vault.iam.role_manager import RoleManager
        from vault.iam.session_manager import SessionConfig, SessionManager

        session_config = SessionConfig(
            session_timeout=timedelta(minutes=15),
            access_token_ttl=timedelta(minutes=5),
            max_session_duration=timedelta(hours=4),
        )
        sm = SessionManager(db, session_config)
        rm = RoleManager(db)

        user_roles = rm.get_user_roles(result["user_id"])
        role_ids = [str(m.role_id) for m in user_roles]

        session, access_token = sm.create_session(
            user_id=result["user_id"],
            roles=role_ids,
        )
        db.commit()

        response = Response(
            content='{"status": "ok"}',
            media_type="application/json",
        )
        _set_session_cookie(response, access_token.token)
        return response
    except Exception:
        db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to create session",
        )
    finally:
        db.close()


@router.post(
    "/auth/refresh/browser",
    status_code=status.HTTP_200_OK,
)
async def browser_refresh(
    request: Request,
) -> Response:
    """Refresh an expiring session cookie.

    Validates the existing session cookie and issues a new
    access token cookie with a fresh expiry.
    """
    result = _get_session_from_cookie(request)
    if result is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired session",
        )

    db, session, user_info = result
    try:
        from vault.iam.session_manager import SessionConfig, SessionManager

        session_config = SessionConfig(
            session_timeout=timedelta(minutes=15),
            access_token_ttl=timedelta(minutes=5),
            max_session_duration=timedelta(hours=4),
        )
        manager = SessionManager(db, session_config)

        # Get current token from cookie
        current_token = request.cookies.get(COOKIE_NAME, "")

        new_token = manager.refresh_token(current_token)
        if new_token is None:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Token refresh failed",
            )

        response = Response(
            content='{"status": "ok"}',
            media_type="application/json",
        )
        _set_session_cookie(response, new_token.token)
        return response
    except HTTPException:
        raise
    except Exception:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Session refresh failed",
        )


@router.post(
    "/auth/logout/browser",
    status_code=status.HTTP_200_OK,
)
async def browser_logout(
    request: Request,
) -> Response:
    """Clear session cookie and invalidate the session.

    Removes the HttpOnly cookie and deletes the session from the database.
    """
    result = _get_session_from_cookie(request)
    if result is None:
        # Still clear the cookie even if session is invalid
        response = Response(
            content='{"status": "ok"}',
            media_type="application/json",
        )
        response.delete_cookie(key=COOKIE_NAME, path="/")
        return response

    db, session, user_info = result
    try:
        from vault.iam.session_manager import SessionConfig, SessionManager

        session_config = SessionConfig(
            session_timeout=timedelta(minutes=15),
            access_token_ttl=timedelta(minutes=5),
            max_session_duration=timedelta(hours=4),
        )
        manager = SessionManager(db, session_config)

        manager.revoke_session(session.id)
        db.commit()
    except Exception:
        db.rollback()
    finally:
        db.close()

    response = Response(
        content='{"status": "ok"}',
        media_type="application/json",
    )
    response.delete_cookie(key=COOKIE_NAME, path="/")
    return response
