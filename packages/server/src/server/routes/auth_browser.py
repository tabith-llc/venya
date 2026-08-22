"""Browser WebAuthn authentication endpoints.

DISABLED — browser auth unmounted as of 2026-08-18.
Code retained for future web UI re-introduction.
Elevation endpoints moved to auth_elevation.py (bearer auth).

Parallel auth endpoints that use Fido2Manager but serialize for browser
consumption via the browser adapter. Tokens are stored in HttpOnly cookies.
"""


import logging
from datetime import datetime, timedelta, timezone
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field

from ..fido2.browser_adapter import (
    challenge_to_browser_options,
    browser_assertion_to_fido2,
)
from core.utils.sensitive_log import token as sensitive_token
from .. import metrics
from ..dependencies import get_current_session, get_db

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


class BrowserElevateRequest(BaseModel):
    pass


class BrowserElevateResponse(BaseModel):
    challenge_id: str
    options: dict[str, Any]


class AuthMeResponse(BaseModel):
    user_id: str
    display_name: str | None
    status: str
    roles: list[str]


class BrowserElevateCompleteRequest(BaseModel):
    challenge_id: str
    response: dict[str, Any]


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
        samesite="lax",
        max_age=COOKIE_MAX_AGE,
        path="/",
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
        logger.info("GET_SESSION DEBUG: no token in cookie")
        return None

    db = backend.get_session()
    try:
        from core.iam.models import Session as SessionModel
        from core.iam.role_manager import RoleManager
        from core.iam.session_manager import SessionConfig, SessionManager

        session_config = SessionConfig(
            session_timeout=timedelta(minutes=15),
            access_token_ttl=timedelta(minutes=5),
            max_session_duration=timedelta(hours=4),
        )
        manager = SessionManager(db, session_config)

        session = (
            db.query(SessionModel)
            .filter(SessionModel.access_token == token)
            .first()
        )
        logger.info(
            "GET_SESSION DEBUG: token=%s, session=%s",
            sensitive_token(token, "ACCESS") if token else "None",
            session.id if session else "None",
        )

        if session is None:
            logger.info("GET_SESSION DEBUG: session not found in DB")
            return None

        if not manager.check_expiry(session):
            logger.info("GET_SESSION DEBUG: session expired, expires_at=%s", session.expires_at)
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
        metrics.AUTH_LOGIN_TOTAL.labels(mode="browser", result="failure").inc()
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
        from core.iam.models import Session as SessionModel
        from core.iam.role_manager import RoleManager
        from core.iam.session_manager import SessionConfig, SessionManager

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
        metrics.AUTH_LOGIN_TOTAL.labels(mode="browser", result="success").inc()

        response = JSONResponse(content={"status": "ok"})
        _set_session_cookie(response, access_token.token)
        return response
    except Exception:
        metrics.AUTH_LOGIN_TOTAL.labels(mode="browser", result="failure").inc()
        import traceback
        logger.error("Login failed:\n%s", traceback.format_exc())
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
    session=Depends(get_current_session),
) -> Response:
    """Refresh an expiring session cookie.

    Validates the existing session cookie and issues a new
    access token cookie with a fresh expiry.
    """
    logger.info("REFRESH DEBUG: cookies=%s", dict(request.cookies))  # noqa: TRY003 — dict repr may contain token, caught by regex fallback
    if session is None:
        logger.info("REFRESH DEBUG: session not found")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired session",
        )

    db, session_model = session

    from core.iam.session_manager import SessionConfig, SessionManager

    session_config = SessionConfig(
        session_timeout=timedelta(minutes=15),
        access_token_ttl=timedelta(minutes=5),
        max_session_duration=timedelta(hours=4),
    )
    manager = SessionManager(db, session_config)

    current_token = request.cookies.get(COOKIE_NAME, "")
    new_token = manager.refresh_token(current_token)
    if new_token is None:
        metrics.AUTH_REFRESH_TOTAL.labels(result="failed").inc()
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token refresh failed",
        )

    db.commit()
    metrics.AUTH_REFRESH_TOTAL.labels(result="success").inc()

    response = Response(
        content='{"status": "ok"}',
        media_type="application/json",
    )
    _set_session_cookie(response, new_token.token)
    return response

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
        from core.iam.session_manager import SessionConfig, SessionManager

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


# --- Elevation endpoints ---

ELEVATION_TOKEN_TTL_SECONDS = 60


def _hash_elevation_token(token: str) -> str:
    """SHA-256 hash an elevation token for secure storage."""
    import hashlib
    return hashlib.sha256(token.encode()).hexdigest()


def _create_elevation_challenge(db, session, fido2_manager, request):
    """Create a WebAuthn elevation challenge tied to the current session.

    Args:
        db: Database session.
        session: The current Session model.
        fido2_manager: The Fido2Manager instance.

    Returns:
        Tuple of (challenge_id, browser_options).
    """
    from core.iam.models import WebAuthnCredential

    # Get user's credentials for the allow list
    credentials = (
        db.query(WebAuthnCredential)
        .filter(WebAuthnCredential.user_id == session.user_id)
        .all()
    )

    if not credentials:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="No WebAuthn credentials found for this user",
        )

    challenge_id, options = fido2_manager.start_authentication(
        user_id=session.user_id,
    )

    browser_options = challenge_to_browser_options(challenge_id, options)

    # Store the session ID with the challenge so we can verify it matches
    # The fido2 manager already stores challenge_id -> options mapping
    # We attach session_id via app state temporarily
    if not hasattr(request.app.state, "_elevation_challenges"):
        request.app.state._elevation_challenges = {}
    request.app.state._elevation_challenges[challenge_id] = {
        "session_id": session.id,
        "user_id": session.user_id,
    }

    return challenge_id, browser_options


@router.post(
    "/auth/elevate/browser/challenge",
    response_model=BrowserElevateResponse,
    status_code=status.HTTP_200_OK,
)
async def browser_elevate_challenge(
    request: Request,
) -> BrowserElevateResponse:
    """Issue a WebAuthn challenge for elevation (sensitive operations).

    Requires an active session cookie. The user must re-authenticate
    with their security key to perform sensitive operations like
    unmasking secret values.
    """
    result = _get_session_from_cookie(request)
    if result is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired session",
        )

    db, session, user_info = result
    try:
        fido2_manager = getattr(request.app.state, "fido2_manager", None)
        if fido2_manager is None:
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="FIDO2 manager not initialized",
            )

        challenge_id, browser_options = _create_elevation_challenge(
            db, session, fido2_manager, request
        )

        return BrowserElevateResponse(
            challenge_id=challenge_id,
            options=browser_options,
        )
    except HTTPException:
        raise
    except Exception as e:
        db.rollback()
        logger.error("Elevation challenge failed: %s", e)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Elevation challenge failed",
        )
    finally:
        db.close()


@router.post(
    "/auth/elevate/browser/assert",
    status_code=status.HTTP_200_OK,
)
async def browser_elevate_assert(
    req: BrowserElevateCompleteRequest,
    request: Request,
) -> dict[str, str]:
    """Verify WebAuthn elevation assertion and return elevation token.

    Verifies the assertion via Fido2Manager, confirms the challenge
    was issued for the current session, and returns a short-lived
    elevation token (60 seconds) for use in sensitive operations.
    """
    result = _get_session_from_cookie(request)
    if result is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired session",
        )

    db, session, user_info = result
    try:
        fido2_manager = getattr(request.app.state, "fido2_manager", None)
        if fido2_manager is None:
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="FIDO2 manager not initialized",
            )

        # Verify the challenge was issued for this session
        elevation_challenges = getattr(
            request.app.state, "_elevation_challenges", {}
        )
        challenge_info = elevation_challenges.get(req.challenge_id)

        if challenge_info is None:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Elevation challenge not found or expired",
            )

        if challenge_info["session_id"] != session.id:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Elevation challenge session mismatch",
            )

        # Verify the assertion
        fido2_response = browser_assertion_to_fido2(req.response)

        try:
            fido2_manager.finish_authentication(
                req.challenge_id, fido2_response,
            )
        except ValueError as e:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail=str(e),
            ) from e

        # Clean up the challenge
        del elevation_challenges[req.challenge_id]

        # Create elevation token
        import secrets as secrets_module

        elevation_token = secrets_module.token_urlsafe(32)
        token_hash = _hash_elevation_token(elevation_token)
        expires_at = datetime.now(timezone.utc) + timedelta(
            seconds=ELEVATION_TOKEN_TTL_SECONDS
        )

        from core.iam.models import ElevationToken

        elevation_record = ElevationToken(
            token_hash=token_hash,
            user_id=session.user_id,
            expires_at=expires_at,
        )
        db.add(elevation_record)
        db.commit()

        logger.info(
            "Elevation token created for user %s",
            session.user_id,
        )

        return {
            "status": "ok",
            "elevation_token": elevation_token,
        }
    except HTTPException:
        raise
    except Exception as e:
        try:
            db.rollback()
        except Exception:  # nosec B110 — rollback best-effort before raising HTTPException
            pass
        logger.error("Elevation assertion failed: %s", e)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Elevation assertion failed",
        ) from e
    finally:
        db.close()


@router.get("/auth/debug/cookie")
async def debug_cookie(request: Request) -> dict:
    """Debug endpoint to check current cookie state."""
    cookie = request.cookies.get(COOKIE_NAME, "NONE")
    return {"cookie": cookie[:30] + "..." if len(cookie) > 30 else cookie}


@router.get(
    "/auth/me",
    response_model=AuthMeResponse,
    status_code=status.HTTP_200_OK,
)
async def auth_me(request: Request) -> AuthMeResponse:
    """Return current authenticated user info.

    Reads the session cookie and returns the current user's
    identity, status, and roles. Used by the dashboard to
    gate admin-only navigation links.
    """
    result = _get_session_from_cookie(request)
    if result is None:
        logger.info("AUTH_ME DEBUG: _get_session_from_cookie returned None")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired session",
        )

    logger.info("AUTH_ME DEBUG: got session, user_id=%s", result[1].user_id if result and len(result) > 1 else "unknown")
    db, session, user_info = result
    try:
        from core.iam.models import User

        user = db.query(User).filter(User.user_id == session.user_id).first()
        if user is None:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="User not found",
            )

        from core.iam.role_manager import RoleManager

        role_manager = RoleManager(db)
        role_members = role_manager.get_user_roles(session.user_id)
        role_names = [member.role.name for member in role_members]

        return AuthMeResponse(
            user_id=session.user_id,
            display_name=user.display_name,
            status=user.status,
            roles=role_names,
        )
    except HTTPException:
        raise
    except Exception as e:
        logger.error("Auth me failed: %s", e)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to retrieve user info",
        )
    finally:
        db.close()
