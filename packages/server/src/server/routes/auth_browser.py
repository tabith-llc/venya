# Copyright (c) 2026 Tabith LLC.
# Use of this source code is governed by the Business Source License 1.1
# included in the LICENSE file at the root of this repository. As of the
# Change Date listed there, the work is available under MPL 2.0.
# SPDX-License-Identifier: BUSL-1.1

"""Browser WebAuthn authentication endpoints.

Router MOUNTED (app.py: app.include_router(auth_browser.router,
prefix="/api/v1")). The browser login entry points
(/auth/login/browser/challenge and /assert) are SessionMiddleware
PUBLIC_PATHS; /auth/refresh/browser is ALSO public by design (#341 —
self-gated handler); every other route in this module —
/auth/logout/browser,
/auth/elevate/browser/challenge, /auth/elevate/browser/assert,
/auth/me — is LIVE and gated by SessionMiddleware, satisfied by the
HttpOnly session cookie or a Bearer token.

The CLI/API elevation endpoints moved to auth_elevation.py (bearer
auth); the browser elevation ceremony stays here.

Parallel auth endpoints that use Fido2Manager but serialize for browser
consumption via the browser adapter. Tokens are stored in HttpOnly cookies.
"""

import logging
from datetime import UTC, datetime, timedelta
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from .. import metrics
from ..audit_lifecycle import (
    ELEVATION_GRANTED,
    SESSION_ENDED,
    SESSION_STARTED,
    audit_lifecycle,
    record_login_failure,
    record_session_end_failure,
)
from ..dependencies import get_db
from ..fido2.browser_adapter import (
    browser_assertion_to_fido2,
    challenge_to_browser_options,
)
from ..fido2.manager import WebAuthnError
from .auth_elevation import _claim_elevation_challenge, _store_elevation_challenge

logger = logging.getLogger("venya.server")

router = APIRouter()

COOKIE_NAME = "venya_access_token"
# Cookie life is the OPERATOR-CONFIGURED session timeout (ticket
# browser-session-hardcoded-300s-cookie #341): callers pass
# config.session.session_timeout (seconds) — no hardcoded constant here.


# --- Request/Response models ---


class BrowserChallengeRequest(BaseModel):
    model_config = {"extra": "forbid"}  # #357 sweep: silent-drop dies here (repo-wide extra=forbid ruling)

    user_id: str | None = Field(
        None,
        description="Optional user ID to target specific credentials",
    )


class BrowserChallengeResponse(BaseModel):
    challenge_id: str
    options: dict[str, Any]


class BrowserAssertionRequest(BaseModel):
    model_config = {"extra": "forbid"}  # #357 sweep: silent-drop dies here (repo-wide extra=forbid ruling)

    challenge_id: str
    response: dict[str, Any]


class BrowserRefreshRequest(BaseModel):
    model_config = {"extra": "forbid"}  # #357 sweep: silent-drop dies here (repo-wide extra=forbid ruling)


class BrowserLogoutRequest(BaseModel):
    model_config = {"extra": "forbid"}  # #357 sweep: silent-drop dies here (repo-wide extra=forbid ruling)


class BrowserElevateRequest(BaseModel):
    model_config = {"extra": "forbid"}  # #357 sweep: silent-drop dies here (repo-wide extra=forbid ruling)


class BrowserElevateResponse(BaseModel):
    challenge_id: str
    options: dict[str, Any]


class AuthMeResponse(BaseModel):
    user_id: str
    display_name: str | None
    status: str
    roles: list[str]


class BrowserElevateCompleteRequest(BaseModel):
    model_config = {"extra": "forbid"}  # #357 sweep: silent-drop dies here (repo-wide extra=forbid ruling)

    challenge_id: str
    response: dict[str, Any]


# --- Helpers ---


def _set_session_cookie(response: Response, access_token: str, max_age: int) -> None:
    """Set the session access token cookie.

    Args:
        response: FastAPI Response object.
        access_token: The access token string.
        max_age: Cookie lifetime in seconds — the configured session_timeout
            (same units; #341).
    """
    response.set_cookie(
        key=COOKIE_NAME,
        value=access_token,
        httponly=True,
        secure=True,
        samesite="lax",
        max_age=max_age,
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
        return None

    db = backend.get_session()
    try:
        from core.iam.models import Session as SessionModel
        from core.iam.role_manager import RoleManager
        from core.iam.session_manager import SessionConfig, SessionManager

        sc = request.app.state.config.session
        session_config = SessionConfig(
            session_timeout=timedelta(seconds=sc.session_timeout),
            access_token_ttl=timedelta(seconds=sc.access_token_ttl),
            max_session_duration=timedelta(seconds=sc.max_session_duration),
        )
        manager = SessionManager(db, session_config)

        session = db.query(SessionModel).filter(SessionModel.access_token == token).first()
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
    fido2_manager = getattr(request.app.state, "fido2_manager", None)
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
    fido2_manager = getattr(request.app.state, "fido2_manager", None)
    if fido2_manager is None:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="FIDO2 manager not initialized",
        )

    try:
        fido2_response = browser_assertion_to_fido2(req.response)
        result = fido2_manager.finish_authentication(
            req.challenge_id,
            fido2_response,
        )
    except WebAuthnError as e:
        metrics.AUTH_LOGIN_TOTAL.labels(mode="browser", result="failure").inc()
        record_login_failure(request, "browser", "assertion")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=str(e),
        ) from e
    except ValueError:
        metrics.AUTH_LOGIN_TOTAL.labels(mode="browser", result="failure").inc()
        logger.exception("Browser login verification failed (internal)")
        record_login_failure(request, "browser", "internal")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Login verification failed",
        ) from None

    backend = getattr(request.app.state, "backend", None)
    if backend is None:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Backend not initialized",
        )

    db = backend.get_session()
    try:
        from core.iam.role_manager import RoleManager
        from core.iam.session_manager import SessionConfig, SessionManager, UserNotActiveError

        sc = request.app.state.config.session
        session_config = SessionConfig(
            session_timeout=timedelta(seconds=sc.session_timeout),
            access_token_ttl=timedelta(seconds=sc.access_token_ttl),
            max_session_duration=timedelta(seconds=sc.max_session_duration),
        )
        sm = SessionManager(db, session_config)
        rm = RoleManager(db)

        user_roles = rm.get_user_roles(result["user_id"])
        role_ids = [str(m.role_id) for m in user_roles]

        session, access_token = sm.create_session(
            user_id=result["user_id"],
            roles=role_ids,
        )
        audit_lifecycle(
            db,
            SESSION_STARTED,
            result["user_id"],
            {"mode": "browser", "session_jti": getattr(session, "access_token_jti", None)},
        )
        db.commit()
        metrics.AUTH_LOGIN_TOTAL.labels(mode="browser", result="success").inc()

        response = JSONResponse(content={"status": "ok"})
        _set_session_cookie(response, access_token.token, sc.session_timeout)
        return response
    except UserNotActiveError:
        # Status gate refused (ticket sec-unauth-webauthn-registration-takeover).
        # Uniform 401 — account state not disclosed; true reason logged only.
        metrics.AUTH_LOGIN_TOTAL.labels(mode="browser", result="failure").inc()
        logger.warning("Browser login refused for user_id=%s: session gate (not active)", result["user_id"])
        db.rollback()
        record_login_failure(request, "browser", "status_gate")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Login verification failed",
        ) from None
    except Exception:
        metrics.AUTH_LOGIN_TOTAL.labels(mode="browser", result="failure").inc()
        import traceback

        logger.error("Login failed:\n%s", traceback.format_exc())
        db.rollback()
        record_login_failure(request, "browser", "internal")
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
    db: Session = Depends(get_db),
) -> Response:
    """Refresh an expiring session cookie.

    #526 (browser-refresh-unreachable-for-idle-expired-session): this handler
    used to ride ``get_current_session``, whose IDLE check 401'd exactly the
    sessions this endpoint exists for. It now self-gates with the bearer
    tier's ruled semantics — ``check_refresh_window`` (HARD CAP only, Option A
    ruling 2026-09-20) — so an idle-expired cookie inside
    ``created_at + max_session_duration`` revives with a rotated token on the
    SAME row (no new session minted), while past the cap the refresh dies and
    re-auth (FIDO2) is required. The shared dependency is deliberately NOT
    loosened: other callers (present and future) keep the strict idle check.
    """
    from core.iam.models import Session as SessionModel
    from core.iam.session_manager import SessionConfig, SessionManager, UserNotActiveError

    current_token = request.cookies.get(COOKIE_NAME, "")
    if not current_token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired session",
        )

    session_model = db.query(SessionModel).filter(SessionModel.access_token == current_token).first()
    if session_model is None:
        metrics.AUTH_REFRESH_TOTAL.labels(result="invalid").inc()
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired session",
        )

    sc = request.app.state.config.session
    session_config = SessionConfig(
        session_timeout=timedelta(seconds=sc.session_timeout),
        access_token_ttl=timedelta(seconds=sc.access_token_ttl),
        max_session_duration=timedelta(seconds=sc.max_session_duration),
    )
    manager = SessionManager(db, session_config)

    # Hard cap only — the bearer twin's gate. Idle expiry must NOT reject
    # here (#526: it is the whole reason this endpoint exists).
    if not manager.check_refresh_window(session_model):
        metrics.AUTH_REFRESH_TOTAL.labels(result="expired").inc()
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired session",
        )
    try:
        new_token = manager.refresh_token(current_token)
    except UserNotActiveError:
        # #524 refresh status gate, cookie plane: the bearer twin's helper
        # refuses a disabled / pending / missing user before minting or
        # extending. Uniform 401 — the handler's existing expired shape, no
        # account-state disclosure; denial-side audit row for the operator.
        metrics.AUTH_REFRESH_TOTAL.labels(result="inactive").inc()
        record_login_failure(request, "browser", "refresh_status_gate")
        logger.warning("Browser refresh refused: session user is not active (session_id=%s)", session_model.id)
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired session",
        ) from None
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
    _set_session_cookie(response, new_token.token, sc.session_timeout)
    return response


def _cookie_cleared_response() -> Response:
    """200 + cleared cookie — the logout-completed shape."""
    response = Response(
        content='{"status": "ok"}',
        media_type="application/json",
    )
    response.delete_cookie(key=COOKIE_NAME, path="/")
    return response


def _logout_when_session_unresolved(request: Request) -> Response:
    """#523 (browser-logout-skips-revoke-when-idle-expired): the logout path
    for a cookie that ``_get_session_from_cookie`` refused.

    A refused cookie is NOT a dead row: ``check_refresh_window`` deliberately
    keeps an IDLE-EXPIRED session refreshable until the hard cap, so a logout
    that only clears the cookie leaves a credential the next person at a
    shared browser can re-mint. Resolve the token with the same lookup the
    rest of this module uses — ``SessionModel.access_token`` — with NO expiry
    gate, and revoke the row if it exists.

    Why the direct lookup is safe when the row may already be gone: it is a
    ``.first()`` — a garbage/unknown token, or a row ``cleanup_expired``
    deleted first, simply returns None; there is nothing to revoke and the
    logout completes clean (200, cookie cleared, no exception, no audit row).
    A found row is revoked fail-closed like the normal path: a revoke failure
    lands the revoked=False row and refuses to claim logout (the cookie
    stays as the retry handle — ruling 2026-10-01).
    """
    from core.iam.models import Session as SessionModel
    from core.iam.session_manager import SessionConfig, SessionManager

    from server.dependencies import get_backend

    token = request.cookies.get(COOKIE_NAME)
    if not token:
        # No cookie at all — nothing presented, nothing to revoke.
        return _cookie_cleared_response()

    backend = get_backend(request)
    db = backend.get_session()
    actor_user_id = None
    session_jti = None
    revoked_ok = True
    try:
        row = db.query(SessionModel).filter(SessionModel.access_token == token).first()
        if row is None:
            return _cookie_cleared_response()

        session_id = row.id
        session_jti = getattr(row, "access_token_jti", None)
        actor_user_id = row.user_id

        sc = request.app.state.config.session
        session_config = SessionConfig(
            session_timeout=timedelta(seconds=sc.session_timeout),
            access_token_ttl=timedelta(seconds=sc.access_token_ttl),
            max_session_duration=timedelta(seconds=sc.max_session_duration),
        )
        manager = SessionManager(db, session_config)

        manager.revoke_session(session_id)
        # The session_expired flag distinguishes this path for operators
        # (#524 AC4): the cookie was cleared on an EXPIRED row the normal
        # validator refused, not on a live session.
        audit_lifecycle(
            db,
            SESSION_ENDED,
            actor_user_id,
            {"mode": "browser", "session_jti": session_jti, "revoked": True, "session_expired": True},
        )
        db.commit()
    except Exception:
        db.rollback()
        logger.exception(
            "Browser logout session revocation failed on the expired-row path (jti=%s)",
            session_jti,
        )
        record_session_end_failure(request, db, actor_user_id, session_jti)
        revoked_ok = False
    finally:
        db.close()

    if not revoked_ok:
        return JSONResponse(
            status_code=503,
            content={
                "status": "error",
                "revoked": False,
                "detail": "session revocation failed; retry logout",
            },
            media_type="application/json",
        )

    return _cookie_cleared_response()


@router.post(
    "/auth/logout/browser",
    status_code=status.HTTP_200_OK,
)
async def browser_logout(
    request: Request,
) -> Response:
    """Clear session cookie and invalidate the session.

    Removes the HttpOnly cookie and deletes the session from the database.
    A cookie whose row the validator refuses (idle-expired inside the hard
    cap — still revivable, #523) is resolved directly and revoked too, so
    "logged out" means the row is gone on every presented-cookie path.
    """
    result = _get_session_from_cookie(request)
    if result is None:
        return _logout_when_session_unresolved(request)

    db, session, user_info = result
    actor_user_id = user_info.get("user_id") if isinstance(user_info, dict) else user_info
    session_jti = getattr(session, "access_token_jti", None)
    revoked_ok = True
    try:
        from core.iam.session_manager import SessionConfig, SessionManager

        sc = request.app.state.config.session
        session_config = SessionConfig(
            session_timeout=timedelta(seconds=sc.session_timeout),
            access_token_ttl=timedelta(seconds=sc.access_token_ttl),
            max_session_duration=timedelta(seconds=sc.max_session_duration),
        )
        manager = SessionManager(db, session_config)

        manager.revoke_session(session.id)
        audit_lifecycle(
            db,
            SESSION_ENDED,
            actor_user_id,
            {"mode": "browser", "session_jti": session_jti, "revoked": True},
        )
        db.commit()
    except Exception:
        db.rollback()
        # Fail-closed (logout-swallows-revoke-failure, ruling 2026-10-01):
        # the revoke failure is loud, the revoked=False row lands, and the
        # response refuses to claim logout.
        logger.exception("Browser logout session revocation failed (jti=%s)", session_jti)
        record_session_end_failure(request, db, actor_user_id, session_jti)
        revoked_ok = False
    finally:
        db.close()

    if not revoked_ok:
        return JSONResponse(
            status_code=503,
            content={
                "status": "error",
                "revoked": False,
                "detail": "session revocation failed; retry logout",
            },
            media_type="application/json",
        )

    return _cookie_cleared_response()


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
    credentials = db.query(WebAuthnCredential).filter(WebAuthnCredential.user_id == session.user_id).all()

    if not credentials:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="No WebAuthn credentials found for this user",
        )

    challenge_id, options = fido2_manager.start_authentication(
        user_id=session.user_id,
    )

    browser_options = challenge_to_browser_options(challenge_id, options)

    # Store the binding in the DB, not app.state (#528, CLI twin's
    # mechanism): any worker claims the same row, a restart does not vaporise
    # a live ceremony, and one consume is atomic. The fido2 manager already
    # stores its own challenge_id -> options mapping; this row is the auth
    # binding (who/what session started it).
    _store_elevation_challenge(db, challenge_id, session.user_id, session.id)

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

        challenge_id, browser_options = _create_elevation_challenge(db, session, fido2_manager, request)

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

        # Verify the challenge was issued for this session. #528 DB-backed
        # claim (was the per-process dict pop): EVERY assert path — success,
        # WebAuthn error, session mismatch, or auditor denial — consumes the
        # row, so a denied or abandoned ceremony never re-arms the challenge
        # (pop-up-front's meaning, #345).
        _claim_elevation_challenge(
            db,
            req.challenge_id,
            session.user_id,
            session.id,
            "/api/v1/auth/elevate/browser/assert",
        )

        # Verify the assertion
        fido2_response = browser_assertion_to_fido2(req.response)

        try:
            fido2_manager.finish_authentication(
                req.challenge_id,
                fido2_response,
            )
        except WebAuthnError as e:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail=str(e),
            ) from e
        except ValueError:
            logger.exception("Elevation assertion verification failed (internal)")
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Elevation verification failed",
            ) from None

        # Auditor-role rework (ruling 1c-ii, blanket issuance-deny): mirror of
        # auth_elevation.elevate_assert — refuse to ISSUE an elevation token
        # to auditor-only callers (last gate before the token exists; the
        # authoritative value-deny is the secrets_get unmask chokepoint).
        # Blanket by ruling: this same issuance gates self-service
        # credential-add (union 1b: any non-auditor membership passes).
        from core.iam.role_manager import RoleManager

        from ..dependencies import auditor_only_permissions

        if auditor_only_permissions(RoleManager(db).get_user_permissions(session.user_id)):
            # Denials are audit-logged (owner ruling 2026-09-30). COMMIT
            # BEFORE the raise; this route's HTTPException path skips
            # rollback (finally only closes), and a committed row survives
            # either way. Value-free: no token material exists yet at this
            # gate. Fail-closed: audit-write failure never upgrades the
            # denial (logged loudly, still 403).
            from core.iam.models import AuditEvent

            try:
                db.add(
                    AuditEvent(
                        event_type="auditor_elevation_denied",
                        user_id=session.user_id,
                        fields={
                            "outcome": "denied",
                            "reason": "auditor-only role",
                            "user_id": session.user_id,
                            "endpoint": "/api/v1/auth/elevate/browser/assert",
                        },
                        timestamp=datetime.now(UTC),
                    )
                )
                db.commit()
            except Exception:
                logger.exception("Audit write failed on auditor elevation deny (still denying)")
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="insufficient role: auditor cannot elevate",
            )

        # Create elevation token
        import secrets as secrets_module

        elevation_token = secrets_module.token_urlsafe(32)
        token_hash = _hash_elevation_token(elevation_token)
        expires_at = datetime.now(UTC) + timedelta(seconds=ELEVATION_TOKEN_TTL_SECONDS)

        from core.iam.models import ElevationToken

        elevation_record = ElevationToken(
            token_hash=token_hash,
            user_id=session.user_id,
            # #527: bind to the session that earned it (cookie plane) — the
            # row's life is the session's life from revoke_session onward.
            session_id=session.id,
            expires_at=expires_at,
        )
        db.add(elevation_record)
        # #301 F2 (Q2: emits on every grant): value-free — mode + endpoint
        # only. Rides the issuance commit (same txn).
        audit_lifecycle(
            db,
            ELEVATION_GRANTED,
            session.user_id,
            {"mode": "browser", "endpoint": "/api/v1/auth/elevate/browser/assert"},
        )
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
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired session",
        )

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
