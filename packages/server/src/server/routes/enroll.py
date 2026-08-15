"""Browser WebAuthn enrollment endpoints (Phase 2).

Two-step enrollment flow:
1. POST /enroll/browser/start — validate token, issue WebAuthn challenge
2. POST /enroll/browser/complete — verify WebAuthn, store credential, create session
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Any

from fastapi import APIRouter, HTTPException, Request, status
from fastapi.responses import JSONResponse

from ..utils.token_binding import verify_binding_hash
from pydantic import BaseModel, Field

from ..fido2.browser_adapter import (
    challenge_to_browser_registration_options,
    browser_registration_to_fido2,
)

logger = logging.getLogger("venya.server")
router = APIRouter()


# --- Request/Response models ---


class BrowserEnrollStartRequest(BaseModel):
    enrollment_token: str = Field(..., description="Plaintext enrollment token")


class BrowserEnrollStartResponse(BaseModel):
    challenge_id: str
    options: dict[str, Any]


class BrowserEnrollCompleteRequest(BaseModel):
    enrollment_token: str = Field(..., description="Plaintext enrollment token")
    challenge_id: str = Field(..., description="Challenge ID from start response")
    response: dict[str, Any] = Field(..., description="WebAuthn attestation response")
    label: str = Field(..., description="Credential label (e.g. 'Primary key')")


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


def _set_session_cookie(response: JSONResponse, token: str) -> None:
    """Set the venya_access_token cookie."""
    response.set_cookie(
        key="venya_access_token",
        value=token,
        httponly=True,
        secure=True,
        samesite="lax",
        max_age=900,  # 15 minutes
    )


# --- Endpoints ---


@router.post(
    "/enroll/browser/start",
    response_model=BrowserEnrollStartResponse,
    status_code=status.HTTP_200_OK,
)
async def browser_enroll_start(
    req: BrowserEnrollStartRequest,
    request: Request,
) -> BrowserEnrollStartResponse:
    """Validate enrollment token and issue WebAuthn registration challenge.

    Transitions token state from 'created' to 'in_progress'.
    """
    db = _get_db(request)
    try:
        from vault.iam.enrollment_manager import EnrollmentError, EnrollmentManager
        from vault.iam.models import User

        em = EnrollmentManager(db)

        # Validate token and check user status
        token = em.validate_token_for_start(req.enrollment_token)

        # Verify cryptographic binding to user's string ID
        user = db.query(User).filter(User.id == token.user_id).first()
        username = user.display_name or user.user_id if user else str(token.user_id)
        server_config = getattr(request.app.state, "config", None)
        pepper = getattr(server_config, "recovery_code_pepper", "") if server_config else ""
        if not verify_binding_hash(
            entity_id=username,
            plaintext_token=req.enrollment_token,
            server_secret=pepper,
            stored_binding_hash=token.binding_hash,
        ):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Enrollment token binding mismatch — token has been invalidated",
            )

        # Transition state to in_progress
        em.mark_token_in_progress(req.enrollment_token)
        db.commit()

        fido2_manager = getattr(request.app.state, "fido2_manager", None)
        if fido2_manager is None:
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="FIDO2 manager not initialized",
            )

        challenge_id, options = fido2_manager.start_registration(
            user_id=str(token.user_id),
            username=username,
        )

        browser_options = challenge_to_browser_registration_options(
            challenge_id, options
        )

        return BrowserEnrollStartResponse(
            challenge_id=challenge_id,
            options=browser_options,
        )
    except HTTPException:
        raise
    except EnrollmentError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e),
        )
    except Exception as e:
        logger.error("Enrollment start failed: %s", e)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Enrollment failed",
        )
    finally:
        db.close()


@router.post(
    "/enroll/browser/complete",
    status_code=status.HTTP_200_OK,
)
async def browser_enroll_complete(
    req: BrowserEnrollCompleteRequest,
    request: Request,
) -> dict[str, str]:
    """Complete browser enrollment: store credential, activate user, create session.

    Transitions token state from 'in_progress' to 'completed' and
    user status from 'pending_enrollment' to 'active'.
    """
    db = _get_db(request)
    try:
        from vault.iam.enrollment_manager import EnrollmentError, EnrollmentManager
        from vault.iam.models import User, WebAuthnCredential

        em = EnrollmentManager(db)

        # Validate token is in in_progress state
        try:
            token = em.get_token_by_plaintext(req.enrollment_token)
            if token is None or token.state not in ("in_progress", "created"):
                raise EnrollmentError("Invalid enrollment token or not in progress")
            if token.expires_at <= datetime.now(timezone.utc):
                raise EnrollmentError("Enrollment token has expired")
        except EnrollmentError as e:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=str(e),
            )

        # Verify cryptographic binding to user's string ID
        user = db.query(User).filter(User.id == token.user_id).first()
        username = user.display_name or user.user_id if user else str(token.user_id)
        server_config = getattr(request.app.state, "config", None)
        pepper = getattr(server_config, "recovery_code_pepper", "") if server_config else ""
        if not verify_binding_hash(
            entity_id=username,
            plaintext_token=req.enrollment_token,
            server_secret=pepper,
            stored_binding_hash=token.binding_hash,
        ):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Enrollment token binding mismatch — token has been invalidated",
            )

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
        user = db.query(User).filter(User.id == token.user_id).first()
        if not user:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="User not found",
            )

        webauthn_cred = WebAuthnCredential(
            user_id=user.user_id,
            credential_id=cred.credential_id,
            public_key=cred.public_key,
            sign_count=cred.sign_count,
            label=req.label,
            is_active=True,
        )
        db.add(webauthn_cred)

        # Update token state and user status
        em.complete_enrollment(req.enrollment_token)

        # Activate user
        user.status = "active"
        user.enrolled_at = datetime.now(timezone.utc)
        user.auth_mode = "webauthn"

        # Create session
        from vault.iam.session_manager import SessionManager

        sm = SessionManager(db)
        roles = [rm.role_id for rm in user.roles] if user and user.roles else []
        session, access_token = sm.create_session(
            user_id=user.user_id,
            roles=[str(r) for r in roles],
        )
        db.commit()

        # Set session cookie
        response = JSONResponse(content={"status": "ok"})
        _set_session_cookie(response, access_token.token)

        logger.info(
            "Browser enrollment complete for user %s (ID: %s)",
            user.user_id if user else "unknown",
            token.user_id,
        )

        return response
    except HTTPException:
        try:
            db.rollback()
        except Exception:
            pass
        raise
    except Exception as e:
        try:
            db.rollback()
        except Exception:
            pass
        logger.error("Enrollment complete failed: %s", e)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Enrollment failed",
        ) from e
    finally:
        db.close()
