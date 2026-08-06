"""Browser WebAuthn enrollment endpoints.

One-time browser enrollment using a token issued by `venya init --no-enroll`.
Tokens are bound to a user_id, have a 15-minute TTL, and are invalidated
after 3 failed attempts.
"""

from __future__ import annotations

import logging
import secrets
import string
from datetime import datetime, timedelta, timezone
from typing import Any

from fastapi import APIRouter, HTTPException, Request, status
from pydantic import BaseModel, Field

from ..fido2.browser_adapter import (
    challenge_to_browser_registration_options,
    browser_registration_to_fido2,
)

logger = logging.getLogger("venya.server")

router = APIRouter()

ALPHABET = string.ascii_letters + string.digits  # base62


def _generate_enrollment_token() -> str:
    """Generate an enrollment token with enrl_ prefix and 128-bit entropy.

    Returns:
        Token string like "enrl_abc123XYZ..."
    """
    raw = secrets.token_bytes(128 // 8)
    number = int.from_bytes(raw, byteorder="big")
    base62 = ""
    while number > 0:
        number, remainder = divmod(number, len(ALPHABET))
        base62 = ALPHABET[remainder] + base62
    return "enrl_" + base62.zfill(26)


# --- Request/Response models ---


class BrowserEnrollRequest(BaseModel):
    token: str = Field(..., description="Enrollment token from venya init")


class BrowserEnrollResponse(BaseModel):
    challenge_id: str
    options: dict[str, Any]


class BrowserEnrollCompleteRequest(BaseModel):
    token: str = Field(..., description="Enrollment token")
    challenge_id: str = Field(..., description="Challenge ID from enroll/browser response")
    response: dict[str, Any] = Field(..., description="WebAuthn attestation response")


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


def _validate_enrollment_token(db, token_value: str, ttl_minutes: int) -> Any:
    """Validate an enrollment token and return it.

    Args:
        db: Database session.
        token_value: The token string to validate.
        ttl_minutes: Token TTL in minutes.

    Returns:
        The EnrollmentToken if valid.

    Raises:
        HTTPException: If token is invalid, expired, consumed, or rate-limited.
    """
    from vault.iam.models import EnrollmentToken

    now = datetime.now(timezone.utc)
    token = (
        db.query(EnrollmentToken)
        .filter(EnrollmentToken.token == token_value)
        .first()
    )

    if token is None:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid enrollment token",
        )

    if token.consumed:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Enrollment token has already been used",
        )

    if token.expires_at < now:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Enrollment token has expired",
        )

    if token.failed_attempts >= 3:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Enrollment token has been invalidated due to too many failed attempts",
        )

    return token


def _increment_failed_attempts(db, token):
    """Increment the failed attempts counter on a token.

    Args:
        db: Database session.
        token: The EnrollmentToken to update.
    """
    token.failed_attempts += 1
    db.flush()


# --- Endpoints ---


@router.post(
    "/enroll/browser",
    response_model=BrowserEnrollResponse,
    status_code=status.HTTP_200_OK,
)
async def browser_enroll_start(
    req: BrowserEnrollRequest,
    request: Request,
) -> BrowserEnrollResponse:
    """Validate enrollment token and issue WebAuthn registration challenge.

    Returns a browser-formatted WebAuthn registration challenge for
    the client to present to the authenticator.
    """
    db = _get_db(request)
    try:
        config = getattr(request.app.state, "config", None)
        ttl_minutes = (
            config.fido2.enrollment_token_ttl
            if config
            else 15
        )

        token = _validate_enrollment_token(db, req.token, ttl_minutes)

        fido2_manager = getattr(request.app.state, "fido2_manager", None)
        if fido2_manager is None:
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="FIDO2 manager not initialized",
            )

        challenge_id, options = fido2_manager.start_registration(
            user_id=token.user_id,
            username=token.user_id,
        )

        browser_options = challenge_to_browser_registration_options(
            challenge_id, options
        )

        return BrowserEnrollResponse(
            challenge_id=challenge_id,
            options=browser_options,
        )
    except HTTPException:
        db.rollback()
        raise
    except Exception as e:
        db.rollback()
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
    """Complete browser enrollment: store credential and consume token.

    Verifies the WebAuthn attestation, stores the credential via
    Fido2Manager, and marks the enrollment token as consumed.
    """
    db = _get_db(request)
    try:
        config = getattr(request.app.state, "config", None)
        ttl_minutes = (
            config.fido2.enrollment_token_ttl
            if config
            else 15
        )

        # Validate token
        token = _validate_enrollment_token(db, req.token, ttl_minutes)

        fido2_manager = getattr(request.app.state, "fido2_manager", None)
        if fido2_manager is None:
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="FIDO2 manager not initialized",
            )

        # Convert and verify registration
        fido2_response = browser_registration_to_fido2(req.response)

        try:
            cred = fido2_manager.finish_registration(
                req.challenge_id,
                fido2_response,
            )
        except ValueError as e:
            _increment_failed_attempts(db, token)
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=str(e),
            ) from e

        # Store credential
        from vault.iam.models import WebAuthnCredential
        import json

        webauthn_cred = WebAuthnCredential(
            credential_id=cred.credential_id,
            user_id=cred.user_id,
            raw_id=cred.credential_data.get("raw_id", ""),
            response=json.dumps(cred.credential_data.get("response", {})),
            transports=json.dumps(cred.transports),
        )
        db.add(webauthn_cred)

        token.consumed = True

        from vault.iam.models import User
        user = db.query(User).filter(User.user_id == token.user_id).first()
        if user:
            user.auth_mode = "webauthn"
            user.enrolled_at = datetime.now(timezone.utc)

        db.commit()

        logger.info(
            "Browser enrollment complete for user %s",
            token.user_id,
        )

        return {"status": "ok", "user_id": token.user_id}
    except HTTPException:
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
        try:
            db.close()
        except Exception:
            pass
