"""Initialization endpoints — two-step FIDO2 enrollment flow."""

import hashlib
import logging
import secrets
from datetime import UTC

from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from ..dependencies import get_db
from ..fido2.browser_adapter import challenge_to_browser_options

router = APIRouter()
logger = logging.getLogger("venya.server")


# --- Request/Response models ---


class InitRequest(BaseModel):
    user_id: str = Field(..., description="User ID for first admin")


class InitResponse(BaseModel):
    challenge_id: str
    options: dict
    user_id: str


class InitCompleteRequest(BaseModel):
    user_id: str = Field(..., description="User ID for first admin")
    challenge_id: str = Field(..., description="FIDO2 challenge ID")
    response: dict = Field(..., description="FIDO2 attestation response")


class InitCompleteResponse(BaseModel):
    success: bool
    recovery_code: str
    user_id: str


# --- Request/Response models ---


class ResetResponse(BaseModel):
    success: bool
    message: str


# --- Endpoints ---


@router.post(
    "/init/reset",
    response_model=ResetResponse,
    status_code=status.HTTP_200_OK,
)
async def init_reset(
    db: Session = Depends(get_db),
) -> ResetResponse:
    """Reset the core to pre-initialization state.

    Permitted when no enrolled user has a valid WebAuthn credential.
    Covers both fresh installs (no users) and failed enrollment
    attempts (user record exists but no usable credential).

    Refuses to reset when at least one enrolled user has a stored
    WebAuthn credential — the system is fully initialized and a
    reset would destroy valid authentication data.
    """
    from core.iam.models import (
        EnrollmentToken,
        Role,
        RoleMember,
        User,
        WebAuthnCredential,
    )

    try:
        # A user is "fully enrolled" only if they have enrolled_at
        # set AND a stored WebAuthn credential. A failed enrollment
        # may leave enrolled_at set without a usable credential —
        # that broken state must be resettable.
        fully_enrolled_count = (
            db.query(User)
            .join(
                WebAuthnCredential,
                User.user_id == WebAuthnCredential.user_id,
            )
            .filter(User.enrolled_at.isnot(None))
            .count()
        )

        if fully_enrolled_count > 0:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Core already initialized with valid credentials. Cannot reset.",
            )

        # Safe to reset: no enrolled user has a working credential.
        # Delete in FK-safe order (children before parents).
        db.query(WebAuthnCredential).delete()
        db.query(EnrollmentToken).delete()
        db.query(RoleMember).delete()
        db.query(User).filter(User.user_id != "system").delete()
        db.query(Role).filter(Role.name == "admin").delete()
        db.commit()

        logger.info("Core reset to pre-initialization state")

        return ResetResponse(
            success=True,
            message="Core reset to pre-initialization state.",
        )
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=str(e),
        )


@router.post(
    "/init",
    response_model=InitResponse,
    status_code=status.HTTP_201_CREATED,
)
async def init_core(
    req: InitRequest,
    request: Request,
    db: Session = Depends(get_db),
) -> InitResponse:
    """Bootstrap the core: create admin role + generate FIDO2 challenge.

    Step 1 of two-step FIDO2 enrollment. Creates the admin role and user
    in pending state (not enrolled), then returns a FIDO2 registration
    challenge for the CLI to present to the security key.

    If admin role already exists with enrolled members → 409.
    If admin role exists but has no enrolled members → resume mode,
    returns a fresh challenge for the pending user.
    """

    from core.iam.models import Role, RoleMember, User

    from ..ca import CAExistsError, CAManager

    try:
        admin_role = db.query(Role).filter(Role.name == "admin").first()

        if admin_role is not None:
            # Check if admin has enrolled members
            enrolled_count = (
                db.query(RoleMember)
                .filter(RoleMember.role_id == admin_role.id)
                .join(User)
                .filter(User.enrolled_at.isnot(None))
                .count()
            )

            if enrolled_count > 0:
                # Already fully initialized — reject
                pending_user = db.query(User).join(RoleMember).filter(RoleMember.role_id == admin_role.id).first()
                user_id_str = pending_user.user_id if pending_user else "unknown"
                raise HTTPException(
                    status_code=status.HTTP_409_CONFLICT,
                    detail=(
                        f"Core already initialized with admin '{user_id_str}'. "
                        "Use --installation-reset to start over."
                    ),
                )

            # A pending enrollment exists — reject, force reset
            pending_user = db.query(User).join(RoleMember).filter(RoleMember.role_id == admin_role.id).first()

            if pending_user is not None:
                raise HTTPException(
                    status_code=status.HTTP_409_CONFLICT,
                    detail=(
                        f"A pending enrollment exists for '{pending_user.user_id}'. "
                        "Use --installation-reset to clear it and start over."
                    ),
                )

        # Fresh init: create admin role, CA, and pending user
        config = getattr(request.app.state, "config", None)
        if config is not None:
            ca_dir = getattr(config, "ca_dir", "/var/lib/venya/ca")
            ca_security = getattr(config, "ca_security", None)
            ca_manager = CAManager(ca_dir, ca_security)
            if not ca_manager.has_ca:
                try:
                    ca_manager.initialize()
                    logger.info("CA initialized during core bootstrap")
                except CAExistsError:
                    logger.debug("CA already exists on disk")

        admin_role = Role(
            name="admin",
            permissions="read-write",
            description="System administrator — full access",
        )
        db.add(admin_role)

        user_role = Role(
            name="user",
            permissions="read",
            description="Regular user — read-only access",
        )
        db.add(user_role)
        db.flush()

        admin_user = User(
            user_id=req.user_id,
            auth_mode="security-key",
            enrolled_at=None,  # Pending FIDO2 enrollment
        )
        db.add(admin_user)

        membership = RoleMember(
            user_id=req.user_id,
            role_id=admin_role.id,
        )
        db.add(membership)
        db.commit()

        fido2_manager = getattr(request.app.state, "fido2_manager", None)
        if fido2_manager is None:
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="FIDO2 manager not initialized",
            )

        challenge_id, options = fido2_manager.start_registration(
            user_id=req.user_id,
            username=req.user_id,
        )

        logger.info(
            "Init step 1: admin %s created, FIDO2 challenge issued",
            req.user_id,
        )

        return InitResponse(
            challenge_id=challenge_id,
            options=challenge_to_browser_options(challenge_id, options),
            user_id=req.user_id,
        )
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=str(e),
        )


@router.post(
    "/init/complete",
    response_model=InitCompleteResponse,
    status_code=status.HTTP_201_CREATED,
)
async def init_complete(
    req: InitCompleteRequest,
    request: Request,
    db: Session = Depends(get_db),
) -> InitCompleteResponse:
    """Complete FIDO2 enrollment for first admin.

    Step 2 of two-step FIDO2 enrollment. Verifies the FIDO2 attestation,
    stores the WebAuthn credential, generates a recovery code (hashed),
    and marks the user as enrolled.
    """
    from datetime import datetime

    from core.iam.models import User, WebAuthnCredential

    from ..fido2.browser_adapter import browser_registration_to_fido2

    try:
        fido2_manager = getattr(request.app.state, "fido2_manager", None)
        if fido2_manager is None:
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="FIDO2 manager not initialized",
            )

        # Convert browser response to fido2 format
        logger.info("init_complete received: user_id=%s, challenge_id=%s", req.user_id, req.challenge_id)
        logger.info("response keys: %s", list(req.response.keys()))
        resp_data = req.response.get("response")
        if resp_data:
            logger.info("response.response length: %d", len(resp_data))
        try:
            fido2_response = browser_registration_to_fido2(req.response)
            logger.info("fido2_response type: %s", type(fido2_response).__name__)
        except Exception as e:
            logger.error("browser_registration_to_fido2 failed: %s: %s", type(e).__name__, e)
            import traceback

            logger.error(traceback.format_exc())
            raise

        # Verify FIDO2 attestation
        try:
            cred = fido2_manager.finish_registration(req.challenge_id, fido2_response)
        except ValueError as e:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=str(e),
            ) from e
        except Exception as e:
            logger.error("finish_registration failed: %s: %s", type(e).__name__, e)
            import traceback

            logger.error(traceback.format_exc())
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail=f"Registration failed: {e!s}",
            ) from e

        # Find the pending user matching the submitted user_id
        from core.iam.models import Role, RoleMember

        admin_role = db.query(Role).filter(Role.name == "admin").first()
        if admin_role is None:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Admin role not found",
            )

        user = (
            db.query(User)
            .join(RoleMember, User.user_id == RoleMember.user_id)
            .filter(RoleMember.role_id == admin_role.id)
            .filter(User.enrolled_at.is_(None))
            .filter(User.user_id == req.user_id)
            .first()
        )
        if user is None:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="No pending enrollment found for this user",
            )

        # Store WebAuthn credential in database
        webauthn_cred = WebAuthnCredential(
            user_id=cred.user_id,
            credential_id=cred.credential_id,
            public_key=cred.public_key,
            sign_count=cred.sign_count,
            is_active=True,
        )
        db.add(webauthn_cred)

        # Generate recovery code (256-bit, base62, 8 groups of 6)
        recovery_code = _generate_recovery_code()

        # Store hash of recovery code for future validation
        pepper = getattr(
            getattr(request.app.state, "config", None),
            "recovery_code_pepper",
            "",
        )
        recovery_code_hash = _hash_recovery_code(recovery_code, pepper)

        user.auth_mode = "webauthn"
        user.status = "active"
        user.enrolled_at = datetime.now(UTC)
        user.recovery_code_hash = recovery_code_hash

        db.commit()

        logger.info(
            "Init step 2: admin %s enrolled via FIDO2, recovery code issued",
            req.user_id,
        )

        return InitCompleteResponse(
            success=True,
            recovery_code=recovery_code,
            user_id=req.user_id,
        )
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=str(e),
        )


def _generate_recovery_code() -> str:
    """Generate a break-glass recovery code.

    256 bits of randomness, encoded as base62, split into 8 groups of 6.
    Format: XXXXXX-XXXXXX-XXXXXX-XXXXXX-XXXXXX-XXXXXX-XXXXXX-XXXXXX
    """
    raw_bytes = secrets.token_bytes(256 // 8)
    # Convert to base62
    alphabet = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
    number = int.from_bytes(raw_bytes, byteorder="big")
    base62 = ""
    while number > 0:
        number, remainder = divmod(number, len(alphabet))
        base62 = alphabet[remainder] + base62
    # Pad to 48 characters (8 groups of 6)
    base62 = base62.zfill(48)
    # Split into groups of 6
    groups = [base62[i : i + 6] for i in range(0, 48, 6)]
    return "-".join(groups)


def _hash_recovery_code(code: str, pepper: str) -> str:
    """Hash a recovery code with a server-side pepper.

    Uses SHA-256 with pepper prepended to the code.
    """
    return hashlib.sha256((pepper + code).encode()).hexdigest()
