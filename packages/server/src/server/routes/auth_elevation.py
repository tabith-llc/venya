# Copyright (c) 2026 Tabith LLC.
# Use of this source code is governed by the Business Source License 1.1
# included in the LICENSE file at the root of this repository. As of the
# Change Date listed there, the work is available under MPL 2.0.
# SPDX-License-Identifier: BUSL-1.1

"""WebAuthn elevation endpoints for CLI/API re-authentication.

These endpoints require bearer-token authentication (Depends(get_current_user))
and are used by the CLI for sensitive operations that require re-authentication
via WebAuthn (e.g., unmasking secrets, adding credentials).

Previously part of auth_browser.py — migrated here when browser auth was
unmounted. The "browser" naming on the old endpoints was historical; they
work identically for CLI clients.
"""

import hashlib
import logging
import secrets
from datetime import UTC, datetime, timedelta

from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from ..audit_lifecycle import ELEVATION_GRANTED, audit_lifecycle
from ..dependencies import get_current_user, get_db
from ..fido2.browser_adapter import browser_assertion_to_fido2, challenge_to_browser_options
from ..fido2.manager import WebAuthnError

logger = logging.getLogger("venya.server")

router = APIRouter()

ELEVATION_TOKEN_TTL_SECONDS = 60


class ElevationChallengeResponse(BaseModel):
    challenge_id: str
    options: dict


class ElevationAssertRequest(BaseModel):
    model_config = {"extra": "forbid"}  # #357 sweep: silent-drop dies here (repo-wide extra=forbid ruling)

    challenge_id: str = Field(..., description="Challenge ID from the challenge response")
    response: dict = Field(..., description="WebAuthn assertion response")


class ElevationAssertResponse(BaseModel):
    status: str
    elevation_token: str


def _store_elevation_challenge(db: Session, challenge_id: str, user_id: str, session_id: int | None) -> None:
    """Persist a pending elevation ceremony binding (#528).

    DB replacement for the old per-process app.state dict: the row is
    committed immediately, so any worker on any core claims the SAME
    record and a restart does not vaporise a live ceremony. Expired rows
    are pruned here — the DB twin of the #345 stale sweep (abandoned
    ceremonies die on the next touch, not at restart).
    """
    from core.iam.models import ElevationChallenge

    now = datetime.now(UTC)
    db.query(ElevationChallenge).filter(ElevationChallenge.expires_at < now).delete(synchronize_session=False)
    db.add(
        ElevationChallenge(
            challenge_id=challenge_id,
            user_id=user_id,
            session_id=session_id,
            state="created",
            created_at=now,
            expires_at=now + timedelta(seconds=ELEVATION_TOKEN_TTL_SECONDS * 5),
        )
    )
    db.commit()


def _claim_elevation_challenge(
    db: Session,
    challenge_id: str,
    caller_user_id: str,
    caller_session_id: int | None,
    endpoint: str,
):
    """Atomically consume the pending row, then verify the binding (#528).

    Claim-COMMITS-BEFORE-CHECKS: the consumed state must survive every
    refusal path — pop-up-front keeps its #345 meaning (a denied ceremony
    never re-arms the challenge), and get_db rolls back escaped
    exceptions, so an uncommitted claim would put the row back in play.
    Single-consume is the atomic UPDATE ... WHERE state='created' (house
    pattern: enrollment_tokens.state / elevation_tokens.used) — two
    concurrent claims, exactly one gets rowcount 1.

    A not-found/expired/already-consumed claim fails closed with the
    uniform 401 and an audit row (value-free: no challenge id, no token
    material — AC2). Returns the claimed row.
    """
    from core.iam.models import AuditEvent, ElevationChallenge

    now = datetime.now(UTC)
    claimed = (
        db.query(ElevationChallenge)
        .filter(
            ElevationChallenge.challenge_id == challenge_id,
            ElevationChallenge.state == "created",
            ElevationChallenge.expires_at > now,
        )
        .update({"state": "consumed"}, synchronize_session=False)
    )
    db.commit()

    if claimed != 1:
        try:
            db.add(
                AuditEvent(
                    event_type="elevation_challenge_denied",
                    user_id=caller_user_id,
                    fields={
                        "outcome": "denied",
                        "reason": "challenge_not_found",
                        "user_id": caller_user_id,
                        "endpoint": endpoint,
                    },
                    timestamp=datetime.now(UTC),
                )
            )
            db.commit()
        except Exception:
            logger.exception("Audit write failed on elevation challenge deny (still denying)")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Elevation challenge not found or expired",
        )

    row = db.query(ElevationChallenge).filter(ElevationChallenge.challenge_id == challenge_id).one()

    if row.user_id != caller_user_id:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Elevation challenge user mismatch",
        )

    # #527 gate, now on the DB row: a second session of the same user
    # cannot finish a ceremony earned elsewhere. mTLS/admin contexts carry
    # session_id None on both sides, so the comparison stays inert for them.
    if row.session_id != caller_session_id:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Elevation challenge session mismatch",
        )

    return row


@router.post(
    "/auth/elevate/challenge",
    response_model=ElevationChallengeResponse,
    status_code=status.HTTP_200_OK,
)
async def elevate_challenge(
    request: Request,
    user_info: dict = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> ElevationChallengeResponse:
    """Issue a WebAuthn challenge for CLI elevation (sensitive operations).

    Requires bearer-token auth. The user must re-authenticate with their
    security key to perform sensitive operations like unmasking secret values.
    """
    fido2_manager = getattr(request.app.state, "fido2_manager", None)
    if fido2_manager is None:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="FIDO2 manager not initialized",
        )

    from core.iam.models import WebAuthnCredential

    credentials = db.query(WebAuthnCredential).filter(WebAuthnCredential.user_id == user_info["user_id"]).all()
    if not credentials:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="No WebAuthn credentials found",
        )

    challenge_id, options = fido2_manager.start_authentication(
        user_id=user_info["user_id"],
    )
    browser_options = challenge_to_browser_options(challenge_id, options)

    # Store the binding in the DB, not app.state (#528): any worker can
    # claim it, a restart cannot lose it, and one consume is atomic.
    _store_elevation_challenge(
        db,
        challenge_id,
        user_info["user_id"],
        user_info.get("session_id"),
    )

    return ElevationChallengeResponse(
        challenge_id=challenge_id,
        options=browser_options,
    )


@router.post(
    "/auth/elevate/assert",
    response_model=ElevationAssertResponse,
    status_code=status.HTTP_200_OK,
)
async def elevate_assert(
    req: ElevationAssertRequest,
    request: Request,
    user_info: dict = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> ElevationAssertResponse:
    """Verify WebAuthn assertion and return a short-lived elevation token.

    Verifies the assertion via Fido2Manager, confirms the challenge
    was issued for the current user, and returns a short-lived
    elevation token (60 seconds) for use in sensitive operations.
    """
    fido2_manager = getattr(request.app.state, "fido2_manager", None)
    if fido2_manager is None:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="FIDO2 manager not initialized",
        )

    # #528: DB-backed claim (was the per-process dict pop). Consumed on
    # EVERY path — success, WebAuthn error, mismatch, or auditor denial —
    # so a denied or abandoned ceremony never re-arms the challenge.
    _claim_elevation_challenge(
        db,
        req.challenge_id,
        user_info["user_id"],
        user_info.get("session_id"),
        "/api/v1/auth/elevate/assert",
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

    # Auditor-role rework (ruling 1c-ii, blanket issuance-deny): refuse to
    # ISSUE an elevation token to auditor-only callers — the last gate before
    # the token exists. Diagnostics only: the authoritative value-deny lives
    # at the secrets_get unmask chokepoint. Blanket by ruling: the token also
    # gates self-service credential-add (credentials._verify_elevation), so
    # an auditor-only user cannot add their own security keys (release-notes
    # wording). Union (1b): any non-auditor membership passes.
    from core.iam.role_manager import RoleManager

    from ..dependencies import auditor_only_permissions

    if auditor_only_permissions(RoleManager(db).get_user_permissions(user_info["user_id"])):
        # Denials are audit-logged (owner ruling 2026-09-30). COMMIT BEFORE
        # the raise — get_db rolls back escaped exceptions. Value-free:
        # no token material exists yet at this gate. Fail-closed: audit-write
        # failure never upgrades the denial (logged loudly, still 403).
        from core.iam.models import AuditEvent

        try:
            db.add(
                AuditEvent(
                    event_type="auditor_elevation_denied",
                    user_id=user_info["user_id"],
                    fields={
                        "outcome": "denied",
                        "reason": "auditor-only role",
                        "user_id": user_info["user_id"],
                        "endpoint": "/api/v1/auth/elevate/assert",
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
    elevation_token = secrets.token_urlsafe(32)
    token_hash = hashlib.sha256(elevation_token.encode()).hexdigest()
    expires_at = datetime.now(UTC) + timedelta(seconds=ELEVATION_TOKEN_TTL_SECONDS)

    from core.iam.models import ElevationToken

    elevation_record = ElevationToken(
        token_hash=token_hash,
        user_id=user_info["user_id"],
        # #527: bind the token to the session that earned it — revoke_session
        # deletes bound rows, so a logged-out session's unconsumed elevation
        # token is no longer consumable. None-tolerant (mTLS/admin contexts).
        session_id=user_info.get("session_id"),
        expires_at=expires_at,
    )
    db.add(elevation_record)
    # #301 F2 (Q2: emits on every grant): value-free — mode + endpoint only,
    # never token/challenge/row-id material. Rides the issuance commit.
    audit_lifecycle(
        db,
        ELEVATION_GRANTED,
        user_info["user_id"],
        {"mode": "cli", "endpoint": "/api/v1/auth/elevate/assert"},
    )
    db.commit()

    return ElevationAssertResponse(
        status="ok",
        elevation_token=elevation_token,
    )
