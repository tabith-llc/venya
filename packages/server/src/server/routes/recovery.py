# Copyright (c) 2026 Tabith LLC.
# Use of this source code is governed by the Business Source License 1.1
# included in the LICENSE file at the root of this repository. As of the
# Change Date listed there, the work is available under MPL 2.0.
# SPDX-License-Identifier: BUSL-1.1

"""Break-glass recovery endpoint."""

import logging
from datetime import UTC

from core.iam.models import User
from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel, Field
from sqlalchemy import update
from sqlalchemy.orm import Session

from ..audit_lifecycle import BREAK_GLASS_RECOVERY_USED, audit_lifecycle
from ..dependencies import get_db
from ..recovery_codes import hash_recovery_code
from ..utils.user_id import USER_ID_PATTERN

logger = logging.getLogger("venya.server")

router = APIRouter()


def claim_recovery_code(db: Session, user_id: str, submitted_hash: str) -> int:
    """Atomically consume the one-shot break-glass code (#512).

    Check-and-burn in ONE conditional UPDATE: the row is matched on
    ``user_id`` AND ``recovery_code_hash == submitted_hash`` and the SAME
    statement sets it to NULL. A second claim of an already-burned code
    matches 0 rows — under PostgreSQL READ COMMITTED the losing UPDATE blocks
    on the winner's row lock, then re-evaluates its WHERE clause against the
    committed row (hash now NULL) and finds nothing. That is why this is
    atomic ACROSS processes: no separate read-then-write window exists, and
    an in-process mutex would prove nothing about the second server process.
    Shape copied from the paired negative already in the repo —
    ``admin_reissue_recovery_code`` (routes/admin.py) burns its elevation
    token the same way.

    Returns the affected row count: exactly 1 means THIS call burned the code.
    """
    return db.execute(
        update(User)
        .where(
            User.user_id == user_id,
            User.recovery_code_hash == submitted_hash,
        )
        .values(recovery_code_hash=None)
        .execution_options(synchronize_session=False)
    ).rowcount


class RecoveryRequest(BaseModel):
    # Re-swept (#371): the #357 exemption existed only while shipped CLIs
    # leaked --force/--confirm into this body; #367 made the client send
    # just the declared fields, so the condition is discharged and the
    # silent-drop class dies here like the rest of the sweep.
    model_config = {"extra": "forbid"}  # #357 sweep: silent-drop dies here (repo-wide extra=forbid ruling)

    code: str = Field(..., description="Break-glass recovery code")
    # #517: this value lands in users.user_id as a NEW ADMIN, so it has to satisfy
    # the same grammar the admin surface requires to ADDRESS an admin
    # (server.utils.user_id, shared with routes/admin.py). Unpatterned, break-glass
    # could mint "Ops_Admin", "A", or a 70-character ID: the admin routes then
    # answer 422 on the very account the operator just recovered, and an over-length
    # value runs into the String(64) column / chk_user_id_format CHECK inside the
    # transaction instead of being refused as a 422 before any write.
    new_user_id: str = Field(..., description="New admin user ID", pattern=USER_ID_PATTERN)


class RecoveryResponse(BaseModel):
    success: bool
    action: str  # "re_establish" or "new_admin"
    user_id: str


@router.post(
    "/recovery",
    response_model=RecoveryResponse,
    status_code=status.HTTP_200_OK,
)
async def recovery(
    req: RecoveryRequest,
    request: Request,
    db: Session = Depends(get_db),
) -> RecoveryResponse:
    """Break-glass recovery.

    Validates the one-shot recovery code (sha256(pepper + code)) against the
    admin's stored hash, mints a new admin, and burns the code (single-use).
    This is the CLI break-glass path for lockout recovery.

    Single-use is enforced by an atomic check-and-burn (``claim_recovery_code``
    below, #512), not by the read this function starts with: the read only
    identifies the source admin for logging and audit. Two concurrent
    submissions of the same code both pass the read, but only one claim can
    match the row — the loser is refused 409.
    """
    from datetime import datetime

    try:
        from core.iam.models import Role, RoleMember

        # Validate recovery code against stored hash
        pepper = getattr(
            getattr(request.app.state, "config", None),
            "recovery_code_pepper",
            "",
        )
        submitted_hash = hash_recovery_code(req.code, pepper)

        # Find admin user with matching recovery code hash — IDENTIFICATION
        # ONLY (#512): this unlocked read answers who the code belongs to; it
        # is not the single-use gate, and the race it leaves open is closed by
        # the atomic claim below.
        admin_user = (
            db.query(User)
            .join(RoleMember)
            .join(Role)
            .filter(Role.name == "admin")
            .filter(User.recovery_code_hash == submitted_hash)
            .first()
        )

        client_ip = request.client.host if request.client else "unknown"

        if admin_user is None:
            logger.critical(
                "Recovery: invalid code attempt from %s (user_id=%s)",
                client_ip,
                req.new_user_id,
            )
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid recovery code",
            )

        logger.critical(
            "Recovery: successful break-glass from %s (source user=%s, new user=%s)",
            client_ip,
            admin_user.user_id,
            req.new_user_id,
        )

        # Burn the one-shot code ATOMICALLY with its check (#512): one
        # conditional UPDATE matches the identified row on the submitted hash
        # and NULLs it in the SAME statement, so exactly one concurrent
        # submission can claim it — the loser re-evaluates against the
        # committed row and matches 0 rows. PostgreSQL READ COMMITTED is the
        # assumed isolation level (the losing UPDATE first takes the row
        # lock, so the two claims serialize on the row itself, not in
        # process). The claim rides this route's transaction: the guards
        # below raising (400 user-exists / 503 no-role) unwind it through
        # get_db's rollback, keeping the pre-#512 contract that a FAILED
        # recovery does not consume the code — the operator needs it for the
        # retry — and the winner's final commit lands burn, new admin,
        # membership and audit row together. Re-issuance of a fresh code for
        # the recovered system is separate scope (see ticket
        # test-recovery-admin-enrollment-key cross-reference).
        if claim_recovery_code(db, admin_user.user_id, submitted_hash) == 0:
            # The read above found the row, but between that read and this
            # statement another submission consumed it: the double-spend the
            # unlocked read-then-burn used to allow. Refuse by name and audit
            # the refusal (commit-before-raise, the #296 denial-audit idiom —
            # get_db's rollback after the raise must not erase the record).
            logger.critical(
                "Recovery: double-spend refused for code held by %s (new user=%s)",
                admin_user.user_id,
                req.new_user_id,
            )
            audit_lifecycle(
                db,
                BREAK_GLASS_RECOVERY_USED,
                admin_user.user_id,
                {
                    "new_user_id": req.new_user_id,
                    "code_consumed": False,
                    "outcome": "refused_code_already_consumed",
                },
            )
            db.commit()
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="Recovery code already consumed by another request",
            )

        # Check if user already exists
        existing = db.query(User).filter(User.user_id == req.new_user_id).first()
        if existing:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"User already exists: {req.new_user_id}",
            )

        # Create new admin user
        new_user = User(
            user_id=req.new_user_id,
            auth_mode="security-key",
            enrolled_at=datetime.now(UTC),
        )
        db.add(new_user)

        # Add admin role
        admin_role = db.query(Role).filter(Role.name == "admin").first()
        if admin_role is None:
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="Admin role not found — admin role must exist before recovery",
            )

        membership = RoleMember(
            user_id=req.new_user_id,
            role_id=admin_role.id,
        )
        db.add(membership)

        # The claim above already burned the row via a bulk UPDATE; expire the
        # loaded ORM object so a later flush in this session can never write
        # the pre-claim (stale) attribute state back.
        db.expire(admin_user)
        audit_lifecycle(
            db,
            BREAK_GLASS_RECOVERY_USED,
            admin_user.user_id,
            {"new_user_id": req.new_user_id, "code_consumed": True},
        )
        db.commit()

        logger.info(
            "Recovery: created new admin user %s (validated by code from %s)", req.new_user_id, admin_user.user_id
        )
        return RecoveryResponse(
            success=True,
            action="new_admin",
            user_id=req.new_user_id,
        )
    except HTTPException:
        raise
    except Exception:
        logger.exception("Recovery failed")
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Recovery failed",
        )
