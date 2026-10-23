# Copyright (c) 2026 Tabith LLC.
# Use of this source code is governed by the Business Source License 1.1
# included in the LICENSE file at the root of this repository. As of the
# Change Date listed there, the work is available under MPL 2.0.
# SPDX-License-Identifier: BUSL-1.1

"""Initialization endpoints — two-step FIDO2 enrollment flow."""

import logging
from datetime import UTC

from core.engine.backend import Backend
from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel, Field
from sqlalchemy import text
from sqlalchemy.orm import Session

from ..audit_lifecycle import (
    ADMIN_INITIALIZED,
    CORE_RESET_REFUSED,
    FIRST_ADMIN_ENROLLED,
    ROLE_DELETED,
    USER_DELETED,
    audit_lifecycle,
)
from ..dependencies import get_backend, get_db, require_admin
from ..fido2.browser_adapter import challenge_to_browser_options
from ..fido2.manager import WebAuthnError
from ..recovery_codes import generate_recovery_code as _generate_recovery_code
from ..recovery_codes import hash_recovery_code as _hash_recovery_code
from ..utils.user_id import USER_ID_PATTERN

router = APIRouter()
logger = logging.getLogger("venya.server")


# --- Request/Response models ---


class InitRequest(BaseModel):
    model_config = {"extra": "forbid"}  # #357 sweep: silent-drop dies here (repo-wide extra=forbid ruling)

    # #532: the bootstrap MINTS users.user_id, so it validates against the same
    # grammar the surface that ADDRESSES it requires — the one definition in
    # server/utils/user_id.py, imported, never copied (mirrors recovery #517).
    user_id: str = Field(..., description="User ID for first admin", pattern=USER_ID_PATTERN)


class InitResponse(BaseModel):
    challenge_id: str
    options: dict
    user_id: str


class InitCompleteRequest(BaseModel):
    model_config = {"extra": "forbid"}  # #357 sweep: silent-drop dies here (repo-wide extra=forbid ruling)

    # #532: step 2 names the SAME identity as step 1 and reaches the same row
    # (enrolled_at, credential, recovery hash) — both models at the tip carry
    # the unpatterned field, so both carry the pattern.
    user_id: str = Field(..., description="User ID for first admin", pattern=USER_ID_PATTERN)
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


# --- Endpoints ---


# --- First-admin bootstrap serialization (#510) ---

#: One fixed advisory-lock key for the whole first-admin bootstrap. Step 1
#: (count → create the pending admin) and step 2 (re-check → enroll) take the
#: SAME key, so the two steps of two different callers cannot interleave. The
#: lock is transaction-scoped, therefore held to the commit that writes the
#: enrollment, and it is a database object: it serializes every process that
#: shares the database, which is what two uvicorn workers do.
INIT_BOOTSTRAP_LOCK_KEY = "venya:init:first-admin"


def _lock_first_admin_bootstrap(db: Session) -> None:
    """Serialize the first-admin bootstrap on PostgreSQL (#510).

    The shape is the one already in this tree —
    ``core/iam/enrollment_manager.create_enrollment_token`` (the #339 cap plus
    the #366 dialect guard): ``FOR UPDATE`` locks only MATCHED rows, so it locks
    nothing in the bootstrap case where no enrolled admin row exists yet to
    lock, which is exactly the case that must serialize. An advisory lock keyed
    on a constant is the shape that survives two processes racing on an empty
    set. ``hashtext`` runs PostgreSQL-side and the key travels as a bind param,
    never interpolated.

    Dialect guard (#366): ``pg_advisory_xact_lock``/``hashtext`` are
    PostgreSQL-only — issued against SQLite the same statement is a runtime
    "no such function" error. The statement therefore goes out only on a
    PostgreSQL bind; a session that cannot report its dialect is treated as
    PostgreSQL so the statement contract stays pinned. SQLite fallback, stated
    plainly: the advisory lock is SKIPPED — cross-process serialization is a
    PostgreSQL-production property. What the SQLite cells in the test suite
    prove is the in-transaction re-check in :func:`init_complete`, not this
    lock; the lock itself is pinned by statement construction plus a
    PostgreSQL-gated race cell that skips on a venue with no scratch database.
    """
    bind = db.get_bind() if hasattr(db, "get_bind") else None
    if bind is None or bind.dialect.name == "postgresql":
        db.execute(
            text("SELECT pg_advisory_xact_lock(hashtext(:key))"),
            {"key": INIT_BOOTSTRAP_LOCK_KEY},
        )


def _enrolled_admin_present(db: Session, admin_role_id: int) -> bool:
    """True when an ``admin``-role member is already enrolled — read FOR UPDATE.

    The re-check inside the transaction that writes the enrollment (#510). Two
    properties are deliberate:

    * Admin-scoped, not :func:`deployment_is_initialized`. That helper answers
      "a reset would destroy identity" and says True for ANY
      ``WebAuthnCredential`` row; using it here would refuse a legitimate
      bootstrap over orphan credential residue left by a partial wipe, and step
      1 already refuses on the narrower admin-scoped predicate. Step 2 refuses
      on exactly the predicate step 1 used, so the two steps agree.
    * ``with_for_update`` on the membership/user join, which is the same
      ``role_members`` rows :meth:`core.iam.role_manager.RoleManager._locked_admin_roster`
      locks (#487). That is the belt for a concurrent roster or status write:
      the advisory lock serializes bootstrap callers among themselves, the row
      lock interlocks this read with the roster guards. PostgreSQL locks;
      SQLite, the test backend, ignores the clause — the posture that helper's
      own docstring records.

    The count is deliberately not a ``count()`` with ``FOR UPDATE``:
    PostgreSQL rejects ``FOR UPDATE`` on an aggregate, so this asks for one
    matching id and stops there.
    """
    from core.iam.models import RoleMember, User

    row = (
        db.query(User.user_id)
        .join(RoleMember, RoleMember.user_id == User.user_id)
        .filter(RoleMember.role_id == admin_role_id, User.enrolled_at.isnot(None))
        .with_for_update()
        .first()
    )
    return row is not None


def deployment_is_initialized(db: Session) -> bool:
    """True once this core holds identity that a reset would destroy (#450).

    The guard this replaces counted users that ALSO had a credential row — an
    INNER JOIN between users and webauthn_credentials — so a user with
    ``enrolled_at`` set and no credential row contributed nothing to the count
    and the wipe went ahead. That is exactly the shape the break-glass flow
    commits: ``routes/recovery.py`` creates the replacement admin with
    ``enrolled_at=datetime.now(UTC)`` and NO credential row (the credential
    arrives in a later ceremony), and ``routes/admin.py`` ``admin_remove``
    hard-deletes credential rows for a user who stays enrolled.

    "Initialized" therefore asks about the two sets independently and refuses
    on either:

    * any user with ``enrolled_at`` set (enrolled, or break-glass created), and
    * any WebAuthn credential row at all — active or retired
      (``routes/credentials.py`` retires with ``is_active=False`` and keeps the row).

    A core with neither answers False, which is the state the fresh-install
    bootstrap reset needs to keep working: there is no identity to protect yet.
    """
    from core.iam.models import User, WebAuthnCredential

    if db.query(User.user_id).filter(User.enrolled_at.isnot(None)).first() is not None:
        return True
    return db.query(WebAuthnCredential.id).first() is not None


def require_admin_when_initialized(
    request: Request,
    backend: Backend = Depends(get_backend),
    db: Session = Depends(get_db),
) -> dict:
    """Gate for POST /api/v1/init/reset: only an admin may reset everything.

    Initialized core → the caller must hold admin authority. No identity at all
    is a 401; an authenticated non-admin gets the 403 ``require_admin`` returns
    (executors presenting mTLS are denied there too — this surface is
    human-only).

    Uninitialized core → an unauthenticated caller may pass, because in that
    window the ONLY caller is the bootstrap itself: ``venya init
    --installation-reset`` posts this route from ``cli/commands.py`` ``cmd_init``,
    and ``"init"`` sits in that module's authenticate-first exemption list, so
    no session exists to present. Gating the pre-init window would brick fresh
    installs and abandoned-ceremony recovery, so it stays reachable and is
    covered by the guard above rather than by an identity check. A token- or
    certificate-gated bootstrap is the follow-on proposed on the ticket; it
    needs installer/CLI work, which is deliberately NOT implemented here.
    """
    if not deployment_is_initialized(db):
        return {"caller": "bootstrap", "user_id": None}

    auth_user = getattr(request.state, "auth_user", None)
    if auth_user is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication required to reset an initialized core",
            headers={"WWW-Authenticate": "Bearer"},
        )
    return require_admin(user_info=auth_user, backend=backend)


require_admin_when_initialized._venya_guard = "admin"  # type: ignore[attr-defined]


@router.post(
    "/init/reset",
    response_model=ResetResponse,
    status_code=status.HTTP_200_OK,
)
async def init_reset(
    db: Session = Depends(get_db),
    auth_user: dict = Depends(require_admin_when_initialized),
) -> ResetResponse:
    """Reset the core to pre-initialization state.

    Destructive: every credential, enrollment token, role membership, user
    (except ``system``) and the admin/user roles are deleted in one commit.

    Authority (#450): on a core that is already initialized this is an
    ADMIN-ONLY operation — the gate is ``require_admin_when_initialized``.
    On a core with no enrolled user and no credential row the bootstrap caller
    (``venya init --installation-reset``) is still permitted, because no
    identity exists yet to require and there is no identity to destroy.

    Gate staleness (#511): that gate is a FastAPI dependency, so it ran BEFORE
    this body and its answer can go stale underneath us — an unauthenticated
    caller passes while the core still looks uninitialized, the operator's
    ``init_complete`` commits in between, and this body would then delete the
    identity set that just landed. The precondition is therefore re-asserted
    HERE, at the moment of the effect (the check-and-consume shape
    ``routes/executors.py`` already uses), and it is re-asserted inside the
    first-admin bootstrap lock, which every init step takes: a concurrent
    ``init_complete`` cannot commit between the re-check and the deletes.
    Multi-process caveat, stated rather than hidden: the advisory lock is
    PostgreSQL-side, so on SQLite it is skipped (the #366 dialect guard) and
    the in-transaction re-check is what the SQLite cells prove.
    """
    from core.iam.models import (
        EnrollmentToken,
        Role,
        RoleMember,
        User,
        WebAuthnCredential,
    )
    from core.iam.models import (
        Session as SessionModel,
    )

    try:
        # #511: take the lock BEFORE the re-check below, so the refusal decision
        # and (on a genuinely uninitialized core) the wipe are one serialized
        # step against the bootstrap that would otherwise land in the middle.
        _lock_first_admin_bootstrap(db)

        # ``user_id`` is None only for the bootstrap pass-through the gate hands
        # back when the core looked uninitialized; an admin caller arrives with
        # an identity and is expected to see an initialized core.
        if auth_user.get("user_id") is None and deployment_is_initialized(db):
            # Denial-side shape from audit_lifecycle's own docstring: no action
            # rides this event, so the audit row commits before the raise. The
            # field table stays value-free and names no principal — this route is
            # reachable unauthenticated, so a name here would be an oracle.
            audit_lifecycle(
                db,
                CORE_RESET_REFUSED,
                None,
                {"outcome": "refused", "reason": "initialized_after_gate", "wipe_executed": False},
            )
            db.commit()
            logger.warning(
                "Core reset refused: an unauthenticated caller passed the #450 gate while this "
                "core was uninitialized and identity appeared before the wipe could run"
            )
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail=(
                    "This core is now already initialized; an unauthenticated reset was refused. "
                    "Sign in as an admin to reset an initialized core."
                ),
            )

        # Snapshot what the wipe is about to remove, both so the audit rows can
        # name the counts (AC: the destructive path is auditable) and because
        # a bulk delete leaves nothing to read afterwards.
        wiped_users = db.query(User).filter(User.user_id != "system").all()
        wiped_roles = db.query(Role).filter(Role.name.in_(["admin", "user"])).all()
        user_snapshot = [
            {
                "target_user_id": user.user_id,
                "operation": "core_reset",
                "memberships_removed": db.query(RoleMember).filter(RoleMember.user_id == user.user_id).count(),
                "credentials_removed": db.query(WebAuthnCredential)
                .filter(WebAuthnCredential.user_id == user.user_id)
                .count(),
                "tokens_revoked": db.query(EnrollmentToken).filter(EnrollmentToken.user_id == user.user_id).count(),
                "sessions_revoked": db.query(SessionModel).filter(SessionModel.user_id == user.user_id).count(),
            }
            for user in wiped_users
        ]
        role_snapshot = [
            {
                "role_id": role.id,
                "role_name": role.name,
                "members_affected": db.query(RoleMember).filter(RoleMember.role_id == role.id).count(),
                "operation": "core_reset",
            }
            for role in wiped_roles
        ]

        # Safe to reset: delete in FK-safe order (children before parents).
        # Sessions go explicitly rather than by FK cascade: a live token for a
        # user this wipe removes is a credential outliving its principal, and
        # the reset should not depend on cascade configuration to revoke it
        # (same posture as admin.py's user removal).
        db.query(WebAuthnCredential).delete()
        db.query(EnrollmentToken).delete()
        db.query(RoleMember).delete()
        db.query(SessionModel).delete()
        db.query(User).filter(User.user_id != "system").delete()
        db.query(Role).filter(Role.name.in_(["admin", "user"])).delete()

        # Same-transaction lifecycle audit (audit_lifecycle is the single
        # writer; the rows ride the reset's own commit, so a wipe and its
        # record are complete-or-nothing). One user_deleted per removed
        # account and one role_deleted per removed role — the existing
        # vocabulary, actor named, counts in the field table.
        actor_user_id = auth_user.get("user_id")
        for fields in user_snapshot:
            audit_lifecycle(db, USER_DELETED, actor_user_id, fields)
        for fields in role_snapshot:
            audit_lifecycle(db, ROLE_DELETED, actor_user_id, fields)
        db.commit()

        logger.info(
            "Core reset to pre-initialization state by %s (users=%d, roles=%d)",
            actor_user_id,
            len(user_snapshot),
            len(role_snapshot),
        )

        return ResetResponse(
            success=True,
            message="Core reset to pre-initialization state.",
        )
    except HTTPException:
        raise
    except Exception as e:
        # Log full detail (incl. any SQL) server-side; never leak it to the client.
        logger.exception("Core reset failed")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Reset failed",
        ) from e


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
        If admin role exists but has no enrolled members → supersede any
        abandoned PENDING enrollment and return a fresh challenge (Finding B:
        a device-less failed ceremony must not brick retry behind a reset).
    """

    from core.iam.models import Role, RoleMember, User

    from ..ca import CAExistsError, CAManager

    try:
        # #510: take the bootstrap lock BEFORE the "already initialized" count
        # below. Two concurrent step-1 calls used to read zero each and both
        # commit a pending admin, which is what lets two step-2 calls enroll.
        _lock_first_admin_bootstrap(db)

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

            # Finding B (init-pin-invalid-after-installation-reset): a PENDING
            # (unenrolled, no stored credential) admin is residue from a failed
            # ceremony — e.g. `venya init` with no key inserted commits this row
            # below, then raises Fido2NotFoundError before any authenticator
            # interaction. Rejecting here forced --installation-reset for a
            # harmless abandoned row. Only a COMPLETED enrollment is protected
            # (enrolled_count > 0, handled above); supersede the pending one(s)
            # and fall through to re-create with a fresh challenge.
            stale_pending = (
                db.query(User)
                .join(RoleMember, RoleMember.user_id == User.user_id)
                .filter(RoleMember.role_id == admin_role.id, User.enrolled_at.is_(None))
                .all()
            )
            for stale in stale_pending:
                db.query(RoleMember).filter(RoleMember.user_id == stale.user_id).delete()
                db.query(User).filter(User.user_id == stale.user_id).delete()
            if stale_pending:
                db.commit()
                # That commit ended the transaction, and with it the advisory
                # lock (#510): re-take it so the create below stays inside the
                # same serialization instead of falling outside it.
                _lock_first_admin_bootstrap(db)
                logger.info(
                    "Init step 1: superseded %d abandoned pending enrollment(s)",
                    len(stale_pending),
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

        # Idempotent get-or-create on roles.name: a re-init over a wiped-but-
        # roles-intact DB (the AGENTS.md re-enrollment recipe leaves roles, and a
        # fresh installer seeds them via migration) must not die on the
        # uq_roles_name UniqueViolation a bare INSERT would raise.
        admin_role = db.query(Role).filter(Role.name == "admin").first()
        if admin_role is None:
            admin_role = Role(
                name="admin",
                permissions="read-write",
                description="System administrator — full access",
            )
            db.add(admin_role)

        user_role = db.query(Role).filter(Role.name == "user").first()
        if user_role is None:
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
        audit_lifecycle(
            db,
            ADMIN_INITIALIZED,
            req.user_id,
            {"outcome": "pending_created", "roles_seeded": ["admin", "user"]},
        )
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
        # Log full detail (incl. any SQL) server-side; never leak it to the client.
        logger.exception("Core initialization failed")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Initialization failed",
        ) from e


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

    A core that already has an enrolled admin answers 409 here as well, not
    only at step 1: two bootstrap flows may each hold a pending row, and only
    one of them may enroll (#510).
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
            # Challenge<->user binding (sec-auth-elevation-authz-hardening #4):
            # the credential must belong to the same user this init complete
            # submission names — the challenge was bound to req.user_id at
            # init step 1; a cross-user challenge_id would split identities
            # between the in-memory store and the DB row.
            if cred.user_id != req.user_id:
                raise WebAuthnError("Registration challenge was issued for a different user")
        except WebAuthnError as e:
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
                detail="Registration failed",
            ) from e

        # Find the pending user matching the submitted user_id
        from core.iam.models import Role, RoleMember

        # #510: the lock goes out before the first read of this transaction, so
        # the re-check below and the enrollment write are one serialized step
        # against every other bootstrap caller — including a second uvicorn
        # worker on the same database.
        _lock_first_admin_bootstrap(db)

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

        # #510 AC3: re-check the initialized state HERE, inside the transaction
        # that writes the enrollment. Step 1's 409 is not enough on its own —
        # before this lock landed, two step-1 calls could both pass the
        # unlocked count and each keep its own pending row, and this route then
        # enrolled both, giving the core two first administrators. Order is
        # deliberate: the pending-row 400 above answers first (that is the
        # superseded-ceremony case the CLI already word-maps), and this refusal
        # comes before ANY write, so the loser stores no credential, no
        # recovery-code hash and no enrolled_at.
        if _enrolled_admin_present(db, admin_role.id):
            # Denial-side shape from audit_lifecycle's own docstring: this event
            # has no action riding on it, so the audit row commits before the
            # raise. Field table stays value-free and names no other principal —
            # /init is reachable unauthenticated, so a name here is an oracle.
            audit_lifecycle(
                db,
                FIRST_ADMIN_ENROLLED,
                req.user_id,
                {"outcome": "refused_already_initialized", "auth_mode": "webauthn", "recovery_code_issued": False},
            )
            db.commit()
            logger.warning(
                "Init step 2: refused enrollment for %s — this core already has an enrolled admin",
                req.user_id,
            )
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail=(
                    "Core already initialized with an enrolled admin; enrollment for "
                    f"'{req.user_id}' was refused. Use --installation-reset to start over."
                ),
            )

        # Store WebAuthn credential in database
        webauthn_cred = WebAuthnCredential(
            user_id=cred.user_id,
            credential_id=cred.credential_id,
            public_key=cred.public_key,
            sign_count=cred.sign_count,
            is_active=True,
            attestation_fmt=cred.attestation_fmt,
            aaguid=cred.aaguid,
            attestation_object=cred.attestation_object,
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
        audit_lifecycle(
            db,
            FIRST_ADMIN_ENROLLED,
            req.user_id,
            {"outcome": "enrolled", "auth_mode": "webauthn", "recovery_code_issued": True},
        )
        db.commit()

        # Persist in-memory entry only after the DB write succeeded
        # (#416 fix-shape (b)): a failed flush/commit leaves no store entry.
        fido2_manager.store.store_credential(cred)

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
        # Log full detail (incl. any SQL) server-side; never leak it to the client.
        logger.exception("Init completion failed")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Enrollment completion failed",
        ) from e
