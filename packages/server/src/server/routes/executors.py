# Copyright (c) 2026 Tabith LLC.
# Use of this source code is governed by the Business Source License 1.1
# included in the LICENSE file at the root of this repository. As of the
# Change Date listed there, the work is available under MPL 2.0.
# SPDX-License-Identifier: BUSL-1.1

"""Executor registration and certificate management endpoints.

Handles executor CSR submission, certificate signing, and revocation
list polling for mTLS-based executor authentication.
"""

import base64
import hashlib
import hmac
import json
import logging
import re
import socket
import ssl
from datetime import UTC, datetime, timedelta
from pathlib import Path
from uuid import uuid4

import httpx2
from core.iam.models import AuditEvent, Executor, ExecutorCert, ExecutorEnrollmentToken, User
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from fastapi import APIRouter, Depends, HTTPException, Request, status
from fastapi.responses import Response
from pydantic import BaseModel, Field, ValidationError
from sqlalchemy import text
from sqlalchemy.orm import Session
from venya_contract import ASKPASS_HELPER_PATH, RelayEnvVar, RelayRequest, RelayResponse, RelaySecret

from .. import metrics
from ..ca import CAManager
from ..dependencies import get_db, require_role
from ..middleware.auth import _extract_identity_from_subject
from ..rate_limit import rate_limit_registration
from ..revocation import executor_revocation_state
from ..utils.executor_id import EXECUTOR_ID_PATTERN
from ..utils.time import effective_expiry_check_time, is_expired
from .secrets import wrap_with_sentinel

# --- Env-shape gating (ticket secret-shape-env-injection) -------------------
# First release carrying relay `env` support. An executor reporting an older
# version — or NULL (a pre-version-reporting daemon, a distinct honest signal)
# — must NOT receive the new wire fields: old daemons validate extra="forbid"
# and would answer a mysterious 502, so the server refuses first with an
# actionable upgrade error (fail-loudly rule).
_ENV_SHAPE_MIN_VERSION = (0, 1, 0, "a", 13)


def _version_tuple(reported: str | None) -> tuple | None:
    """Parse a heartbeat-reported PEP 440 normalized version into a comparable tuple.

    ``X.Y.Z`` optionally followed by a prerelease tag (``a13``/``b1``/``rc2``) →
    ``(X, Y, Z, pre_kind, pre_n)``; final releases get pre_kind ``"z"`` so they
    sort after every prerelease tag. Unparseable or None → None (callers
    fail closed — never send new wire fields to an executor of unknown age).
    """
    if not reported:
        return None
    m = re.match(r"^(\d+)\.(\d+)\.(\d+)(?:([a-z]+)(\d+))?$", reported.strip())
    if not m:
        return None
    return (int(m.group(1)), int(m.group(2)), int(m.group(3)), m.group(4) or "z", int(m.group(5) or 0))


logger = logging.getLogger("venya.server")


def validate_csr_key_strength(csr: x509.CertificateSigningRequest) -> None:
    """Validate that the CSR's public key meets minimum strength requirements.

    Only ECDSA P-256, P-384, and P-521 are accepted.

    Args:
        csr: The parsed Certificate Signing Request.

    Raises:
        ValueError: If the key type or strength is insufficient.
    """
    public_key = csr.public_key()

    if not isinstance(public_key, ec.EllipticCurvePublicKey):
        raise ValueError(  # noqa: TRY004 — API input validation; ValueError → 400 at caller
            f"Unsupported key type: {type(public_key).__name__}. "
            f"Use ECDSA P-256 (secp256r1), P-384 (secp384r1), or P-521 (secp521r1)."
        )

    curve_name = public_key.curve.name
    if curve_name not in ("secp256r1", "secp384r1", "secp521r1"):
        raise ValueError(
            f"Weak or unsupported curve: {curve_name}. "
            f"Use ECDSA P-256 (secp256r1), P-384 (secp384r1), or P-521 (secp521r1)."
        )


router = APIRouter()


# --- Request/Response models ---


class ExecutorRegisterRequest(BaseModel):
    """Request body for executor registration."""

    executor_id: str = Field(
        ...,
        description="Unique executor identifier (lowercase alphanumeric + hyphens)",
        pattern=EXECUTOR_ID_PATTERN,
        min_length=2,
        max_length=64,
    )
    csr_pem: str = Field(..., description="PEM-encoded Certificate Signing Request", max_length=2048)
    enrollment_token: str | None = None
    hostname: str | None = Field(
        default=None,
        max_length=253,
        description=(
            "Accepted for backward compatibility but NOT used for the stored dial address. "
            "The server always records executor_id as the hostname, because the mTLS dial "
            "verifies the peer cert (whose SAN is forced to executor_id) against that address."
        ),
    )


class ExecutorRegisterResponse(BaseModel):
    """Response for successful executor registration."""

    executor_id: str
    cert_pem: str
    ca_cert_pem: str
    serial_number: str
    not_after: str


class RevocationListResponse(BaseModel):
    """Response for revocation list polling."""

    revoked_serials: list[str] = Field(default_factory=list, description="List of revoked certificate serial numbers")
    revoked_identities: list[str] = Field(
        default_factory=list,
        description=(
            "Executor IDs whose IDENTITY is revoked (terminal) — matches any serial. "
            "Additive field (executor-revocation-by-identity); older daemons ignore it."
        ),
    )


class HeartbeatRequest(BaseModel):
    """Request body for heartbeat ping."""

    executor_id: str = Field(
        ...,
        description="Executor identifier",
        pattern=EXECUTOR_ID_PATTERN,
        min_length=2,
        max_length=64,
    )
    cert_fingerprint: str = Field(default="", description="Certificate fingerprint")
    version: str = Field(
        default="",
        max_length=64,
        description=(
            "Executor dist version (ADDITIVE field, wire-compatible: missing or "
            "empty leaves the stored column untouched — pre-version daemons "
            "keep NULL, meaning 'has not reported yet')"
        ),
    )


class HeartbeatResponse(BaseModel):
    """Response for heartbeat ping."""

    revoked: bool = Field(default=False, description="Whether this executor has been revoked")
    new_cert_required: bool = Field(default=False, description="Whether a certificate rotation is needed")


class ExecutorInfo(BaseModel):
    """Executor status information."""

    id: str
    hostname: str
    online: bool
    last_heartbeat: datetime | None
    enrolled_at: datetime | None
    status: str
    version: str | None = None

    model_config = {"from_attributes": True}


class ExecutorsListResponse(BaseModel):
    """Response for executor list."""

    executors: list[ExecutorInfo]


# --- Execution session models ---


class SessionCreateRequest(BaseModel):
    """Request body for creating an execution session."""

    executor_id: str = Field(
        ...,
        description="Target executor ID",
        pattern=EXECUTOR_ID_PATTERN,
        min_length=2,
        max_length=64,
    )
    secret_keys: list[str] = Field(
        default_factory=list,
        description="Secret keys to resolve, wrap, and inject (server-side)",
    )


class SessionCreateResponse(BaseModel):
    """Response for execution session creation."""

    session_id: str
    executor_id: str
    created_at: str
    expires_at: str


class ExecuteRequest(BaseModel):
    """Request body for executing a command on an executor.

    This is the CLIENT -> SERVER inbound model (the FastAPI request body), a
    distinct contract from the server -> executor relay wire. It stays local by
    ruling (refactor-2): the relay wire shape lives in ``venya_contract`` and
    additionally carries the ``secrets`` list the server loads from the session.
    """

    session_id: str = Field(..., description="Execution session ID")
    command: str = Field(..., description="Shell command to execute")


# The relay response shape (executor -> server, and server -> client) is owned by
# venya_contract.RelayResponse — the previous local ExecuteResponse was a duplicate
# copy of that field set and is removed (refactor-2: no local re-declaration).


# --- Helpers ---


def _get_ca_manager(request: Request) -> CAManager:
    """Get the CA manager from app state."""
    ca_manager = getattr(request.app.state, "ca_manager", None)
    if ca_manager is None:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="CA not initialized",
        )
    return ca_manager


def _mark_execution_session_completed(
    db: Session,
    session_id: str,
    command: str,
    completed_at: datetime,
    result: dict,
) -> None:
    """Best-effort post-relay bookkeeping for an execution session.

    Uses a bulk ``UPDATE ... WHERE id=`` rather than mutating the loaded ORM object:
    a bulk UPDATE matching 0 rows is a silent no-op, whereas an ORM flush raises
    ``StaleDataError`` if the row vanished mid-execute — e.g. the
    ``cleanup_expired_execution_sessions`` maintenance pass deleting a session whose
    10-min TTL lapsed during a long relay (ticket execute-stale-session-update-500).
    The command already ran on the executor and the caller returns its result
    regardless; the caller commits the audit event in the same transaction, so the
    command stays audited even when this update no-ops.
    """
    res = db.execute(
        text(
            "UPDATE execution_sessions "
            "SET command = :command, completed_at = :completed_at, exit_code = :exit_code, "
            "stdout = :stdout, stderr = :stderr "
            "WHERE id = :sid"
        ),
        {
            "command": command,
            "completed_at": completed_at,
            "exit_code": result["exit_code"],
            "stdout": result["stdout"],
            "stderr": result["stderr"],
            "sid": session_id,
        },
    )
    if res.rowcount == 0:
        logger.warning(
            "Execution session %s vanished before post-relay bookkeeping (TTL cleanup "
            "race); command result returned, session update skipped",
            session_id,
        )


# --- Endpoints ---


def _dial_hostname_resolvable(hostname: str) -> bool:
    """True if hostname resolves locally.

    executor_id is the relay dial address (the client cert SAN is forced to
    it), so an unresolvable id produces an executor that registers and
    heartbeats but can never be called. Check at registration, not first use.
    """
    try:
        socket.getaddrinfo(hostname, None)
        return True
    except socket.gaierror:
        return False


def _verified_incumbent_serial(request: Request, executor_id: str) -> str | None:
    """Extract the verified mTLS client-cert serial for the incumbent exemption.

    Phase 2 (executor-rotation-require-token-400 ruling 2(a)). Trust boundary:
    nginx verifies the client chain against client-ca-bundle.crt (Root CA +
    Admin CA) and OVERWRITES X-Client-* from its own ssl variables — a
    client-sent header of the same name never survives the proxy, and with no
    (or an unverified) cert the serial variable is empty and nginx drops the
    header. The CN match is a discriminator, not the authorization: an
    Admin-CA cert CAN carry an executor-shaped CN, but only the true incumbent
    can present the Root-CA-issued record serial (random 64-bit at signing,
    no serial-chooser API exists). Returns the serial normalized to the
    record format (lowercase, 16-hex zero-padded — nginx sends uppercase and
    DER encoding may strip leading zero bytes), or None when no verified cert
    for this executor_id was presented.
    """
    if request.headers.get("x-client-verified") != "SUCCESS":
        return None
    presented = request.headers.get("x-client-serial", "").strip()
    if not presented:
        return None
    if _extract_identity_from_subject(request.headers.get("x-client-subject", "")) != executor_id:
        return None
    try:
        return format(int(presented, 16), "016x")
    except ValueError:
        return None


def _incumbent_exemption_applies(db: Session, executor_id: str, presented_serial: str) -> bool:
    """Ruled exemption order (do not reorder): revocation state FIRST, then
    presented == current record serial. executor_revocation_state is the ONE
    revocation source (revocation.py contract names this consumer); a second
    implementation here would be a rotation/revocation split-brain.
    """
    if executor_revocation_state(db, executor_id, presented_serial=presented_serial).revoked:
        return False
    cert = db.query(ExecutorCert).filter(ExecutorCert.executor_id == executor_id).first()
    return cert is not None and (cert.serial_number or "").casefold() == presented_serial


@router.post(
    "/executors/register",
    response_model=ExecutorRegisterResponse,
    status_code=status.HTTP_201_CREATED,
)
async def register_executor(
    req: ExecutorRegisterRequest,
    request: Request,
    _rl: None = Depends(rate_limit_registration),
    db: Session = Depends(get_db),
) -> ExecutorRegisterResponse:
    """Register an executor and obtain a signed mTLS certificate.

    The executor submits a CSR (Certificate Signing Request) signed with
    its temporary keypair. The server signs it with the CA and returns
    the signed certificate plus the CA certificate for verification.

    Also creates a corresponding user account for the executor.
    """
    ca_manager = _get_ca_manager(request)

    # Parse the CSR
    try:
        csr = x509.load_pem_x509_csr(req.csr_pem.strip().encode())
    except Exception:
        metrics.EXECUTOR_REGISTERED.labels(result="invalid_csr").inc()
        logger.exception("CSR parse failed for executor registration")
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid CSR",
        )

    # Validate key strength — reject weak keys before any CA/DB work
    try:
        validate_csr_key_strength(csr)
    except ValueError as e:
        metrics.EXECUTOR_REGISTERED.labels(result="weak_key").inc()
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e),
        )

    # executor_id is the relay dial hostname + cert SAN — reject undialable ids
    # before any CA/DB work (fail at install time, not at first run_command)
    if not _dial_hostname_resolvable(req.executor_id):
        metrics.EXECUTOR_REGISTERED.labels(result="unresolvable_id").inc()
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=(
                f"executor_id '{req.executor_id}' does not resolve. The executor_id is used "
                "as the relay dial hostname and certificate SAN — it must be resolvable "
                "from every core (DNS or /etc/hosts), e.g. the executor's real hostname."
            ),
        )

    # --- Token validation (optional bootstrap auth) ---
    resolved_executor_id = req.executor_id
    token_audit_fields = {}

    if req.enrollment_token:
        pepper = getattr(getattr(request.app.state, "config", None), "recovery_code_pepper", "") or ""
        token_hash = hmac.new(
            pepper.encode("utf-8"),
            req.enrollment_token.encode("utf-8"),
            hashlib.sha256,
        ).hexdigest()

        # Pre-check for diagnostic specificity (non-authoritative)
        token = db.query(ExecutorEnrollmentToken).filter(ExecutorEnrollmentToken.token_hash == token_hash).first()

        if token is None:
            metrics.TOKEN_CONSUMED.labels(result="invalid").inc()
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid enrollment token",
            )
        if token.state == "revoked":
            metrics.TOKEN_CONSUMED.labels(result="revoked").inc()
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Enrollment token has been revoked",
            )
        if token.state == "consumed":
            if token.executor_id == req.executor_id:
                metrics.TOKEN_CONSUMED.labels(result="consumed").inc()
                raise HTTPException(
                    status_code=status.HTTP_409_CONFLICT,
                    detail="Executor already registered with this enrollment token. "
                    "Check if the previous registration succeeded.",
                )
            metrics.TOKEN_CONSUMED.labels(result="consumed").inc()
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Enrollment token has already been consumed by a different executor",
            )
        server_config = getattr(request.app.state, "config", None)
        tolerance = (
            server_config.clock_skew.token_tolerance_seconds
            if server_config and hasattr(server_config, "clock_skew")
            else 60
        )
        if is_expired(token.expires_at, tolerance):
            metrics.TOKEN_CONSUMED.labels(result="expired").inc()
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Enrollment token has expired",
            )

        if token.executor_id != req.executor_id:
            metrics.TOKEN_CONSUMED.labels(result="binding_mismatch").inc()
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Enrollment token bound to different executor_id",
            )

        # Authoritative atomic consumption — closes race window
        now_minus_tolerance = effective_expiry_check_time(tolerance)
        result = db.execute(
            text(
                """
                UPDATE executor_enrollment_tokens
                SET state = 'consumed', used_at = :now
                WHERE token_hash = :hash AND state = 'created' AND expires_at > :now
            """
            ),
            {"hash": token_hash, "now": now_minus_tolerance},
        )

        if result.rowcount != 1:
            # Lost the race — token was consumed between pre-check and UPDATE
            # Re-read to determine why
            token = db.query(ExecutorEnrollmentToken).filter(ExecutorEnrollmentToken.token_hash == token_hash).first()
            if token is None:
                metrics.TOKEN_CONSUMED.labels(result="invalid").inc()
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Enrollment token not found",
                )
            elif token.state == "revoked":
                metrics.TOKEN_CONSUMED.labels(result="revoked").inc()
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Enrollment token has been revoked",
                )
            elif token.state == "consumed":
                metrics.TOKEN_CONSUMED.labels(result="consumed").inc()
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Enrollment token was consumed concurrently",
                )
            else:
                metrics.TOKEN_CONSUMED.labels(result="expired").inc()
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Enrollment token is invalid or expired",
                )

        resolved_executor_id = token.executor_id
        token_audit_fields = {"with_token": True, "token_verified": True, "token_id": token.id}
        logger.info("Enrollment token verified for executor: %s", resolved_executor_id)
    else:
        server_config = getattr(request.app.state, "config", None)
        if server_config and server_config.executor_enrollment.require_token:
            # Phase 2 incumbent exemption (ruling 2(a)): tokenless rotate is
            # accepted ONLY from the verified current-record credential —
            # revocation state first, then serial match (see helper).
            incumbent_serial = _verified_incumbent_serial(request, req.executor_id)
            if incumbent_serial is None or not _incumbent_exemption_applies(db, req.executor_id, incumbent_serial):
                metrics.EXECUTOR_REGISTERED.labels(result="token_required").inc()
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="Enrollment token required. Contact your administrator.",
                )
            token_audit_fields = {"with_token": False, "incumbent_exempt": True}
        else:
            token_audit_fields = {"with_token": False}

    # Terminal identity check (executor-revocation-by-identity, ruling 3/condition 4):
    # a revoked identity can NEVER re-register — even with a valid fresh token,
    # which by this point is already consumed by validation (recorded behavior:
    # admin sees a consumed token + 403; re-enrollment requires a NEW
    # executor_id). Fires before cert issuance and any identity DB write.
    # Serial-history revocation does NOT block here: killing a credential must
    # not kill re-enrollment (that is what the identity form is for).
    _terminal = executor_revocation_state(db, resolved_executor_id)
    if _terminal.reason == "identity":
        metrics.EXECUTOR_REGISTERED.labels(result="identity_revoked").inc()
        logger.warning("Registration rejected — executor identity revoked (terminal): %s", resolved_executor_id)
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=(
                f"Executor identity '{resolved_executor_id}' is revoked (terminal). "
                "Re-enroll under a NEW executor_id; this identity cannot be reused."
            ),
        )

    # Create executor user account if it doesn't exist
    existing_user = db.query(User).filter(User.user_id == resolved_executor_id).first()
    if existing_user is None:
        # Auto-create executor user account
        new_user = User(
            user_id=resolved_executor_id,
            auth_mode="mtls",
        )
        db.add(new_user)
        db.flush()
        logger.info("Auto-created executor user: %s", resolved_executor_id)
    else:
        # Update auth mode if it was something else
        if existing_user.auth_mode != "mtls":
            existing_user.auth_mode = "mtls"

    # Sign the CSR
    try:
        server_config = getattr(request.app.state, "config", None)
        crl_url = server_config.crl.crl_url if server_config and hasattr(server_config, "crl") else None
        cert = ca_manager.sign_csr(csr, resolved_executor_id, crl_url=crl_url)
        metrics.CA_SIGNED_TOTAL.labels(cert_type="executor").inc()
    except RuntimeError as e:
        metrics.EXECUTOR_REGISTERED.labels(result="ca_error").inc()
        logger.error("CA signing failed for %s: %s", resolved_executor_id, e)
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Certificate signing unavailable",
        )

    # Store certificate metadata
    serial_hex = ca_manager.compute_serial_hex(cert.serial_number)
    fingerprint = ca_manager.compute_fingerprint(cert)

    existing_cert = db.query(ExecutorCert).filter(ExecutorCert.executor_id == resolved_executor_id).first()

    cert_record = ExecutorCert(
        executor_id=resolved_executor_id,
        serial_number=serial_hex,
        not_before=cert.not_valid_before_utc,
        not_after=cert.not_valid_after_utc,
        fingerprint=fingerprint,
    )

    if existing_cert:
        # F6 auto-revoke (executor-revocation-by-identity ruling 1): the
        # replaced predecessor serial is CRLed IN THE SAME TRANSACTION — normal
        # operation must not mint off-record chain-valid orphans, and a diverged
        # daemon still running the predecessor dies within one poll (fail-closed).
        old_serial = (existing_cert.serial_number or "").casefold()
        if old_serial and old_serial != serial_hex.casefold():
            from core.iam.models import ExecutorCertRevocation

            prior = db.query(ExecutorCertRevocation).filter(ExecutorCertRevocation.serial_number == old_serial).first()
            if prior is None:
                db.add(
                    ExecutorCertRevocation(
                        serial_number=old_serial,
                        executor_id=resolved_executor_id,
                        revoked_at=datetime.now(UTC),
                        reason="Replaced by re-registration/rotation",
                    )
                )
        # Update existing cert record
        existing_cert.serial_number = serial_hex
        existing_cert.not_before = cert.not_valid_before_utc
        existing_cert.not_after = cert.not_valid_after_utc
        existing_cert.fingerprint = fingerprint
    else:
        db.add(cert_record)

    # Audit event for registration
    audit_event = AuditEvent(
        event_type="executor_registered",
        user_id=None,
        fields={
            "executor_id": resolved_executor_id,
            "serial_number": serial_hex,
            **token_audit_fields,
        },
        timestamp=datetime.now(UTC),
    )
    db.add(audit_event)

    # Upsert the Executor status row so GET /api/v1/executors has data.
    # Hostname = cert identity (executor_id): the mTLS dial verifies the peer cert
    # (SAN forced to executor_id) against this address, so they must match.
    # req.hostname is NOT the stored dial address.
    now_ts = datetime.now(UTC)
    existing_executor = db.query(Executor).filter(Executor.id == resolved_executor_id).first()
    if existing_executor is not None:
        existing_executor.hostname = resolved_executor_id
        if existing_executor.enrolled_at is None:
            existing_executor.enrolled_at = now_ts
        existing_executor.status = "active"
    else:
        db.add(
            Executor(
                id=resolved_executor_id,
                hostname=resolved_executor_id,
                enrolled_at=now_ts,
                status="active",
            )
        )

    try:
        db.commit()
        metrics.EXECUTOR_REGISTERED.labels(result="success").inc()

        # Return signed certificate + CA chain
        cert_pem = cert.public_bytes(serialization.Encoding.PEM).decode()
        ca_cert_pem = ca_manager.get_ca_cert_pem().decode()

        return ExecutorRegisterResponse(
            executor_id=resolved_executor_id,
            cert_pem=cert_pem,
            ca_cert_pem=ca_cert_pem,
            serial_number=serial_hex,
            not_after=cert.not_valid_after_utc.isoformat(),
        )
    except HTTPException:
        metrics.EXECUTOR_REGISTERED.labels(result="db_error").inc()
        raise
    except Exception:
        metrics.EXECUTOR_REGISTERED.labels(result="db_error").inc()
        logger.exception("Registration failed — token state rolled back")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Registration failed",
        )


@router.get(
    "/executors/certs/revocation-list",
    response_model=RevocationListResponse,
)
async def get_revocation_list(
    request: Request,
    db: Session = Depends(get_db),
) -> Response:
    """Get the list of revoked certificate serial numbers.

    Executors poll this endpoint periodically (~every 30s, daemon main loop) to check
    if their certificate has been revoked. Supports conditional GET
    via ETag for caching — returns 304 Not Modified when the list
    has not changed.
    """
    from core.iam.models import ExecutorCertRevocation

    # READ-ONLY (ticket sec-sweep-low-informational #23b): this public GET
    # used to purge expired revocations on every poll (~30s x fleet) — an
    # unauthenticated write-on-read. The purge now runs as a maintenance-loop
    # pass (maintenance.run_maintenance, 5-minute schedule).

    # Fetch remaining revocations
    revocations = db.query(ExecutorCertRevocation).all()
    serials = sorted([r.serial_number for r in revocations])
    # Identity-level revocations (terminal flag on the Executor row) ride
    # alongside the serial history — additive wire field, ETag covers BOTH.
    identities = sorted(row[0] for row in db.query(Executor.id).filter(Executor.revoked_at.isnot(None)).all())
    payload = json.dumps({"s": serials, "i": identities}, sort_keys=True).encode()
    etag = f'"{hashlib.sha256(payload).hexdigest()}"'

    if request.headers.get("if-none-match") == etag:
        return Response(status_code=304, headers={"ETag": etag})

    return Response(
        content=json.dumps({"revoked_serials": serials, "revoked_identities": identities}).encode(),
        media_type="application/json",
        headers={
            "ETag": etag,
            "Cache-Control": "max-age=300",
        },
    )


@router.get(
    "/executors/certs/crl",
)
async def get_crl(
    request: Request,
    db: Session = Depends(get_db),
) -> Response:
    """Get the signed Certificate Revocation List in DER format.

    Public endpoint — no authentication required. READ-ONLY: the expired-
    revocation purge moved to the maintenance loop (ticket
    sec-sweep-low-informational #23b — public GETs must not write).
    Supports conditional GET via ETag for caching.
    """
    from core.iam.models import ExecutorCertRevocation

    ca_manager = _get_ca_manager(request)
    crl_der = ca_manager.generate_crl(db)
    metrics.CA_CRL_GENERATED_TOTAL.inc()

    # ETag based on serial numbers only (CRL timestamps change every request)
    serials = sorted([r.serial_number for r in db.query(ExecutorCertRevocation).all()])
    etag_payload = json.dumps(serials, sort_keys=True).encode()
    etag = f'"{hashlib.sha256(etag_payload).hexdigest()}"'

    if request.headers.get("if-none-match") == etag:
        return Response(status_code=304, headers={"ETag": etag})

    # Lazy zstd import with Accept-Encoding validation and graceful fallback
    accept_encoding = request.headers.get("Accept-Encoding", "")
    use_zstd = "zstd" in accept_encoding

    if use_zstd:
        try:
            from compression import zstd

            compressed = zstd.compress(crl_der, level=3)
        except Exception:
            use_zstd = False

    if use_zstd:
        return Response(
            content=compressed,
            media_type="application/pkix-crl",
            headers={
                "Content-Encoding": "zstd",
                "ETag": etag,
                "Cache-Control": "max-age=30",
                "Vary": "Accept-Encoding",
            },
        )
    else:
        return Response(
            content=crl_der,
            media_type="application/pkix-crl",
            headers={
                "ETag": etag,
                "Cache-Control": "max-age=30",
                "Vary": "Accept-Encoding",
            },
        )


@router.post(
    "/heartbeat",
    response_model=HeartbeatResponse,
    status_code=status.HTTP_200_OK,
)
async def heartbeat(
    req: HeartbeatRequest,
    request: Request,
    db: Session = Depends(get_db),
) -> HeartbeatResponse:
    """Receive heartbeat from executor.

    Executors POST to this endpoint every 30s to signal liveness.
    The server responds with revocation status and cert rotation hint.

    Executor-mTLS gated (ticket sec-endpoint-ratelimit-hardening #7 — was
    PUBLIC: an unauthenticated caller could liveness-stamp any executor row
    and read the fleet revocation/rotation oracle). The middleware verifies
    the client cert (registered, chain-valid CN); this route binds the body
    executor_id to the cert CN so an executor can only stamp ITS OWN row.
    The `revoked` flag is computed from the SHARED revocation state and is a
    fast cooperative stop signal (F3 ride-along — a revoked executor still
    gets its 200 {revoked:true}, the middleware passes it through with
    reject_revoked=False); the enforcing control is the dial-gate refusal in
    create_execution_session/execute (ruling 4).
    """
    from core.iam.models import ExecutorCert

    # Defense-in-depth (mirrors routes/filter.py): the middleware is the choke
    # point that VERIFIES the executor mTLS identity; this check keeps the
    # route from being naked if mounted without it.
    caller = getattr(request.state, "auth_user", {})
    if caller.get("caller") != "executor":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Executor mTLS authentication required",
        )
    # Identity binding: the beat must describe the CERT holder, not an
    # arbitrary row (closes the forged-liveness oracle).
    if req.executor_id != caller.get("executor_id"):
        logger.warning(
            "Heartbeat body executor_id '%s' does not match cert CN '%s' — rejecting",
            req.executor_id,
            caller.get("executor_id"),
        )
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="executor_id does not match client certificate",
        )

    executor_id = req.executor_id
    revoked = False
    new_cert_required = False

    if executor_id:
        # Revoked-ness comes from the SHARED state (executor-revocation-by-identity
        # condition 2 — this computation was a second, record-pointer-only
        # implementation; the helper adds the identity flag).
        revoked = executor_revocation_state(db, executor_id).revoked

        # Rotation hint still reads the record's expiry
        current_cert = db.query(ExecutorCert).filter(ExecutorCert.executor_id == executor_id).first()

        if current_cert:

            # Check if cert needs rotation (within 3 days of expiry)
            now = datetime.now(UTC)
            expiry_threshold = now + timedelta(days=3)
            not_after = current_cert.not_after
            if not_after.tzinfo is None:
                not_after = not_after.replace(tzinfo=UTC)
            if not_after < expiry_threshold:
                new_cert_required = True

    # Liveness timestamp for GET /api/v1/executors — only when the executor row
    # already exists (registration creates it; heartbeats never create rows).
    # REVOKED-WRITE GUARD (user ruling 2026-09-20, ticket
    # sec-endpoint-ratelimit-hardening B1): a revoked executor gets its
    # advisory 200 {revoked:true} but writes NOTHING — a body-driven
    # status="active" stamp from a revoked identity could overwrite or race
    # the revoked presentation in list_executors, resurrecting exactly the
    # confusion the identity-revocation work ended. The row is about to die
    # administratively anyway.
    if executor_id and not revoked:
        executor_row = db.query(Executor).filter(Executor.id == executor_id).first()
        if executor_row is not None:
            executor_row.last_heartbeat = datetime.now(UTC)
            executor_row.status = "active"
            # Additive wire field (feature/version-surfaces): only a non-empty
            # report touches the column — absence/empty NEVER overwrites or
            # NULLs a previously reported version (pre-version daemons keep NULL).
            if req.version:
                executor_row.version = req.version
            db.commit()

    metrics.EXECUTOR_HEARTBEAT_TOTAL.inc()
    return HeartbeatResponse(
        revoked=revoked,
        new_cert_required=new_cert_required,
    )


@router.get(
    "/executors",
    response_model=ExecutorsListResponse,
)
async def list_executors(
    db: Session = Depends(get_db),
    auth_user: dict = Depends(require_role("read")),
) -> ExecutorsListResponse:
    """List registered executors and their availability.

    For operators and LLMs to discover available execution targets.
    Does not expose enrollment tokens, CA details, or admin metadata.

    Online status: true if heartbeat within the last 60 seconds.
    """
    from core.iam.models import Executor

    executors = db.query(Executor).all()

    result = []
    now = datetime.now(UTC)

    for exec_rec in executors:
        is_online = False
        if exec_rec.last_heartbeat:
            delta = now - exec_rec.last_heartbeat
            is_online = delta.total_seconds() < 60

        # Status display is a CLIENT of the shared revocation state (condition 2
        # — no second revoked-ness implementation). Note: this also surfaces
        # serial-form revocation of the CURRENT record serial as "revoked",
        # consistent with the dial refusal.
        _rev = executor_revocation_state(db, exec_rec.id, executor_row=exec_rec)
        if _rev.revoked:
            status = "revoked"
        elif exec_rec.enrolled_at:
            status = "active"
        else:
            status = "inactive"

        result.append(
            ExecutorInfo(
                id=exec_rec.id,
                hostname=exec_rec.hostname,
                online=is_online,
                last_heartbeat=exec_rec.last_heartbeat,
                enrolled_at=exec_rec.enrolled_at,
                status=status,
                version=exec_rec.version,
            )
        )

    return ExecutorsListResponse(executors=result)


@router.post(
    "/executors/sessions",
    response_model=SessionCreateResponse,
    status_code=status.HTTP_201_CREATED,
)
async def create_execution_session(
    req: SessionCreateRequest,
    request: Request,
    db: Session = Depends(get_db),
    auth_user: dict = Depends(require_role("read-write")),
) -> SessionCreateResponse:
    """Create an execution session from secret keys.

    Called by CLI/MCP before executing a command. The server resolves each
    key, decrypts, and sentinel-wraps the value server-side; clients never
    send or receive wrapped values.
    """
    from core.iam.models import ExecutionSession, Executor, SessionSecret

    core = getattr(request.app.state, "core", None)
    if core is None:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Core not initialized",
        )

    # Verify executor exists
    executor = db.query(Executor).filter(Executor.id == req.executor_id).first()
    if executor is None:
        raise HTTPException(status_code=404, detail="Executor not found")

    # Dial gate (executor-revocation-by-identity ruling 4 — the enforcement
    # point that actually stops an uncooperative daemon): shared revocation
    # state governs — identity flag OR current-record serial in the CRL
    # (condition 1: a serial-form revocation of the record serial refuses too).
    _rev = executor_revocation_state(db, req.executor_id, executor_row=executor)
    if _rev.revoked:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Executor '{req.executor_id}' is revoked ({_rev.reason}) — refusing to route execution",
        )

    # Create session with 10-minute TTL
    now = datetime.now(UTC)
    session = ExecutionSession(
        id=str(uuid4()),
        user_id=auth_user["user_id"],
        executor_id=req.executor_id,
        command="",  # Will be set on execute
        created_at=now,
        expires_at=now + timedelta(minutes=10),
    )
    db.add(session)

    # Resolve, wrap, and store secrets server-side (single transaction).
    # Visibility is enforced via core.get_for_injection: a secret resolves iff
    # one of the caller's roles is in its scope OR the caller created it; a
    # scoped-out key 404s indistinguishably from a nonexistent one (no
    # cross-role key-name enumeration). No admin bypass.
    from core.engine.core import CoreAccessError
    from core.iam.role_manager import RoleManager

    rm = RoleManager(db)
    caller_roles = [m.role.name for m in rm.get_user_roles(auth_user["user_id"])]

    mismatched_keys: list[str] = []
    for key in req.secret_keys:
        try:
            secret_id, plaintext, meta = core.get_for_injection(key, auth_user["user_id"], caller_roles)
        except CoreAccessError:
            raise HTTPException(status_code=404, detail=f"Secret '{key}' not found")
        except Exception:
            logger.exception("Failed to decrypt secret '%s' for session %s", key, session.id)
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="Secret decryption unavailable",
            )

        # metadata.executor is an organizational hint; mismatch warns, does not block
        declared = meta.get("executor")
        if declared and declared != req.executor_id:
            mismatched_keys.append(key)
            logger.warning(
                "Session %s: secret '%s' metadata.executor=%s != executor_id=%s (user=%s)",
                session.id,
                key,
                declared,
                req.executor_id,
                auth_user["user_id"],
            )

        db.add(
            SessionSecret(
                session_id=session.id,
                secret_id=secret_id,
                wrapped_value=wrap_with_sentinel(key, plaintext.encode("utf-8")),
            )
        )

    # AUDIT EVENT: Session created
    audit_event = AuditEvent(
        event_type="execution_session_created",
        user_id=auth_user["user_id"],
        fields={
            "session_id": session.id,
            "executor_id": req.executor_id,
            "secret_keys": req.secret_keys,
            "metadata_mismatch": mismatched_keys,
        },
        timestamp=now,
    )
    db.add(audit_event)

    db.commit()

    return SessionCreateResponse(
        session_id=session.id,
        executor_id=session.executor_id,
        created_at=session.created_at.isoformat(),
        expires_at=session.expires_at.isoformat(),
    )


@router.post(
    "/executors/{id}/execute",
    response_model=RelayResponse,
    status_code=status.HTTP_200_OK,
)
async def execute_command_on_executor(
    id: str,
    req: ExecuteRequest,
    request: Request,
    db: Session = Depends(get_db),
    auth_user: dict = Depends(require_role("read-write")),
) -> RelayResponse:
    """Relay command to executor over mTLS.

    1. Verify session exists and is not expired
    2. Load wrapped secrets from session
    3. POST to executor's /execute endpoint (mTLS)
    4. Buffer response, mask output, return
    """
    from core.iam.models import ExecutionSession, Executor, SessionSecret

    # Lookup session
    session = db.query(ExecutionSession).filter(ExecutionSession.id == req.session_id).first()
    if session is None:
        raise HTTPException(status_code=404, detail="Session not found")

    # Check expiration
    if datetime.now(UTC) > session.expires_at:
        raise HTTPException(status_code=400, detail="Session expired")

    # Verify session ownership
    if session.user_id != auth_user["user_id"]:
        raise HTTPException(status_code=403, detail="Session does not belong to user")

    # Verify session is bound to this executor
    if session.executor_id != id:
        raise HTTPException(status_code=403, detail="Session was created for a different executor")

    # Load executor hostname (required for mTLS relay, non-nullable)
    executor = db.query(Executor).filter(Executor.id == id).first()
    if executor is None:
        raise HTTPException(status_code=404, detail="Executor not found")

    # Dial gate #2 (execute): the session may predate the revocation — the
    # shared state is re-checked at relay time, not only at session create.
    _rev = executor_revocation_state(db, id, executor_row=executor)
    if _rev.revoked:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Executor '{id}' is revoked ({_rev.reason}) — refusing to route execution",
        )

    # Load wrapped secrets from session
    secrets = db.query(SessionSecret).filter(SessionSecret.session_id == session.id).all()

    # Shape-derived env entries (ticket secret-shape-env-injection): only when
    # the session carries secrets — the metadata query is lazy so the common
    # no-secret path stays a single round-trip. shape=env:NAME derives a relay
    # env entry referencing the secret; shape=askpass derives the helper
    # wiring. Everything else stays file-injection only.
    env_entries: list[RelayEnvVar] = []
    askpass = False
    if secrets:
        from core.iam.models import Secret

        metas = {
            row.id: (row.meta or {})
            for row in db.query(Secret).filter(Secret.id.in_([s.secret_id for s in secrets])).all()
        }
        for ss in secrets:
            meta = metas.get(ss.secret_id, {})
            shape = meta.get("shape")
            if not isinstance(shape, str):
                continue
            if shape.startswith("env:"):
                # Newline pre-check on our own sentinel wrap ([VENYA:hash8]b64[/VENYA])
                # so the operator gets an actionable 422 HERE instead of a flat
                # executor-side 503 (the env-file format is line-based).
                try:
                    inner = ss.wrapped_value.split("]", 1)[1].rsplit("[/VENYA]", 1)[0]
                    plaintext = base64.b64decode(inner).decode("utf-8")
                except Exception:  # undecodable → the executor fails loudly later; never guessed here
                    plaintext = None
                if plaintext is not None and ("\n" in plaintext or "\r" in plaintext):
                    raise HTTPException(
                        status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                        detail=(
                            f"Secret id {ss.secret_id} (shape '{shape}') contains a newline — env shapes "
                            "are single-line only (the sandbox env-file format is line-based). Re-store "
                            "the value without embedded newlines, or use a file-based shape."
                        ),
                    )
                try:
                    env_entries.append(RelayEnvVar(var_name=shape[4:], secret_id=ss.secret_id))
                except ValueError as exc:  # contract validation (bad identifier)
                    raise HTTPException(
                        status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                        detail=f"Secret id {ss.secret_id} has an invalid env shape '{shape}': {exc}",
                    ) from exc
            elif shape == "askpass":
                askpass = True
                env_entries.append(RelayEnvVar(var_name="GIT_ASKPASS", literal_value=ASKPASS_HELPER_PATH))
                env_entries.append(RelayEnvVar(var_name="SSH_ASKPASS", literal_value=ASKPASS_HELPER_PATH))
                env_entries.append(
                    RelayEnvVar(
                        var_name="VENYA_ASKPASS_SECRET",
                        literal_value=f"/run/secrets/venya/{ss.secret_id}",
                    )
                )
                username = meta.get("username")
                if isinstance(username, str) and username:
                    env_entries.append(RelayEnvVar(var_name="VENYA_ASKPASS_USER", literal_value=username))

    # Version gate BEFORE dialing: never send the new wire fields to an
    # executor that cannot parse them (old daemons validate extra="forbid"
    # and would answer a mysterious 502 — fail loudly, name the upgrade).
    if env_entries or askpass:
        vt = _version_tuple(executor.version)
        if vt is None or vt < _ENV_SHAPE_MIN_VERSION:
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                detail=(
                    f"Executor '{id}' reports version "
                    f"{executor.version or 'unknown (pre-version-reporting daemon)'}, which predates "
                    "env-shape support (requires >= 0.1.0a13). Upgrade the executor (installer re-run) "
                    "or use a file-based shape."
                ),
            )

    # Build request payload via the frozen relay contract (venya_contract) — the
    # server and executor both import these models, so a one-sided field change is
    # an import/type error here, not a runtime 500 at the executor boundary.
    payload = RelayRequest(
        session_id=session.id,
        command=req.command,
        secrets=[RelaySecret(secret_id=s.secret_id, wrapped_value=s.wrapped_value) for s in secrets],
        env=env_entries,
        askpass_helper=askpass,
    ).model_dump()
    if not env_entries and not askpass:
        # Byte-identical to the pre-env wire shape when no env shape is in play:
        # old executors keep parsing every regular request untouched.
        payload.pop("env", None)
        payload.pop("askpass_helper", None)

    # Construct executor URL from hostname
    executor_url = f"https://{executor.hostname}:8443/execute"

    # Set up mTLS client
    config = getattr(request.app.state, "config", None)
    ca_cert_path = str(Path(config.ca_dir) / "ca.crt") if config else None
    mtls_cert = config.mtls_cert if config else None
    mtls_key = config.mtls_key if config else None

    # OSError also catches ssl.SSLError (corrupt cert contents) — keep broad deliberately
    try:
        ssl_ctx = ssl.create_default_context()
        ssl_ctx.load_verify_locations(ca_cert_path)
        if mtls_cert and mtls_key:
            ssl_ctx.load_cert_chain(mtls_cert, mtls_key)
    except (OSError, TypeError) as e:
        logger.warning("TLS misconfiguration: %s", e)
        raise HTTPException(status_code=503, detail="Server TLS misconfiguration")

    # Call executor with mTLS
    try:
        async with httpx2.AsyncClient(verify=ssl_ctx, timeout=300) as client:
            response = await client.post(executor_url, json=payload)
            response.raise_for_status()
            result = response.json()
    except httpx2.ConnectError as e:
        # Walk cause chain (httpx may wrap SSLError/gaierror one or more levels deep)
        _c, _d = (e.__cause__ or e.__context__), 0
        while _c and _d < 5 and not isinstance(_c, (ssl.SSLError, socket.gaierror)):
            _c, _d = (_c.__cause__ or _c.__context__), _d + 1
        if _c and isinstance(_c, ssl.SSLError):
            logger.warning("mTLS verification failed: %s", _c)
            raise HTTPException(status_code=503, detail="mTLS verification failed")
        if _c and isinstance(_c, socket.gaierror):
            logger.warning("Executor hostname does not resolve: %s", executor.hostname)
            raise HTTPException(
                status_code=503,
                detail=f"Executor hostname does not resolve: {executor.hostname}",
            )
        raise HTTPException(status_code=503, detail="Executor unreachable (connection refused)")
    except httpx2.TimeoutException:
        raise HTTPException(status_code=503, detail="Executor timed out")
    except httpx2.RemoteProtocolError as e:
        # Executor died mid-response (e.g. daemon SEGV): peer closed without a
        # complete HTTP message. Sibling of ConnectError/TimeoutException under
        # TransportError — same 503 class (ticket d1-remote-protocol-error-500).
        logger.warning("Executor connection lost mid-response for session %s: %s", session.id, e)
        raise HTTPException(status_code=503, detail="Executor unreachable (connection lost mid-response)")
    except httpx2.HTTPStatusError as e:
        logger.warning("Executor returned HTTP %d for session %s: %s", e.response.status_code, session.id, e)
        raise HTTPException(status_code=e.response.status_code, detail="Executor returned an error")

    # Validate executor response shape before any field access
    try:
        result = RelayResponse(**result).model_dump()
    except ValidationError as e:
        # Body-fragment-free log (sec-secret-redaction-log-leaks #11): the
        # ValidationError repr embeds input_value= fragments of the relay
        # RESPONSE body — this hop must never reach a logger (Stage-2 sign-off
        # invariant), and prefixless content is invisible to the
        # RedactingFormatter layer-2. Log the offending field names + error
        # types only (diagnosability kept, body dropped).
        scrubbed = ", ".join(f"{'.'.join(str(p) for p in err['loc'])}: {err['type']}" for err in e.errors())
        logger.warning("Invalid executor response for session %s (fields: %s)", session.id, scrubbed)
        raise HTTPException(status_code=502, detail="Invalid response from executor")

    # AUDIT EVENT: Command executed
    now = datetime.now(UTC)
    audit_event = AuditEvent(
        event_type="command_executed",
        user_id=auth_user["user_id"],
        fields={
            "session_id": session.id,
            "executor_id": id,
            "command": req.command,
            "exit_code": result["exit_code"],
            "masked_count": result.get("masked_count", 0),
        },
        timestamp=now,
    )
    db.add(audit_event)

    # Mark session as completed via a bulk UPDATE that tolerates a row that vanished
    # mid-execute (ticket execute-stale-session-update-500) — an ORM flush here raised
    # StaleDataError -> 500 after the command already ran. The audit event above commits
    # atomically in the same transaction.
    _mark_execution_session_completed(db, session.id, req.command, now, result)
    db.commit()

    return RelayResponse(**result)
