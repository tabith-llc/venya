"""Executor registration and certificate management endpoints.

Handles executor CSR submission, certificate signing, and revocation
list polling for mTLS-based executor authentication.
"""

from __future__ import annotations

import hashlib
import logging

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from datetime import datetime, timedelta, timezone
from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel, Field
from sqlalchemy import text
from sqlalchemy.orm import Session

from ..ca import CAManager
from ..rate_limit import rate_limit_registration
from ..utils.executor_id import EXECUTOR_ID_PATTERN, validate_executor_id
from ..utils.token_binding import verify_binding_hash
from vault.iam.models import AuditEvent, ExecutorEnrollmentToken, User, ExecutorCert

logger = logging.getLogger("venya.server")

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
    csr_pem: str = Field(..., description="PEM-encoded Certificate Signing Request")
    enrollment_token: str | None = None


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


class HeartbeatResponse(BaseModel):
    """Response for heartbeat ping."""

    revoked: bool = Field(default=False, description="Whether this executor has been revoked")
    new_cert_required: bool = Field(default=False, description="Whether a certificate rotation is needed")


# --- Helpers ---


def _get_db(request: Request):
    """Get a database session from the backend on app state."""
    backend = getattr(request.app.state, "backend", None)
    if backend is None:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Backend not initialized",
        )
    return backend.get_session()


def _get_ca_manager(request: Request) -> CAManager:
    """Get the CA manager from app state."""
    ca_manager = getattr(request.app.state, "ca_manager", None)
    if ca_manager is None:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="CA not initialized",
        )
    return ca_manager


# --- Endpoints ---


@router.post(
    "/executors/register",
    response_model=ExecutorRegisterResponse,
    status_code=status.HTTP_201_CREATED,
)
async def register_executor(
    req: ExecutorRegisterRequest,
    request: Request,
    _rl: None = Depends(rate_limit_registration),
) -> ExecutorRegisterResponse:
    """Register an executor and obtain a signed mTLS certificate.

    The executor submits a CSR (Certificate Signing Request) signed with
    its temporary keypair. The server signs it with the CA and returns
    the signed certificate plus the CA certificate for verification.

    Also creates a corresponding user account for the executor.
    """
    db = _get_db(request)
    ca_manager = _get_ca_manager(request)

    try:
        # Parse the CSR
        try:
            csr = x509.load_pem_x509_csr(req.csr_pem.strip().encode())
        except Exception as e:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Invalid CSR: {e}",
            )

        # --- Token validation (optional bootstrap auth) ---
        resolved_executor_id = req.executor_id
        token_audit_fields = {}

        if req.enrollment_token:
            token_hash = hashlib.sha256(req.enrollment_token.encode("utf-8")).hexdigest()

            # Pre-check for diagnostic specificity (non-authoritative)
            token = (
                db.query(ExecutorEnrollmentToken)
                .filter(ExecutorEnrollmentToken.token_hash == token_hash)
                .first()
            )

            if token is None:
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Invalid enrollment token",
                )
            if token.state == "revoked":
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Enrollment token has been revoked",
                )
            if token.state == "consumed":
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Enrollment token already consumed",
                )
            if token.expires_at <= datetime.now(timezone.utc):
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Enrollment token has expired",
                )

            if token.executor_id != req.executor_id:
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Enrollment token bound to different executor_id",
                )

            # Verify cryptographic binding to executor_id
            server_config = getattr(request.app.state, "config", None)
            pepper = getattr(server_config, "recovery_code_pepper", "") if server_config else ""
            if not verify_binding_hash(
                entity_id=token.executor_id,
                plaintext_token=req.enrollment_token,
                server_secret=pepper,
                stored_binding_hash=token.binding_hash,
            ):
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Enrollment token binding mismatch — token has been invalidated",
                )

            # Authoritative atomic consumption — closes race window
            now = datetime.now(timezone.utc)
            result = db.execute(
                text("""
                    UPDATE executor_enrollment_tokens
                    SET state = 'consumed', used_at = :now
                    WHERE token_hash = :hash AND state = 'created' AND expires_at > :now
                """),
                {"hash": token_hash, "now": now},
            )

            if result.rowcount != 1:
                # Lost the race — token was consumed between pre-check and UPDATE
                db.rollback()
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Enrollment token was consumed concurrently",
                )

            resolved_executor_id = token.executor_id
            token_audit_fields = {"with_token": True, "token_verified": True}
            logger.info("Enrollment token verified for executor: %s", resolved_executor_id)
        else:
            server_config = getattr(request.app.state, "config", None)
            if server_config and server_config.executor_enrollment.require_token:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="Enrollment token required. Contact your administrator.",
                )
            token_audit_fields = {"with_token": False}

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
            cert = ca_manager.sign_csr(csr, resolved_executor_id)
        except RuntimeError as e:
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail=str(e),
            )

        # Store certificate metadata
        serial_hex = ca_manager.compute_serial_hex(cert.serial_number)
        fingerprint = ca_manager.compute_fingerprint(cert)

        existing_cert = (
            db.query(ExecutorCert)
            .filter(ExecutorCert.executor_id == resolved_executor_id)
            .first()
        )

        cert_record = ExecutorCert(
            executor_id=resolved_executor_id,
            serial_number=serial_hex,
            not_before=cert.not_valid_before_utc,
            not_after=cert.not_valid_after_utc,
            fingerprint=fingerprint,
        )

        if existing_cert:
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
            timestamp=datetime.now(timezone.utc),
        )
        db.add(audit_event)

        db.commit()

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
    finally:
        db.close()


@router.get(
    "/executors/certs/revocation-list",
    response_model=RevocationListResponse,
)
async def get_revocation_list(
    request: Request,
) -> RevocationListResponse:
    """Get the list of revoked certificate serial numbers.

    Executors poll this endpoint periodically (every 60s) to check
    if their certificate has been revoked.
    """
    from vault.iam.models import ExecutorCertRevocation

    db = _get_db(request)
    try:
        revocations = db.query(ExecutorCertRevocation).all()
        serials = [r.serial_number for r in revocations]
        return RevocationListResponse(revoked_serials=serials)
    finally:
        db.close()


@router.post(
    "/heartbeat",
    response_model=HeartbeatResponse,
    status_code=status.HTTP_200_OK,
)
async def heartbeat(
    req: HeartbeatRequest,
    request: Request,
) -> HeartbeatResponse:
    """Receive heartbeat from executor.

    Executors POST to this endpoint every 30s to signal liveness.
    The server responds with revocation status and cert rotation hint.

    This is a public endpoint — no authentication required.
    """
    from vault.iam.models import ExecutorCert, ExecutorCertRevocation

    db = _get_db(request)
    try:
        executor_id = req.executor_id
        revoked = False
        new_cert_required = False

        if executor_id:
            # Check if executor's current cert is revoked
            current_cert = (
                db.query(ExecutorCert)
                .filter(ExecutorCert.executor_id == executor_id)
                .first()
            )

            if current_cert:
                # Check revocation list
                revoked = (
                    db.query(ExecutorCertRevocation)
                    .filter(ExecutorCertRevocation.serial_number == current_cert.serial_number)
                    .first()
                    is not None
                )

                # Check if cert needs rotation (within 3 days of expiry)
                from datetime import datetime, timezone, timedelta
                now = datetime.now(timezone.utc)
                expiry_threshold = now + timedelta(days=3)
                not_after = current_cert.not_after
                if not_after.tzinfo is None:
                    not_after = not_after.replace(tzinfo=timezone.utc)
                if not_after < expiry_threshold:
                    new_cert_required = True

        return HeartbeatResponse(
            revoked=revoked,
            new_cert_required=new_cert_required,
        )
    finally:
        db.close()
