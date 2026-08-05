"""Executor registration and certificate management endpoints.

Handles executor CSR submission, certificate signing, and revocation
list polling for mTLS-based executor authentication.
"""

from __future__ import annotations

import logging

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from datetime import datetime, timezone
from fastapi import APIRouter, HTTPException, Request, status
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from ..ca import CAManager

logger = logging.getLogger("venya.server")

router = APIRouter()


# --- Request/Response models ---


class ExecutorRegisterRequest(BaseModel):
    """Request body for executor registration."""

    executor_id: str = Field(..., description="Unique executor identifier", min_length=1, max_length=64)
    csr_pem: str = Field(..., description="PEM-encoded Certificate Signing Request")


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

        # Create executor user account if it doesn't exist
        from vault.iam.models import User, ExecutorCert

        existing_user = db.query(User).filter(User.user_id == req.executor_id).first()
        if existing_user is None:
            # Auto-create executor user account
            new_user = User(
                user_id=req.executor_id,
                auth_mode="mtls",
            )
            db.add(new_user)
            db.flush()
            logger.info("Auto-created executor user: %s", req.executor_id)
        else:
            # Update auth mode if it was something else
            if existing_user.auth_mode != "mtls":
                existing_user.auth_mode = "mtls"

        # Sign the CSR
        try:
            cert = ca_manager.sign_csr(csr, req.executor_id)
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
            .filter(ExecutorCert.executor_id == req.executor_id)
            .first()
        )

        cert_record = ExecutorCert(
            executor_id=req.executor_id,
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

        db.commit()

        # Return signed certificate + CA chain
        cert_pem = cert.public_bytes(serialization.Encoding.PEM).decode()
        ca_cert_pem = ca_manager.get_ca_cert_pem().decode()

        return ExecutorRegisterResponse(
            executor_id=req.executor_id,
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
        body = await request.json()
        executor_id = body.get("executor_id", "")
        cert_fingerprint = body.get("cert_fingerprint", "")

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
