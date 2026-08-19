"""Executor registration and certificate management endpoints.

Handles executor CSR submission, certificate signing, and revocation
list polling for mTLS-based executor authentication.
"""


import hashlib
import hmac
import json
import logging

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from datetime import datetime, timedelta, timezone
from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel, Field
from sqlalchemy import text
from sqlalchemy.orm import Session

from ..ca import CAManager
from ..dependencies import get_db
from ..rate_limit import rate_limit_registration
from ..utils.executor_id import EXECUTOR_ID_PATTERN, validate_executor_id
from ..utils.time import effective_expiry_check_time, is_expired
from .. import metrics
from core.iam.models import AuditEvent, ExecutorEnrollmentToken, User, ExecutorCert

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
        raise ValueError(
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
    except Exception as e:
        metrics.EXECUTOR_REGISTERED.labels(result="invalid_csr").inc()
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid CSR: {e}",
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
        token = (
            db.query(ExecutorEnrollmentToken)
            .filter(ExecutorEnrollmentToken.token_hash == token_hash)
            .first()
        )

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
            text("""
                UPDATE executor_enrollment_tokens
                SET state = 'consumed', used_at = :now
                WHERE token_hash = :hash AND state = 'created' AND expires_at > :now
            """),
            {"hash": token_hash, "now": now_minus_tolerance},
        )

        if result.rowcount != 1:
            # Lost the race — token was consumed between pre-check and UPDATE
            # Re-read to determine why
            token = db.query(ExecutorEnrollmentToken).filter(
                ExecutorEnrollmentToken.token_hash == token_hash
            ).first()
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
            metrics.EXECUTOR_REGISTERED.labels(result="token_required").inc()
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
        server_config = getattr(request.app.state, "config", None)
        crl_url = server_config.crl.crl_url if server_config and hasattr(server_config, "crl") else None
        cert = ca_manager.sign_csr(csr, resolved_executor_id, crl_url=crl_url)
        metrics.CA_SIGNED_TOTAL.labels(cert_type="executor").inc()
    except RuntimeError as e:
        metrics.EXECUTOR_REGISTERED.labels(result="ca_error").inc()
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

    Executors poll this endpoint periodically (every 60s) to check
    if their certificate has been revoked. Supports conditional GET
    via ETag for caching — returns 304 Not Modified when the list
    has not changed.
    """
    from core.iam.models import ExecutorCertRevocation
    from fastapi.responses import Response

    ca_manager = _get_ca_manager(request)
    # Purge old entries to keep table bounded
    server_config = getattr(request.app.state, "config", None)
    retention_days = (
        server_config.crl.crl_retention_days
        if server_config and hasattr(server_config, "crl")
        else 90
    )
    deleted_count = ca_manager.purge_expired_revocations(db, retention_days)
    if deleted_count > 0:
        logger.debug("Purged %d expired revocations (%d day retention)", deleted_count, retention_days)

    # Fetch remaining revocations
    revocations = db.query(ExecutorCertRevocation).all()
    serials = sorted([r.serial_number for r in revocations])
    payload = json.dumps(serials, sort_keys=True).encode()
    etag = f'"{hashlib.sha256(payload).hexdigest()}"'

    if request.headers.get("if-none-match") == etag:
        return Response(status_code=304, headers={"ETag": etag})

    return Response(
        content=json.dumps({"revoked_serials": serials}).encode(),
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

    Public endpoint — no authentication required. Purges expired
    revocation records before generating the CRL. Supports conditional
    GET via ETag for caching.
    """
    from core.iam.models import ExecutorCertRevocation
    from fastapi.responses import Response

    ca_manager = _get_ca_manager(request)
    server_config = getattr(request.app.state, "config", None)
    retention_days = (
        server_config.crl.crl_retention_days
        if server_config and hasattr(server_config, "crl")
        else 90
    )

    ca_manager.purge_expired_revocations(db, retention_days)
    metrics.CA_REVOCATIONS_PURGED_TOTAL.inc()
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
            response_data = compressed
            content_encoding = "zstd"
        except Exception:  # noqa: BLE001 — compression failures are localized
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
    db: Session = Depends(get_db),
) -> HeartbeatResponse:
    """Receive heartbeat from executor.

    Executors POST to this endpoint every 30s to signal liveness.
    The server responds with revocation status and cert rotation hint.

    This is a public endpoint — no authentication required.
    """
    from core.iam.models import ExecutorCert, ExecutorCertRevocation

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

    metrics.EXECUTOR_HEARTBEAT_TOTAL.inc()
    return HeartbeatResponse(
        revoked=revoked,
        new_cert_required=new_cert_required,
    )
