"""Output filtering endpoint for executor."""

import base64
import hashlib
import logging

from fastapi import APIRouter, HTTPException, Request, status
from pydantic import BaseModel, Field

router = APIRouter()
logger = logging.getLogger("venya.server")


# --- Request/Response models ---


class FilterRequest(BaseModel):
    """Filter request from executor."""

    stdout: str = Field(..., description="Base64-encoded stdout bytes")
    stderr: str = Field(..., description="Base64-encoded stderr bytes")


class FilterResponse(BaseModel):
    """Filter response with sanitized output."""

    stdout: str  # Base64-encoded sanitized bytes
    stderr: str  # Base64-encoded sanitized bytes
    masked_count: int = 0
    masked_hashes: list[str] = []


# --- Filtering logic ---


def compute_detection_hashes(value: bytes) -> list[str]:
    """Compute SHA-256 hashes for secret value in multiple encodings.

    Same implementation as in secrets.py — DRY would require
    moving to a shared module.
    """
    import base64 as b64

    hashes = []
    hashes.append(hashlib.sha256(value).hexdigest())
    hashes.append(hashlib.sha256(b64.b64encode(value)).hexdigest())
    hashes.append(hashlib.sha256(value.hex().encode()).hexdigest())
    trimmed = value.strip()
    if trimmed != value:
        hashes.append(hashlib.sha256(trimmed).hexdigest())
    return hashes


def filter_output(
    output: bytes,
    secret_hashes: dict[str, bytes],
) -> tuple[bytes, list[str]]:
    """Filter secret values from output using hash matching.

    Performs substring matching against known secret hashes.

    Args:
        output: The raw output bytes to filter.
        secret_hashes: Dict mapping hash_hex -> secret_bytes.

    Returns:
        Tuple of (filtered_output, list of masked hash prefixes).
    """
    masked_hashes: list[str] = []

    for hash_hex, secret_bytes in secret_hashes.items():
        # Skip empty secret values to avoid matching every position
        if not secret_bytes:
            continue

        # Try raw bytes matching
        if secret_bytes in output:
            output = output.replace(
                secret_bytes,
                f"[REDACTED:{hash_hex[:8]}]".encode(),
            )
            masked_hashes.append(hash_hex[:8])

        # Try base64 matching
        import base64 as b64

        b64_secret = b64.b64encode(secret_bytes)
        if b64_secret in output:
            output = output.replace(
                b64_secret,
                f"[REDACTED:{hash_hex[:8]}]".encode(),
            )
            masked_hashes.append(hash_hex[:8])

        # Try hex matching
        hex_secret = secret_bytes.hex().encode()
        if hex_secret in output:
            output = output.replace(
                hex_secret,
                f"[REDACTED:{hash_hex[:8]}]".encode(),
            )
            masked_hashes.append(hash_hex[:8])

    # Deduplicate masked hashes
    unique = list(dict.fromkeys(masked_hashes))
    return output, unique


# --- Endpoints ---


@router.post(
    "/sessions/{session_id}/filter",
    response_model=FilterResponse,
    status_code=status.HTTP_200_OK,
)
async def filter_session_output(
    session_id: str,
    req: FilterRequest,
    request: Request,
) -> FilterResponse:
    """Filter secret values from captured process output.

    Definitive masking endpoint. Called by executor after Stage 1 local filtering.

    Args:
        session_id: The executor session ID.
        req: Base64-encoded stdout/stderr to filter.

    Returns:
        Sanitized output with masked secrets.
    """
    backend = getattr(request.app.state, "backend", None)
    if backend is None:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Backend not initialized",
        )

    from core.iam.models import Secret, Session as SessionModel

    db = backend.get_session()
    try:
        # Look up session to find injected secrets
        try:
            session_id_int = int(session_id)
        except (ValueError, TypeError):
            session_id_int = None

        session = None
        if session_id_int is not None:
            session = (
                db.query(SessionModel)
                .filter(SessionModel.id == session_id_int)
                .first()
            )

        session_secrets: dict[str, bytes] = {}
        if session is not None:
            from core.engine.encryption import DecryptionError, decrypt_secret as _decrypt_secret_impl

            kek = backend.config.kek
            # Get secrets associated with this session's user
            secrets = (
                db.query(Secret)
                .filter(Secret.created_by == session.user_id)
                .all()
            )
            for secret in secrets:
                if kek is None:
                    logger.warning(
                        "No KEK configured, cannot decrypt secret %s for session %s",
                        secret.id,
                        session_id,
                    )
                    continue
                try:
                    plaintext = _decrypt_secret_impl(
                        kek, secret.wrapped_dek, secret.nonce, secret.encrypted_value
                    )
                except DecryptionError:
                    logger.warning(
                        "Failed to decrypt secret %s for session %s",
                        secret.id,
                        session_id,
                    )
                    continue
                hash_hex = hashlib.sha256(plaintext).hexdigest()
                session_secrets[hash_hex] = plaintext

        # Decode base64 input
        try:
            stdout = base64.b64decode(req.stdout)
        except Exception:
            stdout = b""

        try:
            stderr = base64.b64decode(req.stderr)
        except Exception:
            stderr = b""

        filtered_stdout, stdout_hashes = filter_output(stdout, session_secrets)
        filtered_stderr, stderr_hashes = filter_output(stderr, session_secrets)

        all_hashes = stdout_hashes + stderr_hashes

        return FilterResponse(
            stdout=base64.b64encode(filtered_stdout).decode("ascii"),
            stderr=base64.b64encode(filtered_stderr).decode("ascii"),
            masked_count=len(all_hashes),
            masked_hashes=all_hashes,
        )
    finally:
        db.close()
