# Copyright (c) 2026 Tabith LLC.
# Use of this source code is governed by the Business Source License 1.1
# included in the LICENSE file at the root of this repository. As of the
# Change Date listed there, the work is available under MPL 2.0.
# SPDX-License-Identifier: BUSL-1.1

"""Output filtering endpoint for executor."""

import base64
import hashlib
import logging

from core.engine.backend import Backend
from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from ..dependencies import get_backend, get_db

router = APIRouter()
logger = logging.getLogger("venya.server")


# --- Request/Response models ---


class FilterRequest(BaseModel):
    """Request from executor.

    SIGN-OFF INVARIANT (ticket executor-stage2-plaintext-signoff, ruling
    2026-09-20): the body carries plaintext-equivalent (base64) UNFILTERED
    command output BY DESIGN — Stage-2 is the definitive filter and must see
    pre-Stage-1 bytes to be authoritative over Stage-1 misses. Transport
    protection is mutual mTLS only; request/response bodies at this hop must
    NEVER be logged on either side. Any future logger touching bodies here
    is a REGRESSION.

    Note: no `secrets` field by design — the handler reconstructs plaintext
    from the server's own DB via KEK. Legacy daemons that still send a
    `secrets` key are tolerated (pydantic drops undeclared keys; pinned by
    test_legacy_payload_with_secrets_field_tolerated_and_dropped).
    """

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
    db: Session = Depends(get_db),
    backend: Backend = Depends(get_backend),
) -> FilterResponse:
    """Filter secret values from captured process output.

    Definitive masking endpoint. Called by executor after Stage 1 local filtering.

    Args:
        session_id: The executor session ID.
        req: Base64-encoded stdout/stderr to filter.
        request: The FastAPI request (mTLS caller state).

    Returns:
        Sanitized output with masked secrets.
    """
    from core.iam.models import Secret
    from core.iam.models import Session as SessionModel

    # Verify caller is executor (mTLS) — mirrors routes/secrets.py revoke.
    # The middleware is the choke point that VERIFIES the identity
    # (sec-executor-session-path-no-auth); this check is defense-in-depth so
    # the route is never naked if mounted without the middleware, and it runs
    # BEFORE any secret is decrypted or hash-compared (no pre-auth oracle).
    caller = getattr(request.state, "auth_user", {})
    if caller.get("caller") != "executor":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Executor mTLS authentication required",
        )

    # Look up session to find injected secrets
    try:
        session_id_int = int(session_id)
    except (ValueError, TypeError):
        session_id_int = None

    session = None
    if session_id_int is not None:
        session = db.query(SessionModel).filter(SessionModel.id == session_id_int).first()

    session_secrets: dict[str, bytes] = {}
    if session is not None:
        from core.engine.encryption import DecryptionError
        from core.engine.encryption import decrypt_secret as _decrypt_secret_impl

        kek = backend.config.kek
        # Get secrets associated with this session's user
        secrets = db.query(Secret).filter(Secret.created_by == session.user_id).all()
        for secret in secrets:
            if kek is None:
                logger.warning(
                    "No KEK configured, cannot decrypt secret %s for session %s",
                    secret.id,
                    session_id,
                )
                continue
            try:
                plaintext = _decrypt_secret_impl(kek, secret.wrapped_dek, secret.nonce, secret.encrypted_value)
            except DecryptionError:
                logger.warning(
                    "Failed to decrypt secret %s for session %s",
                    secret.id,
                    session_id,
                )
                continue
            hash_hex = hashlib.sha256(plaintext).hexdigest()
            session_secrets[hash_hex] = plaintext
    else:
        # Non-auth-session path: session_id is not an integer auth-session ID.
        # This catches UUID execution sessions AND integer IDs that failed lookup.
        # We look up bound secrets through the SessionSecret join table.
        from core.engine.encryption import DecryptionError
        from core.engine.encryption import decrypt_secret as _decrypt_secret_impl
        from core.iam.models import ExecutionSession, SessionSecret

        # FAIL CLOSED on unknown sessions (ticket
        # stage2-filter-unknown-session-unmasked-passthrough): this route is the
        # DEFINITIVE masker and the executor adopts its answer over its own
        # Stage-1 masking — an empty-knowledge 200 therefore ships RAW output to
        # the caller. Vanished sessions are a PROVEN real occurrence (the 10-min
        # TTL reaper deletes rows mid-run — execute-stale-session-update-500), so
        # unknown → 404 → the executor's existing "Stage 2 filter failed — using
        # Stage 1 results" fallback keeps masking at one stage, never zero. A
        # session that EXISTS with zero bindings still returns 200 (legitimately
        # nothing to mask).
        exec_session = db.query(ExecutionSession).filter(ExecutionSession.id == session_id).first()
        if exec_session is None:
            logger.warning(
                "Filter called for unknown session %s — refusing empty-knowledge passthrough",
                session_id,
            )
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Session not found",
            )

        bindings = db.query(SessionSecret).filter(SessionSecret.session_id == session_id).all()

        if not bindings:
            logger.warning(
                "Session %s has no secret bindings — masking will be a no-op",
                session_id,
            )
        else:
            for binding in bindings:
                secret = db.query(Secret).filter(Secret.id == binding.secret_id).first()
                if secret is None:
                    logger.warning(
                        "Secret %s bound to session %s not found in DB — skipping",
                        binding.secret_id,
                        session_id,
                    )
                    continue
                kek = backend.config.kek
                if kek is None:
                    logger.warning(
                        "No KEK configured, cannot decrypt secret %s for session %s",
                        binding.secret_id,
                        session_id,
                    )
                    continue
                try:
                    plaintext = _decrypt_secret_impl(kek, secret.wrapped_dek, secret.nonce, secret.encrypted_value)
                except DecryptionError:
                    logger.warning(
                        "Failed to decrypt secret %s for session %s",
                        binding.secret_id,
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
