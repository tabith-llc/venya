# Copyright (c) 2026 Tabith LLC.
# Use of this source code is governed by the Business Source License 1.1
# included in the LICENSE file at the root of this repository. As of the
# Change Date listed there, the work is available under MPL 2.0.
# SPDX-License-Identifier: BUSL-1.1

"""Short-lived admin certificate issuance (RF-6 §2.1/§2.7, refs RF-7).

One path mints a human-plane admin certificate: the person proves they are the
person with a bearer session plus a fresh FIDO2 assertion (the elevation seam
in ``routes/auth_elevation.py``), the workstation holds the keypair and sends a
CSR, and the Admin CA signs it. Private-key material crosses the boundary in
exactly one direction — outbound inside a CSR (RF-6 §2.1) — and never comes
back.

Why the route is not gated behind an admin certificate (RF-6 §2.2, §6.5): the
credential this endpoint mints is the credential such a gate would require, so
a brand-new install could never produce its first human cert. The path rides
the bootstrap shape already proven for ``/api/v1/init/reset`` (#450): the
middleware attaches an identity opportunistically and the HANDLER owns the
decision. The handler is where the session requirement is enforced — see
``_require_human_session``.

Failure modes are all loud and none of them a 500 (RF-6 §2.7): client input
dies as 400/422, missing or spent credentials as 401/403 naming the repair, and
unusable CA material as 503 — ``RuntimeError``/``FileNotFoundError`` stay
distinct from ``ValueError``, exactly as ``sign_admin_csr`` documents.
"""

import logging

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel, Field

from ..ca import ADMIN_SHORT_CERT_LIFETIME_SECONDS, AdminCAManager
from ..dependencies import get_current_user

router = APIRouter()
logger = logging.getLogger("venya.server")

#: PEM CSR ceiling. A P-256 request is a few hundred bytes; the bound stops a
#: caller streaming an oversized body into the parser (same shape as the
#: executor registration field in ``routes/executors.py``).
_CSR_MAX_CHARS = 4096


class AdminIssueCertRequest(BaseModel):
    """The mint request: a CSR and nothing else.

    ``extra="forbid"`` is the RF-6 §2.6 answer to a self-described identity: a
    caller that puts ``identity``/``cn``/``user_id`` in the body is REFUSED at
    validation (422 — the handler never runs) rather than silently ignored. The
    mint is server-described, and the loud version of that rule is the useful
    one (repo-wide ``extra="forbid"`` ruling, #357).
    """

    model_config = {"extra": "forbid"}

    csr_pem: str = Field(
        ...,
        max_length=_CSR_MAX_CHARS,
        description="PEM-encoded PKCS#10 certificate signing request (workstation-generated keypair)",
    )


class AdminIssuedCertResponse(BaseModel):
    """The mint response: the certificate PEM and nothing else (RF-6 §2.7).

    No private key, no CSR echo. Identity and expiry are readable from the
    certificate the caller just received — which is exactly what RF-6 §4.5's
    lifetime-readable check asks the client to do.
    """

    certificate_pem: str


def _require_human_session(user_info: dict) -> str:
    """Return the server-derived identity, or refuse a non-session caller.

    Two shapes can reach a handler on this path under the #450 bootstrap
    treatment (RF-6 §6.5):

    * a validated bearer/cookie session — carries ``user_id`` and
      ``session_id``. This is the ONLY shape the mint accepts: the elevation
      token is bound to that session (#527), and ruling 2 makes the person the
      point of the credential;
    * a crypto-verified admin CERTIFICATE — carries ``caller == "admin"`` and
      no session. Refused here: authorizing a mint with the caller's existing
      admin certificate reproduces the standing-credential dependency this
      whole program exists to delete (RF-6 §2.2, "not an option"), and it is
      the paired negative of the first-human rule (#340-A: cert-only, no
      session, never mints).

    Raises:
        HTTPException: 401 with no authenticated session at all; 403 for a
            certificate-shaped caller. Both texts name the repair command.
    """
    if user_info.get("caller") == "admin":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=(
                "Admin certificate issuance requires a login session, not an admin certificate — "
                "the mint is bound to the session that passed the security-key ceremony. "
                "Repair: venya login, then venya admin elevate."
            ),
        )

    user_id = user_info.get("user_id")
    if not user_id or user_info.get("session_id") is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=(
                "A login session is required to issue an admin certificate. "
                "Repair: venya login, then venya admin elevate."
            ),
        )

    return str(user_id)


def _get_admin_ca_manager(request: Request) -> AdminCAManager:
    """The admin CA manager, or a service fault — never client input.

    RF-6 §2.5/§2.7 error-class contract: an unusable CA is 503, a bad CSR is
    400. A deployment with no admin CA on disk is the service-fault half of
    that split, and the text names the command that creates one.
    """
    manager: AdminCAManager | None = getattr(request.app.state, "admin_ca_manager", None)
    if manager is None or not manager.has_ca:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=(
                "Admin CA is not initialized — cannot sign. "
                "Repair: venya admin init-admin-ca (the core installer runs it during installation)."
            ),
        )
    return manager


def _parse_csr(csr_pem: str) -> x509.CertificateSigningRequest:
    """PEM → CSR, refusing anything else as client input (400, RF-6 §2.7)."""
    try:
        return x509.load_pem_x509_csr(csr_pem.strip().encode())
    except Exception:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid CSR — expected a PEM-encoded certificate signing request",
        ) from None


@router.post(
    "/admin/certs/issue",
    response_model=AdminIssuedCertResponse,
    status_code=status.HTTP_201_CREATED,
)
async def admin_issue_cert(
    req: AdminIssueCertRequest,
    request: Request,
    user_info: dict = Depends(get_current_user),
) -> AdminIssuedCertResponse:
    """Mint a minutes-scale human-plane admin certificate (RF-6 §2.1).

    The identity is the authenticated session's ``user_id`` — never a value
    from the request or from the CSR subject (RF-6 §2.6), which
    ``sign_admin_csr`` discards on the way in.
    """
    identity = _require_human_session(user_info)
    manager = _get_admin_ca_manager(request)
    csr = _parse_csr(req.csr_pem)

    server_config = getattr(request.app.state, "config", None)
    crl_url = server_config.crl.crl_url if server_config and hasattr(server_config, "crl") else None

    try:
        cert = manager.sign_admin_csr(
            csr,
            identity,
            lifetime_seconds=ADMIN_SHORT_CERT_LIFETIME_SECONDS,
            crl_url=crl_url,
        )
    except ValueError as e:
        # Bad CSR material is client input, never a CA fault (same split the
        # executor registration route documents at routes/executors.py:906-915).
        logger.warning("Admin CSR refused for session caller %s: %s", identity, e)
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e)) from None
    except (RuntimeError, FileNotFoundError, OSError) as e:
        # Unusable CA material stays a service fault (RF-6 §2.7) — a different
        # class, so an operator sees "the CA could not sign", not "your CSR is
        # bad", and never a 500.
        logger.exception("Admin CA could not sign for session caller %s", identity)
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Admin CA unavailable — could not sign the request",
        ) from e

    pem = cert.public_bytes(serialization.Encoding.PEM).decode()
    logger.info(
        "Admin certificate issued for %s (serial %x, valid to %s)",
        identity,
        cert.serial_number,
        cert.not_valid_after_utc.isoformat(),
    )
    return AdminIssuedCertResponse(certificate_pem=pem)
