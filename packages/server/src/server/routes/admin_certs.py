# Copyright (c) 2026 Tabith LLC.
# Use of this source code is governed by the Business Source License 1.1
# included in the LICENSE file at the root of this repository. As of the
# Change Date listed there, the work is available under MPL 2.0.
# SPDX-License-Identifier: BUSL-1.1

"""Short-lived admin certificate issuance (RF-6 §2.1–§2.8, refs RF-7).

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

The gate order is the dossier's, top to bottom:

1. a session-shaped caller (``require_admin`` = the §2.6.3 mint-time role check;
   the per-USE role check is §3.3 and lives in the dependency, not here);
2. the caller is a PERSON with a session, not a certificate (§2.2, #340-A);
3. one unused, unexpired elevation token, consumed atomically (§2.7);
4. the mint itself — server-derived identity, ruled lifetime, CA-written
   human-plane marker (§2.5b, §2.6, §3.2);
5. the audit row and the signing metric (§2.8).

Failure modes are all loud and none of them a 500 (RF-6 §2.7): client input
dies as 400/422, missing or spent credentials as 401/403 naming the repair, and
unusable CA material as 503 — ``RuntimeError``/``FileNotFoundError`` stay
distinct from ``ValueError``, exactly as ``sign_admin_csr`` documents.
"""

import hashlib
import logging
from datetime import UTC, datetime, timedelta

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel, Field
from sqlalchemy import update
from sqlalchemy.orm import Session

from .. import metrics
from ..audit_lifecycle import ADMIN_CERT_ISSUED, ADMIN_CERT_REGISTERED, audit_lifecycle
from ..ca import (
    ADMIN_SHORT_CERT_LIFETIME_SECONDS,
    AdminCAManager,
    accepted_csr_curve_names,
    csr_curve_hint,
)
from ..dependencies import get_db, require_admin

router = APIRouter()
logger = logging.getLogger("venya.server")

#: PEM CSR ceiling. A P-256 request is a few hundred bytes; the bound stops a
#: caller streaming an oversized body into the parser (same shape as the
#: executor registration field in ``routes/executors.py``).
_CSR_MAX_CHARS = 4096

#: The elevation ceremony header, shared with the two existing elevation-gated
#: routes (``routes/secrets.py`` unmask, ``routes/admin.py`` recovery-code
#: reissue) so there is exactly one way to prove a fresh assertion.
_ELEVATION_HEADER = "X-Elevation-Token"

#: Mint reason written into the audit row (RF-6 §2.8). This endpoint issues;
#: the renew command (§4.2) re-invokes this same path and is RF-8's surface.
_MINT_REASON = "issue"


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
      no session. Refused here: authorizing issuance with the caller's existing
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
                "Repair: venya login, then venya admin cert renew."
            ),
        )

    user_id = user_info.get("user_id")
    if not user_id or user_info.get("session_id") is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=(
                "A login session is required to issue an admin certificate. "
                "Repair: venya login, then venya admin cert renew."
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
                "Repair: set VENYA_ADMIN_CA_KEY_PASSPHRASE, then run: venya admin init-admin-ca "
                "(the core installer runs it during installation)."
            ),
        )
    return manager


def _parse_csr(csr_pem: str) -> x509.CertificateSigningRequest:
    """PEM → CSR, refusing anything else as client input (400, RF-6 §2.7).

    Runs BEFORE the ceremony burn, together with the curve pre-check below:
    the server can tell a malformed or unsupported request is bad without
    asking the person to touch the key again, so a typo never costs a
    ceremony. ``sign_admin_csr`` still verifies everything itself (defense in
    depth) — this is the ordering, not the authority.
    """
    try:
        return x509.load_pem_x509_csr(csr_pem.strip().encode())
    except Exception:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid CSR — expected a PEM-encoded certificate signing request",
        ) from None


def _preflight_csr_key(csr: x509.CertificateSigningRequest) -> None:
    """Reject an unusable CSR key with a 400 BEFORE the ceremony is spent.

    Same accepted-curve list the signer reads (``accepted_csr_curve_names`` /
    ``csr_curve_hint``, the shared single source the executor path uses too) —
    no admin-specific curve fork, and the signer's own check stays as the
    backstop that also covers the self-signature (which can only be verified
    inside ``sign_admin_csr``).
    """
    public_key = csr.public_key()
    if not isinstance(public_key, ec.EllipticCurvePublicKey):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Unsupported CSR key type: {type(public_key).__name__}. {csr_curve_hint()}",
        )
    if public_key.curve.name not in accepted_csr_curve_names():
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Unsupported curve: {public_key.curve.name}. {csr_curve_hint()}",
        )


def _consume_elevation_token(request: Request, db: Session, user_id: str) -> None:
    """Spend exactly one elevation ceremony on this mint, or refuse (RF-6 §2.7).

    Same conditional UPDATE the two existing elevation-gated routes use
    (``routes/secrets.py:496`` unmask, ``routes/admin.py`` recovery-code
    reissue): match on token hash + THIS user + unused + unexpired, set
    ``used=True``, flush only. The atomic flip is what makes two concurrent
    requests unable to both spend one ceremony, and the deferred commit means a
    refusal further down this handler rolls the burn back — a failed mint never
    quietly consumes the person's touch.

    Expiry is read with the configured clock-skew tolerance, exactly as the
    sibling routes do (never a wider window than the rest of the product).

    Raises:
        HTTPException: 403 when no token was presented at all; 401 when one was
            presented but is unknown, already spent, or expired. Both texts
            name the repair.
    """
    elevation_token = request.headers.get(_ELEVATION_HEADER)
    if not elevation_token:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=(
                "Elevation token required to issue an admin certificate — prove the security key "
                "again first. Repair: venya admin cert renew."
            ),
        )

    from core.iam.models import ElevationToken

    token_hash = hashlib.sha256(elevation_token.encode()).hexdigest()
    server_config = getattr(request.app.state, "config", None)
    tolerance = (
        server_config.clock_skew.token_tolerance_seconds
        if server_config and hasattr(server_config, "clock_skew")
        else 60
    )
    expiry_cutoff = datetime.now(UTC) - timedelta(seconds=tolerance)

    result = db.execute(
        update(ElevationToken)
        .where(
            ElevationToken.token_hash == token_hash,
            ElevationToken.user_id == user_id,
            ElevationToken.used.is_(False),
            ElevationToken.expires_at > expiry_cutoff,
        )
        .values(used=True)
    )
    db.flush()

    if result.rowcount == 0:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=(
                "Invalid or expired elevation token — one touch mints one certificate. "
                "Repair: venya admin cert renew."
            ),
        )


@router.post(
    "/admin/certs/issue",
    response_model=AdminIssuedCertResponse,
    status_code=status.HTTP_201_CREATED,
)
async def admin_issue_cert(
    req: AdminIssueCertRequest,
    request: Request,
    admin: dict = Depends(require_admin),
    db: Session = Depends(get_db),
) -> AdminIssuedCertResponse:
    """Mint a minutes-scale human-plane admin certificate (RF-6 §2.1).

    The identity is the authenticated session's ``user_id`` — never a value
    from the request or from the CSR subject (RF-6 §2.6), which
    ``sign_admin_csr`` discards on the way in.
    """
    # 1-2. Who is asking: a person with a session (role-checked by
    # require_admin, §2.6.3; cert-shaped callers refused, #340-A).
    identity = _require_human_session(admin)
    manager = _get_admin_ca_manager(request)

    # 3. Input validation first: a malformed CSR or an off-list key is
    # something the server can see for itself, so it must NOT cost the person
    # a security-key touch (the ceremony is spent in the next step).
    csr = _parse_csr(req.csr_pem)
    _preflight_csr_key(csr)

    # 4. One ceremony, spent here, atomically.
    _consume_elevation_token(request, db, identity)

    server_config = getattr(request.app.state, "config", None)
    crl_url = server_config.crl.crl_url if server_config and hasattr(server_config, "crl") else None

    # 5. The mint. The ceremony is spent, so a refusal inside the signer (bad
    # self-signature) rolls the burn back with the transaction — one failed
    # attempt does not silently eat a touch.
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

    # 5. Audit + metric (§2.8). The event row rides this transaction; the
    # metric is the existing counter with a distinct label, not a new metric.
    from core.utils.cert_serial import canonical_serial

    curve_name = getattr(cert.public_key().curve, "name", "unknown")
    audit_lifecycle(
        db,
        ADMIN_CERT_ISSUED,
        identity,
        {
            "serial_number": canonical_serial(cert.serial_number),
            "identity": identity,
            "not_valid_before": cert.not_valid_before_utc.isoformat(),
            "not_valid_after": cert.not_valid_after_utc.isoformat(),
            "curve": curve_name,
            "requesting_user_id": identity,
            "reason": _MINT_REASON,
        },
    )
    # 5b. Population (#684). The mint writes its registry row in THIS transaction,
    # beside the ADMIN_CERT_ISSUED audit row, so "the CA signed it" and "the store can
    # name it" are one fact that either both commit or neither does — a credential the
    # core just minted must never be unrevocable because a second write was forgotten.
    # Facts come off the minted certificate, never from the request.
    from ..admin_registry import SOURCE_ISSUE_ROUTE, facts_from_certificate, register_admin_credential

    registry_outcome = register_admin_credential(db, facts_from_certificate(cert), SOURCE_ISSUE_ROUTE)

    metrics.CA_SIGNED_TOTAL.labels(cert_type="admin").inc()
    db.commit()

    logger.info(
        "Admin certificate issued for %s (serial %x, valid to %s; registry %s)",
        identity,
        cert.serial_number,
        cert.not_valid_after_utc.isoformat(),
        registry_outcome,
    )
    return AdminIssuedCertResponse(certificate_pem=cert.public_bytes(serialization.Encoding.PEM).decode())


class AdminRegisterCertRequest(BaseModel):
    """The register request: one admin certificate PEM, and nothing else.

    ``extra="forbid"`` for the same reason the mint refuses a self-described identity
    (#357): a caller cannot hand the store a serial it wants enrolled.
    """

    model_config = {"extra": "forbid"}

    certificate_pem: str = Field(
        ...,
        max_length=16384,
        description="PEM-encoded admin certificate to enroll in the registry (facts are read off it)",
    )


class AdminRegisterCertResponse(BaseModel):
    """What the registry now says about that credential."""

    created: bool
    serial_number: str
    common_name: str


@router.post("/admin/certs/register", response_model=AdminRegisterCertResponse, status_code=status.HTTP_201_CREATED)
async def admin_register_admin_cert(
    req: AdminRegisterCertRequest,
    admin: dict = Depends(require_admin),
    db: Session = Depends(get_db),
) -> AdminRegisterCertResponse:
    """Enroll one EXISTING admin credential in the registry. Admin only, idempotent.

    The remedy the #684 refusal sentence names, and the reason a membership check can be
    default-deny without stranding a legitimate credential: a certificate minted before
    this population existed (or on a host the boot never read) is enrolled by presenting
    the certificate itself. The facts are READ off that PEM
    (``admin_registry.facts_from_certificate``), never taken from the request, so this
    verb cannot be used to enroll an arbitrary serial — same rule and same shape as the
    shipped ``admin_register_core_relay_cert`` (#597).
    """
    from ..admin_registry import SOURCE_REGISTER_ROUTE, facts_from_certificate, register_admin_credential

    try:
        cert = x509.load_pem_x509_certificate(req.certificate_pem.encode())
        facts = facts_from_certificate(cert)
    except (ValueError, OSError) as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"certificate_pem is not a readable admin credential: {exc}",
        ) from exc

    outcome = register_admin_credential(db, facts, SOURCE_REGISTER_ROUTE)
    audit_lifecycle(
        db,
        ADMIN_CERT_REGISTERED,
        admin.get("user_id"),
        {"serial_number": facts.serial_number, "common_name": facts.common_name, "created": outcome == "created"},
    )
    db.commit()
    logger.info("Admin credential registry: %s serial=%s CN=%s", outcome, facts.serial_number, facts.common_name)
    return AdminRegisterCertResponse(
        created=outcome == "created",
        serial_number=facts.serial_number,
        common_name=facts.common_name,
    )
