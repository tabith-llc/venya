# Copyright (c) 2026 Tabith LLC.
# Use of this source code is governed by the Business Source License 1.1
# included in the LICENSE file at the root of this repository. As of the
# Change Date listed there, the work is available under MPL 2.0.
# SPDX-License-Identifier: BUSL-1.1

"""Revoke verb for the core's own relay client credentials (#597).

Mounted as its own router rather than into ``routes/admin.py``, which is another
lane's live file at this seat (s134 batch: flash4 owns it for #662). Same auth
dependency, same audit shape, same serial vocabulary as the sibling
``POST /admin/certs/revoke`` there — copied in form, not imported, so neither leg
has to edit the other's module.

THE RULE THAT MAKES THIS A CONTROL AND NOT A FORM LETTER: **default deny on an
unregistered serial.** A revoke for a serial that is not in
``core_relay_credentials`` is refused with the named reason ``REFUSE_UNREGISTERED``
and a 403, never accepted as a success and never written as a revocation row. That
is issue 263's lesson, already paid for in this project: an empty or partial store
that behaves as an allowlist turns "I revoked it" into a green write that stops
nothing. Here the refusal has a second, sharper reason — the registry row is the
ONLY thing that makes a relay credential nameable at all, so accepting a revoke for
an unnameable credential would be recording a revocation no consumer can ever match.

The remedy is stated in the refusal, because "not registered" on a running core
almost always means "this core's boot did not ingest it" (a pre-#597 install, or a
relay cert minted after the last boot): restart the core, or register it. Not a
mystery 403.

Revocation is TERMINAL for alpha — no un-revoke route exists, the same law as
``Executor.revoked_at`` and the runbook §3/§4 shape. Re-booting the core cannot
clear it either: ``relay_registry.register_relay_credential`` never writes
``revoked_at`` on an existing row.
"""

from __future__ import annotations

import os
import tempfile
from datetime import UTC, datetime
from typing import Any

from core.utils.cert_serial import canonical_serial, serial_match_clause
from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from ..audit_lifecycle import CORE_RELAY_CERT_REGISTERED, CORE_RELAY_CERT_REVOKED, audit_lifecycle
from ..dependencies import get_db, require_admin

router = APIRouter(tags=["admin"])

#: The named refusal for a serial the registry does not name. Kept as a module
#: constant in the project's existing refusal-string shape (see
#: ``relay_listener.REFUSE_*`` and the #603 truth-table's enumerated strings) so a
#: test can pin the vocabulary rather than pattern-match prose.
REFUSE_UNREGISTERED = "REFUSE_UNREGISTERED"

#: The one refusal sentence. It states the cause, the consequence and the remedy.
_UNREGISTERED_DETAIL = (
    f"{REFUSE_UNREGISTERED}: serial {{serial}} is not in the core relay credential registry, so there is no "
    "credential for this request to revoke and no consumer that could ever honour it. Register it first: "
    "restart the core (its boot ingests the relay credential it presents), or enroll it explicitly at "
    "POST /api/v1/admin/core-relay-credentials. An unregistered credential is NOT treated as revoked and NOT "
    "treated as live-by-default — revoking the unknown is how a store becomes an allowlist."
)


class CoreRelayCertRevokeRequest(BaseModel):
    """Body for the revoke verb."""

    model_config = {"extra": "forbid"}  # repo-wide extra=forbid ruling (#357): silent-drop dies here

    serial: str = Field(..., description="Certificate serial of the relay credential to revoke (hex, any spelling)")
    reason: str = Field(default="unspecified", max_length=500, description="Why, for the audit row")


class CoreRelayCertRevokeResponse(BaseModel):
    """Result of the revoke verb."""

    revoked: bool = Field(..., description="True when the registry now names this serial as revoked")
    serial_number: str = Field(..., description="The serial in canonical stored form")
    common_name: str | None = Field(default=None, description="CN the registry holds for it")
    already_revoked: bool = Field(default=False, description="Idempotent repeat of an earlier revoke")
    reason: str = Field(default="", description="Echo of the reason recorded on the row")


class CoreRelayCertRegisterRequest(BaseModel):
    """Body for the explicit-register verb (the installer-side alternative).

    Carries the certificate itself rather than a hand-typed serial, so the registry
    row is derived from the credential and cannot be made to claim a name it does not
    carry. This is what lets the mint step and the store be reconciled WITHOUT an
    installer edit — the operator or a future installer step POSTs the cert the
    installer already wrote to disk.
    """

    model_config = {"extra": "forbid"}

    certificate_pem: str = Field(
        ..., min_length=27, description="The relay client certificate in PEM, exactly as minted on disk"
    )
    reason: str = Field(default="operator-registered", max_length=500)


class CoreRelayCertRegisterResponse(BaseModel):
    """Result of the explicit-register verb."""

    created: bool = Field(..., description="True when this call added the row; False when it already existed")
    serial_number: str
    common_name: str | None = None
    fingerprint: str | None = None


def _validate_serial_or_400(provided: str) -> str:
    """Operator-string gate then canonical WRITE form — same contract as the sibling.

    Non-empty hex, at most 16 digits (unchanged 400 shape), then normalized once at
    the storage boundary via ``canonical_serial`` (#481). Callers compare with
    ``serial_match_clause`` so any stored legacy spelling still matches.
    """
    text = (provided or "").strip()
    try:
        if not text or len(text) > 16:
            raise ValueError("bad length")
        int(text, 16)
    except ValueError:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid serial format — must be hex string (up to 16 chars)",
        ) from None
    return canonical_serial(text)


@router.post("/admin/core-relay-certs/revoke", response_model=CoreRelayCertRevokeResponse)
async def admin_revoke_core_relay_cert(
    req: CoreRelayCertRevokeRequest,
    request: Request,
    admin: dict = Depends(require_admin),
    db: Session = Depends(get_db),
) -> CoreRelayCertRevokeResponse:
    """Revoke a core relay client credential by serial. Admin only, idempotent, default-deny.

    Truth table (every accept paired with a reject):

    | registry row for the serial | revoked_at | outcome |
    |---|---|---|
    | present | NULL | 200 ``revoked=true``, row stamped, audit written |
    | present | set | 200 ``revoked=true, already_revoked=true``, audit records the repeat |
    | ABSENT | — | **403 ``REFUSE_UNREGISTERED``**, nothing written, nothing audited as a revoke |
    | present | NULL | malformed serial → 400 before any lookup |
    """
    from core.iam.models import CoreRelayCredential

    serial = _validate_serial_or_400(req.serial)

    row = db.query(CoreRelayCredential).filter(serial_match_clause(CoreRelayCredential.serial_number, serial)).first()

    if row is None:
        # DEFAULT DENY. Not 404: the point is that the caller is refused, and a 404
        # reads like "nothing of that name exists anywhere" rather than "this store
        # does not vouch for it, so I will not act on it."
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=_UNREGISTERED_DETAIL.format(serial=serial),
        )

    already = row.revoked_at is not None
    if not already:
        row.revoked_at = datetime.now(UTC)
        row.revoke_reason = req.reason
        db.commit()
        db.refresh(row)

    audit_lifecycle(
        db,
        CORE_RELAY_CERT_REVOKED,
        admin.get("user_id"),
        {
            "serial_number": row.serial_number,
            "common_name": row.common_name,
            "reason": req.reason,
            "already_revoked": already,
        },
    )

    return CoreRelayCertRevokeResponse(
        revoked=True,
        serial_number=row.serial_number,
        common_name=row.common_name,
        already_revoked=already,
        reason=req.reason,
    )


@router.post(
    "/admin/core-relay-certs", response_model=CoreRelayCertRegisterResponse, status_code=status.HTTP_201_CREATED
)
async def admin_register_core_relay_cert(
    req: CoreRelayCertRegisterRequest,
    request: Request,
    admin: dict = Depends(require_admin),
    db: Session = Depends(get_db),
) -> CoreRelayCertRegisterResponse:
    """Register a core relay client credential from its certificate. Admin only.

    The facts are READ from the certificate (``relay_registry.read_relay_credential``),
    never taken from the request, so a caller cannot enroll an arbitrary serial. This
    is the verb that closes the gap for a credential the boot ingest has not seen —
    and the reason the installer edit is a proposal rather than a blocker: the mint
    step can hand its certificate here instead of writing a DB row itself.
    """
    from ..relay_registry import read_relay_credential, register_relay_credential

    tmp_path: str | None = None
    try:
        # read_relay_credential takes a path by design (it is the boot reader); write the
        # submitted PEM to a temp file and reuse that ONE parser rather than growing a
        # second certificate reader whose field mapping could drift from the first.
        fd, tmp_path = tempfile.mkstemp(prefix="venya-relay-cert-", suffix=".pem")
        with os.fdopen(fd, "w") as fh:
            fh.write(req.certificate_pem)
        facts = read_relay_credential(tmp_path)
    except (OSError, ValueError) as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"certificate_pem is not a readable relay credential: {exc}",
        ) from exc
    finally:
        if tmp_path:
            try:
                os.unlink(tmp_path)
            except OSError:
                pass

    outcome = register_relay_credential(db, facts)
    audit_lifecycle(
        db,
        CORE_RELAY_CERT_REGISTERED,
        admin.get("user_id"),
        {"serial_number": facts.serial_number, "common_name": facts.common_name, "created": outcome == "created"},
    )
    return CoreRelayCertRegisterResponse(
        created=outcome == "created",
        serial_number=facts.serial_number,
        common_name=facts.common_name,
        fingerprint=facts.cert_fingerprint,
    )


@router.get("/admin/core-relay-certs")
async def admin_list_core_relay_certs(
    request: Request,
    admin: dict = Depends(require_admin),
    db: Session = Depends(get_db),
) -> list[dict[str, Any]]:
    """List the registry — what an operator needs before choosing a serial to revoke.

    Read-only, and it deliberately reports the store's own emptiness as an empty list
    with no suggestion that anything is safe: the default-deny lives in the revoke
    verb, not in this one.
    """
    from core.iam.models import CoreRelayCredential

    rows = db.query(CoreRelayCredential).order_by(CoreRelayCredential.registered_at).all()
    return [
        {
            "serial_number": r.serial_number,
            "common_name": r.common_name,
            "hostname": r.hostname,
            "cert_fingerprint": r.cert_fingerprint,
            "signing_ca_subject": r.signing_ca_subject,
            "issued_at": r.issued_at.isoformat() if r.issued_at else None,
            "not_after": r.not_after.isoformat() if r.not_after else None,
            "registered_at": r.registered_at.isoformat() if r.registered_at else None,
            "revoked": r.revoked_at is not None,
            "revoked_at": r.revoked_at.isoformat() if r.revoked_at else None,
            "revoke_reason": r.revoke_reason,
        }
        for r in rows
    ]
