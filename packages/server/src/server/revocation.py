# Copyright (c) 2026 Tabith LLC.
# Use of this source code is governed by the Business Source License 1.1
# included in the LICENSE file at the root of this repository. As of the
# Change Date listed there, the work is available under MPL 2.0.
# SPDX-License-Identifier: BUSL-1.1

"""Single source of executor revocation state.

Ticket ``executor-revocation-by-identity`` (user rulings 2026-09-20, hybrid):
revocation semantics live HERE and nowhere else. Every consumer — the dial
gates (create_execution_session / execute_command_on_executor), the heartbeat
``revoked`` computation, the list_executors status display, the register
terminal check, and the Phase-2 incumbent exemption
(``executor-rotation-require-token-400``) — MUST route through
``executor_revocation_state``. A second implementation is a
rotation/revocation split-brain (revoked-but-rotating certs or vice versa);
this module is the contract comment that names the semantics source.

Ruled order (do not reorder):

1. IDENTITY FLAG FIRST — ``Executor.revoked_at`` set → revoked regardless of
   which serial/credential is presented. TERMINAL for alpha: no un-revoke
   operation exists; re-enrollment requires a NEW executor_id (runbook §3/§4).
2. SERIAL HISTORY — the presented serial, or when none is presented (dial
   gates, heartbeat) the CURRENT ``ExecutorCert`` record serial, present in
   ``executor_cert_revocations`` → revoked. This makes a serial-form
   revocation of the current record credential refuse dial too (ruling
   condition 1), while a rotated-away predecessor serial in the CRL (F6
   auto-revoke) never taints the identity.
3. Otherwise not revoked.

Lifecycle: the identity flag dies only with the Executor row — never via the
CRL retention purge. The CRL table is append-only serial history and advisory
broadcast; its time-based purge is permitted (ruling 3).
"""

from dataclasses import dataclass
from datetime import datetime
from typing import Any

from sqlalchemy.orm import Session


@dataclass(frozen=True)
class RevocationState:
    """Result of the single revocation check."""

    revoked: bool
    reason: str | None = None  # "identity" | "serial" | None
    revoked_at: datetime | None = None


def executor_revocation_state(
    db: Session,
    executor_id: str,
    presented_serial: str | None = None,
    executor_row: Any = None,
) -> RevocationState:
    """Compute revocation state for an executor identity.

    Args:
        db: Active session.
        executor_id: The executor identity (== cert CN/SAN == Executor row id).
        presented_serial: Serial actually in hand (Phase-2 exemption passes the
            verified client-cert serial). None → fall back to the current
            ExecutorCert record serial (dial/heartbeat/display callers).
        executor_row: Optional preloaded Executor ORM row (list_executors
            passes rows it already holds; avoids per-row requery).

    Returns:
        RevocationState — see module docstring for the ruled order.
    """
    from core.iam.models import Executor, ExecutorCert, ExecutorCertRevocation

    row = executor_row if executor_row is not None else db.query(Executor).filter(Executor.id == executor_id).first()
    if row is not None and getattr(row, "revoked_at", None) is not None:
        return RevocationState(True, "identity", row.revoked_at)

    serial = presented_serial.casefold() if presented_serial else None
    if serial is None:
        cert = db.query(ExecutorCert).filter(ExecutorCert.executor_id == executor_id).first()
        serial = cert.serial_number.casefold() if cert is not None and cert.serial_number else None
    if serial is not None:
        hit = db.query(ExecutorCertRevocation).filter(ExecutorCertRevocation.serial_number == serial).first()
        if hit is not None:
            return RevocationState(True, "serial", hit.revoked_at)

    return RevocationState(False)
