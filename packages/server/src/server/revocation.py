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

#603 AC1 addition (this leg): the read runs under a BOUNDED lock wait, and a read
that cannot answer inside its deadline raises ``RevocationReadUnavailable``
instead of parking the caller. The ORDER above and every answer it produces are
unchanged; only the failure mode of a stalled read changed — from an unbounded
wait that froze the core event loop to a named, counted, refused-in-time fault.
The parameter list below is deliberately NOT widened to carry the refusal's
site label: ``test_liveness_reserved_path_603.py::TestNoSecondImplementation``
pins it ("the reservation moved the SESSION, never the call"), so a caller that
wants its own label wraps the call in ``revocation_read.for_site``.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Any

from sqlalchemy.orm import Session

from .revocation_read import bounded_read


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
    """Compute revocation state for an executor identity, with a bounded lock wait.

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

    Raises:
        RevocationReadUnavailable: the read of the lockable revocation population
            did not answer inside ``crl.revocation_read_lock_timeout_ms``. This is a
            LIST-STATE fault, never a verdict — callers must refuse in the shipped
            stale class (503) and must never read it as "not revoked". Deliberately
            NOT a 403: the daemon treats 403 as permanent rejection
            (``daemon.py:319/_PERMANENT_REGISTER_STATUSES``), so answering a capacity
            fault with 403 would read to the executor as a revocation that never
            happened.
    """
    from core.iam.models import Executor, ExecutorCert, ExecutorCertRevocation
    from core.utils.cert_serial import canonical_serial, serial_match_clause

    # #603 AC1. Both SELECTs below read tables a held ACCESS EXCLUSIVE lock parks, and every
    # caller of this function is reached from an `async def` handler on the single-worker core
    # loop — measured as a 57 s window with zero access-log lines, in which the shipped 45 s
    # freshness ceiling could never fire. The savepoint-scoped deadline in revocation_read.py
    # bounds the WAIT without ever putting a deadline on the caller's own writes (that scoping
    # is measured, not assumed — see that module's docstring). Nothing here re-decides: same
    # ruled order, same answers, a new failure mode for a read that cannot be answered.
    with bounded_read(db):
        row = (
            executor_row if executor_row is not None else db.query(Executor).filter(Executor.id == executor_id).first()
        )
        if row is not None and getattr(row, "revoked_at", None) is not None:
            return RevocationState(True, "identity", row.revoked_at)

        # Serial history, matched in the ONE canonical representation and compared
        # case/padding-insensitively (ticket cert-serial-canonicalization-mismatch
        # #481): legacy rows are stored padded, unpadded, upper and lower, and no
        # migration rewrites them.
        serial = canonical_serial(presented_serial) if presented_serial else None
        if serial is None:
            cert = db.query(ExecutorCert).filter(ExecutorCert.executor_id == executor_id).first()
            serial = canonical_serial(cert.serial_number) if cert is not None and cert.serial_number else None
        if serial is not None:
            hit = (
                db.query(ExecutorCertRevocation)
                .filter(serial_match_clause(ExecutorCertRevocation.serial_number, serial))
                .first()
            )
            if hit is not None:
                return RevocationState(True, "serial", hit.revoked_at)

        return RevocationState(False)
