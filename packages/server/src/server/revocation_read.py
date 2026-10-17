# Copyright (c) 2026 Tabith LLC.
# Use of this source code is governed by the Business Source License 1.1
# included in the LICENSE file at the root of this repository. As of the
# Change Date listed there, the work is available under MPL 2.0.
# SPDX-License-Identifier: BUSL-1.1

"""Bounded-time revocation reads — the #603 AC1 fix that makes the shipped ceiling reachable.

WHY THIS EXISTS. ``executor_cert_revocations`` is read on the request path by the executor-mTLS
middleware, the heartbeat route, the register path, the two dial gates, the audit-ingest path,
the admin list paths and the PUBLIC CRL route — fourteen measured sites in the server package.
Every locked read there is synchronous SQLAlchemy inside an ``async def``, so a held
``ACCESS EXCLUSIVE`` lock parks the single-worker core event loop: measured on a shipping core as
a 57-second window with ZERO access-log lines, poll/health/ready all answering ``000``, and the
shipped 45 s freshness ceiling never getting to fire because the loop it would fire on is frozen
(``wave29-specs-20261016/flash2-603-liveness-offload-s129-report.md`` §5-§6, reproduced against
the anchor face ``81bf4369…``).

THE MEASURED FACT THAT DICTATES THE SHAPE. A blanket ``lock_timeout`` on the SHARED engine is
NOT safe, and this was measured rather than argued: with a 6-second holder on an ``executors``
row, the same legitimate beat-style write that shipped waits 4,037 ms and SUCCEEDS is instead
refused at 2,033 ms with ``canceling statement due to lock timeout``. A fix that trades a loop
freeze for refused writes is not a fix, so the deadline is not a connection- or engine-wide
setting. It is scoped to the read.

THE SEAM, and the four measured properties it is built on. Every locked read runs inside a
SAVEPOINT carrying ``SET LOCAL lock_timeout``; the savepoint is exited by ``ROLLBACK TO`` on a
refusal, and on success by an EXPLICIT ``SET LOCAL lock_timeout = '0'`` and then a release.

1. ``RELEASE SAVEPOINT`` alone does **not** revert ``SET LOCAL`` — the value stayed ``500ms``
   after release (measured). Hence the explicit revert: otherwise one successful read would
   silently leave the NEXT statement in that transaction — usually a legitimate write — under a
   deadline it was never meant to carry.
2. ``ROLLBACK TO SAVEPOINT`` reverts the deadline AND leaves the transaction usable
   (``tx_still_alive = t``, ``lock_timeout = 0``) and discards only work done inside the
   savepoint. A caller's pending write, flushed BEFORE the savepoint opened, therefore survives
   the refusal — which is why this seam flushes on entry. Without that flush, SQLAlchemy's
   autoflush would place the caller's pending write inside the savepoint and the refusal path
   would silently roll it back. A bounded read must never cost a caller its own write.
3. ``SET LOCAL`` (not ``SET``): a connection is pooled and outlives the request, so a session-
   wide setting would follow the deadline onto an unrelated later request on the same
   connection. Both facts above are pinned by cells in
   ``tests/test_revocation_read_bound_603.py``, including a pooled-connection reuse cell.
4. Refusal is 55P03 ONLY. ``QueryCanceled`` (57014, the statement-timeout shape) is NOT folded
   in: a slow scan and a lock wait are different failures, and AC1's first criterion is that the
   LOCK WAIT — the actual failure mode — gets its own named outcome.

THE DEADLINE NUMBER. 300 ms default, named on the config surface as
``crl.revocation_read_lock_timeout_ms`` (env ``VENYA_CRL__REVOCATION_READ_LOCK_TIMEOUT_MS``).
Measured baseline for this query shape on a settled core is 29 ms, so the default is ~10x
headroom over an uncontended read; measured refusal lands at deadline + ~35 ms (288/634/1033/
2035 ms for 250/600/1000/2000 ms deadlines). Against a convoy it replaces a 16,048 ms wait
behind a QUEUED, never-granted ``ACCESS EXCLUSIVE`` with a ~335 ms refusal; against a held lock
it replaces 27,058 ms. Both sit far inside the 45 s ceiling they protect and the daemon's 10 s
request timeout.

WHAT THIS MODULE DOES NOT DO.
* It changes no decision. The ruled order in ``server/revocation.py`` (identity flag first,
  then serial history) is untouched; this bounds WHEN a read may wait, never what it answers.
  It also does not widen ``executor_revocation_state``'s signature — a shipped cell pins that
  parameter list ("the reservation moved the SESSION, never the call"), so the per-site label
  travels in a ContextVar set with ``for_site`` instead of as a seventh argument.
* It never asserts a revocation. A refusal raises ``RevocationReadUnavailable`` — a LIST-STATE
  fault. Callers answer it in the shipped stale-class 503 and never 403, because
  ``daemon.py:319/_PERMANENT_REGISTER_STATUSES`` treats 403 as permanent rejection: a capacity
  fault wearing 403 would read to an executor as a revocation that never happened.
* It does not bound WRITES. The beat's own ``UPDATE executors`` stays unbonded by design — that
  is the traffic a blanket deadline breaks (measured above). Bounding the DDL/maintenance WRITER
  is shape C's ground, assessed separately, not this leg.
* It does not run on SQLite, where ``lock_timeout`` does not exist: the seam is a no-op there
  (the same dialect test the rate limiter uses, ``middleware/rate_limit.py:327``), so the unit
  suites answer byte-for-byte as they do today and the refusal cells use a raise double.
"""

from __future__ import annotations

import logging
from collections.abc import Iterator
from contextlib import contextmanager
from contextvars import ContextVar
from typing import Any

from sqlalchemy import text

from . import metrics

logger = logging.getLogger("venya.server")

#: Default read deadline in milliseconds; see the measured baseline and refusal landing above.
DEFAULT_LOCK_TIMEOUT_MS = 300

#: The one effective value, installed at startup from ``config.crl``. Module-level rather than
#: a per-call argument because the matcher is reached from fourteen sites, most with no
#: Request in hand — and two sources of truth is the drift this ticket exists to kill.
_lock_timeout_ms = DEFAULT_LOCK_TIMEOUT_MS

#: Latch so a persistent lock storm costs ONE warning, not one per refusal — the same reason
#: ``revocation_snapshot`` latches its no-publisher line: un-latched alarms are how real alarms
#: get ignored. The cumulative counter is the alerting surface; this line is the human trace.
_refusal_warned = False

#: PostgreSQL ``lock_not_available`` — the SQLSTATE a ``lock_timeout`` refusal carries.
LOCK_TIMEOUT_SQLSTATE = "55P03"

#: The ONE refusal sentence for a revocation-plane read that could not be answered — shared by
#: the stale-snapshot 503 and the bounded-read 503, because both are LIST-STATE faults and ops
#: must see one wording. ``routes/executors.py`` keeps its shipped ``_STALE_LIST_DETAIL`` name
#: as an alias of this constant; retyping the sentence is the class #603 has a written law about,
#: since a revocation-shaped message can end up naming an event that never happened.
REVOCATION_UNAVAILABLE_DETAIL = "Revocation list stale or unavailable — request refused (no revocation asserted)"

#: Both statements are fixed text with one validated integer interpolated; no caller ever
#: supplies the string. PostgreSQL accepts no bound parameter for a SET value.
_SET_DEADLINE_TEMPLATE = "SET LOCAL lock_timeout = '{ms}ms'"
_CLEAR_DEADLINE = text("SET LOCAL lock_timeout = '0'")

#: Which path is asking. A ContextVar, not an argument, because the matcher's shipped parameter
#: list is pinned by a cell; the default names the plane rather than pretending to be a site.
_site_label: ContextVar[str] = ContextVar("venya_revocation_read_site", default="revocation-plane")


class RevocationReadUnavailable(RuntimeError):
    """The bounded revocation read could not be answered inside its lock deadline.

    Its own class so the refusal is one ``except`` at each caller and the reason is never
    guessed from a ``None``. This is an availability fault on the revocation plane — NOT a
    revocation, and NOT an all-clear. A missing answer here must never be read as "nothing
    revoked", which is the fail-open #603 exists to close.
    """


def configure_lock_timeout(ms: int | None) -> None:
    """Install the effective read deadline from configuration.

    ``None``/0 keeps the shipped default rather than disabling the bound: disabling is not a
    supported posture on this plane, so a config that omits the key must not silently remove
    the protection.
    """
    global _lock_timeout_ms
    if ms and ms > 0:
        _lock_timeout_ms = int(ms)


def current_lock_timeout_ms() -> int:
    """The effective deadline — for the startup check and for cells that pin the number."""
    return _lock_timeout_ms


def current_site() -> str:
    """The active refusal label (``revocation-plane`` when nothing has set one)."""
    return _site_label.get()


@contextmanager
def for_site(name: str) -> Iterator[None]:
    """Label the reads in this scope, so a refusal names the path that hit it.

    Nest-safe: the previous label is restored on exit, including on a raise.
    """
    token = _site_label.set(name)
    try:
        yield
    finally:
        _site_label.reset(token)


def is_refusal_warned() -> bool:
    """True once a refusal has been journalled this process (the latch has fired)."""
    return _refusal_warned


def reset_read_deadline_state() -> None:
    """Clear the latch and restore the default deadline. A test seam mirroring
    ``revocation_snapshot.reset_snapshot_state``; never called by product code."""
    global _refusal_warned, _lock_timeout_ms
    _refusal_warned = False
    _lock_timeout_ms = DEFAULT_LOCK_TIMEOUT_MS


def deadline_statement(ms: int | None = None) -> Any:
    """The SET statement for the effective (or given) deadline, built from a validated int."""
    value = _lock_timeout_ms if ms is None else int(ms)
    return text(_SET_DEADLINE_TEMPLATE.format(ms=value))


def _is_postgresql(db: Any) -> bool:
    """Dialect test in the shape of ``middleware/rate_limit.py:327``. A session with no
    resolvable bind (a bare double) counts as non-PG, keeping the seam out of unit paths."""
    try:
        bind = db.get_bind()
    except Exception:
        return False
    return getattr(getattr(bind, "dialect", None), "name", None) == "postgresql"


def is_lock_timeout(exc: BaseException) -> bool:
    """True for a ``lock_timeout`` refusal (SQLSTATE 55P03), walking a bounded cause chain.

    SQLAlchemy exposes the driver code on ``exc.orig`` (a psycopg ``DatabaseError``), and the
    ``DBAPIError`` itself has no ``pgcode`` attribute — reading only the wrapper is how a real
    refusal gets classified as "some other fault" and escapes the counter, the latch and the
    named outcome. Both faces are checked at every hop, and the chain is walked a bounded number
    of times rather than assumed flat.
    """
    current: BaseException | None = exc
    depth = 0
    while current is not None and depth < 5:
        for candidate in (current, getattr(current, "orig", None)):
            if candidate is None:
                continue
            if getattr(candidate, "pgcode", None) == LOCK_TIMEOUT_SQLSTATE:
                return True
            if getattr(candidate, "sqlstate", None) == LOCK_TIMEOUT_SQLSTATE:
                return True
            errorcode = getattr(candidate, "errorcode", None)
            if isinstance(errorcode, tuple) and LOCK_TIMEOUT_SQLSTATE in errorcode:
                return True
        current = current.__cause__ or current.__context__
        depth += 1
    return False


def note_refusal(site: str, exc: BaseException) -> None:
    """Count EVERY refusal (cumulative, never latched) and WARN once (latched).

    The pairing is deliberate: #651's defect shape was a per-emit warning with no cumulative
    counter, so a losing component could not later state how much it lost. Here the counter is
    unconditional and the log line fires once, which keeps both the alert and the record.
    """
    metrics.REVOCATION_READ_REFUSALS_TOTAL.labels(site=site).inc()
    global _refusal_warned
    if not _refusal_warned:
        _refusal_warned = True
        logger.warning(
            "Revocation read refused at '%s' under the %d ms lock deadline — the revocation "
            "plane is UNAVAILABLE. That is not a revocation and not an all-clear: callers "
            "answer the shipped stale-class 503 and executors keep their last confirmed state "
            "and retry. This line fires ONCE per process by design; the alerting surface is the "
            "cumulative counter venya_revocation_read_refusals_total{site=} (refs #603 AC1). "
            "Underlying fault: %r",
            site,
            _lock_timeout_ms,
            exc,
        )


@contextmanager
def bounded_read(db: Any, *, site: str | None = None) -> Iterator[None]:
    """Run the enclosed SELECT(s) under a bounded lock wait, then restore the transaction.

    ``site`` names the metric label and the log line so ops can say WHICH path refused; omitted,
    it comes from the surrounding ``for_site`` scope. Callers catch ``RevocationReadUnavailable``.
    """
    label = site or current_site()
    if not _is_postgresql(db):
        yield
        return

    # Flush BEFORE the savepoint so a caller's pending write is never inside the scope this
    # function may roll back. Removing this line silently converts a refusal into data loss.
    db.flush()
    sp = db.begin_nested()
    try:
        db.execute(deadline_statement())
        yield
    except Exception as exc:
        sp.rollback()
        if is_lock_timeout(exc):
            note_refusal(label, exc)
            raise RevocationReadUnavailable(
                f"revocation read at '{label}' did not answer inside the {_lock_timeout_ms} ms "
                f"lock deadline (SQLSTATE {LOCK_TIMEOUT_SQLSTATE})"
            ) from exc
        raise
    else:
        # Explicit revert BEFORE the release: RELEASE does not undo SET LOCAL (measured), so
        # this is the only thing standing between one successful read and a deadline on the
        # caller's next write. A revert that itself faults must not replace the answer already
        # read — the guarded-teardown discipline publish_once's finally uses (#626).
        try:
            db.execute(_CLEAR_DEADLINE)
        except Exception as teardown_fault:
            logger.warning(
                "Could not revert the revocation read deadline at '%s': %r — the population "
                "already read is returned; the savepoint is the backstop for the setting, not "
                "this statement",
                label,
                teardown_fault,
            )
        # A nested transaction's ``commit()`` IS ``RELEASE SAVEPOINT`` in SQLAlchemy — there is
        # no ``release()`` on SessionTransaction. Found on the live core, not in the unit suite:
        # the first draft called ``sp.release()`` and every read died with AttributeError, while
        # the test double, which had one, stayed green. That asymmetry is the reason AC1 demanded
        # a physical run, and the comment lives in the code so the next seat does not re-add the
        # method that does not exist.
        sp.commit()
