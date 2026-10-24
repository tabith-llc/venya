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
4. Refusal is 55P03 ONLY *for the lock class*. ``QueryCanceled`` (57014, the statement-timeout
   shape) is NOT folded into it: a slow scan and a lock wait are different failures, and AC1's
   first criterion is that the LOCK WAIT — the actual failure mode — gets its own named outcome.
   #654 adds the OTHER named outcome beside it rather than merging the two: a read cancelled by
   its own statement deadline raises ``RevocationReadScanTimeout`` and counts on a series of its
   own. The 55P03 class, its message, its counter and its latch are byte-unchanged.

THE SCAN DEADLINE (#654 — the row shape A did not cover). ``lock_timeout`` bounds the WAIT for a
lock and nothing else, so a read that is merely SLOW ran under one bound only: the session-wide
``SET statement_timeout = '300s'`` the engine's connect listener installs
(``core/engine/backend.py``) — five hundred times the read's own budget. The measured consequence
is the state nothing in the tree could name: a 12 s revocation read SUCCEEDS, while the executor
polling it gave up at 10 s (``NetworkConfig.request_timeout_seconds``, ``executor/config.py``), so
the caller counts a failure the core recorded as a 200, the single worker loop was parked for the
whole 12 s, and there was no counter, no refusal and no log line anywhere. Inside the same savepoint
the seam therefore sets ``SET LOCAL statement_timeout`` to ``crl.revocation_read_scan_timeout_ms``
(default 2 000 ms): a read that cannot ANSWER by then is refused in the named class above, counted,
and never served late.

THE SCAN REVERT IS NOT THE LOCK REVERT, AND THAT IS MEASURED. The shipped ``_CLEAR_DEADLINE``
restores ``lock_timeout`` to ``'0'`` because PostgreSQL's default for it IS 0 and our session value
is 0. ``statement_timeout`` is asymmetric — our session value is 300 s while PostgreSQL's own
default is 0 — so ``SET LOCAL statement_timeout = '0'`` does not revert the narrowing, it REMOVES
the bound for the rest of the caller's transaction: property 1 inverted. Measured on this box
(PostgreSQL 17, ``SET LOCAL statement_timeout = '200ms'``, then the two revert forms side by side):
the revert-to-``'0'`` form leaves ``current_setting('statement_timeout')`` at ``0`` and a following
``pg_sleep(1)`` survives it; the restore-the-captured-value form leaves ``5min``. So the seam
captures the session value with ``SHOW statement_timeout`` before it narrows, and restores THAT.
Two consequences follow from the capture and both are pinned by cells: the seam never hard-codes
300 s (a third source of truth is the drift class this plane has a written law about), and it never
NARROWS when the session value is already tighter — installing 2 000 ms over an operator's 500 ms
would be a silent widening dressed up as a bound.

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
import re
import time
from collections.abc import Iterator
from contextlib import contextmanager
from contextvars import ContextVar
from typing import Any

from sqlalchemy import text

from . import metrics

logger = logging.getLogger("venya.server")

#: Default read deadline in milliseconds; see the measured baseline and refusal landing above.
DEFAULT_LOCK_TIMEOUT_MS = 300

#: Default SCAN deadline in milliseconds — how long one revocation read may take to EXECUTE, as
#: distinct from how long it may wait for a lock. 2 000 ms is ~6.7x the 300 ms lock budget above
#: and 5x UNDER the daemon's 10 s request timeout, so a refusal still lands while the caller is
#: there to count it; that pairing is the state the 12 s row above leaves.
#: Stated as what it is: this is a chosen default, NOT a measurement of the slowest legitimate
#: read — no populated fleet face was timed here. shortcut: the bound protects at any value, the
#: value wants one door-ON p95 pass. upgrade when a fleet cell measures the slowest legitimate read.
DEFAULT_SCAN_TIMEOUT_MS = 2000

#: The one effective value, installed at startup from ``config.crl``. Module-level rather than
#: a per-call argument because the matcher is reached from fourteen sites, most with no
#: Request in hand — and two sources of truth is the drift this ticket exists to kill.
_lock_timeout_ms = DEFAULT_LOCK_TIMEOUT_MS

#: The one effective scan deadline, installed at startup from ``config.crl`` for the same reason
#: the lock deadline is, and by the same single call site in ``app.py``.
_scan_timeout_ms = DEFAULT_SCAN_TIMEOUT_MS

#: Latch so a persistent lock storm costs ONE warning, not one per refusal — the same reason
#: ``revocation_snapshot`` latches its no-publisher line: un-latched alarms are how real alarms
#: get ignored. The cumulative counter is the alerting surface; this line is the human trace.
_refusal_warned = False

#: The two scan latches, each SEPARATE from the lock latch above on purpose. A seat that read the
#: lock line would tune ``revocation_read_lock_timeout_ms`` for a scan problem, so the scan line
#: never borrows the lock line's wording; and the unreadable-GUC state is its own fact.
_scan_refusal_warned = False
_scan_unreadable_warned = False

#: The #478 latch, separate again on purpose: an operator who reads the unreadable-GUC line tunes a
#: session GUC, and neither of those is the fault this one names (a bind that cannot say its dialect).
#: The counter beside it is never latched — the count survives the latch, which is #651's lesson.
_unbounded_dialect_warned = False

#: The one dialect name that means "the SET LOCAL deadlines in this module will be honoured".
#: Spelled once because the two places that ask the question — the seam's own gate and the
#: unknown-dialect journal — must agree on the answer. Two literals is the drift this file already
#: has a law about.
POSTGRESQL_DIALECT = "postgresql"

#: PostgreSQL ``lock_not_available`` — the SQLSTATE a ``lock_timeout`` refusal carries.
LOCK_TIMEOUT_SQLSTATE = "55P03"

#: PostgreSQL ``query_canceled`` — the SQLSTATE a ``statement_timeout`` cancellation carries. Its
#: own name, never a value inside the lock class: see property 4 above.
SCAN_TIMEOUT_SQLSTATE = "57014"

#: The ONE refusal sentence for a revocation-plane read that could not be answered — shared by
#: the stale-snapshot 503 and the bounded-read 503, because both are LIST-STATE faults and ops
#: must see one wording. ``routes/executors.py`` keeps its shipped ``_STALE_LIST_DETAIL`` name
#: as an alias of this constant; retyping the sentence is the class #603 has a written law about,
#: since a revocation-shaped message can end up naming an event that never happened.
REVOCATION_UNAVAILABLE_DETAIL = "Revocation list stale or unavailable — request refused (no revocation asserted)"

#: The narrowing statements are fixed text with one validated integer interpolated; no caller ever
#: supplies the string, because PostgreSQL accepts no bound parameter for a ``SET`` value. The scan
#: RESTORE is the one statement whose text came from the server (``SHOW statement_timeout``) and it
#: passes ``_SCAN_VALUE_SHAPE`` before it is built — see ``scan_restore_statement``.
_SET_DEADLINE_TEMPLATE = "SET LOCAL lock_timeout = '{ms}ms'"
_CLEAR_DEADLINE = text("SET LOCAL lock_timeout = '0'")

#: The scan pair. The restore template interpolates ONLY a string the server itself printed in
#: answer to ``_SHOW_SCAN_DEADLINE`` and that ``scan_deadline_ms`` accepted — never caller text, and
#: never a hard-coded copy of the session number.
_SET_SCAN_DEADLINE_TEMPLATE = "SET LOCAL statement_timeout = '{ms}ms'"
_RESTORE_SCAN_DEADLINE_TEMPLATE = "SET LOCAL statement_timeout = '{value}'"
_SHOW_SCAN_DEADLINE = text("SHOW statement_timeout")

#: A time GUC exactly as PostgreSQL displays one: a plain count of milliseconds, or a number with
#: one of the unit suffixes it accepts for these settings. Anything else is refused and never
#: reaches SQL text — this is the only thing between a server-printed string and an interpolation.
_SCAN_VALUE_SHAPE = re.compile(r"\d+(?:\.\d+)?(?:us|ms|min|h|s|d)?\Z")

#: Unit suffix to milliseconds, for the compare-never-widen rule.
_SCAN_UNIT_MS = {"us": 0.001, "ms": 1.0, "s": 1000.0, "min": 60000.0, "h": 3600000.0, "d": 86400000.0}

#: Clock seam. Product code calls it directly; a cell may patch THIS name to pin an elapsed read
#: without reaching into the stdlib ``time`` module that every other seat in the process shares.
_monotonic = time.monotonic

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


class RevocationReadScanTimeout(RevocationReadUnavailable):
    """The read was cancelled by its OWN statement deadline (#654): it ran too long, it did not
    wait too long for a lock.

    Deliberately a SUBCLASS, not a sibling. Every shipped arm already catches
    ``RevocationReadUnavailable`` — the one central handler in ``app.py`` and the per-site arms in
    ``middleware/auth.py`` and ``routes/executors.py`` — so a scan refusal is answered by the code
    that exists, in the shipped stale-class 503 with the one shared sentence, and no site had to
    remember a second ``except``. A refusal arm that must be remembered at fourteen sites is a
    refusal arm missing at one; that is why the app owns one handler. Being its own class is what
    keeps it DISTINGUISHABLE: the type, the message, the log line and the counter all name the scan,
    and none of them moves the 55P03 series. Still a LIST-STATE fault — never a revocation, never an
    all-clear.
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
    """The effective lock deadline — for the startup check and for cells that pin the number."""
    return _lock_timeout_ms


def configure_scan_timeout(ms: int | None) -> None:
    """Install the effective scan (statement) deadline from configuration.

    Same posture as ``configure_lock_timeout``: ``None``/0 keeps the shipped default rather than
    disabling the bound, because disabling is not a supported posture on this plane.
    """
    global _scan_timeout_ms
    if ms and ms > 0:
        _scan_timeout_ms = int(ms)


def current_scan_timeout_ms() -> int:
    """The effective scan deadline — for cells that pin the number and for the refusal message."""
    return _scan_timeout_ms


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
    """True once a LOCK-class refusal has been journalled this process (the latch has fired)."""
    return _refusal_warned


def is_scan_refusal_warned() -> bool:
    """True once a SCAN-class refusal has been journalled this process. Its own latch, because a
    seat that read the lock line would tune the wrong number."""
    return _scan_refusal_warned


def reset_read_deadline_state() -> None:
    """Clear the latches and restore both default deadlines. A test seam mirroring
    ``revocation_snapshot.reset_snapshot_state``; never called by product code."""
    global _refusal_warned, _scan_refusal_warned, _scan_unreadable_warned
    global _unbounded_dialect_warned
    global _lock_timeout_ms, _scan_timeout_ms
    _refusal_warned = False
    _scan_refusal_warned = False
    _scan_unreadable_warned = False
    _unbounded_dialect_warned = False
    _lock_timeout_ms = DEFAULT_LOCK_TIMEOUT_MS
    _scan_timeout_ms = DEFAULT_SCAN_TIMEOUT_MS


def is_scan_unreadable_warned() -> bool:
    """True once the unreadable-session-bound state has been journalled this process."""
    return _scan_unreadable_warned


def is_unbounded_dialect_warned() -> bool:
    """True once the unknown-dialect state has been journalled this process (the #478 latch)."""
    return _unbounded_dialect_warned


def deadline_statement(ms: int | None = None) -> Any:
    """The SET statement for the effective (or given) lock deadline, built from a validated int."""
    value = _lock_timeout_ms if ms is None else int(ms)
    return text(_SET_DEADLINE_TEMPLATE.format(ms=value))


def scan_deadline_statement(ms: int | None = None) -> Any:
    """The SET statement for the effective (or given) scan deadline, built from a validated int.

    Same discipline as ``deadline_statement``: the template interpolates an ``int`` and nothing
    else, so a string can never smuggle SQL text into a bound.
    """
    value = _scan_timeout_ms if ms is None else int(ms)
    return text(_SET_SCAN_DEADLINE_TEMPLATE.format(ms=value))


def scan_deadline_ms(raw: object) -> float | None:
    """Milliseconds behind a ``SHOW statement_timeout`` answer, or None when it is unusable.

    ``0`` means NO session bound (PostgreSQL's own default) and answers ``0.0``, not None — the
    caller treats "no bound" as "narrow it" and "unreadable" as "leave it alone". Anything the
    shape guard rejects returns None, and a None is the one answer that must never be interpolated.
    """
    if isinstance(raw, bool) or not isinstance(raw, str):
        return None
    value = raw.strip()
    if not _SCAN_VALUE_SHAPE.match(value):
        return None
    number = value.rstrip("abcdefghijklmnopqrstuvwxyz")
    unit = value[len(number) :]
    try:
        return float(number) * _SCAN_UNIT_MS.get(unit, 1.0)
    except ValueError:
        return None


def scan_restore_statement(raw: str) -> Any | None:
    """The statement that puts the session's own scan bound back, or None if it is not restorable.

    The ONLY path from a server-printed string into SQL text here, and it re-checks the shape
    rather than trusting the caller: a value ``scan_deadline_ms`` could not read is never written.
    """
    value = raw.strip()
    if not _SCAN_VALUE_SHAPE.match(value):
        return None
    return text(_RESTORE_SCAN_DEADLINE_TEMPLATE.format(value=value))


def _dialect_name(db: Any) -> str | None:
    """The bind's dialect name, or None when the session could not say what it is.

    Three answers, not two: a name (``"sqlite"``, ``"postgresql"``, …) is a FACT the seam can act
    on, and ``None`` is the ABSENCE of one. The seam's own posture is unchanged by this leg — on
    ``None`` it still yields and lets the read run unbonded, and :func:`note_unbounded_dialect`
    counts and journals that. Refusing instead is an availability decision the owner has not made.

    NOT the same shape as ``middleware/rate_limit.py:326-327``, whatever an older docstring here
    claimed. That gate asks the same question and resolves the unknown the OTHER way: it guards
    with ``hasattr`` so a bind that cannot be had becomes ``bind is None``, and its test is
    ``if bind is None or bind.dialect.name == "postgresql"`` — an unresolvable bind takes the
    STRICTER (PostgreSQL) branch, and its own docstring says that is deliberate ("a session that
    cannot report its dialect is treated as PostgreSQL so the production contract stays pinned").
    This module treats the same input as non-PG, i.e. the LOOSER branch, and a raising
    ``get_bind`` there is not an error at all, just a silence. Measured both ways at
    ``4620432c`` on the identical input — an object with no ``get_bind``: rate_limit takes its PG
    branch, this seam takes its unbonded branch.

    The divergence is recorded, not repaired: aligning them would move an unknown bind from
    unbonded to bounded-and-potentially-refusing on the revocation path, which is the availability
    call above, and #704's row carries it to the owner rather than a leg answering it here."""
    try:
        bind = db.get_bind()
    except Exception:
        return None
    return getattr(getattr(bind, "dialect", None), "name", None)


def _sqlstate_hit(current: BaseException | None, sqlstate: str, depth: int = 0) -> bool:
    """Shared walker for the two SQLSTATE classes: check the exception AND its ``orig``, and walk
    a bounded cause chain rather than assuming it is flat."""
    while current is not None and depth < 5:
        for candidate in (current, getattr(current, "orig", None)):
            if candidate is None:
                continue
            if getattr(candidate, "pgcode", None) == sqlstate:
                return True
            if getattr(candidate, "sqlstate", None) == sqlstate:
                return True
            errorcode = getattr(candidate, "errorcode", None)
            if isinstance(errorcode, tuple) and sqlstate in errorcode:
                return True
        current = current.__cause__ or current.__context__
        depth += 1
    return False


def is_lock_timeout(exc: BaseException) -> bool:
    """True for a ``lock_timeout`` refusal (SQLSTATE 55P03), walking a bounded cause chain.

    SQLAlchemy exposes the driver code on ``exc.orig`` (a psycopg ``DatabaseError``), and the
    ``DBAPIError`` itself has no ``pgcode`` attribute — reading only the wrapper is how a real
    refusal gets classified as "some other fault" and escapes the counter, the latch and the
    named outcome. Both faces are checked at every hop, and the chain is walked a bounded number
    of times rather than assumed flat.

    55P03 ONLY. That exclusion is AC1 criterion 1, it is pinned by
    ``test_query_canceled_is_not_folded_into_the_lock_refusal``, and #654 did not widen it: the
    scan class is answered by ``is_query_canceled`` beside it, never inside it.
    """
    return _sqlstate_hit(exc, LOCK_TIMEOUT_SQLSTATE)


def is_query_canceled(exc: BaseException) -> bool:
    """True for a ``statement_timeout`` cancellation (SQLSTATE 57014), same bounded walker.

    The class #654 names: the statement ran past its own deadline and PostgreSQL cancelled it. Read
    separately from the lock class on purpose — two failures an operator chases two different ways,
    on two different series, with two different tunable numbers.
    """
    return _sqlstate_hit(exc, SCAN_TIMEOUT_SQLSTATE)


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


def note_scan_refusal(site: str, exc: BaseException) -> None:
    """Count EVERY scan-deadline refusal on its OWN series (cumulative, never latched), warn once.

    Not folded into ``note_refusal``, and not a new label bolted onto the #603 series: a slow scan
    and a lock convoy are different failures (AC1 criterion 1 exists so ops can tell them apart),
    and a label added to an existing series silently re-splits every operator query and dashboard
    built on it. So: new name, same pairing — the counter is unconditional, the line fires once
    (#651's defect shape was a per-emit warning with no counter at all).
    """
    metrics.REVOCATION_READ_SCAN_REFUSALS_TOTAL.labels(site=site).inc()
    global _scan_refusal_warned
    if not _scan_refusal_warned:
        _scan_refusal_warned = True
        logger.warning(
            "Revocation read at '%s' was CANCELLED by its own %d ms statement deadline — it ran "
            "too long, which is NOT the same fault as waiting too long for a lock and is counted on "
            "a separate series. The revocation plane is UNAVAILABLE: that is not a revocation and "
            "not an all-clear, callers answer the shipped stale-class 503 and executors keep their "
            "last confirmed state and retry. This line fires ONCE per process by design; the "
            "alerting surface is the cumulative counter "
            "venya_revocation_read_scan_refusals_total{site=} (refs #654). Underlying fault: %r",
            site,
            _scan_timeout_ms,
            exc,
        )


def note_unbounded_dialect(site: str, dialect: str | None) -> None:
    """Journal the state in which a revocation read ran with NO deadline because the dialect was
    unknown. Counted EVERY time, warned ONCE.

    The behavior is deliberately UNCHANGED — the read still runs, unbonded, exactly as it did
    before this function existed. Refusing instead is an availability decision on a security
    surface (a bind that cannot answer would then deny every revocation check on that core), and
    it is not a lane's or the lead's to make, so this leg makes the fault VISIBLE and leaves the
    policy where it was. See the leg-478 report §1.

    The clean non-PG case is NOT counted here: ``sqlite`` answers the question, and a shipped
    test path must not become an operator alarm. Only ``None`` — "I could not tell" — increments,
    which is the whole distinction this function exists to draw.
    """
    metrics.REVOCATION_READ_UNBOUNDED_TOTAL.labels(site=site).inc()
    global _unbounded_dialect_warned
    if not _unbounded_dialect_warned:
        _unbounded_dialect_warned = True
        logger.warning(
            "Revocation read at '%s' installed NO deadline: the session could not report its "
            "dialect (bind answered %r, not a dialect name), so this read ran UNBOUNDED and a held "
            "lock on the revocation tables would park the core loop here — the #603 AC1 shape. "
            "The read was NOT refused and this is NOT a revocation verdict. This line fires ONCE "
            "per process by design; the alerting surface is the cumulative counter "
            "venya_revocation_read_unbounded_total{site=} (found leg 478, s266).",
            site,
            dialect,
        )


def note_bound_unreadable(site: str, raw: object) -> None:
    """One latched line for the state in which the session's scan bound could not be read.

    Loud, and once. The seam's response is to leave that read under the session bound it found —
    never to install a hard-coded number, never to write an unreadable string into SQL — so the read
    is unbonded by #654's standard while it happens. A silent skip would be the 'check that passes
    only the positive case' shape this plane keeps booking, so the state gets its own line and its
    own cell.
    """
    global _scan_unreadable_warned
    if not _scan_unreadable_warned:
        _scan_unreadable_warned = True
        logger.warning(
            "Revocation read at '%s' got NO scan deadline: SHOW statement_timeout answered %r, "
            "which is not a value the seam can restore, so nothing was narrowed and the session's "
            "own bound stays in force for this read. The lock deadline still applies. This line "
            "fires ONCE per process; the fix is the session GUC, never a hard-coded number here "
            "(refs #654).",
            site,
            raw,
        )


def _apply_scan_bound(db: Any, site: str) -> Any | None:
    """Narrow this read's ``statement_timeout``; return the statement that restores it, or None.

    Three measured rules, each with its own cell:

    1. READ BEFORE NARROWING. The session value is captured with ``SHOW`` and restored verbatim on
       the success path. Reverting to ``'0'`` — the shipped ``lock_timeout`` form — would REMOVE the
       bound for the rest of the caller's transaction, because PostgreSQL's default here is 0 while
       our session value is 300 s. The asymmetry is the trap; the capture is the escape.
    2. NEVER WIDEN. If the session bound is already at or below ours, nothing is set. Installing
       2 000 ms over an operator's 500 ms would loosen the very bound they asked for.
    3. NOTHING UNREADABLE REACHES SQL. If ``SHOW`` did not answer with a shape this module can
       restore, the read is left alone and ``note_bound_unreadable`` says so once.

    The ``SHOW`` itself is deliberately NOT swallowed: a connection that cannot answer it is the
    read's own fault, and it belongs in the caller's arms, not in a quiet branch here.
    """
    raw = db.execute(_SHOW_SCAN_DEADLINE).scalar()
    session_ms = scan_deadline_ms(raw)
    if session_ms is None:
        note_bound_unreadable(site, raw)
        return None
    if session_ms != 0 and session_ms <= _scan_timeout_ms:
        return None
    restore = scan_restore_statement(raw)
    if restore is None:  # unreachable while session_ms is not None; a guard, not a branch
        note_bound_unreadable(site, raw)
        return None
    db.execute(scan_deadline_statement())
    return restore


def note_read_duration(site: str, seconds: float) -> None:
    """Observe one bounded read onto the duration histogram (#654's visibility half).

    Why a series of its own: ``venya_request_duration_seconds`` tops out at a 10.0 bucket, so a 12 s
    read and a 300 s read are the same observation there — a histogram that cannot express the
    quantity the row is about is a histogram of the wrong thing. These buckets reach 300 s, the bound
    that actually governed the read, which is what makes a slow-but-successful read countable at all:
    it raises nothing, so no counter can ever see it.
    """
    metrics.REVOCATION_READ_DURATION_SECONDS.labels(site=site).observe(max(0.0, float(seconds)))


@contextmanager
def bounded_read(db: Any, *, site: str | None = None) -> Iterator[None]:
    """Run the enclosed SELECT(s) under a bounded lock wait AND a bounded execution time.

    ``site`` names the metric label and the log line so ops can say WHICH path refused; omitted,
    it comes from the surrounding ``for_site`` scope. Callers catch ``RevocationReadUnavailable``,
    which also catches the #654 scan subclass — no caller had to be touched to gain the new bound.
    """
    label = site or current_site()
    dialect = _dialect_name(db)
    if dialect != POSTGRESQL_DIALECT:
        # The two non-PG answers are NOT the same fact, and only one of them is normal. A real
        # dialect name (``sqlite``) is a clean negative: the seam is inert and says nothing, so a
        # unit suite or a legacy install does not become an alarm. ``None`` means the bind could
        # not say — the read is about to run with NO bound at all, which is #603's freeze shape at
        # a door nobody was watching, so it gets counted and journalled. The decision to yield is
        # UNCHANGED either way: making that a refusal is an availability call on a security
        # surface, and it is the owner's, not this leg's.
        if dialect is None:
            note_unbounded_dialect(label, dialect)
        yield
        return

    # Flush BEFORE the savepoint so a caller's pending write is never inside the scope this
    # function may roll back. Removing this line silently converts a refusal into data loss.
    db.flush()
    sp = db.begin_nested()
    started = _monotonic()
    scan_restore: Any = None
    try:
        db.execute(deadline_statement())
        # #654: the second bound, in the SAME savepoint, so both are reverted by the same two
        # mechanisms and neither follows the connection onto an unrelated later request.
        scan_restore = _apply_scan_bound(db, label)
        yield
    except Exception as exc:
        sp.rollback()
        note_read_duration(label, _monotonic() - started)
        if is_lock_timeout(exc):
            note_refusal(label, exc)
            raise RevocationReadUnavailable(
                f"revocation read at '{label}' did not answer inside the {_lock_timeout_ms} ms "
                f"lock deadline (SQLSTATE {LOCK_TIMEOUT_SQLSTATE})"
            ) from exc
        if is_query_canceled(exc):
            # The third outcome, named: 57014 keeps its own class, its own series and its own
            # number in this message. It is NOT the lock refusal re-worded, and the order of the
            # two checks above is what keeps a lock convoy from ever being reported as a slow scan
            # (300 ms of waiting trips lock_timeout long before the 2 000 ms scan bound can).
            note_scan_refusal(label, exc)
            raise RevocationReadScanTimeout(
                f"revocation read at '{label}' did not answer inside the {_scan_timeout_ms} ms "
                f"statement deadline (SQLSTATE {SCAN_TIMEOUT_SQLSTATE})"
            ) from exc
        raise
    else:
        note_read_duration(label, _monotonic() - started)
        # Explicit revert BEFORE the release: RELEASE does not undo SET LOCAL (measured), so
        # this is the only thing standing between one successful read and a deadline on the
        # caller's next write. A revert that itself faults must not replace the answer already
        # read — the guarded-teardown discipline publish_once's finally uses (#626).
        try:
            if scan_restore is not None:
                # Restore what the server said its own bound was — never '0', which here would mean
                # NO bound, and never a copy of 300 s, which would be a third source of truth.
                db.execute(scan_restore)
            db.execute(_CLEAR_DEADLINE)
        except Exception as teardown_fault:
            logger.warning(
                "Could not revert the revocation read deadlines at '%s': %r — the population "
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
