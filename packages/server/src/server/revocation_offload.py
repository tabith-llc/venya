# Copyright (c) 2026 Tabith LLC.
# Use of this source code is governed by the Business Source License 1.1
# included in the LICENSE file at the root of this repository. As of the
# Change Date listed there, the work is available under MPL 2.0.
# SPDX-License-Identifier: BUSL-1.1

"""Off-loop revocation reads — the #603 AC1 thread-placement half.

WHY THIS EXISTS. #603's request-path revocation reads are synchronous SQLAlchemy inside
``async def`` handlers on a single-worker core loop. The first fix put a DEADLINE on the wait
(``server/revocation_read.py``, ``bounded_read``: ``SET LOCAL lock_timeout`` + the #654
``statement_timeout``, both savepoint-scoped), so a held ``ACCESS EXCLUSIVE`` now ends in a named
refusal instead of the measured stall — 49 s with zero access-log lines at
``wave29-specs-20261016/flash1-603-tt7-s129-report.md``, 57 s re-measured at
``wave29-specs-20261016/flash2-603-liveness-offload-s129-report.md`` §5-§6.

A deadline bounds HOW LONG one read can hold the loop. It does not move the read off the loop, and
three states the shipped seam names itself therefore still cost the loop real time:

* the refusal itself — the deadline plus the round trip (~35 ms measured), serially, once per
  concurrent reader, because every one of them runs on the one worker;
* a read that answers SLOWLY inside the scan budget (up to 2 s) blocks the loop for that whole
  time while the executor that asked has already gone at 10 s (``NetworkConfig.request_timeout_seconds``);
* the seam's own unbonded branches: a non-PostgreSQL dialect yields with no bound at all, and a bind
  that CANNOT report its dialect yields too — counted and journalled by ``note_unbounded_dialect``,
  decided by the owner and not by this module (#704 carries that row).

So the two layers are not alternatives and this one does not supersede the other: the seam makes a
stall REFUSABLE, this module makes it NON-FREEZING. Moving the read to a worker thread is what keeps
the loop serving the poll, the heartbeat, ``/ready`` and the health endpoint while one revocation read
is waiting, and it is what bounds the cost of the unbonded branches to one worker instead of the core.

THE SHAPE IS COPIED, NOT INVENTED: one Session created, used and closed entirely inside the worker
thread — the ``publish_once`` discipline, which ``revocation_snapshot.py`` states as "part of the fix,
not an optimization". This module never hands a request-scoped Session to a thread.

THE BOUND TRADED AGAINST, named because a fix that trades a loop freeze for silent thread exhaustion
is not a fix:

* The read checks out a connection from the RESERVED liveness pool when the backend carries one
  (``Backend.LIVENESS_POOL_SIZE = 1``, ``LIVENESS_MAX_OVERFLOW = 1``, ``LIVENESS_POOL_TIMEOUT = 2.0``
  — ``core/engine/backend.py``). A second concurrent liveness read during a stall therefore does not
  queue behind the first for a shared-pool slot: it fails its 2.0 s checkout in
  ``sqlalchemy.exc.TimeoutError``, and the caller turns that into the shipped stale-class refusal.
  The bound is small ON PURPOSE — one stalled read costs one reserved connection, never the shared
  pool's 15.
* ``asyncio.to_thread`` runs on the loop's default executor, whose worker count is bounded by the
  interpreter (``min(32, cpu_count + 4)``). Each parked read occupies one worker for the length of
  the DB wait, so a stall of N concurrent readers parks N workers. That is still strictly better than
  freezing the loop — the poll, the heartbeat and the health endpoint keep answering — and the refusal
  is OBSERVABLE, because the reserved-pool timeout raises into the caller's logged stale-class arm
  rather than hanging silently.
* The site label survives the hop. At both shipped sites the label is set INSIDE the off-loop body
  (``for_site("register/incumbent-exemption")``, ``for_site("dial/crl-mint")``) and read by the seam on
  that same thread, so a refusal off the loop still counts under the site that raised it and #656's
  per-site vocabulary stays intact. ``asyncio.to_thread`` also copies the CALLING context into the
  worker, which is what makes the same true for any caller that labels before dispatching; the copy is
  one-directional, and nothing on this plane sets a label inside a worker and reads it back outside.
  Pinned by a cell, because a thread that lost the label would silently re-open the anonymous-plane
  counting hole #656 closed.

FALLBACK, and it is a test-harness fact not a fail-open: when there is no backend on app state to
build a thread-owned Session from (the bare ``FastAPI()`` harnesses that wire a ``MagicMock`` backend,
and any caller that never installed the core lifespan), the caller keeps the shipped inline read
byte-for-byte. The discriminator is the CLASS, not the instance — the same rule
``middleware/auth.py`` uses for the reserved pool, because ``getattr(mock_backend, anything)`` answers
and would silently move a unit cell onto a second mock session and change what it asserts.
"""

from __future__ import annotations

import logging
from collections.abc import Callable

from fastapi import Request
from sqlalchemy.exc import TimeoutError as SQLAlchemyPoolTimeout
from sqlalchemy.orm import Session

logger = logging.getLogger(__name__)

#: Named so a test can assert the observable class instead of a sentence. A reserved-pool
#: checkout that cannot be had within ``Backend.LIVENESS_POOL_TIMEOUT`` is a LIST-STATE
#: failure, never a revocation assertion (the #603 lesson, and the reason this is not a 403
#: — the executor daemon reads 403 on register as permanent rejection).
POOL_TIMEOUT_MARKER = "revocation read pool timeout"


def liveness_session_factory(request: Request) -> Callable[[], Session] | None:
    """Return a factory that opens the BEST available session for an off-loop read.

    Reserved liveness pool when the backend's CLASS offers it (so an ordinary request never consumes
    one of the shared pool's 15 slots for a revocation read), the shared pool otherwise, and ``None``
    when there is no real backend at all — which is the signal for the caller to keep its shipped
    inline read.
    """
    backend = getattr(request.app.state, "backend", None)
    if backend is None:
        return None
    # CLASS-level lookup, never instance-level: a MagicMock answers any attribute name.
    for name in ("get_liveness_session", "get_session"):
        if callable(getattr(type(backend), name, None)):
            factory = getattr(backend, name)
            if callable(factory):
                return factory
    return None


def is_pool_timeout(exc: BaseException) -> bool:
    """True when ``exc`` is the reserved-pool checkout refusal.

    ``sqlalchemy.exc.TimeoutError`` is what ``QueuePool`` raises when no connection is handed out
    within ``pool_timeout``. Under the DBAPI it can also surface wrapped, so the cause chain is walked
    a bounded number of times rather than assumed flat.
    """
    current: BaseException | None = exc
    depth = 0
    while current is not None and depth < 5:
        if isinstance(current, SQLAlchemyPoolTimeout):
            return True
        current = current.__cause__ or current.__context__
        depth += 1
    return False


def log_pool_timeout(site: str, exc: BaseException) -> None:
    """Make the bounded-pool refusal OBSERVABLE — logged, and named with its site.

    Silent thread exhaustion was the failure this section had to rule out; a WARNING that names the
    site and the pool timeout is what makes the trade visible in the journal.
    """
    logger.warning(
        "Off-loop revocation read refused at %s: %s — the reserved liveness pool could not "
        "hand out a connection inside its timeout (%s). The caller answers in the shipped "
        "stale class; NO revocation is asserted and the event loop was not blocked",
        site,
        repr(exc),
        POOL_TIMEOUT_MARKER,
    )


def run_off_loop[T](factory: Callable[[], Session], reader: Callable[[Session], T], site: str) -> T:
    """Worker-thread body: open a Session, run ``reader``, close. Never crosses a Session.

    The session is created, used and closed entirely inside this function, which runs on a worker
    thread — the ``publish_once`` discipline. A raise from ``reader`` (including a reserved-pool
    ``TimeoutError``) propagates to the awaiting caller, which decides the refusal class; this
    function never converts a fault into an all-clear.
    """
    db: Session | None = None
    try:
        db = factory()
        return reader(db)
    finally:
        close = getattr(db, "close", None)
        if callable(close):
            try:
                close()
            except Exception as teardown_fault:
                # Same reasoning as publish_once's guarded close: a faulting close must not replace
                # the result the read already produced, nor escape as a different fault at the call
                # site.
                logger.warning(
                    "Off-loop revocation read at %s could not close its session: %r — the "
                    "value it read is already returned; the pool's own recycle is the backstop",
                    site,
                    teardown_fault,
                    exc_info=True,
                )


async def read_off_loop[T](
    request: Request,
    reader: Callable[[Session], T],
    site: str,
) -> T:
    """Not used by the routes — kept as the single documented entry point for callers.

    The route call sites are written inline (``await asyncio.to_thread(run_off_loop, ...)``) so the
    offload is visible AT THE SITE, which is the discipline the shipped publisher follows. This
    wrapper exists for the shape's one-line reading in docs and tests; if it ever diverges from the
    inline form, the inline form wins and this goes away.
    """
    import asyncio

    factory = liveness_session_factory(request)
    if factory is None:
        raise RuntimeError("no backend session factory — caller must keep the inline read")
    try:
        return await asyncio.to_thread(run_off_loop, factory, reader, site)
    except Exception as exc:
        if is_pool_timeout(exc):
            log_pool_timeout(site, exc)
        raise
