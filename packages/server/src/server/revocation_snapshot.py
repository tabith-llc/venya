# Copyright (c) 2026 Tabith LLC.
# Use of this source code is governed by the Business Source License 1.1
# included in the LICENSE file at the root of this repository. As of the
# Change Date listed there, the work is available under MPL 2.0.
# SPDX-License-Identifier: BUSL-1.1

"""#603 AC2 step 2 (a-prime-ii) — the freshness-bounded revocation-liveness snapshot.

The revocation-liveness population (the two sorted lists the executor poll answers
from) is read here, OFF the request path, by a publisher task the core starts beside
the shipped ``session_cleanup_loop`` (``app.py``). ``routes/executors.py`` answers
``GET /executors/certs/revocation-list`` from the published snapshot, and REFUSES in
the 503 stale class whenever the snapshot it would answer from is missing or has
crossed the ceiling — a poll must never read "nothing revoked" out of data nobody can
vouch for, because an empty population IS "nothing revoked".

THE NUMBERS, and they are constants on purpose (ticket #603 AC2; owner's spec ok and
boundary ruling, both 2026-10-15): a ceiling of 45 s, a refresh interval of 10 s, and
the boundary operator ``>=`` — refuse at exactly the ceiling. Putting the ceiling on
the env-var surface would re-open the drift this ticket exists to kill, so there is no
knob and no installer edit here; ``validate_snapshot_windows`` is a startup check, not
a setting.

What this module does NOT own — the law that keeps it honest:

* NO VERDICT. It stores a population (two sorted lists), never a ``revoked`` answer,
  never a serial match, never an identity match. ``server/revocation.py`` is the one
  matcher and its module contract names a second implementation as the
  rotation/revocation split-brain. This module is the read, not the rulebook.
* ONE AGE DECISION. ``snapshot_is_stale`` is the only place staleness is computed; a
  second age check anywhere (route, publisher, caller) is the same split-brain in new
  clothes.
* THE ETAG IS NOT STORED. Payload and ETag are derived together at serve time by the
  shipped lines in the route, so a cached ETag can never describe a different
  population from the body beside it (the #337 ``crl-cap-etag-divergence`` class).
* MONOTONIC ONLY. Age is elapsed real time since publish, measured on
  ``time.monotonic()`` — never the wall clock (#464: a BACKWARD NTP step would
  otherwise make an entry look young forever, and on THIS plane "young forever" means
  answering "not revoked" from a snapshot that is really past its warrant).
* THE ABSENCE OF AN ANSWER KEEPS ITS SHIPPED MEANING. Step 2 changes WHEN an answer is
  available, never what its absence means: the strike counter, the threshold, the
  cadence, the fault arm and the refusal routing all stay exactly as they ship.
"""

from __future__ import annotations

import asyncio
import logging
import time
from collections.abc import Callable
from dataclasses import dataclass

from sqlalchemy.orm import Session

logger = logging.getLogger("venya.server")

# --- the ruled window -------------------------------------------------------------

#: Freshness ceiling: how long a published population may be answered from. 45 s
#: covers the observed 15-40 s lock-stall band with margin (review item 4, owner's
#: pick, 2026-10-15). Past it the poll REFUSES in the 503 stale class — it does not
#: answer live, and it does not answer "nothing revoked".
REVOCATION_SNAPSHOT_MAX_AGE_SECONDS = 45

#: Publisher interval. ``validate_snapshot_windows`` requires it strictly below the
#: ceiling, so a snapshot can never sit older than one interval when it is read.
REVOCATION_SNAPSHOT_REFRESH_SECONDS = 10


class RevocationSnapshotUnavailable(RuntimeError):
    """No answerable population exists: nothing published yet, or the published
    snapshot has crossed the freshness ceiling.

    Its own class so the refusal site is one ``except`` and the reason is never
    guessed from a ``None`` return. This is an availability fault, NOT a revocation
    assertion — the caller turns it into the shipped stale-class 503.
    """


@dataclass(frozen=True)
class RevocationSnapshot:
    """One immutable published population.

    Frozen because a concurrent reader must never see a half-written list: the
    publisher builds a WHOLE new object and REPLACES the reference (the shipped
    ``relay_listener.reload_ssl_context`` swap law), so a request sees either the old
    snapshot or the new one. ``published_mono`` is a monotonic stamp.
    """

    serials: tuple[str, ...]
    identities: tuple[str, ...]
    published_mono: float


# --- module state (one process — the shipped app is single-worker) ----------------

_published: RevocationSnapshot | None = None
_publisher_running = False
# One-shot latch on the no-publisher warning: the fallback is per-request and a fleet
# polls every ~30 s, so an un-latched warning would be journal noise — which is how
# real alarms get ignored. Re-armed only by ``reset_snapshot_state``.
_unarmed_warned = False


def snapshot_is_stale(snapshot: RevocationSnapshot | None, *, now_mono: float) -> bool:
    """THE single staleness decision: ``age >= ceiling`` refuses.

    ``>=`` is the owner's ruled boundary (2026-10-15, verbatim: ">= — refuse at exactly
    the ceiling"), conservative at the boundary tick for the same reason every other
    rule on this plane is: one extra honest 503 costs a request, while one answer
    served past its warrant costs a stale all-clear on the revocation plane. A missing
    snapshot is stale by the same line — fail closed at boot, never answer live.
    """
    if snapshot is None:
        return True
    return (now_mono - snapshot.published_mono) >= REVOCATION_SNAPSHOT_MAX_AGE_SECONDS


def current_snapshot() -> RevocationSnapshot | None:
    """The published snapshot, or None when nothing has been published."""
    return _published


def publisher_running() -> bool:
    """True while the core's snapshot publisher task owns the revocation read."""
    return _publisher_running


def arm_publisher() -> None:
    """Declare that this process owns the revocation read: no snapshot yet is a REFUSE.

    Called by ``revocation_snapshot_loop`` before its first publish, and by the cells
    that need the armed-but-empty state. Arming is what closes the live-read fallback,
    so the order matters: arm first, publish after.
    """
    global _publisher_running
    _publisher_running = True


def disarm_publisher() -> None:
    """Release ownership of the revocation read (loop exit / cancellation)."""
    global _publisher_running
    _publisher_running = False


def validate_snapshot_windows() -> None:
    """Startup check: the refresh interval must be strictly below the ceiling.

    The shipped idiom is ``config.py``'s ``_session_timeout_within_max`` validator;
    these are module constants rather than config fields, so the check runs when the
    publisher starts. A pair that violates it raises — a publisher that could serve an
    already-stale snapshot never starts.
    """
    if REVOCATION_SNAPSHOT_REFRESH_SECONDS >= REVOCATION_SNAPSHOT_MAX_AGE_SECONDS:
        raise ValueError(
            "REVOCATION_SNAPSHOT_REFRESH_SECONDS "
            f"({REVOCATION_SNAPSHOT_REFRESH_SECONDS}) must stay below "
            "REVOCATION_SNAPSHOT_MAX_AGE_SECONDS "
            f"({REVOCATION_SNAPSHOT_MAX_AGE_SECONDS}): a snapshot at or past the "
            "ceiling must never be answerable, and an interval at or above it makes "
            "that state reachable by construction"
        )


def revocation_populations(db: Session) -> tuple[list[str], list[str]]:
    """Read the revocation population — the single implementation of both reads.

    Moved VERBATIM off ``get_revocation_list`` (the ``ExecutorCertRevocation`` fetch
    plus the ``Executor.revoked_at`` identity scan): same tables, same columns, same
    sort. The publisher calls it and the route's no-publisher fallback calls it, and
    that is the whole point of putting it here — a leg that writes the SELECT twice,
    once in the publisher and once in the route, has built the split-brain that
    ``revocation.py:15-26`` forbids.
    """
    from core.iam.models import Executor, ExecutorCertRevocation

    revocations = db.query(ExecutorCertRevocation).all()
    serials = sorted([r.serial_number for r in revocations])
    # Identity-level revocations (the terminal flag on the Executor row) ride
    # alongside the serial history: additive wire field, and the ETag covers BOTH.
    identities = sorted(row[0] for row in db.query(Executor.id).filter(Executor.revoked_at.isnot(None)).all())
    return serials, identities


def publish_populations(
    serials: list[str] | tuple[str, ...],
    identities: list[str] | tuple[str, ...],
    *,
    published_mono: float | None = None,
) -> RevocationSnapshot:
    """Swap in one whole population — the publish step, with no read.

    ``published_mono`` is the age stamp; left None it is "now" on the monotonic clock.
    Passing it explicitly is what lets the boundary cells pin ``age == ceiling`` to the
    microsecond instead of racing the clock.
    """
    global _published
    snapshot = RevocationSnapshot(
        serials=tuple(serials),
        identities=tuple(identities),
        published_mono=time.monotonic() if published_mono is None else published_mono,
    )
    _published = snapshot
    return snapshot


def publish_snapshot(db: Session) -> RevocationSnapshot:
    """Read and publish in one step — an object swap, never an in-place mutation.

    Returns what it published. A raise here leaves the PREVIOUS snapshot in place: an
    exception never substitutes an empty population, because an empty list is the most
    permissive answer the publisher could fabricate out of a failure.
    """
    serials, identities = revocation_populations(db)
    return publish_populations(serials, identities)


def read_populations(db: Session) -> tuple[list[str], list[str]]:
    """Answer one poll from the snapshot, or raise ``RevocationSnapshotUnavailable``.

    * publisher running → answer ONLY from the published snapshot. Missing or at/past
      the ceiling raises and the route turns that into the stale-class 503, BEFORE any
      payload/ETag is built — which is what makes a stale 304 impossible rather than
      merely unintended (the 304 has no body, so nothing downstream could catch one).
      The request-path DB read is gone; that is the step.
    * no publisher running → fall back to the shipped inline read. A router mounted
      WITHOUT the core lifespan (every unit-test harness that builds a bare
      ``FastAPI()`` and wires a mock ``backend.get_session``) therefore behaves exactly
      as it does today, and so does any future caller that never installed the
      publisher. This is not a fail-open on the ruled property: the fallback still
      reads the live population, and in the shipped process ``lifespan`` starts the
      publisher before any request is served, so the snapshot branch is what answers
      in the field. The publisher's own cold window refuses rather than answering
      live, because once ``_publisher_running`` is set the fallback is gone.
    * ``db`` is consulted in the fallback branch only — a fresh snapshot answers from
      pure memory, with no checkout.
    """
    if not _publisher_running:
        global _unarmed_warned
        if not _unarmed_warned:
            _unarmed_warned = True
            logger.warning(
                "Revocation poll answered from a live DB read: the snapshot publisher is not running "
                "in this process. The answer is current, but the read is back on the lockable path "
                "#603 AC2 exists to take it off — on a shipped core the lifespan starts the publisher "
                "before the first request, so this line means the app was built without it."
            )
        return revocation_populations(db)
    snapshot = _published
    if snapshot_is_stale(snapshot, now_mono=time.monotonic()):
        raise RevocationSnapshotUnavailable(
            "no revocation snapshot inside the freshness ceiling "
            f"({REVOCATION_SNAPSHOT_MAX_AGE_SECONDS} s): the poll must refuse, not answer live"
        )
    return list(snapshot.serials), list(snapshot.identities)  # type: ignore[union-attr]


def publish_once(session_factory: Callable[[], Session]) -> RevocationSnapshot | None:
    """One publish: check out, read, swap, close. Returns None when the read failed.

    The CHECKOUT IS INSIDE THE GUARD on purpose. A pool that cannot be had is the same
    event as a query that cannot be answered — step 1's reserved checkout raises on its
    2 s timeout — and a raise escaping here would escape the loop, end the publisher
    task, and clear the running flag. The route would then fall back to a live DB read
    on the lockable path: a dead publisher that looks healthy. That is the fail-open
    this function exists to prevent, so nothing about a tick is allowed to escape.

    A failure never clears the population: the last good snapshot stays answerable
    until the ceiling, after which ``read_populations`` refuses — an empty population is
    the most permissive answer the publisher could fabricate out of a failure.
    """
    db = None
    try:
        db = session_factory()
        return publish_snapshot(db)
    except Exception:
        logger.warning(
            "Revocation snapshot publish failed — the last snapshot stays served until the "
            "freshness ceiling, then the poll refuses in the stale class",
            exc_info=True,
        )
        return None
    finally:
        close = getattr(db, "close", None)
        if callable(close):
            close()


async def revocation_snapshot_loop(session_factory: Callable[[], Session]) -> None:
    """The publisher coroutine, started beside ``session_cleanup_loop``.

    Publishes FIRST and then waits the interval, so a boot does not spend a whole
    interval answering "no snapshot yet": the cold window the stale class covers is a
    startup artifact, not a recurring one. The flag is set before the first publish
    (so a concurrent early poll refuses rather than answering live) and cleared in the
    ``finally``, which is what makes task cancellation the same thing as "the publisher
    no longer owns the read".

    THE READ RUNS IN A WORKER THREAD. #603 exists because a lock-stalled liveness read
    freezes the single-worker core event loop; a publisher that ran its synchronous
    query ON the loop would move the stall onto a 10 s timer and block everything —
    including the memory-only poll this step exists to protect — for the whole stall.
    ``asyncio.to_thread`` is therefore part of the fix, not an optimization: the
    session is created, used and closed entirely inside the worker thread, so no
    Session ever crosses threads. (This is the server's first offload; ``app.py``
    measured zero hits for ``run_in_threadpool|to_thread`` at the step-2 base.)
    """
    validate_snapshot_windows()
    arm_publisher()
    try:
        while True:
            await asyncio.to_thread(publish_once, session_factory)
            await asyncio.sleep(REVOCATION_SNAPSHOT_REFRESH_SECONDS)
    finally:
        disarm_publisher()


def reset_snapshot_state() -> None:
    """Clear the published snapshot, the running flag and the warning latch. Exposed for testing.

    Module state is process-global and the suites run one process, so a cell that
    armed the publisher without clearing it would silently change what every later
    poll cell observes — the same reason ``health._reset_health_cache`` exists.
    """
    global _published, _publisher_running, _unarmed_warned
    _published = None
    _publisher_running = False
    _unarmed_warned = False
