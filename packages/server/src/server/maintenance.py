# Copyright (c) 2026 Tabith LLC.
# Use of this source code is governed by the Business Source License 1.1
# included in the LICENSE file at the root of this repository. As of the
# Change Date listed there, the work is available under MPL 2.0.
# SPDX-License-Identifier: BUSL-1.1

"""Periodic database maintenance for the server.

Holds the raw-SQL cleanup passes formerly inlined in the ``lifespan``
``session_cleanup_loop`` in :mod:`server.app`. Moved here verbatim so each
pass is unit-testable against a ``Session`` without spinning up the app.
Behavior is preserved exactly: same SQL, same thresholds, same LIMIT, same
per-pass error isolation, same log lines.
"""

import logging
from datetime import UTC, datetime, timedelta

from sqlalchemy import text
from sqlalchemy.orm import Session

logger = logging.getLogger("venya.server")


def cleanup_expired_sessions(
    db: Session,
    *,
    session_timeout: int = 900,
    max_session_duration: int = 14400,
    tolerance: int = 60,
) -> int:
    """Delete sessions past their hard cap. Returns the number deleted.

    Two legs (session-cleanup-skips-hard-cap-sessions #529):

    - idle leg (the original one): deletes rows whose sliding ``expires_at``
      has been dead so long that even continuous activity would have run
      past the hard cap. Conservative by construction.
    - hard-cap leg (the fix): ``created_at`` past ``max_session_duration``.
      A session that keeps getting refreshed always has a future
      ``expires_at``, so the idle leg alone never saw it — yet
      ``check_refresh_window`` already refuses to refresh it (the gate is
      ``created_at + max_session_duration >= now``). The refused row used
      to stay in the table forever: the gate closed the door, nothing took
      the body out. This leg mirrors the gate exactly.

    Tolerance stays on the keep-live side in both legs (delete only what is
    past the line by at least ``tolerance``), same rule as before.

    Index note (AC4): ``expires_at`` is indexed, ``created_at`` is not, so
    the cap leg is evaluated by scan of the sessions table per maintenance
    tick. Acceptable while the table is bounded by active sessions (which
    this fix restores); a ``created_at`` index is a follow-up candidate if
    installs ever show the sweep hot — shipping one here would couple this
    branch's Alembic chain to the elevation train's 035/036 for no measured
    win at fleet scale.
    """
    now = datetime.now(UTC)
    hard_cap_threshold = now - timedelta(seconds=max_session_duration - session_timeout)
    threshold = hard_cap_threshold - timedelta(seconds=tolerance)
    cap_dead = now - timedelta(seconds=max_session_duration + tolerance)
    result = db.execute(
        text(
            """
            DELETE FROM sessions
            WHERE id IN (
                SELECT id FROM sessions
                WHERE expires_at < :threshold
                   OR created_at < :cap_dead
                LIMIT :limit
            )
        """
        ),
        {"threshold": threshold, "cap_dead": cap_dead, "limit": 1000},
    )
    db.commit()
    return result.rowcount


def cleanup_expired_execution_sessions(db: Session) -> int:
    """Delete execution_sessions past their expires_at (10-min TTL). Returns rows deleted.

    execution_sessions were NEVER cleaned up: the ``ix_execution_sessions_expires_at``
    index (migration 025) was orphaned, and each row stores command + stdout + stderr
    (Text — up to ~512 KB with the 256 KB-per-stream truncation cap), so the table grew
    unbounded on a busy fleet. The stored stdout/stderr are write-only: no endpoint reads
    them back (the audit trail lives in ``audit_events``). Deleting past ``expires_at``
    honors the documented TTL (ticket execute-stale-session-update-500).

    FK child first: ``execution_session_secrets.session_id -> execution_sessions.id`` has
    no ON DELETE CASCADE, so child rows must go before the parent or the DELETE raises an
    FK violation. Both deletes use the identical ``expires_at`` predicate (no LIMIT) so
    they target the same row set — a per-statement LIMIT without ORDER BY could diverge
    and orphan a parent delete.
    """
    # shortcut: no LIMIT (unbounded batch). The backlog is one-time; if a huge first-run
    # delete ever proves problematic, bound it via a materialized id set selected once —
    # NOT a writable CTE (FK visibility across CTE sub-statements is not guaranteed).
    now = datetime.now(UTC)
    db.execute(
        text(
            "DELETE FROM execution_session_secrets "
            "WHERE session_id IN (SELECT id FROM execution_sessions WHERE expires_at < :now)"
        ),
        {"now": now},
    )
    result = db.execute(
        text("DELETE FROM execution_sessions WHERE expires_at < :now"),
        {"now": now},
    )
    db.commit()
    return result.rowcount


def purge_admin_identity_metadata(db: Session, *, days: int = 90) -> int:
    """Blank executor enrollment identity metadata older than ``days``.

    Returns the number of rows updated.
    """
    cutoff = datetime.now(UTC) - timedelta(days=days)
    result = db.execute(
        text(
            """UPDATE executor_enrollment_tokens
                SET created_by_session_id = NULL,
                    created_from_ip = NULL,
                    created_from_user_agent = NULL,
                    admin_meta_wrapped_dek = NULL,
                    admin_meta_nonce = NULL,
                    admin_meta_ciphertext = NULL
                WHERE created_at < :cutoff
                  AND (created_by_session_id IS NOT NULL
                       OR created_from_ip IS NOT NULL
                       OR created_from_user_agent IS NOT NULL
                       OR admin_meta_wrapped_dek IS NOT NULL)"""
        ),
        {"cutoff": cutoff},
    )
    db.commit()
    return result.rowcount


def cleanup_rate_limit_counters(db: Session, *, hours: int = 1) -> int:
    """Delete expired rate-limit failure counters. Returns the number deleted."""
    result = db.execute(
        text("DELETE FROM rate_limit_failures WHERE window_start < :threshold"),
        {"threshold": datetime.now(UTC) - timedelta(hours=hours)},
    )
    db.commit()
    return result.rowcount


def run_maintenance(db: Session, config) -> None:
    """Run all cleanup passes against ``db``.

    Args:
        db: The DB session (caller owns close/rollback).
        config: The ``ServerConfig`` (or ``None``). Missing fields fall back to
            the same defaults the inline loop used (900 / 14400 / 60).

    There is NO revocation-purge pass here any more, and no ``ca_manager`` parameter to
    carry one (#685, owner ruling 2026-10-20): ``ExecutorCertRevocation`` is exempt from
    time-based purge, so a row that names a revoked executor credential stays in the
    membership population for as long as the credential itself would have been valid —
    and longer. The pass and the parameter were removed TOGETHER rather than left in
    place calling nothing, because a required positional whose only documented purpose
    was the purge is the silent no-op the 2026-09-21 ruling was written to prevent.
    """
    session_timeout = getattr(getattr(config, "session", None), "session_timeout", 900)
    max_session_duration = getattr(getattr(config, "session", None), "max_session_duration", 14400)
    tolerance = getattr(getattr(config, "clock_skew", None), "token_tolerance_seconds", 60)

    # Primary pass — errors propagate to the caller (which rolls back + logs).
    deleted = cleanup_expired_sessions(
        db,
        session_timeout=session_timeout,
        max_session_duration=max_session_duration,
        tolerance=tolerance,
    )
    logger.info("Session cleanup: deleted %d expired sessions", deleted)

    # Execution-session cleanup — isolated secondary pass (ticket
    # execute-stale-session-update-500): the relay bookkeeping table grew unbounded
    # because nothing ever deleted expired execution_sessions rows.
    try:
        exec_deleted = cleanup_expired_execution_sessions(db)
        if exec_deleted:
            logger.info("Execution-session cleanup: deleted %d expired execution_sessions", exec_deleted)
    except Exception:
        db.rollback()
        logger.exception("Execution-session cleanup failed")

    # Secondary passes — each isolated; one failing does not abort the others.
    try:
        purged = purge_admin_identity_metadata(db)
        if purged:
            logger.info("Purged admin identity metadata for %d expired tokens", purged)
    except Exception:
        db.rollback()
        logger.exception("Admin identity metadata purge failed")

    try:
        cleaned = cleanup_rate_limit_counters(db)
        if cleaned:
            logger.info("Cleaned up %d expired rate limit counters", cleaned)
    except Exception:
        db.rollback()
        logger.exception("Rate limit cleanup failed")

    # #685 (owner ruling 2026-10-20) — the pass that used to sit here is gone.
    # It called CAManager.purge_expired_revocations, which DELETEd
    # ExecutorCertRevocation rows older than `crl.crl_retention_days` (default 90),
    # relocated off the two public CRL GETs by ticket sec-sweep-low-informational #23b.
    # That table is the membership population for credential validity, so truth about a
    # revoked credential was being aged out on a timer: a purge-dropped row stops
    # answering in revocation.py's serial lookup and stops being listed in the CRL, and
    # the revoked executor keeps dialing. Exempt now, permanently — `ExecutorCert` rows
    # were never purged either, so the two tables agree.
    # The bound that keeps a REVERT from reintroducing the hazard lives with the knob
    # itself (`config.CRLConfig._retention_covers_revoked_population_lifetime`), and it refuses a
    # window shorter than the longest leaf-certificate lifetime whose revocations live in the two
    # revocation tables — max(EXECUTOR_VALIDITY_DAYS 30, ADMIN_CERT_VALIDITY_DAYS 90) = 90 — so no
    # config value can ever again name a purge window that would drop a row for a still-valid
    # credential, on either plane, wired or not.
    # The admin plane is untouched: `AdminCAManager.purge_expired_revocations` still
    # exists and is still NOT wired into this loop, exactly as it was before this leg.
