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
    """Delete sessions past their hard cap. Returns the number deleted."""
    now = datetime.now(UTC)
    hard_cap_threshold = now - timedelta(seconds=max_session_duration - session_timeout)
    threshold = hard_cap_threshold - timedelta(seconds=tolerance)
    result = db.execute(
        text(
            """
            DELETE FROM sessions
            WHERE id IN (
                SELECT id FROM sessions
                WHERE expires_at < :threshold
                LIMIT :limit
            )
        """
        ),
        {"threshold": threshold, "limit": 1000},
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
    # ponytail: no LIMIT (unbounded batch). The backlog is one-time; if a huge first-run
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


def run_maintenance(db: Session, config, ca_manager) -> None:
    """Run all cleanup passes against ``db``.

    Args:
        db: The DB session (caller owns close/rollback).
        config: The ``ServerConfig`` (or ``None``). Missing fields fall back to
            the same defaults the inline loop used (900 / 14400 / 60).
        ca_manager: The ``CAManager`` (or ``None`` in unit contexts) — REQUIRED
            positional so a forgotten wiring fails loudly (TypeError) instead
            of silently skipping the revocation purge (user ruling 2026-09-21).
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

    # Revocation-table purge — RELOCATED from the two public CRL GETs (ticket
    # sec-sweep-low-informational #23b): unauthenticated write-on-read ran at
    # fleet_size x 2/min; the table stays bounded on this 5-minute schedule
    # instead. BOUNDARY (interactive ruling on the revocation rework, confirmed
    # against ca.py purge_expired_revocations): SERIAL-level rows only
    # (ExecutorCertRevocation kill-history, retention-bounded) — identity-level
    # revocation (Executor.revoked_at) is TERMINAL and is never touched by the
    # purge; the relocation does not widen purge semantics.
    if ca_manager is not None:
        try:
            from . import metrics

            retention_days = getattr(getattr(config, "crl", None), "crl_retention_days", 90)
            purged = ca_manager.purge_expired_revocations(db, retention_days)
            metrics.CA_REVOCATIONS_PURGED_TOTAL.inc()
            if purged:
                logger.info("Revocation purge: deleted %d expired serial-level revocations", purged)
        except Exception:
            db.rollback()
            logger.exception("Revocation purge failed")
