# Copyright (c) 2026 Tabith LLC.
# Use of this source code is governed by the Business Source License 1.1
# included in the LICENSE file at the root of this repository. As of the
# Change Date listed there, the work is available under MPL 2.0.
# SPDX-License-Identifier: BUSL-1.1

"""Single writer for admin lifecycle audit events (ticket
admin-lifecycle-audit-events, owner ruling batch 2026-09-30).

Every lifecycle event row is CONSTRUCTED here and nowhere else (pinned by
tests/test_lifecycle_audit_events.py) — sites pass an event constant, the
actor principal, and the approved value-free field table.

Posture (ruled Q4, one posture for all sites): SAME TRANSACTION. The helper
only db.add()s — the event row rides the site's own commit, so an audit-write
failure aborts the action (complete-or-nothing, append-only guarantee). The
two record-only events (login_failed, and the logout revoked=False row after
the pre-existing rollback) have no action to ride, so their sites commit
before raising/returning — the established denial-side shape.

Actor convention (ruled Q5): the migration 022 principal verbatim — session
user_id, mTLS cert identity, or self-asserted id as stored. NULL only where
no principal exists (login_failed rows: ruled Q6 variant B — value-free,
NEVER a username, user id, or IP, so audit adds no enumeration oracle).
"""

import logging
from datetime import UTC, datetime
from typing import Any

from sqlalchemy.orm import Session

logger = logging.getLogger("venya.server")

# Event vocabulary (approved field tables: brief admin-lifecycle-audit-events A1 §2)
ADMIN_INITIALIZED = "admin_initialized"
FIRST_ADMIN_ENROLLED = "first_admin_enrolled"
BREAK_GLASS_RECOVERY_USED = "break_glass_recovery_used"
SESSION_STARTED = "session_started"
SESSION_ENDED = "session_ended"
LOGIN_FAILED = "login_failed"
USER_CREATED = "user_created"
USER_UPDATED = "user_updated"
USER_DELETED = "user_deleted"
ROLE_CREATED = "role_created"
ROLE_UPDATED = "role_updated"
ROLE_DELETED = "role_deleted"
MEMBER_ADDED = "member_added"
MEMBER_REMOVED = "member_removed"
CREDENTIAL_ADDED = "credential_added"
CREDENTIAL_REMOVED = "credential_removed"
# Ticket adjacent-lifecycle-audit-families #301 (owner rulings Q1-Q7, 2026-10-01)
KEY_VERSION_ROTATED = "key_version_rotated"
KEY_VERSION_ROLLED_BACK = "key_version_rolled_back"
KEY_VERSION_DEACTIVATED = "key_version_deactivated"
KEY_VERSION_REVOKED = "key_version_revoked"
ELEVATION_GRANTED = "elevation_granted"
EXECUTOR_REVOKED = "executor_revoked"
EXECUTOR_CERT_REVOKED = "executor_cert_revoked"
ADMIN_CERT_REVOKED = "admin_cert_revoked"
# RF-7 chunk 2 (refs RF-6 §2.8): the issuance side of the same pair. Field table
# is the §2.8 list — canonical serial, embedded identity, validity window, curve,
# requesting user_id, mint reason. NEVER the CSR bytes, the public key, or the
# cert PEM: the audit row is readable by non-admin auditors.
ADMIN_CERT_ISSUED = "admin_cert_issued"
USER_REENROLLED = "user_reenrolled"
CORE_RESET_REFUSED = "core_reset_refused"  # #511: a reset the in-transaction guard stopped
ENROLLMENT_TOKEN_ISSUED = "enrollment_token_issued"  # nosec B105 — audit event name, not a password
ENROLLMENT_TOKEN_REVOKED = "enrollment_token_revoked"  # nosec B105 — audit event name, not a password
COMMAND_POLICY_CHANGED = "command_policy_changed"
EXECUTOR_ENROLLMENT_TOKEN_CREATED = "executor_enrollment_token_created"  # nosec B105 — audit event name, not a password
# #602 AC1 shape (a): the human-unmask SUCCESS arm records the disclosure, not
# only its denial (the README's "every disclosure is an audit event"). The row
# names WHICH key was disclosed and WHO read it; nothing about the VALUE is
# recorded — no plaintext, no token, no token hash. Value-free by construction,
# so it is searchable beside the deny row it pairs with
# (auditor_secret_read_denied).
#
# CONSTANT-NAME NOTE (deliberate, not a typo to "fix"): the name carries no
# SECRET_/TOKEN_ keyword on purpose, because bandit B105 and the detect-secrets
# "Secret Keyword" detector both key on the VARIABLE NAME, not the value — a
# keyword-shaped name would need a bandit suppression (a new row in the
# generated register) and a fake finding in .detect-secrets-baseline, for a
# string that is not a credential. The auditor-facing value below is what the
# log stores.
VALUE_DISCLOSED = "secret_value_disclosed"


def _json_safe(value: Any) -> Any:
    """Keep field tables JSON-serializable defensively (test doubles may hand
    back non-int rowcounts); real paths pass primitives through untouched."""
    if value is None or isinstance(value, (bool, int, float, str)):
        return value
    if isinstance(value, (list, tuple)):
        return [_json_safe(v) for v in value]
    return str(value)


def audit_lifecycle(
    db: Session,
    event_type: str,
    actor_user_id: str | None,
    fields: dict[str, Any],
) -> None:
    """Add the lifecycle audit row to `db` — no commit (rides the action's transaction).

    Args:
        db: The site's own Session — same transaction as the lifecycle write.
        event_type: One of the module constants (free strings are a test failure).
        actor_user_id: The principal per the migration-022 convention, or None
            only where no principal exists (login_failed).
        fields: Value-free field table (ids/names/booleans/ints). NEVER tokens,
            codes, hashes, passphrases, public keys, or IPs (pinned negative).
    """
    from core.iam.models import AuditEvent

    known = {
        ADMIN_INITIALIZED,
        FIRST_ADMIN_ENROLLED,
        BREAK_GLASS_RECOVERY_USED,
        SESSION_STARTED,
        SESSION_ENDED,
        LOGIN_FAILED,
        USER_CREATED,
        USER_UPDATED,
        USER_DELETED,
        ROLE_CREATED,
        ROLE_UPDATED,
        ROLE_DELETED,
        MEMBER_ADDED,
        MEMBER_REMOVED,
        CREDENTIAL_ADDED,
        CREDENTIAL_REMOVED,
        KEY_VERSION_ROTATED,
        KEY_VERSION_ROLLED_BACK,
        KEY_VERSION_DEACTIVATED,
        KEY_VERSION_REVOKED,
        ELEVATION_GRANTED,
        EXECUTOR_REVOKED,
        EXECUTOR_CERT_REVOKED,
        ADMIN_CERT_REVOKED,
        ADMIN_CERT_ISSUED,
        USER_REENROLLED,
        CORE_RESET_REFUSED,
        ENROLLMENT_TOKEN_ISSUED,
        ENROLLMENT_TOKEN_REVOKED,
        COMMAND_POLICY_CHANGED,
        EXECUTOR_ENROLLMENT_TOKEN_CREATED,
        VALUE_DISCLOSED,
    }
    if event_type not in known:
        raise ValueError(f"unknown lifecycle event: {event_type}")

    db.add(
        AuditEvent(
            event_type=event_type,
            user_id=actor_user_id,
            fields={k: _json_safe(v) for k, v in fields.items()},
            timestamp=datetime.now(UTC),
        )
    )


def record_login_failure(request: Any, mode: str, reason: str) -> None:
    """Record-only login_failed row (ruled Q6 variant B: NO username, user
    id, or IP — ever, so audit adds no enumeration oracle).

    No action rides this event, so it commits in its own best-effort
    transaction: an audit-write failure must never change the login-failure
    response (byte-identical failure shapes are pinned, ticket
    admin-lifecycle-audit-events)."""
    backend = getattr(request.app.state, "backend", None)
    if backend is None:
        return
    db = backend.get_session()
    try:
        audit_lifecycle(db, LOGIN_FAILED, None, {"outcome": "failed", "mode": mode, "reason": reason})
        db.commit()
    except Exception:
        db.rollback()
        logger.exception("lifecycle audit write failed on login failure (%s/%s)", mode, reason)
    finally:
        db.close()


def record_session_end_failure(request: Any, db: Any, actor_user_id: str | None, session_jti: str | None) -> None:
    """Logout revoked=False row after the PRE-EXISTING swallowed revoke failure
    (ticket admin-lifecycle-audit-events; the swallow itself is a separate
    bug — its fix must not change this leg's control flow)."""
    try:
        audit_lifecycle(
            db,
            SESSION_ENDED,
            actor_user_id,
            {"mode": "browser", "session_jti": _json_safe(session_jti), "revoked": False},
        )
        db.commit()
    except Exception:
        db.rollback()
        logger.exception("lifecycle audit write failed on logout revoke-failure record")
