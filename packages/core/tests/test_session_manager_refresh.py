# Copyright (c) 2026 Tabith LLC.
# Use of this source code is governed by the Business Source License 1.1
# included in the LICENSE file at the root of this repository. As of the
# Change Date listed there, the work is available under MPL 2.0.
# SPDX-License-Identifier: BUSL-1.1

"""Refresh-window semantics (ticket mcp-refresh-path-unreachable, Option A,
user ruling 2026-09-20): /auth/refresh is gated by the HARD CAP only —
idle-expired sessions are revived within max_session_duration; past the cap,
refresh dies and FIDO2 re-auth is required.

Mock-db cells with AWARE datetime attrs by necessity: sqlite hands back naive
datetimes for the manager's aware comparisons (storage-engine artifact,
production is timestamptz — house precedent: test_session_middleware, the
dial-gate cell in test_executor_revocation_identity). The datetime GATING is
the subject under test. The middleware's idle-expiry 401 (the refresh trigger)
is UNCHANGED and stays pinned in server/tests/test_session_middleware.py.
"""

from datetime import UTC, datetime, timedelta
from types import SimpleNamespace
from unittest.mock import MagicMock

from core.iam.session_manager import SessionConfig, SessionManager


def _row(*, age: timedelta, idle_dead: bool, token: str = "tok-old"):
    cfg = SessionConfig()
    now = datetime.now(UTC)
    return SimpleNamespace(
        id=1,
        user_id="u1",
        created_at=now - age,
        expires_at=now - timedelta(minutes=1) if idle_dead else now + cfg.session_timeout,
        access_token=token,
        access_token_jti="jti-old",
    )


def _mgr(rows):
    """SessionManager over a mock db; `rows` is the first() side_effect list."""
    db = MagicMock()
    db.query.return_value.filter.return_value.first.side_effect = list(rows)
    return SessionManager(db, SessionConfig())


def test_idle_expired_within_hard_cap_revives():
    """The ruling cell: idle-expired (expires_at past) but created 1h ago
    (< 4h cap) → refresh succeeds, session extended into the future, token
    rotated on the row."""
    row = _row(age=timedelta(hours=1), idle_dead=True)
    new = _mgr([row, row]).refresh_token("tok-old")  # 2nd: extend_session requery
    assert new is not None
    assert new.token != "tok-old"
    assert row.access_token == new.token
    assert row.expires_at > datetime.now(UTC)  # revived


def test_past_hard_cap_refuses_even_if_recently_active():
    """Paired negative: created 5h ago (> 4h cap) → None, regardless of idle state."""
    row = _row(age=timedelta(hours=5), idle_dead=False)
    assert _mgr([row]).refresh_token("tok-old") is None


def test_idle_expired_past_hard_cap_refuses():
    """The gate-1 physical shape (session idle-died, cap long past) stays dead."""
    row = _row(age=timedelta(hours=24), idle_dead=True)
    assert _mgr([row]).refresh_token("tok-old") is None


def test_old_token_dead_after_rotation():
    """Rotation invalidates the presented token — a theft race leaves exactly
    one holder with a live token (the ruled detectability property)."""
    row = _row(age=timedelta(minutes=5), idle_dead=False)
    # refresh 1: lookup + extend requery; refresh 2 (old token): lookup misses
    mgr = _mgr([row, row, None])
    assert mgr.refresh_token("tok-old") is not None
    assert mgr.refresh_token("tok-old") is None


def test_live_session_refresh_positive_control():
    """Pre-existing behavior preserved: an active session refreshes."""
    row = _row(age=timedelta(minutes=5), idle_dead=False)
    assert _mgr([row, row]).refresh_token("tok-old") is not None


def test_unknown_token_refuses():
    assert _mgr([None]).refresh_token("never-issued") is None
