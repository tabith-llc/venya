# Copyright (c) 2026 Tabith LLC.
# Use of this source code is governed by the Business Source License 1.1
# included in the LICENSE file at the root of this repository. As of the
# Change Date listed there, the work is available under MPL 2.0.
# SPDX-License-Identifier: BUSL-1.1

"""#342: the bearer token's advertised TTL is PERSISTED on the session row.

Mock-db cells (house precedent: test_session_manager_refresh.py) — the
creation write and the refresh rotation are asserted on the row object the
manager hands the session; schema landing is pinned separately in
test_migration_034_access_token_expiry.py.
"""

from datetime import UTC, datetime, timedelta
from types import SimpleNamespace
from unittest.mock import MagicMock

from core.iam.session_manager import SessionConfig, SessionManager


def _mgr(rows):
    db = MagicMock()
    db.query.return_value.filter.return_value.first.side_effect = list(rows)
    return db


def test_create_session_persists_token_expiry():
    # first() consumed once by the create-time user-status gate.
    user_row = SimpleNamespace(user_id="u1", status="active")
    db = _mgr([user_row])
    config = SessionConfig(access_token_ttl=timedelta(seconds=77))
    manager = SessionManager(db, config)
    session, token = manager.create_session("u1")
    added = [c.args[0] for c in db.add.call_args_list]
    assert session in added
    assert session.access_token_expires_at == token.expires_at
    assert (
        datetime.now(UTC) + timedelta(seconds=70)
        < session.access_token_expires_at
        < datetime.now(UTC) + timedelta(seconds=120)
    )


def test_refresh_rotates_persisted_expiry():
    cfg = SessionConfig(access_token_ttl=timedelta(seconds=60))
    stale = datetime.now(UTC) - timedelta(seconds=30)
    session = SimpleNamespace(
        id=1,
        user_id="u1",
        created_at=datetime.now(UTC) - timedelta(minutes=5),
        expires_at=datetime.now(UTC) + timedelta(minutes=10),
        access_token="tok-old",
        access_token_jti="jti-old",
        access_token_expires_at=stale,
    )
    db = _mgr([session, session])  # token lookup, then extend_session's re-read
    manager = SessionManager(db, cfg)
    new_token = manager.refresh_token("tok-old")
    assert new_token is not None
    assert session.access_token == new_token.token
    assert session.access_token_expires_at == new_token.expires_at
    assert session.access_token_expires_at > stale
