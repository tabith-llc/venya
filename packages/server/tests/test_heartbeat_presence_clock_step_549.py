# Copyright (c) 2026 Tabith LLC.
# Use of this source code is governed by the Business Source License 1.1
# included in the LICENSE file at the root of this repository. As of the
# Change Date listed there, the work is available under MPL 2.0.
# SPDX-License-Identifier: BUSL-1.1

"""#549 site 2 — the executor heartbeat presence window on a stepped clock.

The presence decision is SERVER-side: ``routes/executors.py``'s
``list_executors`` ages each row's stored ``last_heartbeat`` against its own
``datetime.now(UTC)``. Both sides are DB ``timestamptz`` WALL stamps (the beat
is written by the ``heartbeat`` handler with ``datetime.now(UTC)``), so this is
the "clamp where wall stamps persist" half of the #464 ruling — NOT a monotonic
conversion: a monotonic reading taken in one process is meaningless against a
stamp written by another.

The parent window was one-sided: ``delta.total_seconds() < 60``. A NEGATIVE
delta — a stamp ahead of the reader's clock, which is what a FORWARD step at the
writer or a BACKWARD step at the reader produces — satisfied ``< 60`` and read
LIVE. An hour-long backward step at the reader therefore presented every stamp
written before the step as live for a full hour, well past its true 60 s window
(measured at the parent: delta -3560 s and -2 s both reported ``online: true``).

**Ruled shape: option (a)** — ``0 <= delta < 60``; a stamp ahead of the reading
is NOT online. Reasoning (named per the #549 AC, not defaulted silently):
presence is the claim that routes work at a target, and a stamp the reader
cannot place in its own past is a claim it cannot prove — false LIVE is the
unsafe direction. The cost is the other half of the sentence: a genuinely live
executor whose stamp sits ahead of a stepped-back reader clock reads absent
until its next beat lands on the corrected clock, which is a short gap — the
daemon's main loop beats on a literal 30 s cadence
(``self._shutdown_event.wait(30.0)`` in ``executor/daemon.py`` ``_main_loop``,
verified at this base; it is not a config knob).
So the failure is a short, self-healing display gap, not a stale routing
target. Option (b) (a skew tolerance window) was rejected: it would keep the
false-LIVE half open by the width of the tolerance, and that tolerance value
belongs to certificate validity in ``executor/daemon.py``, not to presence.

The 60 s window VALUE is unchanged and no config knob is added; the response
contract is unchanged (``online`` stays a bool, ``last_heartbeat`` still echoes
the stored stamp) — the contract cell below pins that.

Clock control: the rows are mock ORM records, so each cell places the stamp at
a real offset from the wall clock and the route computes its own ``now``. That
keeps the cells honest about the production arithmetic (no fake clock patched
over the route) and the 0.5 s boundary margins hold because the only elapsed
time between the stamp and the reading is the request itself.
"""

from datetime import UTC, datetime, timedelta
from unittest.mock import MagicMock, patch

import pytest
from fastapi import FastAPI
from server.dependencies import get_current_user
from server.routes import executors as executors_routes
from starlette.testclient import TestClient

TEST_USER = {"user_id": "test-user", "roles": ["devops"], "caller": "human"}

#: The presence window is 60 s and is NOT changed by this fix — the boundary
#: cells use this only to say so in one place.
WINDOW_SECONDS = 60.0

#: Half-second margins: the route's ``now`` is taken after the test builds the
#: stamp, so the real delta carries the request's own (millisecond) runtime.
MARGIN = 0.5


@pytest.fixture(autouse=True)
def _default_role_permissions():
    """Default: every user holds a read-write role (mirrors tests/test_executors.py)."""
    rm = MagicMock()
    rm.get_user_permissions.side_effect = lambda uid: {1: "read-write"}
    with patch("server.dependencies.RoleManager", return_value=rm):
        yield rm


def _row(*, last_heartbeat, executor_id="exec-1", hostname="192.0.2.14"):
    """A mock ORM Executor row. Only the fields list_executors reads are set."""
    row = MagicMock()
    row.id = executor_id
    row.hostname = hostname
    row.last_heartbeat = last_heartbeat
    row.enrolled_at = datetime.now(UTC) - timedelta(days=5)
    row.revoked_at = None
    row.status = "active"
    row.version = None
    return row


def _app_with_rows(rows):
    """App whose session answers the Executor query with ``rows`` and every
    cert/revocation lookup with nothing (so ``status`` comes from enrollment)."""
    from core.iam.models import Executor

    app = FastAPI()
    backend = MagicMock()
    session = MagicMock()

    def _query(model):
        query = MagicMock()
        query.all.return_value = list(rows) if model is Executor else []
        query.first.return_value = None
        query.filter.return_value.first.return_value = None
        query.filter.return_value.all.return_value = []
        return query

    session.query.side_effect = _query
    backend.get_session.return_value = session
    app.state.backend = backend
    app.include_router(executors_routes.router, prefix="/api/v1")
    app.dependency_overrides[get_current_user] = lambda: TEST_USER
    return app


def _entry(row):
    """The single executor entry the route returns for ``row`` (raw JSON body)."""
    client = TestClient(_app_with_rows([row]), raise_server_exceptions=False)
    resp = client.get("/api/v1/executors")
    assert resp.status_code == 200
    body = resp.json()
    assert len(body["executors"]) == 1
    return body["executors"][0]


class TestFutureStampIsNotOnline:
    """Option (a): a stamp ahead of the reader's clock does NOT read live."""

    def test_forward_step_at_writer_is_not_online(self):
        """Load-bearing cell. The writer's clock stepped FORWARD an hour when it
        stamped the beat, so the reader's ``now`` is an hour behind the stamp
        (delta = -3600 s). Option (a) encoded: absent. The parent read this live
        because ``-3600 < 60``."""
        row = _row(last_heartbeat=datetime.now(UTC) + timedelta(seconds=3600))

        assert _entry(row)["online"] is False

    def test_two_second_future_skew_is_not_online(self):
        """Tiny forward skew (delta = -2 s). Option (a) has NO tolerance, so this
        is absent too — under a rejected option (b) window this would be the
        inside-tolerance live case. Chosen deliberately: presence is a routing
        claim, and a stamp the reader cannot place in its own past is unprovable
        at any width."""
        row = _row(last_heartbeat=datetime.now(UTC) + timedelta(seconds=2))

        assert _entry(row)["online"] is False

    def test_backward_step_at_reader_does_not_hold_a_stale_row_live(self):
        """Backward half. A beat lands 40 s before the reader's clock steps an
        hour back: the stamp is now 3560 s AHEAD of the reader's ``now``, and
        the parent's one-sided test called it live — for the whole hour until the
        clock walked back past it. Asserted: ABSENT, i.e. the clock's own reading
        ("it is in the future, so it is fresh") is refused; presence returns with
        the next beat, which the paired positive below shows."""
        ahead = 3600.0 - 40.0
        row = _row(last_heartbeat=datetime.now(UTC) + timedelta(seconds=ahead))

        assert _entry(row)["online"] is False

    def test_next_beat_after_a_backward_step_is_online_again(self):
        """Paired positive for the cell above: a beat taken AFTER the step (so it
        sits in the reader's past again) reads live immediately — the refusal is
        about an unplaceable stamp, not about a stepped clock being trusted ever
        again."""
        row = _row(last_heartbeat=datetime.now(UTC) - timedelta(seconds=10))

        assert _entry(row)["online"] is True


class TestOrdinaryAgingUnchanged:
    """The window's ordinary behavior and its two ends are untouched."""

    def test_ten_seconds_old_is_online(self):
        row = _row(last_heartbeat=datetime.now(UTC) - timedelta(seconds=10))

        assert _entry(row)["online"] is True

    def test_120_seconds_old_is_offline(self):
        row = _row(last_heartbeat=datetime.now(UTC) - timedelta(seconds=120))

        assert _entry(row)["online"] is False

    def test_never_beaten_is_offline_and_does_not_raise(self):
        """``last_heartbeat IS NULL`` (registered, never beat): absent, and the
        None path must not raise on a subtraction. A 500 here would take the
        whole fleet list down with one pending row."""
        row = _row(last_heartbeat=None)

        entry = _entry(row)
        assert entry["online"] is False
        assert entry["last_heartbeat"] is None

    def test_stamp_equal_to_the_reading_is_online(self):
        """The window's lower edge is INCLUSIVE: a delta of exactly 0 is the
        freshest possible beat and must read live (the clamp is ``0 <= delta``,
        not ``0 < delta``)."""
        now = datetime.now(UTC)
        # The beat is stamped at the same instant the request begins, so the
        # route's own ``now`` is never behind it; ``>=`` is the honest assert.
        entry = _entry(_row(last_heartbeat=now))

        assert entry["online"] is True

    def test_just_under_the_window_is_online(self):
        """Boundary, live half: 60 s - margin is inside the window."""
        row = _row(last_heartbeat=datetime.now(UTC) - timedelta(seconds=WINDOW_SECONDS - MARGIN))

        assert _entry(row)["online"] is True

    def test_just_over_the_window_is_offline(self):
        """Boundary, absent half: 60 s + margin is outside. The window VALUE is
        unchanged by this fix — these two cells are the proof."""
        row = _row(last_heartbeat=datetime.now(UTC) + timedelta(seconds=-(WINDOW_SECONDS + MARGIN)))

        assert _entry(row)["online"] is False


class TestResponseContractUnchanged:
    """Zero mutation on the response contract: same fields, same types."""

    def test_entry_shape_is_unchanged_for_a_live_row(self):
        body = _entry(_row(last_heartbeat=datetime.now(UTC) - timedelta(seconds=10)))

        assert set(body) == {"id", "hostname", "online", "last_heartbeat", "enrolled_at", "status", "version"}
        assert isinstance(body["online"], bool)
        assert isinstance(body["id"], str)
        assert isinstance(body["hostname"], str)
        assert isinstance(body["status"], str)
        assert isinstance(body["last_heartbeat"], str)
        assert isinstance(body["enrolled_at"], str)

    def test_entry_shape_is_unchanged_for_a_refused_future_stamp(self):
        """The refusal changes the ``online`` VALUE only. Same field set, same
        types, and ``last_heartbeat`` still echoes the stored stamp verbatim —
        an operator can see the row and its odd stamp rather than a dropped
        entry."""
        stamp = datetime.now(UTC) + timedelta(seconds=3600)
        body = _entry(_row(last_heartbeat=stamp))

        assert set(body) == {"id", "hostname", "online", "last_heartbeat", "enrolled_at", "status", "version"}
        assert body["online"] is False
        assert isinstance(body["online"], bool)
        assert datetime.fromisoformat(body["last_heartbeat"]) == stamp
        assert body["status"] == "active"
