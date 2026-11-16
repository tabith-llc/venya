# Copyright (c) 2026 Tabith LLC.
# Use of this source code is governed by the Business Source License 1.1
# included in the LICENSE file at the root of this repository. As of the
# Change Date listed there, the work is available under MPL 2.0.
# SPDX-License-Identifier: BUSL-1.1

"""Core-trail face of leg 1424 (iid #798): the trail must not read "ran" and nothing else.

The finding's audit half is exact: for a run whose egress the sandbox proxy refused, the
core recorded `command_executed`. That row is TRUE — the command ran, and the proxy answered
it — and as the sole record of the run it is misleading, because a destination the policy
never admitted was never reached. So this writes a second row beside it, and leaves the
executed row byte-identical (same keys, same exit code). No schema change: `event_type` is a
free String(64) column and `fields` is text, so nothing here needs a migration.
"""

from datetime import UTC, datetime, timedelta
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from fastapi import FastAPI
from server.dependencies import get_current_user
from server.routes import executors as executors_routes
from starlette.testclient import TestClient

TEST_USER = {"user_id": "test-user", "roles": ["devops"], "caller": "human"}


@pytest.fixture(autouse=True)
def _default_role_permissions():
    """Every user holds a read-write role, the same seam the relay-payload cells use: these
    cells are about the trail the route writes, not about the permission gate."""
    rm = MagicMock()
    rm.get_user_permissions.side_effect = lambda uid: {1: "read-write"}
    with patch("server.dependencies.RoleManager", return_value=rm):
        yield


def _current_cert():
    """A registered, unexpired `ExecutorCert` row: the #586 dial gate refuses an executor the
    core holds no current certificate for, so a cell that wants the relay to RUN models the
    registered state rather than the old "no row" simplification."""
    return SimpleNamespace(
        serial_number="0000000000001000",
        not_after=datetime.now(UTC) + timedelta(days=30),
    )


def _create_test_app():
    """The smallest app that serves the execute route, wired the way the sibling relay cells
    wire it (same route module, same auth override, same sanitized-422 handler)."""
    app = FastAPI()
    backend = MagicMock()
    backend.get_session.return_value = MagicMock()
    app.state.backend = backend

    mock_config = MagicMock()
    mock_config.ca_dir = "/var/lib/venya/ca"
    mock_config.mtls_cert = None
    mock_config.mtls_key = None
    app.state.config = mock_config

    app.state.core = MagicMock()
    app.state.core.decrypt_secret.return_value = "s3cret-value"
    app.state.core.get_for_injection.return_value = (1, "s3cret-value", {})

    app.include_router(executors_routes.router, prefix="/api/v1")
    from fastapi.exceptions import RequestValidationError
    from server.app import _validation_error_handler

    app.add_exception_handler(RequestValidationError, _validation_error_handler)
    app.dependency_overrides[get_current_user] = lambda: TEST_USER
    return app, backend


# The measured refusal face, as the executor answers it after reading its own runtime log.
RELAY_FACES = {
    "denied": {
        "exit_code": 0,
        "stdout": "Approval required for example.com:80.\n",
        "stderr": "venya: the sandbox proxy refused this run's egress to example.com:80",
        "masked_count": 0,
        "egress_denied": True,
        "egress_denied_host": "example.com:80",
    },
    # ★ The paired negative, in both of its forms: an explicit False, and the four-key body an
    # executor from before this change sends. Neither may write a denial row, or every run
    # would look denied in the trail.
    "delivered": {"exit_code": 0, "stdout": "ok\n", "stderr": "", "masked_count": 0},
    "delivered_explicit": {
        "exit_code": 0,
        "stdout": "ok\n",
        "stderr": "",
        "masked_count": 0,
        "egress_denied": False,
        "egress_denied_host": "",
    },
}


def _queries(mock_db):
    """The uniform query mock the sibling harness uses, with a live cert row so the relay
    gate passes and the request reaches the response-handling half."""
    session = MagicMock()
    session.id = "sess-1424"
    session.user_id = "test-user"
    session.expires_at = datetime.now(UTC) + timedelta(minutes=5)
    session.executor_id = "exec-1"
    session.command = ""
    session.completed_at = None
    session.exit_code = None
    session.stdout = None
    session.stderr = None

    executor = MagicMock()
    executor.id = "exec-1"
    executor.hostname = "192.0.2.14"
    executor.revoked_at = None
    executor.serial_number = None
    executor.not_after = datetime.now(UTC) + timedelta(days=30)

    def by_model(model):
        if model.__name__ == "ExecutionSession":
            q = MagicMock()
            q.filter.return_value.first.return_value = session
            return q
        if model.__name__ == "Executor":
            q = MagicMock()
            q.filter.return_value.first.return_value = executor
            return q
        if model.__name__ == "SessionSecret":
            q = MagicMock()
            q.all.return_value = []
            return q
        if model.__name__ == "ExecutorCert":
            q = MagicMock()
            q.filter.return_value.first.return_value = _current_cert()
            return q
        if model.__name__ == "ExecutorCertRevocation":
            q = MagicMock()
            q.filter.return_value.first.return_value = None
            return q
        return MagicMock()

    mock_db.query.side_effect = by_model
    mock_db.add = MagicMock()
    mock_db.commit = MagicMock()


@pytest.fixture(autouse=True)
def _fake_dial_crl_store():
    """The transport is faked in every cell here (the AsyncClient is a MagicMock), so the
    dial-side CRL store is stubbed to None — the same seam the relay-payload cells use, so
    these cells test the audit shape and not the handshake."""
    with patch("server.routes.executors._ensure_dial_crl_store", return_value=None):
        yield


def _dial(relay_body):
    """One POST through the route with the relay's answer faked at the transport."""
    app, backend = _create_test_app()
    mock_db = MagicMock()
    _queries(mock_db)
    backend.get_session.return_value = mock_db

    response = MagicMock()
    response.status_code = 200
    response.json.return_value = dict(relay_body)
    response.raise_for_status = MagicMock()

    client = MagicMock()
    client.__aenter__ = AsyncMock(return_value=client)
    client.__aexit__ = AsyncMock(return_value=False)
    client.post = AsyncMock(return_value=response)

    with (
        patch("server.routes.executors.httpx2.AsyncClient", return_value=client),
        patch("server.routes.executors.ssl.SSLContext", return_value=MagicMock()),
    ):
        api = TestClient(app, raise_server_exceptions=False)
        resp = api.post(
            "/api/v1/executors/exec-1/execute",
            json={"session_id": "sess-1424", "command": ["/usr/bin/curl", "http://example.com/"]},
        )
    return resp, mock_db


def _rows_added(mock_db):
    rows = []
    for call in mock_db.add.call_args_list:
        event = call[0][0] if call[0] else None
        if event is not None and hasattr(event, "event_type"):
            rows.append(event)
    return rows


def _fields(event):
    """The row's payload as the route handed it over.

    `AuditEvent.fields` is a Text column with a serializer, so what lands on the object
    after validation is a JSON string, not the dict the route passed in — reading it as a
    dict here would compare characters.
    """
    import json

    return json.loads(event.fields) if isinstance(event.fields, str) else event.fields


class TestDeniedRunWritesItsOwnRow:
    def test_denied_egress_adds_an_egress_denied_row(self):
        resp, mock_db = _dial(RELAY_FACES["denied"])
        assert resp.status_code == 200, resp.text
        rows = [r for r in _rows_added(mock_db) if r.event_type == "egress_denied"]
        assert len(rows) == 1, [r.event_type for r in _rows_added(mock_db)]
        fields = _fields(rows[0])
        assert fields["egress_host"] == "example.com:80"
        assert fields["session_id"] == "sess-1424"
        assert fields["executor_id"] == "exec-1"

    def test_the_executed_row_is_left_exactly_as_it_was(self):
        """The denial row is ADDED, not substituted: `command_executed` is a true statement
        about the process and other readers depend on its key set."""
        _, mock_db = _dial(RELAY_FACES["denied"])
        executed = [r for r in _rows_added(mock_db) if r.event_type == "command_executed"]
        assert len(executed) == 1
        assert set(_fields(executed[0])) == {"session_id", "executor_id", "command", "exit_code", "masked_count"}
        assert _fields(executed[0])["exit_code"] == 0


@pytest.mark.parametrize("face", ["delivered", "delivered_explicit"])
class TestDeliveredRunWritesWhatItAlwaysWrote:
    def test_no_denial_row_for_a_run_that_reached_its_destination(self, face):
        resp, mock_db = _dial(RELAY_FACES[face])
        assert resp.status_code == 200, resp.text
        rows = [r.event_type for r in _rows_added(mock_db)]
        assert "egress_denied" not in rows
        assert "command_executed" in rows

    def test_the_served_answer_carries_no_denial_when_there_was_none(self, face):
        resp, _mock_db = _dial(RELAY_FACES[face])
        body = resp.json()
        assert body["egress_denied"] is False
        assert body["egress_denied_host"] == ""
