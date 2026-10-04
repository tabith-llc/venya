# Copyright (c) 2026 Tabith LLC.
# Use of this source code is governed by the Business Source License 1.1
# included in the LICENSE file at the root of this repository. As of the
# Change Date listed there, the work is available under MPL 2.0.
# SPDX-License-Identifier: BUSL-1.1

"""Tests for execution relay endpoints.

Covers session creation, command relay, audit events, and session validation.
"""

import json
import logging
import socket
import ssl
from datetime import UTC, datetime, timedelta
from unittest.mock import AsyncMock, MagicMock, patch

import httpx2
import pytest
from core.engine.core import CoreAccessError
from fastapi import FastAPI
from server.dependencies import get_current_user
from server.routes import executors as executors_routes
from server.routes.executors import _ENV_SHAPE_MIN_VERSION, _version_tuple
from server.routes.secrets import wrap_with_sentinel
from starlette.testclient import TestClient

TEST_USER = {"user_id": "test-user", "roles": ["devops"], "caller": "human"}


@pytest.fixture(autouse=True)
def _default_role_permissions():
    """Default: every user holds a read-write role."""
    rm = MagicMock()
    rm.get_user_permissions.side_effect = lambda uid: {1: "read-write"}
    with patch("server.dependencies.RoleManager", return_value=rm):
        yield rm


def _create_test_app(backend=None):
    """Create a minimal test app with executor routes."""
    app = FastAPI()

    if backend is None:
        backend = MagicMock()
    backend.get_session.return_value = MagicMock()
    app.state.backend = backend

    # Set up minimal config for mTLS relay
    mock_config = MagicMock()
    mock_config.ca_dir = "/var/lib/venya/ca"
    mock_config.mtls_cert = None
    mock_config.mtls_key = None
    app.state.config = mock_config

    # Server-side secret resolution/wrapping
    app.state.core = MagicMock()
    app.state.core.decrypt_secret.return_value = "s3cret-value"
    app.state.core.get_for_injection.return_value = (1, "s3cret-value", {})

    app.include_router(executors_routes.router, prefix="/api/v1")
    # #334: same sanitized-422 handler production wires in create_app
    from fastapi.exceptions import RequestValidationError
    from server.app import _validation_error_handler

    app.add_exception_handler(RequestValidationError, _validation_error_handler)

    app.dependency_overrides[get_current_user] = lambda: TEST_USER

    return app, backend


def _mock_secret_rows(*rows):
    """Build mock Secret ORM rows (id, key, meta)."""
    secrets = []
    for i, (key, meta) in enumerate(rows, start=1):
        s = MagicMock()
        s.id = i
        s.key = key
        s.meta = meta
        secrets.append(s)
    return secrets


# --- Session creation tests ---


def _mock_db_for_session(executor, secrets_first_side_effect):
    """Mock db session serving Executor + per-key Secret queries."""
    mock_session = MagicMock()
    executor_q = MagicMock()
    executor_q.filter.return_value.first.return_value = executor
    secret_q = MagicMock()
    secret_q.filter.return_value.order_by.return_value.first.side_effect = secrets_first_side_effect

    def query_side_effect(model):
        if model.__name__ == "Executor":
            return executor_q
        if model.__name__ in ("ExecutorCert", "ExecutorCertRevocation"):
            # updated: the shared revocation state (executor-revocation-by-identity)
            # queries cert/CRL when no identity flag is set — model "no rows".
            none_q = MagicMock()
            none_q.filter.return_value.first.return_value = None
            return none_q
        return secret_q

    mock_session.query.side_effect = query_side_effect
    return mock_session


class TestCreateExecutionSession:
    """Tests for POST /api/v1/executors/sessions."""

    def test_create_session_returns_session_id(self):
        """Session creation returns a valid session_id."""
        app, backend = _create_test_app()
        mock_session = MagicMock()
        mock_executor = MagicMock()
        mock_executor.id = "exec-1"
        mock_executor.hostname = "192.0.2.14"
        mock_executor.revoked_at = None  # updated: shared revocation state reads this (executor-revocation-by-identity)
        mock_executor.serial_number = None  # stands in for "no ExecutorCert row" under uniform query mocks
        mock_query = MagicMock()
        mock_query.first.return_value = mock_executor
        mock_query.filter.return_value.first.return_value = mock_executor
        mock_session.query.return_value = mock_query
        backend.get_session.return_value = mock_session

        client = TestClient(app, raise_server_exceptions=False)
        resp = client.post(
            "/api/v1/executors/sessions",
            json={"executor_id": "exec-1"},
        )

        assert resp.status_code == 201
        data = resp.json()
        assert "session_id" in data
        assert data["executor_id"] == "exec-1"
        assert "created_at" in data
        assert "expires_at" in data

    def test_create_session_404_unknown_executor(self):
        """Session creation returns 404 for unknown executor."""
        app, backend = _create_test_app()
        mock_db = _mock_db_for_session(None, [])
        backend.get_session.return_value = mock_db

        client = TestClient(app, raise_server_exceptions=False)
        resp = client.post(
            "/api/v1/executors/sessions",
            json={"executor_id": "nonexistent"},
        )

        assert resp.status_code == 404

    def test_create_session_503_core_not_initialized(self):
        """Session creation returns 503 when core is not initialized."""
        app, _ = _create_test_app()
        app.state.core = None
        client = TestClient(app, raise_server_exceptions=False)
        resp = client.post(
            "/api/v1/executors/sessions",
            json={"executor_id": "exec-1"},
        )
        assert resp.status_code == 503

    def test_create_session_404_unknown_key(self):
        """Session creation returns 404 for an unknown secret key."""
        app, backend = _create_test_app()
        mock_executor = MagicMock()
        mock_executor.id = "exec-1"
        mock_executor.hostname = "192.0.2.14"
        mock_executor.revoked_at = None  # updated: shared revocation state reads this (executor-revocation-by-identity)
        mock_executor.serial_number = None  # stands in for "no ExecutorCert row" under uniform query mocks
        mock_db = _mock_db_for_session(mock_executor, [None])
        backend.get_session.return_value = mock_db
        app.state.core.get_for_injection.side_effect = CoreAccessError("Secret not found: missing-key")

        client = TestClient(app, raise_server_exceptions=False)
        resp = client.post(
            "/api/v1/executors/sessions",
            json={"executor_id": "exec-1", "secret_keys": ["missing-key"]},
        )

        assert resp.status_code == 404

    def test_scoped_out_key_404_indistinguishable_from_missing(self):
        """Paired negative (secret-role-scoping-unenforced): a role-scoped-out
        key yields the exact same 404 detail shape as a nonexistent key — no
        cross-role key-name enumeration."""
        app, backend = _create_test_app()
        mock_executor = MagicMock()
        mock_executor.id = "exec-1"
        mock_executor.hostname = "192.0.2.14"
        mock_executor.revoked_at = None  # updated: shared revocation state reads this (executor-revocation-by-identity)
        mock_executor.serial_number = None  # stands in for "no ExecutorCert row" under uniform query mocks
        mock_db = _mock_db_for_session(mock_executor, [None])
        backend.get_session.return_value = mock_db

        client = TestClient(app, raise_server_exceptions=False)

        app.state.core.get_for_injection.side_effect = CoreAccessError("Secret not found: admin-only")
        resp1 = client.post(
            "/api/v1/executors/sessions",
            json={"executor_id": "exec-1", "secret_keys": ["admin-only"]},
        )
        app.state.core.get_for_injection.side_effect = CoreAccessError("Secret not found: truly-missing")
        resp2 = client.post(
            "/api/v1/executors/sessions",
            json={"executor_id": "exec-1", "secret_keys": ["truly-missing"]},
        )

        assert resp1.status_code == 404
        assert resp2.status_code == 404
        assert resp1.json()["detail"] == "Secret 'admin-only' not found"
        assert resp2.json()["detail"] == "Secret 'truly-missing' not found"

    def test_create_session_stores_wrapped_secrets(self):
        """Keys are resolved and wrapped server-side into SessionSecret rows."""
        from server.routes.secrets import wrap_with_sentinel

        app, backend = _create_test_app()
        mock_executor = MagicMock()
        mock_executor.id = "exec-1"
        mock_executor.hostname = "192.0.2.14"
        mock_executor.revoked_at = None  # updated: shared revocation state reads this (executor-revocation-by-identity)
        mock_executor.serial_number = None  # stands in for "no ExecutorCert row" under uniform query mocks
        secrets = _mock_secret_rows(("db-password", None), ("api-key", None))
        mock_db = _mock_db_for_session(mock_executor, list(secrets))
        backend.get_session.return_value = mock_db
        app.state.core.get_for_injection.side_effect = [
            (1, "s3cret-value", {}),
            (2, "s3cret-value", {}),
        ]

        client = TestClient(app, raise_server_exceptions=False)
        resp = client.post(
            "/api/v1/executors/sessions",
            json={"executor_id": "exec-1", "secret_keys": ["db-password", "api-key"]},
        )

        assert resp.status_code == 201

        added = [c[0][0] for c in mock_db.add.call_args_list if c[0]]
        session_secrets = [s for s in added if getattr(s, "wrapped_value", None) is not None]
        assert len(session_secrets) == 2
        assert [s.secret_id for s in session_secrets] == [1, 2]
        assert [s.wrapped_value for s in session_secrets] == [
            wrap_with_sentinel("db-password", b"s3cret-value"),
            wrap_with_sentinel("api-key", b"s3cret-value"),
        ]

    def test_audit_event_contains_secret_keys(self):
        """A3: audit event records session, executor, and the secret keys."""
        app, backend = _create_test_app()
        mock_executor = MagicMock()
        mock_executor.id = "exec-1"
        mock_executor.hostname = "192.0.2.14"
        mock_executor.revoked_at = None  # updated: shared revocation state reads this (executor-revocation-by-identity)
        mock_executor.serial_number = None  # stands in for "no ExecutorCert row" under uniform query mocks
        secrets = _mock_secret_rows(("db-password", None))
        mock_db = _mock_db_for_session(mock_executor, list(secrets))
        backend.get_session.return_value = mock_db
        app.state.core.get_for_injection.side_effect = [(1, "s3cret-value", {})]

        client = TestClient(app, raise_server_exceptions=False)
        resp = client.post(
            "/api/v1/executors/sessions",
            json={"executor_id": "exec-1", "secret_keys": ["db-password"]},
        )

        assert resp.status_code == 201

        audit_event = None
        for call in mock_db.add.call_args_list:
            event = call[0][0] if call[0] else None
            if event and hasattr(event, "event_type") and event.event_type == "execution_session_created":
                audit_event = event
                break

        assert audit_event is not None
        assert audit_event.user_id == "test-user"
        fields = eval(audit_event.fields) if isinstance(audit_event.fields, str) else audit_event.fields
        assert "session_id" in fields
        assert fields["executor_id"] == "exec-1"
        assert fields["secret_keys"] == ["db-password"]
        assert fields["metadata_mismatch"] == []

    def test_metadata_mismatch_warns_not_blocks(self):
        """A4: metadata.executor mismatch is recorded in audit, session proceeds."""
        app, backend = _create_test_app()
        mock_executor = MagicMock()
        mock_executor.id = "exec-1"
        mock_executor.hostname = "192.0.2.14"
        mock_executor.revoked_at = None  # updated: shared revocation state reads this (executor-revocation-by-identity)
        mock_executor.serial_number = None  # stands in for "no ExecutorCert row" under uniform query mocks
        secrets = _mock_secret_rows(("db-password", {"executor": "other-exec"}))
        mock_db = _mock_db_for_session(mock_executor, list(secrets))
        backend.get_session.return_value = mock_db
        app.state.core.get_for_injection.side_effect = [(1, "s3cret-value", {"executor": "other-exec"})]

        client = TestClient(app, raise_server_exceptions=False)
        resp = client.post(
            "/api/v1/executors/sessions",
            json={"executor_id": "exec-1", "secret_keys": ["db-password"]},
        )

        assert resp.status_code == 201

        audit_event = None
        for call in mock_db.add.call_args_list:
            event = call[0][0] if call[0] else None
            if event and hasattr(event, "event_type") and event.event_type == "execution_session_created":
                audit_event = event
                break

        assert audit_event is not None
        fields = eval(audit_event.fields) if isinstance(audit_event.fields, str) else audit_event.fields
        assert fields["metadata_mismatch"] == ["db-password"]

    def test_session_10_minute_ttl(self):
        """Session expires_at is created_at + 10 minutes."""
        app, backend = _create_test_app()
        mock_db = _mock_db_for_session(MagicMock(id="exec-1", hostname="192.0.2.14", revoked_at=None), [])
        backend.get_session.return_value = mock_db

        client = TestClient(app, raise_server_exceptions=False)
        resp = client.post(
            "/api/v1/executors/sessions",
            json={"executor_id": "exec-1"},
        )

        assert resp.status_code == 201
        data = resp.json()
        created = datetime.fromisoformat(data["created_at"])
        expires = datetime.fromisoformat(data["expires_at"])
        delta = expires - created
        assert delta == timedelta(minutes=10)


# --- Command execution relay tests ---


class TestExecuteCommandOnExecutor:
    """Tests for POST /api/v1/executors/{id}/execute."""

    def test_execute_session_not_found(self):
        """Execute returns 404 for unknown session."""
        app, backend = _create_test_app()
        mock_session = MagicMock()
        mock_query = MagicMock()
        mock_filtered = MagicMock()
        mock_filtered.first.return_value = None
        mock_query.filter.return_value = mock_filtered
        mock_session.query.return_value = mock_query
        backend.get_session.return_value = mock_session

        client = TestClient(app, raise_server_exceptions=False)
        resp = client.post(
            "/api/v1/executors/exec-1/execute",
            json={"session_id": "nonexistent", "command": ["echo", "hello"]},
        )

        assert resp.status_code == 404

    def test_execute_session_expired(self):
        """Execute returns 400 for expired session."""
        app, backend = _create_test_app()
        mock_session = MagicMock()
        mock_execution_session = MagicMock()
        mock_execution_session.id = "sess-1"
        mock_execution_session.user_id = "test-user"
        mock_execution_session.expires_at = datetime.now(UTC) - timedelta(minutes=11)

        mock_query = MagicMock()
        mock_filtered = MagicMock()
        mock_filtered.first.return_value = mock_execution_session
        mock_query.filter.return_value = mock_filtered
        mock_session.query.return_value = mock_query
        backend.get_session.return_value = mock_session

        client = TestClient(app, raise_server_exceptions=False)
        resp = client.post(
            "/api/v1/executors/exec-1/execute",
            json={"session_id": "sess-1", "command": ["echo", "hello"]},
        )

        assert resp.status_code == 400

    def test_execute_session_ownership(self):
        """Execute returns 403 when session belongs to different user."""
        app, backend = _create_test_app()
        mock_session = MagicMock()
        mock_execution_session = MagicMock()
        mock_execution_session.id = "sess-1"
        mock_execution_session.user_id = "other-user"
        mock_execution_session.expires_at = datetime.now(UTC) + timedelta(minutes=5)

        mock_query = MagicMock()
        mock_filtered = MagicMock()
        mock_filtered.first.return_value = mock_execution_session
        mock_query.filter.return_value = mock_filtered
        mock_session.query.return_value = mock_query
        backend.get_session.return_value = mock_session

        client = TestClient(app, raise_server_exceptions=False)
        resp = client.post(
            "/api/v1/executors/exec-1/execute",
            json={"session_id": "sess-1", "command": ["echo", "hello"]},
        )

        assert resp.status_code == 403

    def test_execute_session_executor_mismatch(self):
        """A2: execute returns 403 when the session was created for another executor."""
        app, backend = _create_test_app()
        mock_session = MagicMock()
        mock_execution_session = MagicMock()
        mock_execution_session.id = "sess-1"
        mock_execution_session.user_id = "test-user"
        mock_execution_session.executor_id = "exec-2"
        mock_execution_session.expires_at = datetime.now(UTC) + timedelta(minutes=5)

        mock_query = MagicMock()
        mock_filtered = MagicMock()
        mock_filtered.first.return_value = mock_execution_session
        mock_query.filter.return_value = mock_filtered
        mock_session.query.return_value = mock_query
        backend.get_session.return_value = mock_session

        client = TestClient(app, raise_server_exceptions=False)
        resp = client.post(
            "/api/v1/executors/exec-1/execute",
            json={"session_id": "sess-1", "command": ["echo", "hello"]},
        )

        assert resp.status_code == 403
        assert "different executor" in resp.json()["detail"]

    def test_execute_audit_event_command_executed(self):
        """Verify command_executed audit event is created."""
        app, backend = _create_test_app()
        mock_db = MagicMock()

        # Session query: return mock session
        mock_exec_session = MagicMock()
        mock_exec_session.id = "sess-1"
        mock_exec_session.user_id = "test-user"
        mock_exec_session.expires_at = datetime.now(UTC) + timedelta(minutes=5)
        mock_exec_session.executor_id = "exec-1"
        mock_exec_session.command = ""
        mock_exec_session.completed_at = None
        mock_exec_session.exit_code = None
        mock_exec_session.stdout = None
        mock_exec_session.stderr = None

        mock_session_query = MagicMock()
        mock_session_filtered = MagicMock()
        mock_session_filtered.first.return_value = mock_exec_session
        mock_session_query.filter.return_value = mock_session_filtered

        # Executor query: return mock executor
        mock_executor = MagicMock()
        mock_executor.id = "exec-1"
        mock_executor.hostname = "192.0.2.14"
        mock_executor.revoked_at = None  # updated: shared revocation state reads this (executor-revocation-by-identity)
        mock_executor.serial_number = None  # stands in for "no ExecutorCert row" under uniform query mocks

        mock_executor_query = MagicMock()
        mock_executor_filtered = MagicMock()
        mock_executor_filtered.first.return_value = mock_executor
        mock_executor_query.filter.return_value = mock_executor_filtered

        # Secrets query: return empty list
        mock_secrets_query = MagicMock()
        mock_secrets_query.all.return_value = []

        def query_side_effect(model):
            if model.__name__ == "ExecutionSession":
                return mock_session_query
            elif model.__name__ == "Executor":
                return mock_executor_query
            elif model.__name__ == "SessionSecret":
                return mock_secrets_query
            elif model.__name__ in ("ExecutorCert", "ExecutorCertRevocation"):
                # updated: shared revocation state models "no cert/CRL rows"
                none_q = MagicMock()
                none_q.filter.return_value.first.return_value = None
                return none_q
            return mock_session_query

        mock_db.query.side_effect = query_side_effect
        mock_db.add = MagicMock()
        mock_db.commit = MagicMock()
        backend.get_session.return_value = mock_db

        # Mock httpx2.AsyncClient and SSL context
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "exit_code": 0,
            "stdout": "hello world\n",
            "stderr": "",
            "masked_count": 0,
        }
        mock_response.raise_for_status = MagicMock()

        mock_client = MagicMock()
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)
        mock_client.post = AsyncMock(return_value=mock_response)

        mock_ssl_ctx = MagicMock()

        with patch("server.routes.executors.httpx2.AsyncClient", return_value=mock_client):
            with patch("server.routes.executors.ssl.create_default_context", return_value=mock_ssl_ctx):
                client = TestClient(app, raise_server_exceptions=False)
                resp = client.post(
                    "/api/v1/executors/exec-1/execute",
                    json={"session_id": "sess-1", "command": ["echo", "hello"]},
                )

        assert resp.status_code == 200
        # #322: the relay payload carries the argv LIST verbatim (no server-side
        # join); the audit fields carry only the rendered display text (below).
        assert mock_client.post.call_args.kwargs["json"]["command"] == ["echo", "hello"]

        # Check audit event
        audit_event = None
        for call in mock_db.add.call_args_list:
            event = call[0][0] if call[0] else None
            if event and hasattr(event, "event_type") and event.event_type == "command_executed":
                audit_event = event
                break

        assert audit_event is not None
        assert audit_event.user_id == "test-user"
        fields = eval(audit_event.fields) if isinstance(audit_event.fields, str) else audit_event.fields
        assert fields["session_id"] == "sess-1"
        assert fields["executor_id"] == "exec-1"
        assert fields["command"] == "echo hello"
        assert fields["exit_code"] == 0
        assert fields["masked_count"] == 0

    def test_execute_audit_event_contains_exit_code(self):
        """Audit event contains exit_code and masked_count from executor response."""
        app, backend = _create_test_app()
        mock_db = MagicMock()

        # Session query: return mock session
        mock_exec_session = MagicMock()
        mock_exec_session.id = "sess-1"
        mock_exec_session.user_id = "test-user"
        mock_exec_session.expires_at = datetime.now(UTC) + timedelta(minutes=5)
        mock_exec_session.executor_id = "exec-1"
        mock_exec_session.command = ""
        mock_exec_session.completed_at = None
        mock_exec_session.exit_code = None
        mock_exec_session.stdout = None
        mock_exec_session.stderr = None

        mock_session_query = MagicMock()
        mock_session_filtered = MagicMock()
        mock_session_filtered.first.return_value = mock_exec_session
        mock_session_query.filter.return_value = mock_session_filtered

        # Executor query: return mock executor
        mock_executor = MagicMock()
        mock_executor.id = "exec-1"
        mock_executor.hostname = "192.0.2.14"
        mock_executor.revoked_at = None  # updated: shared revocation state reads this (executor-revocation-by-identity)
        mock_executor.serial_number = None  # stands in for "no ExecutorCert row" under uniform query mocks

        mock_executor_query = MagicMock()
        mock_executor_filtered = MagicMock()
        mock_executor_filtered.first.return_value = mock_executor
        mock_executor_query.filter.return_value = mock_executor_filtered

        # Secrets query: return empty list
        mock_secrets_query = MagicMock()
        mock_secrets_query.all.return_value = []

        def query_side_effect(model):
            if model.__name__ == "ExecutionSession":
                return mock_session_query
            elif model.__name__ == "Executor":
                return mock_executor_query
            elif model.__name__ == "SessionSecret":
                return mock_secrets_query
            elif model.__name__ in ("ExecutorCert", "ExecutorCertRevocation"):
                # updated: shared revocation state models "no cert/CRL rows"
                none_q = MagicMock()
                none_q.filter.return_value.first.return_value = None
                return none_q
            return mock_session_query

        mock_db.query.side_effect = query_side_effect
        mock_db.add = MagicMock()
        mock_db.commit = MagicMock()
        backend.get_session.return_value = mock_db

        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "exit_code": 42,
            "stdout": "output with [REDACTED:abcd]secret[/REDACTED]\n",
            "stderr": "warn\n",
            "masked_count": 3,
        }
        mock_response.raise_for_status = MagicMock()

        mock_client = MagicMock()
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)
        mock_client.post = AsyncMock(return_value=mock_response)

        mock_ssl_ctx = MagicMock()

        with patch("server.routes.executors.httpx2.AsyncClient", return_value=mock_client):
            with patch("server.routes.executors.ssl.create_default_context", return_value=mock_ssl_ctx):
                client = TestClient(app, raise_server_exceptions=False)
                resp = client.post(
                    "/api/v1/executors/exec-1/execute",
                    json={"session_id": "sess-1", "command": ["echo", "secret"]},
                )

        assert resp.status_code == 200

        audit_event = None
        for call in mock_db.add.call_args_list:
            event = call[0][0] if call[0] else None
            if event and hasattr(event, "event_type") and event.event_type == "command_executed":
                audit_event = event
                break

        assert audit_event is not None
        fields = eval(audit_event.fields) if isinstance(audit_event.fields, str) else audit_event.fields
        assert fields["exit_code"] == 42
        assert fields["masked_count"] == 3


# --- Executor unreachable tests ---


class TestExecutorReachability:
    """Tests for executor connection failures."""

    def test_execute_executor_unreachable(self):
        """Execute returns 503 when executor is unreachable."""
        app, backend = _create_test_app()
        mock_session = MagicMock()
        mock_session.id = "sess-1"
        mock_session.user_id = "test-user"
        mock_session.expires_at = datetime.now(UTC) + timedelta(minutes=5)
        mock_session.executor_id = "exec-1"

        mock_executor = MagicMock()
        mock_executor.id = "exec-1"
        mock_executor.hostname = "192.0.2.14"
        mock_executor.revoked_at = None  # updated: shared revocation state reads this (executor-revocation-by-identity)
        mock_executor.serial_number = None  # stands in for "no ExecutorCert row" under uniform query mocks

        mock_query = MagicMock()
        mock_query.first.side_effect = [mock_session, mock_executor]
        mock_session.query.return_value = mock_query
        backend.get_session.return_value = mock_session

        with patch("server.routes.executors.httpx2.AsyncClient") as mock_client_cls:
            mock_client_cls.side_effect = Exception("connection refused")

            client = TestClient(app, raise_server_exceptions=False)
            resp = client.post(
                "/api/v1/executors/exec-1/execute",
                json={"session_id": "sess-1", "command": ["echo", "hello"]},
            )

            assert resp.status_code == 500  # Generic error for unexpected exceptions

    def test_connect_error_with_ssl_cause_returns_mtls_message(self):
        """ConnectError with SSLError in cause chain → 503 'mTLS verification failed'."""

        app, backend = _create_test_app()
        mock_db = MagicMock()

        mock_exec_session = MagicMock()
        mock_exec_session.id = "sess-1"
        mock_exec_session.user_id = "test-user"
        mock_exec_session.expires_at = datetime.now(UTC) + timedelta(minutes=5)
        mock_exec_session.executor_id = "exec-1"

        mock_session_query = MagicMock()
        mock_session_filtered = MagicMock()
        mock_session_filtered.first.return_value = mock_exec_session
        mock_session_query.filter.return_value = mock_session_filtered

        mock_executor = MagicMock()
        mock_executor.id = "exec-1"
        mock_executor.hostname = "192.0.2.14"
        mock_executor.revoked_at = None  # updated: shared revocation state reads this (executor-revocation-by-identity)
        mock_executor.serial_number = None  # stands in for "no ExecutorCert row" under uniform query mocks

        mock_executor_query = MagicMock()
        mock_executor_filtered = MagicMock()
        mock_executor_filtered.first.return_value = mock_executor
        mock_executor_query.filter.return_value = mock_executor_filtered

        mock_secrets_query = MagicMock()
        mock_secrets_query.all.return_value = []

        def query_side_effect(model):
            if model.__name__ == "ExecutionSession":
                return mock_session_query
            elif model.__name__ == "Executor":
                return mock_executor_query
            elif model.__name__ == "SessionSecret":
                return mock_secrets_query
            elif model.__name__ in ("ExecutorCert", "ExecutorCertRevocation"):
                # updated: shared revocation state models "no cert/CRL rows"
                none_q = MagicMock()
                none_q.filter.return_value.first.return_value = None
                return none_q
            return mock_session_query

        mock_db.query.side_effect = query_side_effect
        backend.get_session.return_value = mock_db

        ssl_err = ssl.SSLError(1, "certificate verify failed")
        connect_err = httpx2.ConnectError("verify failed")
        connect_err.__cause__ = ssl_err

        mock_ssl_ctx = MagicMock()
        with patch("server.routes.executors.httpx2.AsyncClient") as mock_client_cls:
            mock_client_cls.side_effect = connect_err
            with patch("server.routes.executors.ssl.create_default_context", return_value=mock_ssl_ctx):
                client = TestClient(app, raise_server_exceptions=False)
                resp = client.post(
                    "/api/v1/executors/exec-1/execute",
                    json={"session_id": "sess-1", "command": ["echo", "hello"]},
                )

        assert resp.status_code == 503
        assert "mTLS verification failed" in resp.json()["detail"]

    def test_connect_error_without_ssl_cause_returns_unreachable(self):
        """ConnectError with no SSL cause → 503 'unreachable' (not mTLS message)."""

        app, backend = _create_test_app()
        mock_db = MagicMock()

        mock_exec_session = MagicMock()
        mock_exec_session.id = "sess-1"
        mock_exec_session.user_id = "test-user"
        mock_exec_session.expires_at = datetime.now(UTC) + timedelta(minutes=5)
        mock_exec_session.executor_id = "exec-1"

        mock_session_query = MagicMock()
        mock_session_filtered = MagicMock()
        mock_session_filtered.first.return_value = mock_exec_session
        mock_session_query.filter.return_value = mock_session_filtered

        mock_executor = MagicMock()
        mock_executor.id = "exec-1"
        mock_executor.hostname = "192.0.2.14"
        mock_executor.revoked_at = None  # updated: shared revocation state reads this (executor-revocation-by-identity)
        mock_executor.serial_number = None  # stands in for "no ExecutorCert row" under uniform query mocks

        mock_executor_query = MagicMock()
        mock_executor_filtered = MagicMock()
        mock_executor_filtered.first.return_value = mock_executor
        mock_executor_query.filter.return_value = mock_executor_filtered

        mock_secrets_query = MagicMock()
        mock_secrets_query.all.return_value = []

        def query_side_effect(model):
            if model.__name__ == "ExecutionSession":
                return mock_session_query
            elif model.__name__ == "Executor":
                return mock_executor_query
            elif model.__name__ == "SessionSecret":
                return mock_secrets_query
            elif model.__name__ in ("ExecutorCert", "ExecutorCertRevocation"):
                # updated: shared revocation state models "no cert/CRL rows"
                none_q = MagicMock()
                none_q.filter.return_value.first.return_value = None
                return none_q
            return mock_session_query

        mock_db.query.side_effect = query_side_effect
        backend.get_session.return_value = mock_db

        connect_err = httpx2.ConnectError("connection refused")

        mock_ssl_ctx = MagicMock()
        with patch("server.routes.executors.httpx2.AsyncClient") as mock_client_cls:
            mock_client_cls.side_effect = connect_err
            with patch("server.routes.executors.ssl.create_default_context", return_value=mock_ssl_ctx):
                client = TestClient(app, raise_server_exceptions=False)
                resp = client.post(
                    "/api/v1/executors/exec-1/execute",
                    json={"session_id": "sess-1", "command": ["echo", "hello"]},
                )

        assert resp.status_code == 503
        assert "mTLS" not in resp.json()["detail"]

    def test_remote_protocol_error_returns_503(self):
        """D1: executor dies mid-response (RemoteProtocolError) → 503, not 500.

        Same class as the ConnectError/TimeoutException guards (M1/M4 lineage):
        the caught set was incomplete, so a peer closing without a complete
        HTTP message escaped as an unhandled 500.
        """

        app, backend = _create_test_app()
        mock_db = MagicMock()

        mock_exec_session = MagicMock()
        mock_exec_session.id = "sess-1"
        mock_exec_session.user_id = "test-user"
        mock_exec_session.expires_at = datetime.now(UTC) + timedelta(minutes=5)
        mock_exec_session.executor_id = "exec-1"

        mock_session_query = MagicMock()
        mock_session_filtered = MagicMock()
        mock_session_filtered.first.return_value = mock_exec_session
        mock_session_query.filter.return_value = mock_session_filtered

        mock_executor = MagicMock()
        mock_executor.id = "exec-1"
        mock_executor.hostname = "192.0.2.14"
        mock_executor.revoked_at = None  # updated: shared revocation state reads this (executor-revocation-by-identity)
        mock_executor.serial_number = None  # stands in for "no ExecutorCert row" under uniform query mocks

        mock_executor_query = MagicMock()
        mock_executor_filtered = MagicMock()
        mock_executor_filtered.first.return_value = mock_executor
        mock_executor_query.filter.return_value = mock_executor_filtered

        mock_secrets_query = MagicMock()
        mock_secrets_query.all.return_value = []

        def query_side_effect(model):
            if model.__name__ == "ExecutionSession":
                return mock_session_query
            elif model.__name__ == "Executor":
                return mock_executor_query
            elif model.__name__ == "SessionSecret":
                return mock_secrets_query
            elif model.__name__ in ("ExecutorCert", "ExecutorCertRevocation"):
                # updated: shared revocation state models "no cert/CRL rows"
                none_q = MagicMock()
                none_q.filter.return_value.first.return_value = None
                return none_q
            return mock_session_query

        mock_db.query.side_effect = query_side_effect
        backend.get_session.return_value = mock_db

        protocol_err = httpx2.RemoteProtocolError(
            "peer closed connection without sending complete message body (incomplete chunked read)"
        )

        mock_ssl_ctx = MagicMock()
        with patch("server.routes.executors.httpx2.AsyncClient") as mock_client_cls:
            mock_client_cls.side_effect = protocol_err
            with patch("server.routes.executors.ssl.create_default_context", return_value=mock_ssl_ctx):
                client = TestClient(app, raise_server_exceptions=False)
                resp = client.post(
                    "/api/v1/executors/exec-1/execute",
                    json={"session_id": "sess-1", "command": ["echo", "hello"]},
                )

        assert resp.status_code == 503
        assert "connection lost" in resp.json()["detail"]

    def test_connect_error_dns_failure_returns_does_not_resolve(self):
        """ConnectError with gaierror cause → 503 'does not resolve' (not 'connection refused')."""

        app, backend = _create_test_app()
        mock_db = MagicMock()

        mock_exec_session = MagicMock()
        mock_exec_session.id = "sess-1"
        mock_exec_session.user_id = "test-user"
        mock_exec_session.expires_at = datetime.now(UTC) + timedelta(minutes=5)
        mock_exec_session.executor_id = "exec-1"

        mock_session_query = MagicMock()
        mock_session_filtered = MagicMock()
        mock_session_filtered.first.return_value = mock_exec_session
        mock_session_query.filter.return_value = mock_session_filtered

        mock_executor = MagicMock()
        mock_executor.id = "exec-1"
        mock_executor.hostname = "no-such-exec"
        mock_executor.revoked_at = None  # updated: shared revocation state reads this

        mock_executor_query = MagicMock()
        mock_executor_filtered = MagicMock()
        mock_executor_filtered.first.return_value = mock_executor
        mock_executor_query.filter.return_value = mock_executor_filtered

        mock_secrets_query = MagicMock()
        mock_secrets_query.all.return_value = []

        def query_side_effect(model):
            if model.__name__ == "ExecutionSession":
                return mock_session_query
            elif model.__name__ == "Executor":
                return mock_executor_query
            elif model.__name__ == "SessionSecret":
                return mock_secrets_query
            elif model.__name__ in ("ExecutorCert", "ExecutorCertRevocation"):
                # updated: shared revocation state models "no cert/CRL rows"
                none_q = MagicMock()
                none_q.filter.return_value.first.return_value = None
                return none_q
            return mock_session_query

        mock_db.query.side_effect = query_side_effect
        backend.get_session.return_value = mock_db

        connect_err = httpx2.ConnectError("name resolution failed")
        connect_err.__cause__ = socket.gaierror(-2, "Name or service not known")

        mock_ssl_ctx = MagicMock()
        with patch("server.routes.executors.httpx2.AsyncClient") as mock_client_cls:
            mock_client_cls.side_effect = connect_err
            with patch("server.routes.executors.ssl.create_default_context", return_value=mock_ssl_ctx):
                client = TestClient(app, raise_server_exceptions=False)
                resp = client.post(
                    "/api/v1/executors/exec-1/execute",
                    json={"session_id": "sess-1", "command": ["echo", "hello"]},
                )

        assert resp.status_code == 503
        assert "does not resolve" in resp.json()["detail"]


# --- Malformed executor response tests (M1) ---


class TestMalformedExecutorResponse:
    """Malformed executor responses (200 + bad body) must return 502, not 500."""

    def _setup_db(self, backend, response_body: dict):
        app, backend = _create_test_app()
        mock_db = MagicMock()

        mock_exec_session = MagicMock()
        mock_exec_session.id = "sess-1"
        mock_exec_session.user_id = "test-user"
        mock_exec_session.expires_at = datetime.now(UTC) + timedelta(minutes=5)
        mock_exec_session.executor_id = "exec-1"
        mock_exec_session.command = ""
        mock_exec_session.completed_at = None
        mock_exec_session.exit_code = None
        mock_exec_session.stdout = None
        mock_exec_session.stderr = None

        mock_session_query = MagicMock()
        mock_session_filtered = MagicMock()
        mock_session_filtered.first.return_value = mock_exec_session
        mock_session_query.filter.return_value = mock_session_filtered

        mock_executor = MagicMock()
        mock_executor.id = "exec-1"
        mock_executor.hostname = "192.0.2.14"
        mock_executor.revoked_at = None  # updated: shared revocation state reads this (executor-revocation-by-identity)
        mock_executor.serial_number = None  # stands in for "no ExecutorCert row" under uniform query mocks

        mock_executor_query = MagicMock()
        mock_executor_filtered = MagicMock()
        mock_executor_filtered.first.return_value = mock_executor
        mock_executor_query.filter.return_value = mock_executor_filtered

        mock_secrets_query = MagicMock()
        mock_secrets_query.all.return_value = []

        def query_side_effect(model):
            if model.__name__ == "ExecutionSession":
                return mock_session_query
            elif model.__name__ == "Executor":
                return mock_executor_query
            elif model.__name__ == "SessionSecret":
                return mock_secrets_query
            elif model.__name__ in ("ExecutorCert", "ExecutorCertRevocation"):
                # updated: shared revocation state models "no cert/CRL rows"
                none_q = MagicMock()
                none_q.filter.return_value.first.return_value = None
                return none_q
            return mock_session_query

        mock_db.query.side_effect = query_side_effect
        mock_db.add = MagicMock()
        mock_db.commit = MagicMock()
        backend.get_session.return_value = mock_db

        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = response_body
        mock_response.raise_for_status = MagicMock()

        mock_client = MagicMock()
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)
        mock_client.post = AsyncMock(return_value=mock_response)

        mock_ssl_ctx = MagicMock()

        return app, backend, mock_client, mock_ssl_ctx

    def test_missing_stderr_returns_502(self):
        """200 response missing 'stderr' key → 502."""
        app, _backend, mock_client, mock_ssl_ctx = self._setup_db(
            MagicMock(),
            {"exit_code": 0, "stdout": "ok\n"},  # missing stderr
        )
        with patch("server.routes.executors.httpx2.AsyncClient", return_value=mock_client):
            with patch("server.routes.executors.ssl.create_default_context", return_value=mock_ssl_ctx):
                client = TestClient(app, raise_server_exceptions=False)
                resp = client.post(
                    "/api/v1/executors/exec-1/execute",
                    json={"session_id": "sess-1", "command": ["echo", "hello"]},
                )
        assert resp.status_code == 502

    def test_wrong_type_exit_code_returns_502(self):
        """200 response with non-integer exit_code → 502."""
        app, _backend, mock_client, mock_ssl_ctx = self._setup_db(
            MagicMock(),
            {"exit_code": "zero", "stdout": "ok\n", "stderr": ""},
        )
        with patch("server.routes.executors.httpx2.AsyncClient", return_value=mock_client):
            with patch("server.routes.executors.ssl.create_default_context", return_value=mock_ssl_ctx):
                client = TestClient(app, raise_server_exceptions=False)
                resp = client.post(
                    "/api/v1/executors/exec-1/execute",
                    json={"session_id": "sess-1", "command": ["echo", "hello"]},
                )
        assert resp.status_code == 502

    def test_extra_key_returns_502(self):
        """200 response with an extra/unknown key → 502 (extra=forbid).

        refactor-2 negative half: pre-contract, pydantic's default silently DROPPED
        unknown keys and returned 200, so a one-sided field rename of a defaulted
        field (e.g. masked_count -> redacted_count on the server only) lost data with
        no error. The frozen relay contract (venya_contract, extra="forbid") rejects
        unknown fields, making a one-sided addition/rename a loud 502 at the boundary.
        This aligns with the class contract (malformed -> 502) and its two siblings
        (missing field, wrong type); the old "extra keys dropped -> 200" behavior was
        the inconsistent one and is deliberately reversed by the extra=forbid ruling.
        """
        app, _backend, mock_client, mock_ssl_ctx = self._setup_db(
            MagicMock(),
            {
                "exit_code": 0,
                "stdout": "hello\n",
                "stderr": "",
                "masked_count": 1,
                "rogue_field": "should not appear",
            },
        )
        with patch("server.routes.executors.httpx2.AsyncClient", return_value=mock_client):
            with patch("server.routes.executors.ssl.create_default_context", return_value=mock_ssl_ctx):
                client = TestClient(app, raise_server_exceptions=False)
                resp = client.post(
                    "/api/v1/executors/exec-1/execute",
                    json={"session_id": "sess-1", "command": ["echo", "hello"]},
                )
        assert resp.status_code == 502

    def test_malformed_response_log_carries_no_body_fragments(self, caplog):
        """#11 regression (sec-secret-redaction-log-leaks): the relay-response
        hop must NEVER put body content in the journal. Pre-fix, logging the
        ValidationError embedded input_value= fragments of the response body
        (prefixless — RedactingFormatter layer-2 cannot catch them), violating
        the Stage-2 sign-off invariant. Post-fix only field names + error
        types are logged."""
        import logging

        body_marker = "RELAY-BODY-MARKER-DO-NOT-LOG"
        app, _backend, mock_client, mock_ssl_ctx = self._setup_db(
            MagicMock(),
            {
                "exit_code": 0,
                "stdout": body_marker,
                "stderr": "",
                "masked_count": 0,
                "rogue_field": body_marker,
            },
        )
        with patch("server.routes.executors.httpx2.AsyncClient", return_value=mock_client):
            with patch("server.routes.executors.ssl.create_default_context", return_value=mock_ssl_ctx):
                client = TestClient(app, raise_server_exceptions=False)
                with caplog.at_level(logging.WARNING):
                    resp = client.post(
                        "/api/v1/executors/exec-1/execute",
                        json={"session_id": "sess-1", "command": ["echo", "hello"]},
                    )
        assert resp.status_code == 502
        # paired truth table: body content absent, scrubbed field summary present
        assert body_marker not in caplog.text
        assert "input_value" not in caplog.text
        assert "rogue_field" in caplog.text  # offending field IS named (diagnosability kept)


# --- TLS misconfiguration tests (M2) ---


class TestTlsMisconfiguration:
    """TLS setup failures (missing/corrupt certs) must return 503, not 500."""

    def _setup(self, backend=None):
        app, backend = _create_test_app(backend)
        mock_db = MagicMock()

        mock_exec_session = MagicMock()
        mock_exec_session.id = "sess-1"
        mock_exec_session.user_id = "test-user"
        mock_exec_session.expires_at = datetime.now(UTC) + timedelta(minutes=5)
        mock_exec_session.executor_id = "exec-1"

        mock_session_query = MagicMock()
        mock_session_filtered = MagicMock()
        mock_session_filtered.first.return_value = mock_exec_session
        mock_session_query.filter.return_value = mock_session_filtered

        mock_executor = MagicMock()
        mock_executor.id = "exec-1"
        mock_executor.hostname = "192.0.2.14"
        mock_executor.revoked_at = None  # updated: shared revocation state reads this (executor-revocation-by-identity)
        mock_executor.serial_number = None  # stands in for "no ExecutorCert row" under uniform query mocks

        mock_executor_query = MagicMock()
        mock_executor_filtered = MagicMock()
        mock_executor_filtered.first.return_value = mock_executor
        mock_executor_query.filter.return_value = mock_executor_filtered

        mock_secrets_query = MagicMock()
        mock_secrets_query.all.return_value = []

        def query_side_effect(model):
            if model.__name__ == "ExecutionSession":
                return mock_session_query
            elif model.__name__ == "Executor":
                return mock_executor_query
            elif model.__name__ == "SessionSecret":
                return mock_secrets_query
            elif model.__name__ in ("ExecutorCert", "ExecutorCertRevocation"):
                # updated: shared revocation state models "no cert/CRL rows"
                none_q = MagicMock()
                none_q.filter.return_value.first.return_value = None
                return none_q
            return mock_session_query

        mock_db.query.side_effect = query_side_effect
        mock_db.add = MagicMock()
        mock_db.commit = MagicMock()
        backend.get_session.return_value = mock_db

        return app, backend

    def test_ca_cert_missing_returns_503(self):
        """load_verify_locations raises FileNotFoundError → 503."""
        app, _backend = self._setup()
        mock_ssl_ctx = MagicMock()
        mock_ssl_ctx.load_verify_locations.side_effect = FileNotFoundError("ca.crt not found")

        with patch("server.routes.executors.ssl.create_default_context", return_value=mock_ssl_ctx):
            client = TestClient(app, raise_server_exceptions=False)
            resp = client.post(
                "/api/v1/executors/exec-1/execute",
                json={"session_id": "sess-1", "command": ["echo", "hello"]},
            )
        assert resp.status_code == 503

    def test_none_ca_path_returns_503(self):
        """load_verify_locations(None) raises TypeError → 503 (config missing)."""
        app, _backend = self._setup()
        mock_ssl_ctx = MagicMock()
        mock_ssl_ctx.load_verify_locations.side_effect = TypeError("load_verify_locations expects a path, not None")

        with patch("server.routes.executors.ssl.create_default_context", return_value=mock_ssl_ctx):
            client = TestClient(app, raise_server_exceptions=False)
            resp = client.post(
                "/api/v1/executors/exec-1/execute",
                json={"session_id": "sess-1", "command": ["echo", "hello"]},
            )
        assert resp.status_code == 503

    def test_mtls_cert_missing_returns_503(self):
        """load_cert_chain raises FileNotFoundError → 503 (mtls cert/key missing)."""
        app, _backend = self._setup()
        # Override config to have mtls cert/key set (so the branch is taken)
        app.state.config.mtls_cert = "/etc/venya/relay/relay-client.crt"
        app.state.config.mtls_key = "/etc/venya/relay/relay-client.key"

        mock_ssl_ctx = MagicMock()
        mock_ssl_ctx.load_cert_chain.side_effect = FileNotFoundError("relay-client.crt not found")

        with patch("server.routes.executors.ssl.create_default_context", return_value=mock_ssl_ctx):
            client = TestClient(app, raise_server_exceptions=False)
            resp = client.post(
                "/api/v1/executors/exec-1/execute",
                json={"session_id": "sess-1", "command": ["echo", "hello"]},
            )
        assert resp.status_code == 503


# --- Env-shape derivation + version gate (ticket secret-shape-env-injection) --


def _execute_env_harness(meta: dict, version: str | None, plaintext: str = "s3cret-value"):
    """App + mocks for one execute call over a session with ONE secret
    (id 1, key k1) carrying `meta`; executor reports `version`."""
    app, backend = _create_test_app()
    mock_db = MagicMock()

    mock_exec_session = MagicMock()
    mock_exec_session.id = "sess-env"
    mock_exec_session.user_id = "test-user"
    mock_exec_session.expires_at = datetime.now(UTC) + timedelta(minutes=5)
    mock_exec_session.executor_id = "exec-1"
    mock_session_query = MagicMock()
    mock_session_query.filter.return_value.first.return_value = mock_exec_session

    mock_executor = MagicMock()
    mock_executor.id = "exec-1"
    mock_executor.hostname = "192.0.2.14"
    mock_executor.revoked_at = None
    mock_executor.serial_number = None
    mock_executor.version = version
    mock_executor_query = MagicMock()
    mock_executor_query.filter.return_value.first.return_value = mock_executor

    ss = MagicMock()
    ss.secret_id = 1
    ss.wrapped_value = wrap_with_sentinel("k1", plaintext.encode())
    mock_secrets_query = MagicMock()
    mock_secrets_query.filter.return_value.all.return_value = [ss]

    sec_row = MagicMock()
    sec_row.id = 1
    sec_row.meta = meta
    mock_meta_query = MagicMock()
    mock_meta_query.filter.return_value.all.return_value = [sec_row]

    def query_side_effect(*models):
        name = models[0].__name__
        if name == "ExecutionSession":
            return mock_session_query
        if name == "Executor":
            return mock_executor_query
        if name == "SessionSecret":
            return mock_secrets_query
        if name == "Secret":
            return mock_meta_query
        none_q = MagicMock()
        none_q.filter.return_value.first.return_value = None
        return none_q

    mock_db.query.side_effect = query_side_effect
    backend.get_session.return_value = mock_db

    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.json.return_value = {"exit_code": 0, "stdout": "ok\n", "stderr": "", "masked_count": 0}
    mock_response.raise_for_status = MagicMock()
    mock_client = MagicMock()
    mock_client.__aenter__ = AsyncMock(return_value=mock_client)
    mock_client.__aexit__ = AsyncMock(return_value=False)
    mock_client.post = AsyncMock(return_value=mock_response)
    return app, mock_client


def _run_execute(app, mock_client):
    with patch("server.routes.executors.httpx2.AsyncClient", return_value=mock_client):
        with patch("server.routes.executors.ssl.create_default_context", return_value=MagicMock()):
            client = TestClient(app, raise_server_exceptions=False)
            return client.post(
                "/api/v1/executors/exec-1/execute",
                json={"session_id": "sess-env", "command": ["printenv", "MY_TOKEN"]},
            )


def _sent_payload(mock_client):
    return mock_client.post.call_args.kwargs["json"]


class TestEnvShapeDerivation:
    def test_env_shape_derives_relay_entry(self):
        app, mc = _execute_env_harness({"shape": "env:MY_TOKEN"}, "0.1.0a13")
        resp = _run_execute(app, mc)
        assert resp.status_code == 200
        payload = _sent_payload(mc)
        assert payload["env"] == [{"var_name": "MY_TOKEN", "secret_id": 1, "literal_value": None}]
        assert payload["askpass_helper"] is False
        assert payload["secrets"][0]["secret_id"] == 1  # file injection ALWAYS rides along

    def test_askpass_shape_derives_helper_wiring(self):
        app, mc = _execute_env_harness({"shape": "askpass", "username": "gituser"}, "0.1.0a13")
        resp = _run_execute(app, mc)
        assert resp.status_code == 200
        payload = _sent_payload(mc)
        assert payload["askpass_helper"] is True
        env = {e["var_name"]: e for e in payload["env"]}
        assert env["GIT_ASKPASS"]["literal_value"] == "/run/secrets/venya/.venya-askpass"
        assert env["SSH_ASKPASS"]["literal_value"] == "/run/secrets/venya/.venya-askpass"
        assert env["VENYA_ASKPASS_SECRET"]["literal_value"] == "/run/secrets/venya/1"
        assert env["VENYA_ASKPASS_USER"]["literal_value"] == "gituser"

    def test_no_shape_payload_is_wire_identical_to_old(self):
        """No env shape in play -> the payload carries EXACTLY the three
        pre-env keys (no env/askpass additions ride the wire; the command
        VALUE is the #322 argv list on both ends of the coordinated change)."""
        app, mc = _execute_env_harness({"executor": "exec-1"}, "0.1.0a12")  # old version OK here
        resp = _run_execute(app, mc)
        assert resp.status_code == 200
        assert set(_sent_payload(mc).keys()) == {"session_id", "command", "secrets"}

    def test_old_executor_version_gated_422(self):
        app, mc = _execute_env_harness({"shape": "env:MY_TOKEN"}, "0.1.0a12")
        resp = _run_execute(app, mc)
        assert resp.status_code == 422
        assert "env-shape support" in resp.json()["detail"]
        assert "0.1.0a13" in resp.json()["detail"]
        assert mc.post.await_count == 0  # never dialed

    def test_null_version_gated_422(self):
        app, mc = _execute_env_harness({"shape": "env:MY_TOKEN"}, None)
        resp = _run_execute(app, mc)
        assert resp.status_code == 422
        assert "pre-version-reporting" in resp.json()["detail"]
        assert mc.post.await_count == 0

    def test_newline_env_value_rejected_422(self):
        app, mc = _execute_env_harness({"shape": "env:MY_TOKEN"}, "0.1.0a13", plaintext="line1\nline2")
        resp = _run_execute(app, mc)
        assert resp.status_code == 422
        assert "single-line" in resp.json()["detail"]
        assert mc.post.await_count == 0

    def test_newer_versions_pass_gate(self):
        for version in ("0.1.0a14", "0.1.0b1", "0.1.0", "0.2.0", "1.0.0"):
            app, mc = _execute_env_harness({"shape": "env:MY_TOKEN"}, version)
            resp = _run_execute(app, mc)
            assert resp.status_code == 200, version


class TestVersionTuple:
    def test_ordering(self):
        assert _version_tuple("0.1.0a12") < _ENV_SHAPE_MIN_VERSION
        assert _version_tuple("0.1.0a13") == _ENV_SHAPE_MIN_VERSION
        assert _version_tuple("0.1.0a9") < _ENV_SHAPE_MIN_VERSION  # numeric, not lexicographic
        assert _version_tuple("0.1.0b1") > _ENV_SHAPE_MIN_VERSION
        assert _version_tuple("0.1.0") > _ENV_SHAPE_MIN_VERSION  # final beats prerelease
        assert _version_tuple("0.1.1") > _ENV_SHAPE_MIN_VERSION

    def test_unparseable_fails_closed(self):
        for bad in (None, "", "garbage", "0.1", "v0.1.0a13", "0.1.0a13+local"):
            assert _version_tuple(bad) is None, bad

    def test_spelled_out_prerelease_canonicalized(self):
        """#324 latent sort bug, pinned fixed: pyproject ships ``0.1.0alphaNN``.

        A raw ``alpha`` pre_kind sorted lexicographically ABOVE every
        single-letter tag (``"alpha" > "a"``), so ``alpha2`` wrongly passed the
        ``a13`` env-shape gate. Canonicalization must land alpha/beta on the
        PEP 440 short forms.
        """
        assert _version_tuple("0.1.0alpha2") < _ENV_SHAPE_MIN_VERSION  # THE bug cell
        assert _version_tuple("0.1.0alpha13") == _ENV_SHAPE_MIN_VERSION
        assert _version_tuple("0.1.0alpha16") > _ENV_SHAPE_MIN_VERSION
        assert _version_tuple("0.1.0beta1") == _version_tuple("0.1.0b1")

    def test_final_sorts_above_every_spelling(self):
        assert _version_tuple("0.1.0") > _version_tuple("0.1.0alpha99")
        assert _version_tuple("0.1.0") > _version_tuple("0.1.0rc2")


class TestExecuteRequestStrictUtf8:
    r"""#334 layer 2 (posture B): argv elements must be strict-UTF-8 encodable
    at REQUEST VALIDATION — a lone surrogate that reached the relay would
    execute and then kill the completion audit write (side effects kept,
    record lost). FastAPI's body-validation 422 fires before the handler
    resolves, so session state never moves. Tripwire below proves the
    ordering: the completion-audit write cannot receive such a payload.
    No runtime sanitizer — deny on ambiguity, per the fail-closed mandate;
    the byte-faithful relaxation is ticketed (#335).

    NOTE on delivery: the surrogate is sent as RAW escaped JSON bytes
    (``content=``), exactly how the MCP/LLM seam (ticket #324) carries
    ``\udXXX`` — TestClient's own json serializer would refuse to build
    such a request, which is not the server's concern."""

    @staticmethod
    def _surrogate_body(**overrides):
        import json as _json

        body = {"session_id": "sess-1", "command": ["touch", "bad\ud800name"]}
        body.update(overrides)
        return _json.dumps(body).encode("ascii")

    def _client_missing_session(self):
        app, backend = _create_test_app()
        mock_session = MagicMock()
        mock_q = MagicMock()
        mock_q.filter.return_value.first.return_value = None
        mock_session.query.return_value = mock_q
        backend.get_session.return_value = mock_session
        return TestClient(app, raise_server_exceptions=False), mock_session

    def test_surrogate_element_422s_before_session(self):
        client, db = self._client_missing_session()
        resp = client.post(
            "/api/v1/executors/exec-1/execute",
            content=self._surrogate_body(),
            headers={"Content-Type": "application/json"},
        )
        assert resp.status_code == 422
        msg = str(resp.json()["detail"])
        # names the offending index; the value is NEVER echoed
        assert "argv element 1" in msg
        assert "\ud800" not in resp.text  # neither raw nor escaped echo
        # zero session state: the handler never ran — not even the lookup
        db.query.assert_not_called()
        db.commit.assert_not_called()

    def test_tripwire_completion_audit_write_unreachable(self):
        """Ordering proof: the 422 short-circuits the handler, so the
        completion-audit writer (_mark_execution_session_completed, the very
        call that died on PG encoding in #334's trace) is never reached."""
        client, _db = self._client_missing_session()
        with patch.object(executors_routes, "_mark_execution_session_completed") as audit_write:
            resp = client.post(
                "/api/v1/executors/exec-1/execute",
                content=self._surrogate_body(command=["echo", "\udfff"]),
                headers={"Content-Type": "application/json"},
            )
        assert resp.status_code == 422
        audit_write.assert_not_called()

    def test_normal_unicode_passes_validation(self):
        """Paired positive: astral-plane text (emoji/CJK/accents) validates
        cleanly and the request reaches the handler (404 = unknown session in
        this mock, proving the validator did NOT reject it)."""
        client, _db = self._client_missing_session()
        resp = client.post(
            "/api/v1/executors/exec-1/execute",
            json={"session_id": "sess-1", "command": ["echo", "h\u00e9llo \U0001f510\U0001f680 \u65e5\u672c"]},
        )
        assert resp.status_code == 404

    def test_plain_argv_proceeds_to_session_lookup(self):
        """Discipline check: the gate is scoped to the argv list only — a
        plain valid request flows into the handler's session lookup."""
        client, _db = self._client_missing_session()
        resp = client.post(
            "/api/v1/executors/exec-1/execute",
            json={"session_id": "sess-1", "command": ["ls"]},
        )
        assert resp.status_code == 404


class TestRelayTimeoutAudit407:
    """#407 fail-honest audit: a relay-timeout raise writes ONE command_executed row
    (outcome "relay_timeout", NULL exit_code) BEFORE the 503 — today the raise precedes
    the success-path audit write and the get_db rollback erases the run's record entirely.
    Truth table: timeout->row exists with honest tag (positive); non-timeout 503 writes
    no row (paired negative); audit failure never masks the 503 (best-effort half);
    success path unchanged, no duplicate tagged row (paired negative)."""

    @staticmethod
    def _relay_harness(commit_side_effect=None):
        """Dial-stage harness: valid session/executor, empty secrets, and the request
        session AND the best-effort audit session are the SAME mock_db (mirrors
        backend.get_session.return_value in _create_test_app)."""
        app, backend = _create_test_app()
        mock_db = MagicMock()
        if commit_side_effect is not None:
            mock_db.commit.side_effect = commit_side_effect

        mock_exec_session = MagicMock()
        mock_exec_session.id = "sess-1"
        mock_exec_session.user_id = "test-user"
        mock_exec_session.expires_at = datetime.now(UTC) + timedelta(minutes=5)
        mock_exec_session.executor_id = "exec-1"

        mock_session_query = MagicMock()
        mock_session_filtered = MagicMock()
        mock_session_filtered.first.return_value = mock_exec_session
        mock_session_query.filter.return_value = mock_session_filtered

        mock_executor = MagicMock()
        mock_executor.id = "exec-1"
        mock_executor.hostname = "192.0.2.14"
        mock_executor.revoked_at = None
        mock_executor.serial_number = None

        mock_executor_query = MagicMock()
        mock_executor_filtered = MagicMock()
        mock_executor_filtered.first.return_value = mock_executor
        mock_executor_query.filter.return_value = mock_executor_filtered

        mock_secrets_query = MagicMock()
        mock_secrets_query.all.return_value = []

        def query_side_effect(model):
            if model.__name__ == "ExecutionSession":
                return mock_session_query
            elif model.__name__ == "Executor":
                return mock_executor_query
            elif model.__name__ == "SessionSecret":
                return mock_secrets_query
            elif model.__name__ in ("ExecutorCert", "ExecutorCertRevocation"):
                none_q = MagicMock()
                none_q.filter.return_value.first.return_value = None
                return none_q
            return mock_session_query

        mock_db.query.side_effect = query_side_effect
        backend.get_session.return_value = mock_db
        return app, mock_db

    @staticmethod
    def _command_executed_rows(mock_db):
        rows = []
        for call in mock_db.add.call_args_list:
            event = call[0][0] if call[0] else None
            if event is not None and getattr(event, "event_type", None) == "command_executed":
                rows.append(event)
        return rows

    def _post_execute(self, app, side_effect):
        mock_ssl_ctx = MagicMock()
        with patch("server.routes.executors.httpx2.AsyncClient", side_effect=side_effect):
            with patch("server.routes.executors.ssl.create_default_context", return_value=mock_ssl_ctx):
                client = TestClient(app, raise_server_exceptions=False)
                return client.post(
                    "/api/v1/executors/exec-1/execute",
                    json={"session_id": "sess-1", "command": ["sleep", "9999"]},
                )

    def test_relay_timeout_writes_honest_command_executed_row(self):
        """Positive half: ReadTimeout (the real scalar-timeout class, a TimeoutException
        subclass) -> 503 AND one command_executed row tagged outcome="relay_timeout"
        with NULL exit_code/masked_count (response-body-only values do not exist here)."""
        app, mock_db = self._relay_harness()
        resp = self._post_execute(app, httpx2.ReadTimeout("read timed out"))

        assert resp.status_code == 503
        assert resp.json()["detail"] == "Executor timed out"

        rows = self._command_executed_rows(mock_db)
        assert len(rows) == 1
        row = rows[0]
        assert row.user_id == "test-user"
        fields = json.loads(row.fields) if isinstance(row.fields, str) else row.fields
        assert fields["session_id"] == "sess-1"
        assert fields["executor_id"] == "exec-1"
        assert fields["command"] == "sleep 9999"
        assert fields["outcome"] == "relay_timeout"
        assert fields["exit_code"] is None
        assert fields["masked_count"] is None
        # best-effort half of the shape: the row rides its OWN standalone commit
        mock_db.commit.assert_called()

    def test_relay_timeout_commit_failure_still_returns_503(self, caplog):
        """Best-effort half: the audit commit raising must not mask the 503 — the
        exception is rolled back, logged, and swallowed (record_login_failure posture)."""
        app, mock_db = self._relay_harness(commit_side_effect=RuntimeError("db down"))
        with caplog.at_level(logging.ERROR, logger="server.routes.executors"):
            resp = self._post_execute(app, httpx2.ReadTimeout("read timed out"))

        assert resp.status_code == 503
        assert resp.json()["detail"] == "Executor timed out"
        mock_db.rollback.assert_called()
        assert any("Relay-timeout audit write failed" in r.getMessage() for r in caplog.records)

    def test_non_timeout_transport_error_writes_no_row(self):
        """Paired negative: the OTHER 503 transports (RemoteProtocolError here,
        sibling of the timeout guard) stay byte-unchanged — no audit row is written."""
        app, mock_db = self._relay_harness()
        err = httpx2.RemoteProtocolError("peer closed without complete message")
        resp = self._post_execute(app, err)

        assert resp.status_code == 503
        assert "connection lost" in resp.json()["detail"]
        assert self._command_executed_rows(mock_db) == []

    def test_success_path_writes_one_untagged_row(self):
        """Paired negative: success keeps the EXISTING row shape — exactly one
        command_executed, real exit_code/masked_count, NO outcome tag key (no
        duplicate fail-honest row on the happy path)."""
        app, mock_db = self._relay_harness()

        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {"exit_code": 0, "stdout": "ok\n", "stderr": "", "masked_count": 0}
        mock_response.raise_for_status = MagicMock()
        mock_client = MagicMock()
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)
        mock_client.post = AsyncMock(return_value=mock_response)

        mock_ssl_ctx = MagicMock()
        with patch("server.routes.executors.httpx2.AsyncClient", return_value=mock_client):
            with patch("server.routes.executors.ssl.create_default_context", return_value=mock_ssl_ctx):
                client = TestClient(app, raise_server_exceptions=False)
                resp = client.post(
                    "/api/v1/executors/exec-1/execute",
                    json={"session_id": "sess-1", "command": ["sleep", "9999"]},
                )

        assert resp.status_code == 200
        rows = self._command_executed_rows(mock_db)
        assert len(rows) == 1
        fields = json.loads(rows[0].fields) if isinstance(rows[0].fields, str) else rows[0].fields
        assert "outcome" not in fields
        assert fields["exit_code"] == 0
        assert fields["masked_count"] == 0


class TestPolicyRejectionRelay410:
    """#410 server half: the executor's CommandRejected 422 lane must carry
    its reason through the relay->server hop to the client; every other
    relay error status keeps the generic detail (the listener's 400 lane
    echoes request fragments and must not be relayed onward verbatim)."""

    def _harness_with_response(self, response: httpx2.Response):
        """App + mocks identical to TestMalformedExecutorResponse._setup_db,
        but the relay call yields `response` (a real httpx2 Response, so
        raise_for_status/json behave exactly like production)."""
        app, backend = _create_test_app()
        mock_db = MagicMock()

        mock_exec_session = MagicMock()
        mock_exec_session.id = "sess-1"
        mock_exec_session.user_id = "test-user"
        mock_exec_session.expires_at = datetime.now(UTC) + timedelta(minutes=5)
        mock_exec_session.executor_id = "exec-1"

        mock_session_query = MagicMock()
        mock_session_query.filter.return_value.first.return_value = mock_exec_session

        mock_executor = MagicMock()
        mock_executor.id = "exec-1"
        mock_executor.hostname = "192.0.2.14"
        mock_executor.revoked_at = None
        mock_executor.serial_number = None
        mock_executor.version = "0.1.0a14"

        mock_executor_query = MagicMock()
        mock_executor_query.filter.return_value.first.return_value = mock_executor

        mock_secrets_query = MagicMock()
        mock_secrets_query.all.return_value = []

        def query_side_effect(model):
            if model.__name__ == "ExecutionSession":
                return mock_session_query
            elif model.__name__ == "Executor":
                return mock_executor_query
            elif model.__name__ == "SessionSecret":
                return mock_secrets_query
            none_q = MagicMock()
            none_q.filter.return_value.first.return_value = None
            return none_q

        mock_db.query.side_effect = query_side_effect
        backend.get_session.return_value = mock_db

        mock_client = MagicMock()
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)
        mock_client.post = AsyncMock(return_value=response)

        with patch("server.routes.executors.httpx2.AsyncClient", return_value=mock_client):
            with patch("server.routes.executors.ssl.create_default_context", return_value=MagicMock()):
                tc = TestClient(app, raise_server_exceptions=False)
                resp = tc.post(
                    "/api/v1/executors/exec-1/execute",
                    json={"session_id": "sess-1", "command": ["sudo", "rm", "-rf", "/"]},
                )
        return resp

    @staticmethod
    def _relay(status: int, body: dict) -> httpx2.Response:
        request = httpx2.Request("POST", "https://192.0.2.14:8443/execute")
        return httpx2.Response(status, json=body, request=request)

    def test_rejection_reason_survives_the_hop(self):
        """Positive: relay 422 CommandRejected detail reaches the client."""
        reason = "Command rejected: Dangerous pattern matched: rm -rf"
        resp = self._harness_with_response(self._relay(422, {"detail": reason}))
        assert resp.status_code == 422
        assert resp.json()["detail"] == reason

    def test_relay_503_detail_stays_generic(self):
        """Paired negative (truth table): transport 503 keeps status but the
        generic detail — no relay body is echoed on this lane."""
        resp = self._harness_with_response(self._relay(503, {"detail": "execution failed"}))
        assert resp.status_code == 503
        assert resp.json()["detail"] == "Executor returned an error"

    def test_non_rejection_422_detail_stays_generic(self):
        """Paired negative (allow-list discipline): a 422 whose detail does
        not carry the CommandRejected prefix is NOT forwarded — the prefix
        is the contract, not the status alone."""
        resp = self._harness_with_response(
            self._relay(422, {"detail": "malformed request: WrappedSecret(wrapped_value='...')"})
        )
        assert resp.status_code == 422
        assert resp.json()["detail"] == "Executor returned an error"

    def test_422_non_json_body_stays_generic(self):
        """Paired negative (robustness): non-JSON relay body on the 422 lane
        degrades to the generic detail, never a 500."""
        request = httpx2.Request("POST", "https://192.0.2.14:8443/execute")
        resp = self._harness_with_response(httpx2.Response(422, text="gate blew up", request=request))
        assert resp.status_code == 422
        assert resp.json()["detail"] == "Executor returned an error"
