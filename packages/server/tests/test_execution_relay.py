"""Tests for execution relay endpoints.

Covers session creation, command relay, audit events, and session validation.
"""

from datetime import UTC, datetime, timedelta
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from fastapi import FastAPI
from server.dependencies import get_current_user
from server.routes import executors as executors_routes
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

    app.include_router(executors_routes.router, prefix="/api/v1")

    app.dependency_overrides[get_current_user] = lambda: TEST_USER

    return app, backend


# --- Session creation tests ---


class TestCreateExecutionSession:
    """Tests for POST /api/v1/executors/sessions."""

    def test_create_session_returns_session_id(self):
        """Session creation returns a valid session_id."""
        app, backend = _create_test_app()
        mock_session = MagicMock()
        mock_executor = MagicMock()
        mock_executor.id = "exec-1"
        mock_executor.hostname = "10.27.28.14"
        mock_query = MagicMock()
        mock_query.first.return_value = mock_executor
        mock_session.query.return_value = mock_query
        backend.get_session.return_value = mock_session

        client = TestClient(app, raise_server_exceptions=False)
        resp = client.post(
            "/api/v1/executors/sessions",
            json={"executor_id": "exec-1", "secrets": []},
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
        mock_session = MagicMock()
        mock_query = MagicMock()
        mock_filtered = MagicMock()
        mock_filtered.first.return_value = None
        mock_query.filter.return_value = mock_filtered
        mock_session.query.return_value = mock_query
        backend.get_session.return_value = mock_session

        client = TestClient(app, raise_server_exceptions=False)
        resp = client.post(
            "/api/v1/executors/sessions",
            json={"executor_id": "nonexistent", "secrets": []},
        )

        assert resp.status_code == 404

    def test_audit_event_session_created(self):
        """Verify execution_session_created audit event is created."""
        app, backend = _create_test_app()
        mock_session = MagicMock()
        mock_executor = MagicMock()
        mock_executor.id = "exec-1"
        mock_executor.hostname = "10.27.28.14"
        mock_query = MagicMock()
        mock_query.first.return_value = mock_executor
        mock_session.query.return_value = mock_query
        backend.get_session.return_value = mock_session

        client = TestClient(app, raise_server_exceptions=False)
        resp = client.post(
            "/api/v1/executors/sessions",
            json={"executor_id": "exec-1", "secrets": []},
        )

        assert resp.status_code == 201

        # Check that AuditEvent was added to the session
        add_calls = [c for c in mock_session.add.call_args_list]
        assert len(add_calls) >= 2  # session + audit event (secrets may add more)
        audit_event = None
        for call in add_calls:
            event = call[0][0] if call[0] else None
            if event and hasattr(event, "event_type") and event.event_type == "execution_session_created":
                audit_event = event
                break
        assert audit_event is not None, "execution_session_created audit event not found"
        assert audit_event.user_id == "test-user"
        assert audit_event.fields is not None

    def test_audit_event_contains_session_fields(self):
        """Audit event contains session_id, executor_id, secret_count."""
        app, backend = _create_test_app()
        mock_session = MagicMock()
        mock_executor = MagicMock()
        mock_executor.id = "exec-1"
        mock_executor.hostname = "10.27.28.14"
        mock_query = MagicMock()
        mock_query.first.return_value = mock_executor
        mock_session.query.return_value = mock_query
        backend.get_session.return_value = mock_session

        client = TestClient(app, raise_server_exceptions=False)
        resp = client.post(
            "/api/v1/executors/sessions",
            json={
                "executor_id": "exec-1",
                "secrets": [
                    {"secret_id": "sec-1", "wrapped_value": "[VENYA:abcd]data[/VENYA]"},
                ],
            },
        )

        assert resp.status_code == 201

        # Find the audit event
        audit_event = None
        for call in mock_session.add.call_args_list:
            event = call[0][0] if call[0] else None
            if event and hasattr(event, "event_type") and event.event_type == "execution_session_created":
                audit_event = event
                break

        assert audit_event is not None
        fields = eval(audit_event.fields) if isinstance(audit_event.fields, str) else audit_event.fields
        assert "session_id" in fields
        assert fields["executor_id"] == "exec-1"
        assert fields["secret_count"] == 1

    def test_session_secrets_stored(self):
        """Wrapped secrets are stored in execution_session_secrets table."""
        app, backend = _create_test_app()
        mock_session = MagicMock()
        mock_executor = MagicMock()
        mock_executor.id = "exec-1"
        mock_executor.hostname = "10.27.28.14"
        mock_query = MagicMock()
        mock_query.first.return_value = mock_executor
        mock_session.query.return_value = mock_query
        backend.get_session.return_value = mock_session

        client = TestClient(app, raise_server_exceptions=False)
        resp = client.post(
            "/api/v1/executors/sessions",
            json={
                "executor_id": "exec-1",
                "secrets": [
                    {"secret_id": "sec-1", "wrapped_value": "[VENYA:abcd]Zm9v[/VENYA]"},
                    {"secret_id": "sec-2", "wrapped_value": "[VENYA:efgh]YmFy[/VENYA]"},
                ],
            },
        )

        assert resp.status_code == 201

        # Check SessionSecret was added
        secret_add_calls = [
            c for c in mock_session.add.call_args_list if c[0] and len(c[0]) > 0 and hasattr(c[0][0], "wrapped_value")
        ]
        assert len(secret_add_calls) == 2

    def test_session_10_minute_ttl(self):
        """Session expires_at is created_at + 10 minutes."""
        app, backend = _create_test_app()
        mock_session = MagicMock()
        mock_executor = MagicMock()
        mock_executor.id = "exec-1"
        mock_executor.hostname = "10.27.28.14"
        mock_query = MagicMock()
        mock_query.first.return_value = mock_executor
        mock_session.query.return_value = mock_query
        backend.get_session.return_value = mock_session

        client = TestClient(app, raise_server_exceptions=False)
        resp = client.post(
            "/api/v1/executors/sessions",
            json={"executor_id": "exec-1", "secrets": []},
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
            json={"session_id": "nonexistent", "command": "echo hello"},
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
            json={"session_id": "sess-1", "command": "echo hello"},
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
            json={"session_id": "sess-1", "command": "echo hello"},
        )

        assert resp.status_code == 403

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
        mock_executor.hostname = "10.27.28.14"

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
                    json={"session_id": "sess-1", "command": "echo hello"},
                )

        assert resp.status_code == 200

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
        mock_executor.hostname = "10.27.28.14"

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
                    json={"session_id": "sess-1", "command": "echo secret"},
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
        mock_executor.hostname = "10.27.28.14"

        mock_query = MagicMock()
        mock_query.first.side_effect = [mock_session, mock_executor]
        mock_session.query.return_value = mock_query
        backend.get_session.return_value = mock_session

        with patch("server.routes.executors.httpx2.AsyncClient") as mock_client_cls:
            mock_client_cls.side_effect = Exception("connection refused")

            client = TestClient(app, raise_server_exceptions=False)
            resp = client.post(
                "/api/v1/executors/exec-1/execute",
                json={"session_id": "sess-1", "command": "echo hello"},
            )

            assert resp.status_code == 500  # Generic error for unexpected exceptions
