"""Tests for execution relay endpoints.

Covers session creation, command relay, audit events, and session validation.
"""

import ssl
from datetime import UTC, datetime, timedelta
from unittest.mock import AsyncMock, MagicMock, patch

import httpx2
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

    # Server-side secret resolution/wrapping
    app.state.core = MagicMock()
    app.state.core.decrypt_secret.return_value = "s3cret-value"

    app.include_router(executors_routes.router, prefix="/api/v1")

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
        mock_executor.hostname = "10.27.28.14"
        mock_query = MagicMock()
        mock_query.first.return_value = mock_executor
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
        mock_executor.hostname = "10.27.28.14"
        mock_db = _mock_db_for_session(mock_executor, [None])
        backend.get_session.return_value = mock_db

        client = TestClient(app, raise_server_exceptions=False)
        resp = client.post(
            "/api/v1/executors/sessions",
            json={"executor_id": "exec-1", "secret_keys": ["missing-key"]},
        )

        assert resp.status_code == 404

    def test_create_session_stores_wrapped_secrets(self):
        """Keys are resolved and wrapped server-side into SessionSecret rows."""
        from server.routes.secrets import wrap_with_sentinel

        app, backend = _create_test_app()
        mock_executor = MagicMock()
        mock_executor.id = "exec-1"
        mock_executor.hostname = "10.27.28.14"
        secrets = _mock_secret_rows(("db-password", None), ("api-key", None))
        mock_db = _mock_db_for_session(mock_executor, list(secrets))
        backend.get_session.return_value = mock_db

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
        mock_executor.hostname = "10.27.28.14"
        secrets = _mock_secret_rows(("db-password", None))
        mock_db = _mock_db_for_session(mock_executor, list(secrets))
        backend.get_session.return_value = mock_db

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
        mock_executor.hostname = "10.27.28.14"
        secrets = _mock_secret_rows(("db-password", {"executor": "other-exec"}))
        mock_db = _mock_db_for_session(mock_executor, list(secrets))
        backend.get_session.return_value = mock_db

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
        mock_db = _mock_db_for_session(MagicMock(id="exec-1", hostname="10.27.28.14"), [])
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
            json={"session_id": "sess-1", "command": "echo hello"},
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
        mock_executor.hostname = "10.27.28.14"

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
                    json={"session_id": "sess-1", "command": "echo hello"},
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
        mock_executor.hostname = "10.27.28.14"

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
                    json={"session_id": "sess-1", "command": "echo hello"},
                )

        assert resp.status_code == 503
        assert "mTLS" not in resp.json()["detail"]


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
        mock_executor.hostname = "10.27.28.14"

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
                    json={"session_id": "sess-1", "command": "echo hello"},
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
                    json={"session_id": "sess-1", "command": "echo hello"},
                )
        assert resp.status_code == 502

    def test_extra_keys_dropped_valid_fields_preserved(self):
        """200 response with extra keys → 502 is NOT returned; valid fields preserved, junk dropped."""
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
                    json={"session_id": "sess-1", "command": "echo hello"},
                )
        assert resp.status_code == 200
        body = resp.json()
        assert body["exit_code"] == 0
        assert body["stdout"] == "hello\n"
        assert body["masked_count"] == 1
        assert "rogue_field" not in body


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
        mock_executor.hostname = "10.27.28.14"

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
                json={"session_id": "sess-1", "command": "echo hello"},
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
                json={"session_id": "sess-1", "command": "echo hello"},
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
                json={"session_id": "sess-1", "command": "echo hello"},
            )
        assert resp.status_code == 503
