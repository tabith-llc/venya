"""Tests for executor enrollment token server endpoints.

Tests cover:
- Admin enroll endpoint: generates token, returns plaintext
- Register endpoint: validates token, resolves executor_id
- Register endpoint: backward compatible without token
- Register endpoint: rejected when require_enrollment_token=true
"""

import hashlib
import logging
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
from fastapi import FastAPI
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.testclient import TestClient

from server.routes import admin as admin_routes, executors as executors_routes


def _create_test_app(backend=None, auth_user=None, require_token=False, ca_manager=None):
    """Create a minimal test app with admin and executor routes."""
    app = FastAPI()
    if backend is None:
        backend = MagicMock()
        backend.get_session.return_value = MagicMock()
    app.state.backend = backend

    if require_token:
        from server.config import ServerConfig
        from server.config import ExecutorEnrollmentConfig
        app.state.config = ServerConfig(executor_enrollment=ExecutorEnrollmentConfig(require_token=True))

    if ca_manager is not None:
        app.state.ca_manager = ca_manager

    app.include_router(admin_routes.router, prefix="/api/v1")
    app.include_router(executors_routes.router, prefix="/api/v1")

    class AuthMiddleware(BaseHTTPMiddleware):
        async def dispatch(self, request: Request, call_next):
            if auth_user is not None:
                request.state.auth_user = auth_user
            return await call_next(request)

    app.add_middleware(AuthMiddleware)
    return app


def _generate_test_csr():
    """Generate a valid CSR for testing."""
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Venya"),
        x509.NameAttribute(NameOID.COMMON_NAME, "test-exec"),
    ])
    csr = (
        x509.CertificateSigningRequestBuilder()
        .subject_name(subject)
        .sign(private_key, hashes.SHA256())
    )
    return csr.public_bytes(serialization.Encoding.PEM).decode()


def _make_mock_ca():
    """Create a mock CA manager."""
    mock_ca = MagicMock()
    mock_cert = MagicMock()
    mock_cert.serial_number = 12345
    mock_cert.not_valid_before_utc = datetime.now(timezone.utc)
    mock_cert.not_valid_after_utc = datetime.now(timezone.utc) + timedelta(days=365)
    mock_cert.public_bytes.return_value = b"-----BEGIN CERTIFICATE-----\ntest\n-----END CERTIFICATE-----"
    mock_ca.sign_csr.return_value = mock_cert
    mock_ca.compute_serial_hex.return_value = "00:01:02:03"
    mock_ca.compute_fingerprint.return_value = "SHA256:ab:cd:ef"
    mock_ca.get_ca_cert_pem.return_value = b"-----BEGIN CERTIFICATE-----\nca\n-----END CERTIFICATE-----"
    return mock_ca


class TestAdminEnrollExecutor:
    """Tests for POST /admin/executors/{executor_id}/enroll."""

    def test_enroll_generates_token(self):
        """Enroll generates enrl_exec_ prefixed token."""
        mock_db = MagicMock()
        backend = MagicMock()
        backend.get_session.return_value = mock_db
        app = _create_test_app(backend=backend, auth_user={"user_id": "test-admin", "role": "admin"})

        client = TestClient(app, raise_server_exceptions=False)
        response = client.post("/api/v1/admin/executors/jump-1/enroll")
        assert response.status_code == 201
        data = response.json()
        assert data["enrollment_token"].startswith("enrl_exec_")
        assert data["executor_id"] == "jump-1"
        assert data["expires_in_seconds"] == 1800

    def test_enroll_returns_503_when_no_backend(self):
        """Returns 503 when backend is not initialized."""
        app = FastAPI()
        app.state.backend = None
        app.include_router(admin_routes.router, prefix="/api/v1")

        client = TestClient(app, raise_server_exceptions=False)
        response = client.post("/api/v1/admin/executors/jump-1/enroll")
        assert response.status_code == 503
        assert "Backend not initialized" in response.json()["detail"]

    def test_enroll_creates_audit_event(self):
        """Enroll creates an audit event in the database."""
        mock_db = MagicMock()
        backend = MagicMock()
        backend.get_session.return_value = mock_db

        added_objects = []

        class TrackAdd:
            def add(self, obj):
                added_objects.append(obj)
            def commit(self):
                pass
            def close(self):
                pass

        mock_db2 = TrackAdd()
        backend.get_session.return_value = mock_db2

        app = _create_test_app(backend=backend, auth_user={"user_id": "admin-1"})

        client = TestClient(app, raise_server_exceptions=False)
        response = client.post("/api/v1/admin/executors/test-exec/enroll")
        assert response.status_code == 201

        # Check that two objects were added (token + audit event)
        assert len(added_objects) == 2

    def test_enroll_uses_requester_as_created_by(self):
        """Enroll records the requesting admin as created_by."""
        mock_db = MagicMock()
        backend = MagicMock()
        backend.get_session.return_value = mock_db

        added_objects = []

        class TrackAdd:
            def add(self, obj):
                added_objects.append(obj)
            def commit(self):
                pass
            def close(self):
                pass

        mock_db2 = TrackAdd()
        backend.get_session.return_value = mock_db2

        app = _create_test_app(backend=backend, auth_user={"user_id": "auditor-42"})

        client = TestClient(app, raise_server_exceptions=False)
        response = client.post("/api/v1/admin/executors/audit-exec/enroll")
        assert response.status_code == 201

        # First added object is the token
        token_obj = added_objects[0]
        assert token_obj.created_by == "auditor-42"
        assert token_obj.executor_id == "audit-exec"


class TestRegisterEndpointWithToken:
    """Tests for executor registration with enrollment token."""

    def test_token_valid_resolves_executor_id(self):
        """Valid token resolves executor_id from token."""
        mock_db = MagicMock()
        backend = MagicMock()
        backend.get_session.return_value = mock_db
        app = _create_test_app(
            backend=backend, auth_user={"user_id": "admin"},
            ca_manager=_make_mock_ca(),
        )

        mock_token = MagicMock()
        mock_token.executor_id = "token-exec-1"
        mock_token.state = "created"
        mock_token.expires_at = datetime.now(timezone.utc) + timedelta(minutes=10)

        # Setup query mock: token lookup returns mock_token, user lookup returns None
        token_query = MagicMock()
        token_query.filter.return_value.first.return_value = mock_token
        user_query = MagicMock()
        user_query.filter.return_value.first.return_value = None

        def query_side_effect(model):
            if hasattr(model, '__tablename__') and model.__tablename__ == "executor_enrollment_tokens":
                return token_query
            return user_query

        mock_db.query.side_effect = query_side_effect

        client = TestClient(app, raise_server_exceptions=False)
        response = client.post(
            "/api/v1/executors/register",
            json={
                "executor_id": "token-exec-1",
                "csr_pem": _generate_test_csr(),
                "enrollment_token": "enrl_exec_testtoken",
            },
        )
        assert response.status_code == 201
        data = response.json()
        assert data["executor_id"] == "token-exec-1"

    def test_token_mismatched_executor_id_returns_401(self):
        """Token executor_id must match request executor_id."""
        mock_db = MagicMock()
        backend = MagicMock()
        backend.get_session.return_value = mock_db
        app = _create_test_app(
            backend=backend, auth_user={"user_id": "admin"},
            ca_manager=_make_mock_ca(),
        )

        mock_token = MagicMock()
        mock_token.executor_id = "token-exec-1"
        mock_token.state = "created"
        mock_token.expires_at = datetime.now(timezone.utc) + timedelta(minutes=10)

        token_query = MagicMock()
        token_query.filter.return_value.first.return_value = mock_token

        mock_db.query.side_effect = lambda model: token_query

        client = TestClient(app, raise_server_exceptions=False)
        response = client.post(
            "/api/v1/executors/register",
            json={
                "executor_id": "different-id",
                "csr_pem": _generate_test_csr(),
                "enrollment_token": "enrl_exec_testtoken",
            },
        )
        assert response.status_code == 401
        assert "bound to different executor_id" in response.json()["detail"]

    def test_token_invalid_returns_401(self):
        """Invalid token returns 401 Unauthorized."""
        mock_db = MagicMock()
        backend = MagicMock()
        backend.get_session.return_value = mock_db
        app = _create_test_app(backend=backend, ca_manager=_make_mock_ca())

        token_query = MagicMock()
        token_query.filter.return_value.first.return_value = None

        mock_db.query.side_effect = lambda model: token_query

        client = TestClient(app, raise_server_exceptions=False)
        response = client.post(
            "/api/v1/executors/register",
            json={
                "executor_id": "test-1",
                "csr_pem": _generate_test_csr(),
                "enrollment_token": "enrl_exec_wrongtoken",
            },
        )
        assert response.status_code == 401
        assert "Invalid enrollment token" in response.json()["detail"]

    def test_token_expired_returns_401(self):
        """Expired token returns 401 Unauthorized."""
        mock_db = MagicMock()
        backend = MagicMock()
        backend.get_session.return_value = mock_db
        app = _create_test_app(backend=backend, ca_manager=_make_mock_ca())

        mock_token = MagicMock()
        mock_token.state = "created"
        mock_token.expires_at = datetime.now(timezone.utc) - timedelta(hours=1)

        token_query = MagicMock()
        token_query.filter.return_value.first.return_value = mock_token

        mock_db.query.side_effect = lambda model: token_query

        client = TestClient(app, raise_server_exceptions=False)
        response = client.post(
            "/api/v1/executors/register",
            json={
                "executor_id": "test-1",
                "csr_pem": _generate_test_csr(),
                "enrollment_token": "enrl_exec_expired",
            },
        )
        assert response.status_code == 401
        assert "expired" in response.json()["detail"].lower()

    def test_token_already_consumed_returns_401(self):
        """Already consumed token returns 401 Unauthorized."""
        mock_db = MagicMock()
        backend = MagicMock()
        backend.get_session.return_value = mock_db
        app = _create_test_app(backend=backend, ca_manager=_make_mock_ca())

        mock_token = MagicMock()
        mock_token.state = "consumed"
        mock_token.expires_at = datetime.now(timezone.utc) + timedelta(minutes=10)

        token_query = MagicMock()
        token_query.filter.return_value.first.return_value = mock_token

        mock_db.query.side_effect = lambda model: token_query

        client = TestClient(app, raise_server_exceptions=False)
        response = client.post(
            "/api/v1/executors/register",
            json={
                "executor_id": "test-1",
                "csr_pem": _generate_test_csr(),
                "enrollment_token": "enrl_exec_used",
            },
        )
        assert response.status_code == 401
        assert "not in 'created' state" in response.json()["detail"]

    def test_no_token_backward_compatible(self):
        """Without token, uses executor_id from request body."""
        mock_db = MagicMock()
        backend = MagicMock()
        backend.get_session.return_value = mock_db
        app = _create_test_app(backend=backend, ca_manager=_make_mock_ca())

        user_query = MagicMock()
        user_query.filter.return_value.first.return_value = None

        mock_db.query.side_effect = lambda model: user_query

        client = TestClient(app, raise_server_exceptions=False)
        response = client.post(
            "/api/v1/executors/register",
            json={
                "executor_id": "test-1",
                "csr_pem": _generate_test_csr(),
            },
        )
        assert response.status_code == 201
        assert response.json()["executor_id"] == "test-1"

    def test_no_token_when_required_returns_400(self):
        """When require_enrollment_token=true and no token, returns 400."""
        mock_db = MagicMock()
        backend = MagicMock()
        backend.get_session.return_value = mock_db
        app = _create_test_app(backend=backend, require_token=True, ca_manager=_make_mock_ca())

        user_query = MagicMock()
        user_query.filter.return_value.first.return_value = None

        mock_db.query.side_effect = lambda model: user_query

        client = TestClient(app, raise_server_exceptions=False)
        response = client.post(
            "/api/v1/executors/register",
            json={
                "executor_id": "test-1",
                "csr_pem": _generate_test_csr(),
            },
        )
        assert response.status_code == 400
        assert "Enrollment token required" in response.json()["detail"]

    def test_token_state_marked_consumed(self):
        """Valid token state is updated to 'consumed'."""
        mock_db = MagicMock()
        backend = MagicMock()
        backend.get_session.return_value = mock_db
        app = _create_test_app(backend=backend, ca_manager=_make_mock_ca())

        mock_token = MagicMock()
        mock_token.executor_id = "consumed-exec"
        mock_token.state = "created"
        mock_token.expires_at = datetime.now(timezone.utc) + timedelta(minutes=10)

        token_query = MagicMock()
        token_query.filter.return_value.first.return_value = mock_token
        user_query = MagicMock()
        user_query.filter.return_value.first.return_value = None

        def query_side_effect(model):
            if hasattr(model, '__tablename__') and model.__tablename__ == "executor_enrollment_tokens":
                return token_query
            return user_query

        mock_db.query.side_effect = query_side_effect

        client = TestClient(app, raise_server_exceptions=False)
        response = client.post(
            "/api/v1/executors/register",
            json={
                "executor_id": "consumed-exec",
                "csr_pem": _generate_test_csr(),
                "enrollment_token": "enrl_exec_valid",
            },
        )
        assert response.status_code == 201
        assert mock_token.state == "consumed"
        assert mock_token.used_at is not None

    def test_invalid_csr_returns_400(self):
        """Invalid CSR format returns 400 Bad Request."""
        mock_db = MagicMock()
        backend = MagicMock()
        backend.get_session.return_value = mock_db
        app = _create_test_app(backend=backend, ca_manager=_make_mock_ca())

        client = TestClient(app, raise_server_exceptions=False)
        response = client.post(
            "/api/v1/executors/register",
            json={
                "executor_id": "test-1",
                "csr_pem": "not a valid csr",
            },
        )
        assert response.status_code == 400
        assert "Invalid CSR" in response.json()["detail"]

    def test_ca_not_initialized_returns_503(self):
        """Registration returns 503 when CA is not initialized."""
        mock_db = MagicMock()
        backend = MagicMock()
        backend.get_session.return_value = mock_db
        app = _create_test_app(backend=backend)

        client = TestClient(app, raise_server_exceptions=False)
        response = client.post(
            "/api/v1/executors/register",
            json={
                "executor_id": "test-1",
                "csr_pem": _generate_test_csr(),
            },
        )
        assert response.status_code == 503
        assert "CA not initialized" in response.json()["detail"]


class TestTokenTTL:
    """Tests for configurable token TTL (Issue #5)."""

    def test_default_ttl_is_1800(self):
        """Default TTL should be 1800 seconds (30 minutes)."""
        from server.config import ServerConfig, ExecutorEnrollmentConfig

        config = ServerConfig()
        assert config.executor_enrollment.token_ttl_seconds == 1800

    def test_token_ttl_uses_configured_value(self):
        """Token should use configured TTL, not hardcoded value."""
        from server.config import ServerConfig, ExecutorEnrollmentConfig

        mock_db = MagicMock()
        backend = MagicMock()
        backend.get_session.return_value = mock_db

        custom_ttl = 600  # 10 minutes
        app = _create_test_app(
            backend=backend,
            auth_user={"user_id": "test-admin"},
        )
        app.state.config = ServerConfig(
            executor_enrollment=ExecutorEnrollmentConfig(token_ttl_seconds=custom_ttl)
        )

        client = TestClient(app, raise_server_exceptions=False)
        response = client.post("/api/v1/admin/executors/jump-1/enroll")
        assert response.status_code == 201
        data = response.json()
        assert data["expires_in_seconds"] == custom_ttl

    def test_token_ttl_minimum_enforced(self):
        """TTL below minimum (120s) should raise validation error."""
        from server.config import ExecutorEnrollmentConfig

        with pytest.raises(Exception):  # Pydantic ValidationError
            ExecutorEnrollmentConfig(token_ttl_seconds=60)

    def test_token_ttl_maximum_enforced(self):
        """TTL above maximum (86400s) should raise validation error."""
        from server.config import ExecutorEnrollmentConfig

        with pytest.raises(Exception):  # Pydantic ValidationError
            ExecutorEnrollmentConfig(token_ttl_seconds=90000)

    def test_response_includes_expires_at(self):
        """Response should include expires_at ISO 8601 timestamp."""
        mock_db = MagicMock()
        backend = MagicMock()
        backend.get_session.return_value = mock_db
        app = _create_test_app(backend=backend, auth_user={"user_id": "test-admin"})

        client = TestClient(app, raise_server_exceptions=False)
        response = client.post("/api/v1/admin/executors/jump-1/enroll")
        assert response.status_code == 201
        data = response.json()
        assert "expires_at" in data
        # Should be valid ISO 8601
        from datetime import datetime
        expires_at = datetime.fromisoformat(data["expires_at"])
        assert expires_at.tzinfo is not None

    def test_token_ttl_warns_on_extended(self):
        """TTL above 4h should produce a warning log."""
        from server.config import ExecutorEnrollmentConfig

        with patch("server.config.logger") as mock_logger:
            config = ExecutorEnrollmentConfig(token_ttl_seconds=14401)
            # Trigger the validator
            config.model_validate(config.model_dump())

        assert any("TTL" in str(call) and ">4h" in str(call) for call in mock_logger.warning.call_args_list)
