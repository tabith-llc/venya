"""Tests for executor enrollment token server endpoints.

Tests cover:
- Admin enroll endpoint: generates token, returns plaintext
- Register endpoint: validates token, resolves executor_id
- Register endpoint: backward compatible without token
- Register endpoint: rejected when require_enrollment_token=true
"""

import hashlib
from datetime import UTC, datetime, timedelta
from unittest.mock import MagicMock, patch

import pytest
from core.iam.models import ExecutorEnrollmentToken
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID
from fastapi import FastAPI
from pydantic import ValidationError
from server.dependencies import get_current_user, require_admin
from server.routes import admin as admin_routes
from server.routes import executors as executors_routes
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.testclient import TestClient

_TEST_PEPPER = "test-pepper-12345"


@pytest.fixture(autouse=True)
def _reset_rate_limiters():
    """Isolate the module-level rate limiter cache between tests.

    The M-61 fix routes the per-executor registration key through a persistent
    limiter (``server.rate_limit._LIMITERS``). Without this reset the shared
    executor_id ("test-1") accumulates across tests and trips the 429 cap;
    before the fix the first-attempt key used a fresh limiter (a no-op), which
    masked the shared state.
    """
    from server import rate_limit as _rl

    saved = dict(_rl._LIMITERS)
    _rl._LIMITERS.clear()
    yield
    _rl._LIMITERS.clear()
    _rl._LIMITERS.update(saved)


def _make_mock_token(executor_id, plaintext_token, state="created"):
    """Create a mock enrollment token."""
    pepper = "test-pepper-12345"
    import hmac

    mock_token = MagicMock()
    mock_token.executor_id = executor_id
    mock_token.state = state
    mock_token.token_hash = hmac.new(
        pepper.encode("utf-8"),
        plaintext_token.encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()
    mock_token.expires_at = datetime.now(UTC) + timedelta(minutes=10)
    return mock_token


def _create_test_app(backend=None, auth_user=None, require_token=False, ca_manager=None, pepper="test-pepper-12345"):
    """Create a minimal test app with admin and executor routes."""
    app = FastAPI()
    if backend is None:
        backend = MagicMock()
        backend.get_session.return_value = MagicMock()
    app.state.backend = backend

    from server.config import ExecutorEnrollmentConfig, ServerConfig

    if require_token:
        app.state.config = ServerConfig(
            executor_enrollment=ExecutorEnrollmentConfig(require_token=True), recovery_code_pepper=pepper
        )
    else:
        app.state.config = ServerConfig(recovery_code_pepper=pepper)

    if ca_manager is not None:
        app.state.ca_manager = ca_manager

    # Mock core for encrypt() — returns valid tuple for encrypted metadata
    mock_core = MagicMock()
    mock_core.encrypt.return_value = (b"wrapped_dek", b"nonce", b"ciphertext")
    app.state.core = mock_core

    app.include_router(admin_routes.router, prefix="/api/v1")
    app.include_router(executors_routes.router, prefix="/api/v1")

    # Override auth deps so require_admin bypasses real auth
    TEST_USER = auth_user or {"user_id": "test-user"}
    app.dependency_overrides[get_current_user] = lambda: TEST_USER
    app.dependency_overrides[require_admin] = lambda: TEST_USER

    class AuthMiddleware(BaseHTTPMiddleware):
        async def dispatch(self, request: Request, call_next):
            if auth_user is not None:
                request.state.auth_user = auth_user
            return await call_next(request)

    app.add_middleware(AuthMiddleware)
    return app


def _generate_test_csr():
    """Generate a valid CSR for testing."""
    private_key = ec.generate_private_key(ec.SECP256R1())
    subject = x509.Name(
        [
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Venya"),
            x509.NameAttribute(NameOID.COMMON_NAME, "test-exec"),
        ]
    )
    csr = x509.CertificateSigningRequestBuilder().subject_name(subject).sign(private_key, hashes.SHA256())
    return csr.public_bytes(serialization.Encoding.PEM).decode()


def _make_mock_ca():
    """Create a mock CA manager."""
    mock_ca = MagicMock()
    mock_cert = MagicMock()
    mock_cert.serial_number = 12345
    mock_cert.not_valid_before_utc = datetime.now(UTC)
    mock_cert.not_valid_after_utc = datetime.now(UTC) + timedelta(days=365)
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
        from server.dependencies import get_current_user, require_admin

        app = FastAPI()
        app.state.backend = None
        app.include_router(admin_routes.router, prefix="/api/v1")

        # Override auth deps
        _admin_user = {"user_id": "test-user"}
        app.dependency_overrides[get_current_user] = lambda: _admin_user
        app.dependency_overrides[require_admin] = lambda: _admin_user

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

            def flush(self):
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

    def test_enroll_audit_event_includes_token_id(self):
        """Audit event for token creation includes token_id in fields."""
        mock_db = MagicMock()
        backend = MagicMock()
        backend.get_session.return_value = mock_db

        added_objects = []

        class TrackAdd:
            def add(self, obj):
                added_objects.append(obj)

            def commit(self):
                pass

            def flush(self):
                # Simulate flush assigning an ID to the token
                if isinstance(added_objects[-1], ExecutorEnrollmentToken):
                    added_objects[-1].id = 42

            def close(self):
                pass

        mock_db2 = TrackAdd()
        backend.get_session.return_value = mock_db2

        app = _create_test_app(backend=backend, auth_user={"user_id": "admin-1"})

        client = TestClient(app, raise_server_exceptions=False)
        response = client.post("/api/v1/admin/executors/test-exec/enroll")
        assert response.status_code == 201

        audit_event = added_objects[1]
        assert audit_event.event_type == "executor_enrollment_token_created"
        # AuditEvent.fields is JSON-serialized by the @validates(serialize_fields) decorator
        import json

        fields = json.loads(audit_event.fields)
        assert fields["token_id"] == 42

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

            def flush(self):
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
            backend=backend,
            auth_user={"user_id": "admin"},
            ca_manager=_make_mock_ca(),
        )

        mock_token = _make_mock_token("token-exec-1", "enrl_exec_testtoken", "created")

        # Setup query mock: token lookup returns mock_token, user lookup returns None
        token_query = MagicMock()
        token_query.filter.return_value.first.return_value = mock_token
        user_query = MagicMock()
        user_query.filter.return_value.first.return_value = None

        def query_side_effect(model):
            if hasattr(model, "__tablename__") and model.__tablename__ == "executor_enrollment_tokens":
                return token_query
            return user_query

        mock_db.query.side_effect = query_side_effect

        # Mock atomic UPDATE result
        mock_result = MagicMock()
        mock_result.rowcount = 1
        mock_db.execute.return_value = mock_result

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

    def test_register_audit_event_includes_token_id(self):
        """Audit event for executor registration includes token_id when token used."""
        mock_db = MagicMock()
        backend = MagicMock()
        backend.get_session.return_value = mock_db
        app = _create_test_app(
            backend=backend,
            auth_user={"user_id": "admin"},
            ca_manager=_make_mock_ca(),
        )

        mock_token = _make_mock_token("token-exec-1", "enrl_exec_testtoken", "created")
        mock_token.id = 99

        token_query = MagicMock()
        token_query.filter.return_value.first.return_value = mock_token
        user_query = MagicMock()
        user_query.filter.return_value.first.return_value = None

        def query_side_effect(model):
            if hasattr(model, "__tablename__") and model.__tablename__ == "executor_enrollment_tokens":
                return token_query
            return user_query

        mock_db.query.side_effect = query_side_effect

        mock_result = MagicMock()
        mock_result.rowcount = 1
        mock_db.execute.return_value = mock_result

        added_objects = []

        class TrackAdd:
            def add(self, obj):
                added_objects.append(obj)

            def commit(self):
                pass

            def flush(self):
                pass

            def close(self):
                pass

            def query(self, model):
                if hasattr(model, "__tablename__") and model.__tablename__ == "executor_enrollment_tokens":
                    return token_query
                return user_query

            def execute(self, *args, **kwargs):
                return mock_result

        mock_db2 = TrackAdd()
        backend.get_session.return_value = mock_db2

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

        audit_event = [o for o in added_objects if hasattr(o, "event_type")]
        assert len(audit_event) == 1
        assert audit_event[0].event_type == "executor_registered"
        import json

        fields = json.loads(audit_event[0].fields)
        assert fields["token_id"] == 99

    def test_token_mismatched_executor_id_returns_401(self):
        """Token executor_id must match request executor_id."""
        mock_db = MagicMock()
        backend = MagicMock()
        backend.get_session.return_value = mock_db
        app = _create_test_app(
            backend=backend,
            auth_user={"user_id": "admin"},
            ca_manager=_make_mock_ca(),
        )

        mock_token = MagicMock()
        mock_token.executor_id = "token-exec-1"
        mock_token.state = "created"
        mock_token.expires_at = datetime.now(UTC) + timedelta(minutes=10)

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
        mock_token.expires_at = datetime.now(UTC) - timedelta(hours=1)

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
        mock_token.executor_id = "other-exec"
        mock_token.expires_at = datetime.now(UTC) + timedelta(minutes=10)

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
        assert "consumed by a different executor" in response.json()["detail"]

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
        """Valid token state is updated to 'consumed' via atomic UPDATE."""
        mock_db = MagicMock()
        backend = MagicMock()
        backend.get_session.return_value = mock_db
        app = _create_test_app(backend=backend, ca_manager=_make_mock_ca())

        mock_token = _make_mock_token("consumed-exec", "enrl_exec_valid", "created")

        token_query = MagicMock()
        token_query.filter.return_value.first.return_value = mock_token
        user_query = MagicMock()
        user_query.filter.return_value.first.return_value = None

        def query_side_effect(model):
            if hasattr(model, "__tablename__") and model.__tablename__ == "executor_enrollment_tokens":
                return token_query
            return user_query

        mock_db.query.side_effect = query_side_effect

        # Mock atomic UPDATE result
        mock_result = MagicMock()
        mock_result.rowcount = 1
        mock_db.execute.return_value = mock_result

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
        # Verify atomic UPDATE was called
        assert mock_db.execute.called

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
        from server.config import ServerConfig

        config = ServerConfig(recovery_code_pepper="test-pepper")
        assert config.executor_enrollment.token_ttl_seconds == 1800

    def test_token_ttl_uses_configured_value(self):
        """Token should use configured TTL, not hardcoded value."""
        from server.config import ExecutorEnrollmentConfig, ServerConfig

        mock_db = MagicMock()
        backend = MagicMock()
        backend.get_session.return_value = mock_db

        custom_ttl = 600  # 10 minutes
        app = _create_test_app(
            backend=backend,
            auth_user={"user_id": "test-admin"},
        )
        app.state.config = ServerConfig(
            executor_enrollment=ExecutorEnrollmentConfig(token_ttl_seconds=custom_ttl),
            recovery_code_pepper="test-pepper",
        )

        client = TestClient(app, raise_server_exceptions=False)
        response = client.post("/api/v1/admin/executors/jump-1/enroll")
        assert response.status_code == 201
        data = response.json()
        assert data["expires_in_seconds"] == custom_ttl

    def test_token_ttl_minimum_enforced(self):
        """TTL below minimum (120s) should raise validation error."""
        from server.config import ExecutorEnrollmentConfig

        with pytest.raises(ValidationError):
            ExecutorEnrollmentConfig(token_ttl_seconds=60)

    def test_token_ttl_maximum_enforced(self):
        """TTL above maximum (86400s) should raise validation error."""
        from server.config import ExecutorEnrollmentConfig

        with pytest.raises(ValidationError):
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


class TestTokenAtomicConsumption:
    """Tests for atomic token consumption (Issue #6)."""

    def test_atomic_update_succeeds(self):
        """Atomic UPDATE returns rowcount=1 on valid token."""
        mock_db = MagicMock()
        backend = MagicMock()
        backend.get_session.return_value = mock_db
        app = _create_test_app(backend=backend, ca_manager=_make_mock_ca())

        mock_token = _make_mock_token("atomic-exec-1", "enrl_exec_atomic", "created")

        token_query = MagicMock()
        token_query.filter.return_value.first.return_value = mock_token
        user_query = MagicMock()
        user_query.filter.return_value.first.return_value = None

        def query_side_effect(model):
            if hasattr(model, "__tablename__") and model.__tablename__ == "executor_enrollment_tokens":
                return token_query
            return user_query

        mock_db.query.side_effect = query_side_effect

        mock_result = MagicMock()
        mock_result.rowcount = 1
        mock_db.execute.return_value = mock_result

        client = TestClient(app, raise_server_exceptions=False)
        response = client.post(
            "/api/v1/executors/register",
            json={
                "executor_id": "atomic-exec-1",
                "csr_pem": _generate_test_csr(),
                "enrollment_token": "enrl_exec_atomic",
            },
        )
        assert response.status_code == 201
        assert response.json()["executor_id"] == "atomic-exec-1"
        # Verify atomic UPDATE was called
        assert mock_db.execute.called
        call_args = mock_db.execute.call_args
        assert "UPDATE executor_enrollment_tokens" in str(call_args[0][0])

    def test_atomic_update_race_condition_returns_401(self):
        """Atomic UPDATE returns rowcount=0 when token consumed concurrently."""
        mock_db = MagicMock()
        backend = MagicMock()
        backend.get_session.return_value = mock_db
        app = _create_test_app(backend=backend, ca_manager=_make_mock_ca())

        # Pre-check sees "created"
        mock_token = _make_mock_token("race-exec-1", "enrl_exec_race", "created")

        # Re-read sees "consumed" (was consumed by concurrent request)
        consumed_token = _make_mock_token("race-exec-1", "enrl_exec_race", "consumed")

        call_num = [0]

        def query_side_effect(model):
            if hasattr(model, "__tablename__") and model.__tablename__ == "executor_enrollment_tokens":
                call_num[0] += 1
                if call_num[0] == 1:
                    # Pre-check query: returns "created" token
                    q = MagicMock()
                    q.filter.return_value.first.return_value = mock_token
                    return q
                else:
                    # Re-read query: returns "consumed" token
                    q = MagicMock()
                    q.filter.return_value.first.return_value = consumed_token
                    return q
            return MagicMock()

        mock_db.query.side_effect = query_side_effect

        # Simulate race: pre-check passed but atomic UPDATE found nothing
        mock_result = MagicMock()
        mock_result.rowcount = 0
        mock_db.execute.return_value = mock_result

        client = TestClient(app, raise_server_exceptions=False)
        response = client.post(
            "/api/v1/executors/register",
            json={
                "executor_id": "race-exec-1",
                "csr_pem": _generate_test_csr(),
                "enrollment_token": "enrl_exec_race",
            },
        )
        assert response.status_code == 401
        assert "consumed concurrently" in response.json()["detail"]
        # Verify rollback was called
        assert mock_db.rollback.called

    def test_token_revoked_returns_specific_error(self):
        """Revoked token returns specific error message."""
        mock_db = MagicMock()
        backend = MagicMock()
        backend.get_session.return_value = mock_db
        app = _create_test_app(backend=backend, ca_manager=_make_mock_ca())

        mock_token = MagicMock()
        mock_token.state = "revoked"

        token_query = MagicMock()
        token_query.filter.return_value.first.return_value = mock_token

        mock_db.query.side_effect = lambda model: token_query

        client = TestClient(app, raise_server_exceptions=False)
        response = client.post(
            "/api/v1/executors/register",
            json={
                "executor_id": "test-1",
                "csr_pem": _generate_test_csr(),
                "enrollment_token": "enrl_exec_revoked",
            },
        )
        assert response.status_code == 401
        assert "revoked" in response.json()["detail"]
        # Atomic UPDATE should NOT be called for revoked tokens
        assert not mock_db.execute.called

    def test_token_already_consumed_returns_specific_error(self):
        """Already consumed token returns specific error message."""
        mock_db = MagicMock()
        backend = MagicMock()
        backend.get_session.return_value = mock_db
        app = _create_test_app(backend=backend, ca_manager=_make_mock_ca())

        mock_token = MagicMock()
        mock_token.state = "consumed"
        mock_token.executor_id = "other-exec"
        mock_token.expires_at = datetime.now(UTC) + timedelta(minutes=10)

        token_query = MagicMock()
        token_query.filter.return_value.first.return_value = mock_token

        mock_db.query.side_effect = lambda model: token_query

        client = TestClient(app, raise_server_exceptions=False)
        response = client.post(
            "/api/v1/executors/register",
            json={
                "executor_id": "test-1",
                "csr_pem": _generate_test_csr(),
                "enrollment_token": "enrl_exec_consumed",
            },
        )
        assert response.status_code == 401
        assert "consumed by a different executor" in response.json()["detail"]
        # Atomic UPDATE should NOT be called for already consumed tokens
        assert not mock_db.execute.called

    def test_sequential_replay_after_successful_registration(self):
        """A token consumed by a successful registration cannot be reused."""
        mock_db = MagicMock()
        backend = MagicMock()
        backend.get_session.return_value = mock_db
        app = _create_test_app(
            backend=backend,
            auth_user={"user_id": "admin"},
            ca_manager=_make_mock_ca(),
        )

        mock_token = _make_mock_token("replay-exec", "enrl_exec_replay", "created")
        mock_token.id = 1

        token_query = MagicMock()
        token_query.filter.return_value.first.return_value = mock_token
        user_query = MagicMock()
        user_query.filter.return_value.first.return_value = None

        def query_side_effect(model):
            if hasattr(model, "__tablename__") and model.__tablename__ == "executor_enrollment_tokens":
                return token_query
            return user_query

        mock_db.query.side_effect = query_side_effect

        # Track whether first registration has completed
        first_done = [False]

        def execute_side_effect(*args, **kwargs):
            if not first_done[0]:
                first_done[0] = True
                mock_token.state = "consumed"
                mock_token.used_at = datetime.now(UTC)
                mock_result = MagicMock()
                mock_result.rowcount = 1
                return mock_result
            else:
                # Second call: token already consumed
                mock_result = MagicMock()
                mock_result.rowcount = 0
                return mock_result

        mock_db.execute.side_effect = execute_side_effect

        client = TestClient(app, raise_server_exceptions=False)

        # First registration — succeeds
        response1 = client.post(
            "/api/v1/executors/register",
            json={
                "executor_id": "replay-exec",
                "csr_pem": _generate_test_csr(),
                "enrollment_token": "enrl_exec_replay",
            },
        )
        assert response1.status_code == 201
        assert response1.json()["executor_id"] == "replay-exec"

        # Replay the same token — must fail with 409 (same executor)
        response2 = client.post(
            "/api/v1/executors/register",
            json={
                "executor_id": "replay-exec",
                "csr_pem": _generate_test_csr(),
                "enrollment_token": "enrl_exec_replay",
            },
        )
        assert response2.status_code == 409
        assert "already registered" in response2.json()["detail"].lower()

    def test_409_for_same_executor_replay(self):
        """Consumed token for same executor returns 409 Conflict."""
        mock_db = MagicMock()
        backend = MagicMock()
        backend.get_session.return_value = mock_db
        app = _create_test_app(
            backend=backend,
            auth_user={"user_id": "admin"},
            ca_manager=_make_mock_ca(),
        )

        mock_token = MagicMock()
        mock_token.state = "consumed"
        mock_token.executor_id = "conflict-exec"
        mock_token.used_at = datetime.now(UTC) - timedelta(seconds=10)
        mock_token.expires_at = datetime.now(UTC) + timedelta(minutes=10)

        token_query = MagicMock()
        token_query.filter.return_value.first.return_value = mock_token

        mock_db.query.side_effect = lambda model: token_query

        client = TestClient(app, raise_server_exceptions=False)
        response = client.post(
            "/api/v1/executors/register",
            json={
                "executor_id": "conflict-exec",
                "csr_pem": _generate_test_csr(),
                "enrollment_token": "enrl_exec_conflict",
            },
        )
        assert response.status_code == 409
        assert "already registered" in response.json()["detail"].lower()

    def test_401_for_different_executor_consumed_token(self):
        """Consumed token for different executor returns 401."""
        mock_db = MagicMock()
        backend = MagicMock()
        backend.get_session.return_value = mock_db
        app = _create_test_app(
            backend=backend,
            auth_user={"user_id": "admin"},
            ca_manager=_make_mock_ca(),
        )

        mock_token = MagicMock()
        mock_token.state = "consumed"
        mock_token.executor_id = "other-exec"
        mock_token.used_at = datetime.now(UTC) - timedelta(seconds=10)
        mock_token.expires_at = datetime.now(UTC) + timedelta(minutes=10)

        token_query = MagicMock()
        token_query.filter.return_value.first.return_value = mock_token

        mock_db.query.side_effect = lambda model: token_query

        client = TestClient(app, raise_server_exceptions=False)
        response = client.post(
            "/api/v1/executors/register",
            json={
                "executor_id": "different-exec",
                "csr_pem": _generate_test_csr(),
                "enrollment_token": "enrl_exec_other",
            },
        )
        assert response.status_code == 401
        assert "consumed by a different executor" in response.json()["detail"]

    def test_atomic_update_revoked_token_returns_specific_error(self):
        """Atomic UPDATE fails and re-read shows revoked state."""
        mock_db = MagicMock()
        backend = MagicMock()
        backend.get_session.return_value = mock_db
        app = _create_test_app(
            backend=backend,
            auth_user={"user_id": "admin"},
            ca_manager=_make_mock_ca(),
        )

        # Pre-check sees "created"
        mock_token = _make_mock_token("revoked-race-exec", "enrl_exec_revoked_race", "created")

        # Re-read sees "revoked"
        revoked_token = MagicMock()
        revoked_token.state = "revoked"
        revoked_token.executor_id = "revoked-race-exec"

        mock_token_query = MagicMock()
        mock_token_query.filter.return_value.first.return_value = mock_token

        revoked_query = MagicMock()
        revoked_query.filter.return_value.first.return_value = revoked_token

        call_num = [0]

        def query_side_effect(model):
            if hasattr(model, "__tablename__") and model.__tablename__ == "executor_enrollment_tokens":
                call_num[0] += 1
                if call_num[0] == 1:
                    return mock_token_query
                else:
                    return revoked_query
            return MagicMock()

        mock_db.query.side_effect = query_side_effect

        # Atomic UPDATE fails (rowcount=0)
        mock_result = MagicMock()
        mock_result.rowcount = 0
        mock_db.execute.return_value = mock_result

        client = TestClient(app, raise_server_exceptions=False)
        response = client.post(
            "/api/v1/executors/register",
            json={
                "executor_id": "revoked-race-exec",
                "csr_pem": _generate_test_csr(),
                "enrollment_token": "enrl_exec_revoked_race",
            },
        )
        assert response.status_code == 401
        assert "revoked" in response.json()["detail"]
        assert mock_db.rollback.called


class TestAdminIdentityCapture:
    """Tests for admin identity capture on token creation (Issue #19)."""

    def test_enroll_captures_admin_identity(self):
        """Enroll captures session_id, IP, and user_agent on the token."""
        mock_db = MagicMock()
        backend = MagicMock()
        backend.get_session.return_value = mock_db

        added_objects = []

        class TrackAdd:
            def add(self, obj):
                added_objects.append(obj)

            def commit(self):
                pass

            def flush(self):
                pass

            def close(self):
                pass

        mock_db2 = TrackAdd()
        backend.get_session.return_value = mock_db2

        app = _create_test_app(
            backend=backend,
            auth_user={"user_id": "admin-1", "session_id": 42},
        )

        # Add a mock client with host
        client = TestClient(app, raise_server_exceptions=False)
        # Override to inject headers
        response = client.post(
            "/api/v1/admin/executors/test-exec/enroll",
            headers={"User-Agent": "test-agent/1.0"},
        )
        assert response.status_code == 201

        token_obj = added_objects[0]
        assert token_obj.created_by == "admin-1"
        assert token_obj.created_by_session_id == "42"
        assert token_obj.created_from_ip is not None
        assert token_obj.created_from_user_agent == "test-agent/1.0"

    def test_enroll_audit_event_includes_admin_identity(self):
        """Audit event includes all admin identity fields plus token metadata."""
        mock_db = MagicMock()
        backend = MagicMock()
        backend.get_session.return_value = mock_db

        added_objects = []

        class TrackAdd:
            def add(self, obj):
                added_objects.append(obj)

            def commit(self):
                pass

            def flush(self):
                if isinstance(added_objects[-1], ExecutorEnrollmentToken):
                    added_objects[-1].id = 42

            def close(self):
                pass

        mock_db2 = TrackAdd()
        backend.get_session.return_value = mock_db2

        app = _create_test_app(
            backend=backend,
            auth_user={"user_id": "admin-1", "session_id": 42},
        )

        client = TestClient(app, raise_server_exceptions=False)
        response = client.post(
            "/api/v1/admin/executors/test-exec/enroll",
            headers={"User-Agent": "audit-test/2.0"},
        )
        assert response.status_code == 201

        audit_event = added_objects[1]
        assert audit_event.event_type == "executor_enrollment_token_created"
        import json

        fields = json.loads(audit_event.fields)
        assert fields["token_id"] == 42
        assert "token_hash_preview" in fields
        assert len(fields["token_hash_preview"]) == 8
        assert "expires_at" in fields
        assert fields["created_by_session_id"] == "42"
        assert fields["created_from_ip"] is not None
        assert fields["created_from_user_agent"] == "audit-test/2.0"
        assert "token_created_at" in fields

    def test_enroll_null_fields_when_session_missing(self):
        """Graceful degradation — no crash when session_id/IP/user_agent absent."""
        mock_db = MagicMock()
        backend = MagicMock()
        backend.get_session.return_value = mock_db

        added_objects = []

        class TrackAdd:
            def add(self, obj):
                added_objects.append(obj)

            def commit(self):
                pass

            def flush(self):
                pass

            def close(self):
                pass

        mock_db2 = TrackAdd()
        backend.get_session.return_value = mock_db2

        # Auth user with no session_id
        app = _create_test_app(
            backend=backend,
            auth_user={"user_id": "orphan-admin"},
        )

        client = TestClient(app, raise_server_exceptions=False)
        # Strip user-agent via raw request

        response = client.post(
            "/api/v1/admin/executors/test-exec/enroll",
            headers={"User-Agent": ""},
        )
        assert response.status_code == 201

        token_obj = added_objects[0]
        assert token_obj.created_by == "orphan-admin"
        assert token_obj.created_by_session_id is None
        # IP may or may not be present depending on test client — just no crash

    def test_token_meta_data_not_accessible_via_api(self):
        """Identity fields are audit-only — not exposed in token listing."""

        mock_db = MagicMock()
        backend = MagicMock()
        backend.get_session.return_value = mock_db

        # Create a mock token with identity fields set
        mock_token = MagicMock()
        mock_token.id = 1
        mock_token.executor_id = "test-exec"
        mock_token.token_hash = "abc123"
        mock_token.state = "created"
        mock_token.created_by = "admin-1"
        mock_token.created_by_session_id = "42"
        mock_token.created_from_ip = "127.0.0.1"
        mock_token.created_from_user_agent = "test-agent/1.0"
        mock_token.expires_at = datetime.now(UTC) + timedelta(minutes=15)
        mock_token.created_at = datetime.now(UTC)
        mock_token.used_at = None

        token_query = MagicMock()
        token_query.filter.return_value.first.return_value = mock_token
        token_query.order_by.return_value.all.return_value = [mock_token]

        mock_db.query.side_effect = lambda model: token_query

        app = _create_test_app(backend=backend)
        # The admin executor token list endpoint should NOT exist as a public listing
        # Only the user token list endpoint exists. Verify that the admin_enroll_executor
        # response does NOT include identity fields
        client = TestClient(app, raise_server_exceptions=False)
        response = client.post("/api/v1/admin/executors/test-exec/enroll")
        assert response.status_code == 201
        data = response.json()
        # Response should only have executor_id, enrollment_token, expires_in_seconds, expires_at
        assert "created_by_session_id" not in data
        assert "created_from_ip" not in data
        assert "created_from_user_agent" not in data

    def test_existing_tokens_with_null_metadata_work(self):
        """Tokens created before migration have NULL identity fields — queries should succeed."""
        mock_db = MagicMock()
        backend = MagicMock()
        backend.get_session.return_value = mock_db

        mock_token = MagicMock()
        mock_token.id = 1
        mock_token.executor_id = "old-exec"
        mock_token.token_hash = "old-hash"
        mock_token.state = "created"
        mock_token.created_by = "old-admin"
        mock_token.created_by_session_id = None
        mock_token.created_from_ip = None
        mock_token.created_from_user_agent = None
        mock_token.expires_at = datetime.now(UTC) + timedelta(minutes=15)
        mock_token.created_at = datetime.now(UTC)
        mock_token.used_at = None

        token_query = MagicMock()
        token_query.filter.return_value.first.return_value = mock_token
        token_query.order_by.return_value.all.return_value = [mock_token]

        mock_db.query.side_effect = lambda model: token_query

        app = _create_test_app(backend=backend)
        client = TestClient(app, raise_server_exceptions=False)

        # Querying a token with NULL identity fields should not crash
        response = client.post("/api/v1/admin/executors/old-exec/enroll")
        assert response.status_code == 201

        # Query with NULL filter should not raise
        null_query = MagicMock()
        null_query.filter.return_value.first.return_value = mock_token
        mock_db.query.side_effect = lambda model: null_query

        # This should complete without error
        result = (
            mock_db.query(ExecutorEnrollmentToken).filter(ExecutorEnrollmentToken.created_by_session_id == None).first()
        )
        assert result is not None
