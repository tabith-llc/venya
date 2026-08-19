"""Tests for executor_id validation (Issue #9).

Tests cover:
- Shared validator utility: valid IDs, invalid IDs, edge cases
- Heartbeat endpoint: rejects invalid executor_id with 422
- Admin enroll endpoint: rejects invalid executor_id with 400
- Pydantic model: rejects invalid executor_id with 422
- Executor config: rejects invalid executor_id on init
"""

from unittest.mock import MagicMock

import pytest
from fastapi import FastAPI
from starlette.testclient import TestClient

from server.utils.executor_id import (
    EXECUTOR_ID_PATTERN,
    EXECUTOR_ID_MAX_LENGTH,
    EXECUTOR_ID_MIN_LENGTH,
    validate_executor_id,
)


# ---------------------------------------------------------------------------
# Validator utility tests
# ---------------------------------------------------------------------------


class TestValidateExecutorId:
    """Tests for the shared validate_executor_id() function."""

    def test_valid_simple_id(self):
        """Simple lowercase alphanumeric IDs are valid."""
        assert validate_executor_id("ab") == "ab"
        assert validate_executor_id("abc") == "abc"
        assert validate_executor_id("a1b2c3") == "a1b2c3"

    def test_valid_with_hyphens(self):
        """IDs with internal hyphens are valid."""
        assert validate_executor_id("jump-1") == "jump-1"
        assert validate_executor_id("exec-01") == "exec-01"
        assert validate_executor_id("a1-b2-c3") == "a1-b2-c3"
        assert validate_executor_id("venya-exec") == "venya-exec"

    def test_valid_max_length(self):
        """64-character ID is valid."""
        assert validate_executor_id("a" + "-" * 62 + "b") == "a" + "-" * 62 + "b"

    def test_single_char_rejected(self):
        """Single character ID is rejected (min 2)."""
        with pytest.raises(ValueError, match="2-64"):
            validate_executor_id("a")

    def test_two_chars_valid(self):
        """Two character ID is valid (minimum)."""
        assert validate_executor_id("ab") == "ab"

    def test_empty_string_rejected(self):
        """Empty string is rejected."""
        with pytest.raises(ValueError, match="non-empty"):
            validate_executor_id("")

    def test_none_rejected(self):
        """None is rejected."""
        with pytest.raises(ValueError, match="non-empty"):
            validate_executor_id(None)  # type: ignore

    def test_uppercase_rejected(self):
        """Uppercase letters are rejected."""
        for char in "ABCDEFGHIJKLMNOPQRSTUVWXYZ":
            with pytest.raises(ValueError):
                validate_executor_id(f"J{char}mp")

    def test_underscore_rejected(self):
        """Underscores are rejected."""
        with pytest.raises(ValueError, match="lowercase"):
            validate_executor_id("jump_1")
        with pytest.raises(ValueError, match="lowercase"):
            validate_executor_id("jump_1_test")

    def test_leading_hyphen_rejected(self):
        """Leading hyphen is rejected."""
        with pytest.raises(ValueError, match="lowercase"):
            validate_executor_id("-jump1")

    def test_trailing_hyphen_rejected(self):
        """Trailing hyphen is rejected."""
        with pytest.raises(ValueError, match="lowercase"):
            validate_executor_id("jump1-")

    def test_special_chars_rejected(self):
        """Special characters are rejected."""
        for bad in ["jump;DROP TABLE", "jump' OR '1'='1", "jump!@#$"]:
            with pytest.raises(ValueError):
                validate_executor_id(bad)

    def test_shell_metacharacters_rejected(self):
        """Shell metacharacters are rejected."""
        with pytest.raises(ValueError):
            validate_executor_id("jump1$(whoami)")
        with pytest.raises(ValueError):
            validate_executor_id("jump1`id`")
        with pytest.raises(ValueError):
            validate_executor_id("jump1|cat /etc/passwd")

    def test_newline_injection_rejected(self):
        """Newline injection is rejected."""
        with pytest.raises(ValueError):
            validate_executor_id("jump1\nmalicious")
        with pytest.raises(ValueError):
            validate_executor_id("jump1\rmalicious")

    def test_sql_injection_rejected(self):
        """SQL injection payloads are rejected."""
        with pytest.raises(ValueError):
            validate_executor_id("jump1'; DROP TABLE users; --")
        with pytest.raises(ValueError):
            validate_executor_id("admin'--")

    def test_too_long_rejected(self):
        """65+ character ID is rejected."""
        with pytest.raises(ValueError, match="64"):
            validate_executor_id("a" * 65)

    def test_max_length_exactly_64_valid(self):
        """Exactly 64 characters is valid."""
        validate_executor_id("a" * 64)  # Should not raise

    def test_valid_id_roundtrip(self):
        """Valid IDs pass through unchanged."""
        for valid_id in ["ab", "jump-1", "exec-01", "a1-b2-c3", "venya-exec"]:
            assert validate_executor_id(valid_id) == valid_id


# ---------------------------------------------------------------------------
# Heartbeat endpoint tests (P0 — unauthenticated)
# ---------------------------------------------------------------------------


class TestHeartbeatValidation:
    """Tests for heartbeat endpoint executor_id validation."""

    def _create_app(self, with_backend=False):
        from server.routes import executors as executors_routes

        app = FastAPI()
        if with_backend:
            backend = MagicMock()
            db = MagicMock()
            db.query.return_value.filter.return_value.first.return_value = None
            backend.get_session.return_value = db
            app.state.backend = backend
        app.include_router(executors_routes.router, prefix="/api/v1")
        return app

    def test_heartbeat_valid_executor_id(self):
        """Valid executor_id is accepted (returns 503 for missing backend, not 422)."""
        app = self._create_app()
        client = TestClient(app, raise_server_exceptions=False)
        resp = client.post(
            "/api/v1/heartbeat",
            json={"executor_id": "test-exec-1", "cert_fingerprint": "abc"},
        )
        # Returns 503 because no backend is configured, but validation passed (not 422)
        assert resp.status_code == 503

    def test_heartbeat_uppercase_rejected(self):
        """Uppercase executor_id returns 422."""
        app = self._create_app(with_backend=True)
        client = TestClient(app, raise_server_exceptions=False)
        resp = client.post(
            "/api/v1/heartbeat",
            json={"executor_id": "Jump-1", "cert_fingerprint": "abc"},
        )
        assert resp.status_code == 422
        data = resp.json()
        assert any("executor_id" in str(d.get("loc", "")) for d in data.get("detail", []))

    def test_heartbeat_underscore_rejected(self):
        """Underscore in executor_id returns 422."""
        app = self._create_app(with_backend=True)
        client = TestClient(app, raise_server_exceptions=False)
        resp = client.post(
            "/api/v1/heartbeat",
            json={"executor_id": "jump_1", "cert_fingerprint": "abc"},
        )
        assert resp.status_code == 422

    def test_heartbeat_leading_hyphen_rejected(self):
        """Leading hyphen in executor_id returns 422."""
        app = self._create_app(with_backend=True)
        client = TestClient(app, raise_server_exceptions=False)
        resp = client.post(
            "/api/v1/heartbeat",
            json={"executor_id": "-jump1", "cert_fingerprint": "abc"},
        )
        assert resp.status_code == 422

    def test_heartbeat_trailing_hyphen_rejected(self):
        """Trailing hyphen in executor_id returns 422."""
        app = self._create_app(with_backend=True)
        client = TestClient(app, raise_server_exceptions=False)
        resp = client.post(
            "/api/v1/heartbeat",
            json={"executor_id": "jump1-", "cert_fingerprint": "abc"},
        )
        assert resp.status_code == 422

    def test_heartbeat_empty_rejected(self):
        """Empty executor_id returns 422."""
        app = self._create_app(with_backend=True)
        client = TestClient(app, raise_server_exceptions=False)
        resp = client.post(
            "/api/v1/heartbeat",
            json={"executor_id": "", "cert_fingerprint": "abc"},
        )
        assert resp.status_code == 422

    def test_heartbeat_single_char_rejected(self):
        """Single character executor_id returns 422."""
        app = self._create_app(with_backend=True)
        client = TestClient(app, raise_server_exceptions=False)
        resp = client.post(
            "/api/v1/heartbeat",
            json={"executor_id": "a", "cert_fingerprint": "abc"},
        )
        assert resp.status_code == 422

    def test_heartbeat_sql_injection_rejected(self):
        """SQL injection in executor_id returns 422."""
        app = self._create_app(with_backend=True)
        client = TestClient(app, raise_server_exceptions=False)
        resp = client.post(
            "/api/v1/heartbeat",
            json={"executor_id": "jump1'; DROP TABLE users; --", "cert_fingerprint": "abc"},
        )
        assert resp.status_code == 422

    def test_heartbeat_shell_metachar_rejected(self):
        """Shell metacharacters in executor_id returns 422."""
        app = self._create_app(with_backend=True)
        client = TestClient(app, raise_server_exceptions=False)
        resp = client.post(
            "/api/v1/heartbeat",
            json={"executor_id": "jump1$(whoami)", "cert_fingerprint": "abc"},
        )
        assert resp.status_code == 422


# ---------------------------------------------------------------------------
# Admin enroll endpoint tests (P0 — high-impact)
# ---------------------------------------------------------------------------


class TestAdminEnrollValidation:
    """Tests for admin enroll endpoint executor_id validation."""

    def _create_app(self, backend=None):
        from server.routes import admin as admin_routes
        from server.config import ServerConfig
        from server.dependencies import get_current_user, require_admin

        app = FastAPI()
        if backend is None:
            backend = MagicMock()
            backend.get_session.return_value = MagicMock()
        app.state.backend = backend
        app.state.config = ServerConfig(recovery_code_pepper="test-pepper")
        # Mock core for encrypt() — returns valid tuple for encrypted metadata
        mock_core = MagicMock()
        mock_core.encrypt.return_value = (b"wrapped_dek", b"nonce", b"ciphertext")
        app.state.core = mock_core
        app.include_router(admin_routes.router, prefix="/api/v1")

        # Override auth deps so require_admin bypasses real auth
        _admin_user = {"user_id": "admin-1"}
        app.dependency_overrides[get_current_user] = lambda: _admin_user
        app.dependency_overrides[require_admin] = lambda: _admin_user
        return app

    def test_enroll_valid_executor_id(self):
        """Valid executor_id is accepted."""
        from unittest.mock import MagicMock

        mock_db = MagicMock()
        backend = MagicMock()
        backend.get_session.return_value = mock_db
        app = self._create_app(backend=backend)

        client = TestClient(app, raise_server_exceptions=False)
        response = client.post("/api/v1/admin/executors/jump-1/enroll")
        assert response.status_code == 201

    def test_enroll_uppercase_rejected(self):
        """Uppercase executor_id returns 400."""
        app = self._create_app()
        client = TestClient(app, raise_server_exceptions=False)
        response = client.post("/api/v1/admin/executors/Jump-1/enroll")
        assert response.status_code == 400

    def test_enroll_underscore_rejected(self):
        """Underscore in executor_id returns 400."""
        app = self._create_app()
        client = TestClient(app, raise_server_exceptions=False)
        response = client.post("/api/v1/admin/executors/jump_1/enroll")
        assert response.status_code == 400

    def test_enroll_leading_hyphen_rejected(self):
        """Leading hyphen in executor_id returns 400."""
        app = self._create_app()
        client = TestClient(app, raise_server_exceptions=False)
        response = client.post("/api/v1/admin/executors/-jump1/enroll")
        assert response.status_code == 400

    def test_enroll_trailing_hyphen_rejected(self):
        """Trailing hyphen in executor_id returns 400."""
        app = self._create_app()
        client = TestClient(app, raise_server_exceptions=False)
        response = client.post("/api/v1/admin/executors/jump1-/enroll")
        assert response.status_code == 400

    def test_enroll_sql_injection_rejected(self):
        """SQL injection in executor_id returns 400."""
        app = self._create_app()
        client = TestClient(app, raise_server_exceptions=False)
        response = client.post("/api/v1/admin/executors/jump1';--/enroll")
        assert response.status_code == 400


# ---------------------------------------------------------------------------
# Pydantic model tests
# ---------------------------------------------------------------------------


class TestPydanticModelValidation:
    """Tests for Pydantic model executor_id validation."""

    def test_register_request_valid_id(self):
        """Valid executor_id passes Pydantic validation."""
        from server.routes.executors import ExecutorRegisterRequest

        req = ExecutorRegisterRequest(
            executor_id="test-exec-1",
            csr_pem="-----BEGIN CERTIFICATE REQUEST-----\ntest\n-----END CERTIFICATE REQUEST-----",
        )
        assert req.executor_id == "test-exec-1"

    def test_register_request_uppercase_rejected(self):
        """Uppercase executor_id fails Pydantic validation."""
        from server.routes.executors import ExecutorRegisterRequest

        with pytest.raises(Exception):  # ValidationError
            ExecutorRegisterRequest(
                executor_id="Jump-1",
                csr_pem="-----BEGIN CERTIFICATE REQUEST-----\ntest\n-----END CERTIFICATE REQUEST-----",
            )

    def test_register_request_underscore_rejected(self):
        """Underscore in executor_id fails Pydantic validation."""
        from server.routes.executors import ExecutorRegisterRequest

        with pytest.raises(Exception):  # ValidationError
            ExecutorRegisterRequest(
                executor_id="jump_1",
                csr_pem="-----BEGIN CERTIFICATE REQUEST-----\ntest\n-----END CERTIFICATE REQUEST-----",
            )

    def test_register_request_leading_hyphen_rejected(self):
        """Leading hyphen fails Pydantic validation."""
        from server.routes.executors import ExecutorRegisterRequest

        with pytest.raises(Exception):  # ValidationError
            ExecutorRegisterRequest(
                executor_id="-jump1",
                csr_pem="-----BEGIN CERTIFICATE REQUEST-----\ntest\n-----END CERTIFICATE REQUEST-----",
            )

    def test_register_request_trailing_hyphen_rejected(self):
        """Trailing hyphen fails Pydantic validation."""
        from server.routes.executors import ExecutorRegisterRequest

        with pytest.raises(Exception):  # ValidationError
            ExecutorRegisterRequest(
                executor_id="jump1-",
                csr_pem="-----BEGIN CERTIFICATE REQUEST-----\ntest\n-----END CERTIFICATE REQUEST-----",
            )

    def test_register_request_single_char_rejected(self):
        """Single character executor_id fails Pydantic validation."""
        from server.routes.executors import ExecutorRegisterRequest

        with pytest.raises(Exception):  # ValidationError
            ExecutorRegisterRequest(
                executor_id="a",
                csr_pem="-----BEGIN CERTIFICATE REQUEST-----\ntest\n-----END CERTIFICATE REQUEST-----",
            )

    def test_register_request_too_long_rejected(self):
        """65-character executor_id fails Pydantic validation."""
        from server.routes.executors import ExecutorRegisterRequest

        with pytest.raises(Exception):  # ValidationError
            ExecutorRegisterRequest(
                executor_id="a" * 65,
                csr_pem="-----BEGIN CERTIFICATE REQUEST-----\ntest\n-----END CERTIFICATE REQUEST-----",
            )

    def test_register_request_64_chars_valid(self):
        """64-character executor_id passes Pydantic validation."""
        from server.routes.executors import ExecutorRegisterRequest

        req = ExecutorRegisterRequest(
            executor_id="a" * 64,
            csr_pem="-----BEGIN CERTIFICATE REQUEST-----\ntest\n-----END CERTIFICATE REQUEST-----",
        )
        assert len(req.executor_id) == 64

    def test_register_request_sql_injection_rejected(self):
        """SQL injection in executor_id fails Pydantic validation."""
        from server.routes.executors import ExecutorRegisterRequest

        with pytest.raises(Exception):  # ValidationError
            ExecutorRegisterRequest(
                executor_id="jump1'; DROP TABLE; --",
                csr_pem="-----BEGIN CERTIFICATE REQUEST-----\ntest\n-----END CERTIFICATE REQUEST-----",
            )


# ---------------------------------------------------------------------------
# Executor config tests
# ---------------------------------------------------------------------------


class TestExecutorConfigValidation:
    """Tests for executor config executor_id validation."""

    def test_config_valid_executor_id(self):
        """Valid executor_id passes config validation."""
        from executor.config import ExecutorConfig

        config = ExecutorConfig(server_url="https://test.example.com")
        # Default is "default" which is valid
        assert config.executor_id == "default"

    def test_config_valid_custom_id(self):
        """Custom valid executor_id passes config validation."""
        from executor.config import ExecutorConfig

        config = ExecutorConfig(server_url="https://test.example.com", executor_id="jump-1")
        assert config.executor_id == "jump-1"

    def test_config_underscore_rejected(self):
        """Underscore in executor_id fails config validation."""
        from executor.config import ExecutorConfig

        with pytest.raises(ValueError, match="lowercase"):
            ExecutorConfig(server_url="https://test.example.com", executor_id="jump_1")

    def test_config_leading_hyphen_rejected(self):
        """Leading hyphen in executor_id fails config validation."""
        from executor.config import ExecutorConfig

        with pytest.raises(ValueError, match="lowercase"):
            ExecutorConfig(server_url="https://test.example.com", executor_id="-jump1")

    def test_config_trailing_hyphen_rejected(self):
        """Trailing hyphen in executor_id fails config validation."""
        from executor.config import ExecutorConfig

        with pytest.raises(ValueError, match="lowercase"):
            ExecutorConfig(server_url="https://test.example.com", executor_id="jump1-")

    def test_config_uppercase_rejected(self):
        """Uppercase in executor_id fails config validation."""
        from executor.config import ExecutorConfig

        with pytest.raises(ValueError, match="lowercase"):
            ExecutorConfig(server_url="https://test.example.com", executor_id="Jump-1")

    def test_config_single_char_rejected(self):
        """Single character executor_id fails config validation."""
        from executor.config import ExecutorConfig

        with pytest.raises(ValueError, match="2-64"):
            ExecutorConfig(server_url="https://test.example.com", executor_id="a")

    def test_config_empty_rejected(self):
        """Empty executor_id fails config validation."""
        from executor.config import ExecutorConfig

        with pytest.raises(ValueError, match="2-64"):
            ExecutorConfig(server_url="https://test.example.com", executor_id="")

    def test_config_too_long_rejected(self):
        """65-character executor_id fails config validation."""
        from executor.config import ExecutorConfig

        with pytest.raises(ValueError, match="2-64"):
            ExecutorConfig(server_url="https://test.example.com", executor_id="a" * 65)
