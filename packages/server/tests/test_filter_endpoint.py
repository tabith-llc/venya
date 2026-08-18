"""Tests for filter endpoint."""

from types import SimpleNamespace
from unittest.mock import MagicMock

from fastapi import FastAPI
from starlette.testclient import TestClient

from server.routes import filter as filter_routes


def _create_test_app(backend=None):
    """Create a minimal test app with filter route."""
    from starlette.middleware.base import BaseHTTPMiddleware
    from starlette.requests import Request

    app = FastAPI()
    if backend is not None:
        app.state.backend = backend
    app.include_router(filter_routes.router, prefix="/api/v1")

    class AuthMiddleware(BaseHTTPMiddleware):
        async def dispatch(self, request: Request, call_next):
            return await call_next(request)

    app.add_middleware(AuthMiddleware)
    return app


class TestFilterSessionOutput:
    """Tests for filter endpoint."""

    def test_filter_no_secrets(self):
        """POST /sessions/{id}/filter should return output unmodified when no secrets."""
        session = SimpleNamespace(id=123, user_id="user1")
        secret = SimpleNamespace(id=1, key="mysecretkey", created_by="user1")

        class MockQuery:
            def filter(self, *args, **kwargs):
                return self
            def first(self):
                return session
            def all(self):
                return [secret]

        db = MagicMock()
        db.query.return_value = MockQuery()

        backend = MagicMock()
        backend.get_session.return_value = db
        app = _create_test_app(backend=backend)

        client = TestClient(app, raise_server_exceptions=False)
        import base64
        stdout = base64.b64encode(b"hello world").decode()
        stderr = base64.b64encode(b"error msg").decode()
        resp = client.post(
            "/api/v1/sessions/sess-123/filter",
            json={"stdout": stdout, "stderr": stderr},
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["stdout"] == stdout
        assert data["stderr"] == stderr

    def test_filter_no_backend(self):
        """POST /sessions/{id}/filter should return 503 if no backend."""
        app = _create_test_app()

        client = TestClient(app, raise_server_exceptions=False)
        resp = client.post(
            "/api/v1/sessions/sess-123/filter",
            json={"stdout": "aGVsbG8=", "stderr": "d29ybGQ="},
        )
        assert resp.status_code == 503

    def test_filter_invalid_b64(self):
        """POST /sessions/{id}/filter should handle invalid base64 gracefully."""
        session = SimpleNamespace(id=123, user_id="user1")

        class MockQuery:
            def filter(self, *args, **kwargs):
                return self
            def first(self):
                return session
            def all(self):
                return []

        db = MagicMock()
        db.query.return_value = MockQuery()

        backend = MagicMock()
        backend.get_session.return_value = db
        app = _create_test_app(backend=backend)

        client = TestClient(app, raise_server_exceptions=False)
        resp = client.post(
            "/api/v1/sessions/sess-123/filter",
            json={"stdout": "not-valid-base64!!!", "stderr": "also!invalid"},
        )
        assert resp.status_code == 200
        data = resp.json()
        # Should return empty output for invalid base64
        assert data["stdout"] == ""
        assert data["stderr"] == ""

    def test_filter_with_session_no_secrets(self):
        """POST /sessions/{id}/filter should handle session with no secrets."""
        session = SimpleNamespace(id=123, user_id="user1")

        class MockQuery:
            def filter(self, *args, **kwargs):
                return self
            def first(self):
                return session
            def all(self):
                return []

        db = MagicMock()
        db.query.return_value = MockQuery()

        backend = MagicMock()
        backend.get_session.return_value = db
        app = _create_test_app(backend=backend)

        client = TestClient(app, raise_server_exceptions=False)
        import base64
        stdout = base64.b64encode(b"output with no secrets").decode()
        stderr = base64.b64encode(b"stderr clean").decode()
        resp = client.post(
            "/api/v1/sessions/sess-123/filter",
            json={"stdout": stdout, "stderr": stderr},
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["stdout"] == stdout
        assert data["masked_count"] == 0

    def test_filter_redacts_decrypted_secret_value(self):
        """POST /sessions/{id}/filter should redact decrypted secret values, not key names."""
        import base64
        from unittest.mock import patch

        session = SimpleNamespace(id=123, user_id="user1")

        # The actual secret value that should be redacted
        secret_value = b"AKIAIOSFODNN7EXAMPLE"
        secret_key_name = "aws_api_key"

        # Mock secret with encrypted fields
        secret = SimpleNamespace(
            id=1,
            key=secret_key_name,
            created_by="user1",
            encrypted_value=b"encrypted_data",
            nonce=b"nonce12345678901",
            wrapped_dek=b"wrapped_dk12345678",
        )

        class MockQuery:
            def filter(self, *args, **kwargs):
                return self
            def first(self):
                return session
            def all(self):
                return [secret]

        db = MagicMock()
        db.query.return_value = MockQuery()

        backend = MagicMock()
        backend.get_session.return_value = db
        backend.config.kek = b"A" * 32  # 32-byte KEK
        app = _create_test_app(backend=backend)

        client = TestClient(app, raise_server_exceptions=False)

        # Output contains the plaintext secret value
        stdout_with_secret = base64.b64encode(
            b"running command, output: AKIAIOSFODNN7EXAMPLE done"
        ).decode()
        stderr = base64.b64encode(b"clean stderr").decode()

        with patch(
            "core.engine.encryption.decrypt_secret"
        ) as mock_decrypt:
            mock_decrypt.return_value = secret_value

            # Use integer session ID so session lookup executes
            resp = client.post(
                "/api/v1/sessions/123/filter",
                json={"stdout": stdout_with_secret, "stderr": stderr},
            )

        assert resp.status_code == 200
        data = resp.json()
        decoded_stdout = base64.b64decode(data["stdout"]).decode()
        # The secret value should be redacted
        assert "AKIAIOSFODNN7EXAMPLE" not in decoded_stdout
        assert "[REDACTED:" in decoded_stdout
        # The key name should NOT be redacted (it wasn't in the output anyway)
        assert data["masked_count"] == 1

    def test_filter_skips_undecryptable_secret(self):
        """POST /sessions/{id}/filter should skip secrets that fail decryption."""
        import base64
        from unittest.mock import patch

        session = SimpleNamespace(id=123, user_id="user1")

        secret = SimpleNamespace(
            id=1,
            key="mysecret",
            created_by="user1",
            encrypted_value=b"encrypted_data",
            nonce=b"nonce12345678901",
            wrapped_dek=b"wrapped_dk12345678",
        )

        class MockQuery:
            def filter(self, *args, **kwargs):
                return self
            def first(self):
                return session
            def all(self):
                return [secret]

        db = MagicMock()
        db.query.return_value = MockQuery()

        backend = MagicMock()
        backend.get_session.return_value = db
        backend.config.kek = b"A" * 32
        app = _create_test_app(backend=backend)

        client = TestClient(app, raise_server_exceptions=False)

        stdout = base64.b64encode(b"output with secret AKIAIOSFODNN7EXAMPLE here").decode()
        stderr = base64.b64encode(b"clean").decode()

        from core.engine.encryption import DecryptionError

        with patch(
            "core.engine.encryption.decrypt_secret"
        ) as mock_decrypt:
            mock_decrypt.side_effect = DecryptionError("invalid tag")

            resp = client.post(
                "/api/v1/sessions/123/filter",
                json={"stdout": stdout, "stderr": stderr},
            )

        assert resp.status_code == 200
        data = resp.json()
        # Output should be unmodified since decryption failed
        assert data["stdout"] == stdout
        assert data["masked_count"] == 0

    def test_filter_skips_when_no_kek(self):
        """POST /sessions/{id}/filter should skip secrets when KEK is None."""
        import base64

        session = SimpleNamespace(id=123, user_id="user1")

        secret = SimpleNamespace(
            id=1,
            key="mysecret",
            created_by="user1",
            encrypted_value=b"encrypted_data",
            nonce=b"nonce12345678901",
            wrapped_dek=b"wrapped_dk12345678",
        )

        class MockQuery:
            def filter(self, *args, **kwargs):
                return self
            def first(self):
                return session
            def all(self):
                return [secret]

        db = MagicMock()
        db.query.return_value = MockQuery()

        backend = MagicMock()
        backend.get_session.return_value = db
        backend.config.kek = None
        app = _create_test_app(backend=backend)

        client = TestClient(app, raise_server_exceptions=False)

        stdout = base64.b64encode(b"output with secret AKIAIOSFODNN7EXAMPLE here").decode()
        stderr = base64.b64encode(b"clean").decode()

        resp = client.post(
            "/api/v1/sessions/123/filter",
            json={"stdout": stdout, "stderr": stderr},
        )

        assert resp.status_code == 200
        data = resp.json()
        assert data["stdout"] == stdout
        assert data["masked_count"] == 0
