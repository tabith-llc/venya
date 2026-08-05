"""Integration tests for executor daemon + server filter pipeline.

Tests the full flow: executor captures command output → sends to server
filter endpoint → secrets detected and masked → sanitized output returned.
"""

import base64
import hashlib
from types import SimpleNamespace
from unittest.mock import MagicMock

from fastapi import FastAPI
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.testclient import TestClient

from server.routes import filter as filter_routes


# ---------------------------------------------------------------------------
# Test app factory
# ---------------------------------------------------------------------------


def _create_test_app(backend=None, auth_user=None):
    """Create a minimal test app with filter route."""
    app = FastAPI()
    if backend is not None:
        app.state.backend = backend
    app.include_router(filter_routes.router, prefix="/api/v1")

    class AuthMiddleware(BaseHTTPMiddleware):
        async def dispatch(self, request: Request, call_next):
            if auth_user is not None:
                request.state.auth_user = auth_user
            return await call_next(request)

    app.add_middleware(AuthMiddleware)
    return app


def _make_mock_session(user_id="user1"):
    """Create a mock session object."""
    return SimpleNamespace(id=1, user_id=user_id)


def _make_mock_secret(key="api-key", created_by="user1"):
    """Create a mock secret object."""
    secret = SimpleNamespace(id=1, key=key, created_by=created_by)
    return secret


def _make_backend(session=None, secrets=None):
    """Create a mock backend with session and secrets."""
    if secrets is None:
        secrets = [_make_mock_secret()]

    class MockQuery:
        def __init__(self, results):
            self.results = results

        def filter(self, *args, **kwargs):
            return self

        def first(self):
            return session

        def all(self):
            return secrets

    db = MagicMock()
    db.query.return_value = MockQuery(secrets)
    db.get_session.return_value = db

    backend = MagicMock()
    backend.get_session.return_value = db
    return backend


# ---------------------------------------------------------------------------
# Stage 2 integration: executor → server filter
# ---------------------------------------------------------------------------


class TestStage2FilterIntegration:
    """Integration tests for the executor Stage 2 filter pipeline.

    These tests simulate the full flow where an executor sends captured
    command output to the server for definitive secret filtering.
    """

    def test_stage2_detects_raw_secret_in_stdout(self):
        """Executor sends output containing raw secret — server detects and masks."""
        secret_key = "my-api-key"
        secret_bytes = secret_key.encode()
        secret_hash = hashlib.sha256(secret_bytes).hexdigest()

        session = _make_mock_session()
        secret = _make_mock_secret(key=secret_key)
        backend = _make_backend(session=session, secrets=[secret])
        app = _create_test_app(backend=backend)

        client = TestClient(app, raise_server_exceptions=False)
        stdout = base64.b64encode(b"Connecting with my-api-key to server").decode()
        stderr = base64.b64encode(b"no error").decode()

        resp = client.post(
            "/api/v1/sessions/1/filter",
            json={"stdout": stdout, "stderr": stderr},
        )

        assert resp.status_code == 200
        data = resp.json()
        decoded_stdout = base64.b64decode(data["stdout"])
        assert secret_bytes not in decoded_stdout
        assert f"[REDACTED:{secret_hash[:8]}]".encode() in decoded_stdout
        assert data["masked_count"] >= 1
        assert secret_hash[:8] in data["masked_hashes"]

    def test_stage2_detects_secret_in_stderr(self):
        """Executor sends output containing secret in stderr — server detects and masks."""
        secret_key = "db-password"
        secret_bytes = secret_key.encode()
        secret_hash = hashlib.sha256(secret_bytes).hexdigest()

        session = _make_mock_session()
        secret = _make_mock_secret(key=secret_key)
        backend = _make_backend(session=session, secrets=[secret])
        app = _create_test_app(backend=backend)

        client = TestClient(app, raise_server_exceptions=False)
        stdout = base64.b64encode(b"command ran ok").decode()
        stderr = base64.b64encode(b"ERROR: password db-password rejected").decode()

        resp = client.post(
            "/api/v1/sessions/1/filter",
            json={"stdout": stdout, "stderr": stderr},
        )

        assert resp.status_code == 200
        data = resp.json()
        decoded_stderr = base64.b64decode(data["stderr"])
        assert secret_bytes not in decoded_stderr
        assert data["masked_count"] >= 1

    def test_stage2_detects_base64_encoded_secret(self):
        """Secret appearing as base64 in output is detected."""
        secret_key = "b64-secret-key"
        secret_bytes = secret_key.encode()
        secret_hash = hashlib.sha256(secret_bytes).hexdigest()
        b64_secret = base64.b64encode(secret_bytes).decode()

        session = _make_mock_session()
        secret = _make_mock_secret(key=secret_key)
        backend = _make_backend(session=session, secrets=[secret])
        app = _create_test_app(backend=backend)

        client = TestClient(app, raise_server_exceptions=False)
        stdout = base64.b64encode(f"config: {b64_secret} end".encode()).decode()
        stderr = base64.b64encode(b"clean").decode()

        resp = client.post(
            "/api/v1/sessions/1/filter",
            json={"stdout": stdout, "stderr": stderr},
        )

        assert resp.status_code == 200
        data = resp.json()
        decoded_stdout = base64.b64decode(data["stdout"])
        assert b64_secret.encode() not in decoded_stdout
        assert data["masked_count"] >= 1

    def test_stage2_detects_hex_encoded_secret(self):
        """Secret appearing as hex in output is detected."""
        secret_key = "hex-secret"
        secret_bytes = secret_key.encode()
        hex_secret = secret_bytes.hex().encode()

        session = _make_mock_session()
        secret = _make_mock_secret(key=secret_key)
        backend = _make_backend(session=session, secrets=[secret])
        app = _create_test_app(backend=backend)

        client = TestClient(app, raise_server_exceptions=False)
        stdout = base64.b64encode(f"data: {hex_secret.decode()} done".encode()).decode()
        stderr = base64.b64encode(b"ok").decode()

        resp = client.post(
            "/api/v1/sessions/1/filter",
            json={"stdout": stdout, "stderr": stderr},
        )

        assert resp.status_code == 200
        data = resp.json()
        decoded_stdout = base64.b64decode(data["stdout"])
        assert hex_secret not in decoded_stdout
        assert data["masked_count"] >= 1

    def test_stage2_multiple_secrets_all_masked(self):
        """Multiple secrets in output — all detected and masked."""
        secret1_key = "api-key-one"
        secret2_key = "api-key-two"
        secret1_bytes = secret1_key.encode()
        secret2_bytes = secret2_key.encode()

        session = _make_mock_session()
        secrets = [
            _make_mock_secret(key=secret1_key),
            _make_mock_secret(key=secret2_key),
        ]
        backend = _make_backend(session=session, secrets=secrets)
        app = _create_test_app(backend=backend)

        client = TestClient(app, raise_server_exceptions=False)
        stdout = base64.b64encode(
            f"key1={secret1_key} key2={secret2_key} end".encode()
        ).decode()
        stderr = base64.b64encode(b"clean").decode()

        resp = client.post(
            "/api/v1/sessions/1/filter",
            json={"stdout": stdout, "stderr": stderr},
        )

        assert resp.status_code == 200
        data = resp.json()
        decoded_stdout = base64.b64decode(data["stdout"])
        assert secret1_bytes not in decoded_stdout
        assert secret2_bytes not in decoded_stdout
        assert data["masked_count"] >= 2

    def test_stage2_no_secrets_in_output(self):
        """Output with no secrets — returns unmodified."""
        session = _make_mock_session()
        secret = _make_mock_secret(key="not-in-output")
        backend = _make_backend(session=session, secrets=[secret])
        app = _create_test_app(backend=backend)

        client = TestClient(app, raise_server_exceptions=False)
        stdout = base64.b64encode(b"all clear, nothing to see").decode()
        stderr = base64.b64encode(b"clean stderr").decode()

        resp = client.post(
            "/api/v1/sessions/1/filter",
            json={"stdout": stdout, "stderr": stderr},
        )

        assert resp.status_code == 200
        data = resp.json()
        assert data["stdout"] == stdout
        assert data["stderr"] == stderr
        assert data["masked_count"] == 0
        assert data["masked_hashes"] == []

    def test_stage2_session_no_secrets(self):
        """Session exists but has no secrets — output passes through."""
        session = _make_mock_session()

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
        stdout = base64.b64encode(b"output with api-key-123").decode()
        stderr = base64.b64encode(b"clean").decode()

        resp = client.post(
            "/api/v1/sessions/1/filter",
            json={"stdout": stdout, "stderr": stderr},
        )

        assert resp.status_code == 200
        data = resp.json()
        assert data["stdout"] == stdout
        assert data["masked_count"] == 0

    def test_stage2_nonexistent_session(self):
        """Session not found — output passes through unfiltered."""
        session = None

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
        stdout = base64.b64encode(b"output with secret-value").decode()
        stderr = base64.b64encode(b"clean").decode()

        resp = client.post(
            "/api/v1/sessions/99999/filter",
            json={"stdout": stdout, "stderr": stderr},
        )

        assert resp.status_code == 200
        data = resp.json()
        assert data["stdout"] == stdout
        assert data["masked_count"] == 0

    def test_stage2_user_scoping_secrets(self):
        """Only secrets belonging to the session's user are filtered."""
        session = _make_mock_session(user_id="user1")
        secret_user1 = _make_mock_secret(key="user1-key", created_by="user1")
        secret_user2 = _make_mock_secret(key="user2-key", created_by="user2")

        class MockQuery:
            def __init__(self, results):
                self.results = results

            def filter(self, *args, **kwargs):
                return self

            def first(self):
                return session

            def all(self):
                return self.results

        db = MagicMock()
        db.query.return_value = MockQuery([secret_user1, secret_user2])

        backend = MagicMock()
        backend.get_session.return_value = db
        app = _create_test_app(backend=backend)

        client = TestClient(app, raise_server_exceptions=False)
        # Output contains both secrets — only user1's should be masked
        stdout = base64.b64encode(
            f"user1: user1-key user2: user2-key end".encode()
        ).decode()
        stderr = base64.b64encode(b"clean").decode()

        resp = client.post(
            "/api/v1/sessions/1/filter",
            json={"stdout": stdout, "stderr": stderr},
        )

        assert resp.status_code == 200
        data = resp.json()
        decoded_stdout = base64.b64decode(data["stdout"])
        assert b"user1-key" not in decoded_stdout  # user1's secret masked
        assert data["masked_count"] >= 1

    def test_stage2_same_secret_multiple_times(self):
        """Same secret appearing multiple times — all occurrences masked, ID reported once."""
        secret_key = "repeated-key"
        secret_bytes = secret_key.encode()

        session = _make_mock_session()
        secret = _make_mock_secret(key=secret_key)
        backend = _make_backend(session=session, secrets=[secret])
        app = _create_test_app(backend=backend)

        client = TestClient(app, raise_server_exceptions=False)
        stdout = base64.b64encode(
            f"{secret_key} {secret_key} {secret_key} end".encode()
        ).decode()
        stderr = base64.b64encode(b"clean").decode()

        resp = client.post(
            "/api/v1/sessions/1/filter",
            json={"stdout": stdout, "stderr": stderr},
        )

        assert resp.status_code == 200
        data = resp.json()
        decoded_stdout = base64.b64decode(data["stdout"])
        assert secret_bytes not in decoded_stdout
        # All occurrences should be replaced with redaction markers
        assert decoded_stdout.count(b"[REDACTED:") == 3

    def test_stage2_large_output(self):
        """Large output (near 256KB limit) is filtered correctly."""
        secret_key = "large-secret"
        secret_bytes = secret_key.encode()

        session = _make_mock_session()
        secret = _make_mock_secret(key=secret_key)
        backend = _make_backend(session=session, secrets=[secret])
        app = _create_test_app(backend=backend)

        client = TestClient(app, raise_server_exceptions=False)
        padding = b"X" * 100000
        stdout_content = padding + secret_bytes + padding
        stdout = base64.b64encode(stdout_content).decode()
        stderr = base64.b64encode(b"clean").decode()

        resp = client.post(
            "/api/v1/sessions/1/filter",
            json={"stdout": stdout, "stderr": stderr},
        )

        assert resp.status_code == 200
        data = resp.json()
        decoded_stdout = base64.b64decode(data["stdout"])
        assert secret_bytes not in decoded_stdout
        assert data["masked_count"] >= 1

    def test_stage2_empty_output(self):
        """Empty stdout/stderr returns empty output."""
        backend = _make_backend()
        app = _create_test_app(backend=backend)

        client = TestClient(app, raise_server_exceptions=False)
        resp = client.post(
            "/api/v1/sessions/1/filter",
            json={"stdout": "", "stderr": ""},
        )

        assert resp.status_code == 200
        data = resp.json()
        assert data["stdout"] == ""
        assert data["stderr"] == ""
        assert data["masked_count"] == 0

    def test_stage2_no_backend_returns_503(self):
        """No backend configured — returns 503."""
        app = _create_test_app()

        client = TestClient(app, raise_server_exceptions=False)
        resp = client.post(
            "/api/v1/sessions/1/filter",
            json={"stdout": "aGVsbG8=", "stderr": "d29ybGQ="},
        )

        assert resp.status_code == 503
        assert "Backend not initialized" in resp.json()["detail"]

    def test_stage2_invalid_session_id_string(self):
        """Non-integer session ID — handled gracefully, no secrets loaded."""
        backend = _make_backend()
        app = _create_test_app(backend=backend)

        client = TestClient(app, raise_server_exceptions=False)
        stdout = base64.b64encode(b"output with api-key-123").decode()
        stderr = base64.b64encode(b"clean").decode()

        resp = client.post(
            "/api/v1/sessions/sess-abc-123/filter",
            json={"stdout": stdout, "stderr": stderr},
        )

        assert resp.status_code == 200
        data = resp.json()
        # Non-integer session ID falls through to no secrets loaded
        assert data["stdout"] == stdout
        assert data["masked_count"] == 0

    def test_stage2_both_streams_contain_secrets(self):
        """Secrets in both stdout and stderr — both filtered."""
        secret_stdout_key = "stdout-secret"
        secret_stderr_key = "stderr-secret"

        session = _make_mock_session()
        secrets = [
            _make_mock_secret(key=secret_stdout_key),
            _make_mock_secret(key=secret_stderr_key),
        ]
        backend = _make_backend(session=session, secrets=secrets)
        app = _create_test_app(backend=backend)

        client = TestClient(app, raise_server_exceptions=False)
        stdout = base64.b64encode(f"value: {secret_stdout_key} end".encode()).decode()
        stderr = base64.b64encode(f"err: {secret_stderr_key} end".encode()).decode()

        resp = client.post(
            "/api/v1/sessions/1/filter",
            json={"stdout": stdout, "stderr": stderr},
        )

        assert resp.status_code == 200
        data = resp.json()
        decoded_stdout = base64.b64decode(data["stdout"])
        decoded_stderr = base64.b64decode(data["stderr"])
        assert secret_stdout_key.encode() not in decoded_stdout
        assert secret_stderr_key.encode() not in decoded_stderr
        assert data["masked_count"] >= 2

    def test_stage2_redaction_marker_format(self):
        """Redaction markers follow the [REDACTED:{hash}] format."""
        secret_key = "marker-test-key"
        secret_bytes = secret_key.encode()
        secret_hash = hashlib.sha256(secret_bytes).hexdigest()

        session = _make_mock_session()
        secret = _make_mock_secret(key=secret_key)
        backend = _make_backend(session=session, secrets=[secret])
        app = _create_test_app(backend=backend)

        client = TestClient(app, raise_server_exceptions=False)
        stdout = base64.b64encode(secret_bytes).decode()
        stderr = base64.b64encode(b"clean").decode()

        resp = client.post(
            "/api/v1/sessions/1/filter",
            json={"stdout": stdout, "stderr": stderr},
        )

        assert resp.status_code == 200
        data = resp.json()
        decoded_stdout = base64.b64decode(data["stdout"])
        expected_marker = f"[REDACTED:{secret_hash[:8]}]".encode()
        assert expected_marker in decoded_stdout
        assert secret_bytes not in decoded_stdout

    def test_stage2_executor_pipeline_stdout(self):
        """Simulates executor._send_to_stage2 flow for stdout."""
        secret_key = "pipeline-key"
        secret_bytes = secret_key.encode()

        session = _make_mock_session()
        secret = _make_mock_secret(key=secret_key)
        backend = _make_backend(session=session, secrets=[secret])
        app = _create_test_app(backend=backend)

        client = TestClient(app, raise_server_exceptions=False)

        # Simulate what executor._send_to_stage2 does
        raw_stdout = b"API_TOKEN=pipeline-key endpoint=https://api.example.com"
        raw_stderr = b"Starting pipeline..."
        payload = {
            "stdout": base64.b64encode(raw_stdout).decode(),
            "stderr": base64.b64encode(raw_stderr).decode(),
        }

        resp = client.post(
            "/api/v1/sessions/1/filter",
            json=payload,
        )

        assert resp.status_code == 200
        data = resp.json()

        # Verify response format matches what executor expects
        assert "stdout" in data
        assert "stderr" in data
        assert "masked_hashes" in data

        filtered_stdout = base64.b64decode(data["stdout"])
        filtered_stderr = base64.b64decode(data["stderr"])

        assert secret_bytes not in filtered_stdout
        assert b"API_TOKEN=" in filtered_stdout  # context preserved
        assert b"https://api.example.com" in filtered_stdout

    def test_stage2_executor_pipeline_stderr(self):
        """Simulates executor._send_to_stage2 flow for stderr."""
        secret_key = "error-secret"
        secret_bytes = secret_key.encode()

        session = _make_mock_session()
        secret = _make_mock_secret(key=secret_key)
        backend = _make_backend(session=session, secrets=[secret])
        app = _create_test_app(backend=backend)

        client = TestClient(app, raise_server_exceptions=False)

        raw_stdout = b"command completed"
        raw_stderr = f"Fatal error: {secret_key} is invalid".encode()
        payload = {
            "stdout": base64.b64encode(raw_stdout).decode(),
            "stderr": base64.b64encode(raw_stderr).decode(),
        }

        resp = client.post(
            "/api/v1/sessions/1/filter",
            json=payload,
        )

        assert resp.status_code == 200
        data = resp.json()
        filtered_stderr = base64.b64decode(data["stderr"])
        assert secret_bytes not in filtered_stderr
        assert b"Fatal error:" in filtered_stderr  # context preserved

    def test_stage2_filter_output_function_directly(self):
        """Test filter_output helper function directly."""
        from server.routes.filter import filter_output

        secret_bytes = b"direct-test-secret"
        secret_hash = hashlib.sha256(secret_bytes).hexdigest()
        secret_hashes = {secret_hash: secret_bytes}

        output = b"Using direct-test-secret in config"
        filtered, masked = filter_output(output, secret_hashes)

        assert secret_bytes not in filtered
        assert f"[REDACTED:{secret_hash[:8]}]".encode() in filtered
        assert secret_hash[:8] in masked

    def test_stage2_filter_output_multiple_encodings(self):
        """Test filter_output detects secret in raw, base64, and hex forms."""
        from server.routes.filter import filter_output

        secret_bytes = b"encoding-test"
        secret_hash = hashlib.sha256(secret_bytes).hexdigest()
        secret_hashes = {secret_hash: secret_bytes}

        # Raw form
        filtered, masked = filter_output(
            b"value: encoding-test end", secret_hashes
        )
        assert b"encoding-test" not in filtered

        # Base64 form
        b64_secret = base64.b64encode(secret_bytes)
        filtered, masked = filter_output(
            f"b64: {b64_secret.decode()} end".encode(), secret_hashes
        )
        assert b64_secret not in filtered

        # Hex form
        hex_secret = secret_bytes.hex().encode()
        filtered, masked = filter_output(
            f"hex: {hex_secret.decode()} end".encode(), secret_hashes
        )
        assert hex_secret not in filtered

    def test_stage2_detection_hashes_consistent(self):
        """compute_detection_hashes produces consistent hashes."""
        from server.routes.filter import compute_detection_hashes

        value = b"consistency-check"
        hashes1 = compute_detection_hashes(value)
        hashes2 = compute_detection_hashes(value)

        assert hashes1 == hashes2
        assert len(hashes1) >= 3
        assert hashes1[0] == hashlib.sha256(value).hexdigest()

    def test_stage2_session_secret_lookup_by_user_id(self):
        """Filter endpoint looks up secrets by session user_id."""
        secret_key = "scoped-secret"
        secret_bytes = secret_key.encode()

        session = _make_mock_session(user_id="scoped-user")
        secret = _make_mock_secret(key=secret_key, created_by="scoped-user")

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
        stdout = base64.b64encode(f"config: {secret_key} done".encode()).decode()
        stderr = base64.b64encode(b"ok").decode()

        resp = client.post(
            "/api/v1/sessions/1/filter",
            json={"stdout": stdout, "stderr": stderr},
        )

        assert resp.status_code == 200
        data = resp.json()
        decoded = base64.b64decode(data["stdout"])
        assert secret_bytes not in decoded
        assert data["masked_count"] >= 1

    def test_stage2_db_session_closed_after_use(self):
        """Backend DB session is closed after filter completes."""
        db = MagicMock()
        db.query.return_value.filter.return_value.first.return_value = _make_mock_session()
        db.query.return_value.filter.return_value.all.return_value = []

        backend = MagicMock()
        backend.get_session.return_value = db
        app = _create_test_app(backend=backend)

        client = TestClient(app, raise_server_exceptions=False)
        stdout = base64.b64encode(b"clean output").decode()
        stderr = base64.b64encode(b"clean stderr").decode()

        resp = client.post(
            "/api/v1/sessions/1/filter",
            json={"stdout": stdout, "stderr": stderr},
        )

        assert resp.status_code == 200
        db.close.assert_called_once()

    def test_stage2_invalid_base64_graceful(self):
        """Invalid base64 in request — returns empty output, no crash."""
        backend = _make_backend()
        app = _create_test_app(backend=backend)

        client = TestClient(app, raise_server_exceptions=False)
        resp = client.post(
            "/api/v1/sessions/1/filter",
            json={"stdout": "!!!not-base64!!!", "stderr": "!!!also-invalid!!!"},
        )

        assert resp.status_code == 200
        data = resp.json()
        assert data["stdout"] == ""
        assert data["stderr"] == ""
        assert data["masked_count"] == 0

    def test_stage2_empty_secret_key(self):
        """Secret with empty key — no crash, passes through."""
        session = _make_mock_session()
        secret = SimpleNamespace(id=1, key="", created_by="user1")

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
        stdout = base64.b64encode(b"normal output").decode()
        stderr = base64.b64encode(b"clean").decode()

        resp = client.post(
            "/api/v1/sessions/1/filter",
            json={"stdout": stdout, "stderr": stderr},
        )

        assert resp.status_code == 200
        data = resp.json()
        assert data["stdout"] == stdout
        assert data["masked_count"] == 0
