# Copyright (c) 2026 Tabith LLC.
# Use of this source code is governed by the Business Source License 1.1
# included in the LICENSE file at the root of this repository. As of the
# Change Date listed there, the work is available under MPL 2.0.
# SPDX-License-Identifier: BUSL-1.1

"""Tests for filter endpoint."""

from types import SimpleNamespace
from unittest.mock import MagicMock

from fastapi import FastAPI
from server.routes import filter as filter_routes
from starlette.testclient import TestClient


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
            # The real SessionMiddleware grants this only after verifying the
            # executor mTLS identity (sec-executor-session-path-no-auth); the
            # route-level caller check below is defense-in-depth.
            request.state.auth_user = {"caller": "executor", "executor_id": "venya-exec-1"}
            return await call_next(request)

    app.add_middleware(AuthMiddleware)
    return app


class TestFilterSessionOutput:
    """Tests for filter endpoint."""

    def test_filter_no_secrets(self):
        """POST /sessions/{id}/filter should return output unmodified when no secrets."""
        session = SimpleNamespace(id=123, user_id="user1")

        class MockQuery:
            def filter(self, *args, **kwargs):
                return self

            def first(self):
                return session

        class EmptyMockQuery:
            def filter(self, *args, **kwargs):
                return self

            def all(self):
                return []

        db = MagicMock()

        def query_side_effect(model):
            if model.__name__ == "Secret":
                return EmptyMockQuery()
            return MockQuery()

        db.query.side_effect = query_side_effect

        backend = MagicMock()
        backend.get_session.return_value = db
        app = _create_test_app(backend=backend)

        client = TestClient(app, raise_server_exceptions=False)
        import base64

        # Use an integer session_id so the auth-session path is taken
        # (the test mocks SessionModel lookup; Secret query returns empty)
        stdout = base64.b64encode(b"hello world").decode()
        stderr = base64.b64encode(b"error msg").decode()
        resp = client.post(
            "/api/v1/sessions/123/filter",
            json={"stdout": stdout, "stderr": stderr},
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["stdout"] == stdout
        assert data["stderr"] == stderr

    def test_legacy_payload_with_secrets_field_tolerated_and_dropped(self):
        """Wire-compat truth table (ruling 2026-09-20, ticket
        executor-stage2-plaintext-signoff): the executor's dead `secrets`
        field was deleted from the sender — but OLD daemons still send it.
        FilterRequest never declared it (pydantic drops extra keys), so a
        legacy payload must return 200 with a response IDENTICAL to the
        new shape. Old daemons talking to new cores must not break."""
        session = SimpleNamespace(id=123, user_id="user1")

        class MockQuery:
            def filter(self, *args, **kwargs):
                return self

            def first(self):
                return session

        class EmptyMockQuery:
            def filter(self, *args, **kwargs):
                return self

            def all(self):
                return []

        db = MagicMock()

        def query_side_effect(model):
            if model.__name__ == "Secret":
                return EmptyMockQuery()
            return MockQuery()

        db.query.side_effect = query_side_effect

        backend = MagicMock()
        backend.get_session.return_value = db
        app = _create_test_app(backend=backend)
        client = TestClient(app, raise_server_exceptions=False)

        import base64

        stdout = base64.b64encode(b"hello world").decode()
        stderr = base64.b64encode(b"error msg").decode()

        legacy = client.post(
            "/api/v1/sessions/123/filter",
            json={
                "stdout": stdout,
                "stderr": stderr,
                "secrets": [{"secret_id": "s1", "hash": "abc123"}],
            },
        )
        current = client.post(
            "/api/v1/sessions/123/filter",
            json={"stdout": stdout, "stderr": stderr},
        )
        assert legacy.status_code == 200
        assert current.status_code == 200
        assert legacy.json() == current.json()
        assert legacy.json()["stdout"] == stdout

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
        stdout_with_secret = base64.b64encode(b"running command, output: AKIAIOSFODNN7EXAMPLE done").decode()
        stderr = base64.b64encode(b"clean stderr").decode()

        with patch("core.engine.encryption.decrypt_secret") as mock_decrypt:
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

        with patch("core.engine.encryption.decrypt_secret") as mock_decrypt:
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

    def test_filter_execution_session_uuid_masks_output(self):
        """POST /sessions/{uuid}/filter should mask via SessionSecret bindings."""
        import base64
        from unittest.mock import patch

        binding = SimpleNamespace(secret_id=1)

        secret = SimpleNamespace(
            id=1,
            key="mysecret",
            encrypted_value=b"encrypted_data",
            nonce=b"nonce12345678901",
            wrapped_dek=b"wrapped_dk12345678",
        )

        class MockQuery:
            def filter(self, *args, **kwargs):
                return self

            def all(self):
                return [binding]

            def first(self):
                # ExecutionSession existence check (stage2 fail-closed fix):
                # this test's session EXISTS with bindings.
                return SimpleNamespace(id="exec-session-uuid")

        class SecretMockQuery:
            def filter(self, *args, **kwargs):
                return self

            def first(self):
                return secret

        db = MagicMock()

        def query_side_effect(model):
            if model.__name__ == "Secret":
                return SecretMockQuery()
            return MockQuery()

        db.query.side_effect = query_side_effect

        backend = MagicMock()
        backend.get_session.return_value = db
        backend.config.kek = b"A" * 32
        app = _create_test_app(backend=backend)

        client = TestClient(app, raise_server_exceptions=False)

        stdout = base64.b64encode(b"output with secret AKIAIOSFODNN7EXAMPLE here").decode()
        stderr = base64.b64encode(b"clean").decode()

        plaintext = b"AKIAIOSFODNN7EXAMPLE"

        with patch("core.engine.encryption.decrypt_secret") as mock_decrypt:
            mock_decrypt.return_value = plaintext

            resp = client.post(
                "/api/v1/sessions/550e8400-e29b-41d4-a716-446655440000/filter",
                json={"stdout": stdout, "stderr": stderr},
            )

        assert resp.status_code == 200
        data = resp.json()
        # Output should be masked since the execution-session lookup found bindings
        assert data["masked_count"] > 0
        decoded_stdout = base64.b64decode(data["stdout"]).decode()
        assert "[REDACTED:" in decoded_stdout

    def test_filter_execution_session_zero_bindings_logs_warning(self, caplog):
        """POST /sessions/{uuid}/filter with no bindings returns output unmodified."""
        import base64

        class MockQuery:
            def filter(self, *args, **kwargs):
                return self

            def all(self):
                return []

            def first(self):
                # ExecutionSession existence check (stage2 fail-closed fix):
                # the session EXISTS; it simply has zero secret bindings —
                # the legitimate 200 no-op case.
                return SimpleNamespace(id="550e8400-e29b-41d4-a716-446655440000")

        db = MagicMock()
        db.query.return_value = MockQuery()

        backend = MagicMock()
        backend.get_session.return_value = db
        app = _create_test_app(backend=backend)

        client = TestClient(app, raise_server_exceptions=False)

        stdout = base64.b64encode(b"hello world").decode()
        stderr = base64.b64encode(b"error msg").decode()

        resp = client.post(
            "/api/v1/sessions/550e8400-e29b-41d4-a716-446655440000/filter",
            json={"stdout": stdout, "stderr": stderr},
        )

        assert resp.status_code == 200
        data = resp.json()
        assert data["stdout"] == stdout
        assert data["stderr"] == stderr
        assert "no secret bindings" in caplog.text


class TestFilterRouteCallerCheck:
    """Route-level caller check (defense-in-depth, mirrors secrets.py revoke).

    Paired negative for sec-executor-session-path-no-auth: without the
    executor caller state the route must 403 BEFORE any secret is decrypted
    or hash-compared — no pre-auth oracle even if the middleware gate is
    ever bypassed or misconfigured.
    """

    def _create_app(self, auth_user=None):
        from starlette.middleware.base import BaseHTTPMiddleware
        from starlette.requests import Request

        app = FastAPI()
        app.include_router(filter_routes.router, prefix="/api/v1")

        class AuthMiddleware(BaseHTTPMiddleware):
            async def dispatch(self, request: Request, call_next):
                if auth_user is not None:
                    request.state.auth_user = auth_user
                return await call_next(request)

        app.add_middleware(AuthMiddleware)
        return app

    def test_no_caller_state_rejected_403_before_secret_queries(self):
        """No auth_user state → 403 before any secret query/decryption.

        (get_db opens a session during dependency resolution — the no-DB-touch
        guarantee lives at the middleware gate; here we pin that no secret
        lookup runs, i.e. no pre-auth oracle at the route level either.)
        """
        backend = MagicMock()
        db = backend.get_session.return_value
        app = self._create_app(auth_user=None)
        app.state.backend = backend
        client = TestClient(app, raise_server_exceptions=False)
        resp = client.post(
            "/api/v1/sessions/123/filter",
            json={"stdout": "aGk=", "stderr": ""},
        )
        assert resp.status_code == 403
        assert resp.json()["detail"] == "Executor mTLS authentication required"
        db.query.assert_not_called()

    def test_human_caller_rejected_403(self):
        """Bearer-authenticated human caller is NOT an executor → 403."""
        backend = MagicMock()
        app = self._create_app(auth_user={"caller": "human", "user_id": "u1"})
        app.state.backend = backend
        client = TestClient(app, raise_server_exceptions=False)
        resp = client.post(
            "/api/v1/sessions/123/filter",
            json={"stdout": "aGk=", "stderr": ""},
        )
        assert resp.status_code == 403


class TestFilterUnknownSessionFailClosed:
    """Ticket stage2-filter-unknown-session-unmasked-passthrough: the
    DEFINITIVE masker must never answer 200-with-raw for a session it has no
    knowledge of — the executor adopts Stage-2 over its own Stage-1 masking,
    so an empty-knowledge 200 ships plaintext to the caller. The mid-run TTL
    reaper race is PROVEN real (execute-stale-session-update-500). Unknown →
    404 → executor keeps Stage-1. Existing-with-zero-secrets → 200 (legit)."""

    def _client(self, side_effect):
        db = MagicMock()
        db.query.side_effect = side_effect
        backend = MagicMock()
        backend.get_session.return_value = db
        return TestClient(_create_test_app(backend=backend), raise_server_exceptions=False)

    def _post(self, client, session_id):
        import base64

        stdout = base64.b64encode(b"top-secret-value").decode()
        return client.post(
            f"/api/v1/sessions/{session_id}/filter",
            json={"stdout": stdout, "stderr": base64.b64encode(b"").decode()},
        )

    def _nothing_exists(self, model):
        q = MagicMock()
        q.filter.return_value.first.return_value = None
        q.filter.return_value.all.return_value = []
        return q

    def test_unknown_uuid_session_404_never_passthrough(self):
        import base64

        resp = self._post(self._client(self._nothing_exists), "ce3306e7-dead-beef-0000-000000000000")
        assert resp.status_code == 404
        assert "top-secret-value" not in resp.text
        assert base64.b64encode(b"top-secret-value").decode() not in resp.text

    def test_unknown_integer_session_404(self):
        resp = self._post(self._client(self._nothing_exists), "999")
        assert resp.status_code == 404

    def test_known_execution_session_zero_secrets_still_200(self):
        import base64

        def qse(model):
            q = MagicMock()
            if model.__name__ == "ExecutionSession":
                q.filter.return_value.first.return_value = SimpleNamespace(id="known-1")
            else:
                q.filter.return_value.first.return_value = None
                q.filter.return_value.all.return_value = []
            return q

        resp = self._post(self._client(qse), "known-1")
        assert resp.status_code == 200
        assert resp.json()["stdout"] == base64.b64encode(b"top-secret-value").decode()
