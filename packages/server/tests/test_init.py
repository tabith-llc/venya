"""Tests for initialization endpoints (two-step FIDO2 enrollment)."""

from types import SimpleNamespace
from unittest.mock import MagicMock

from fastapi import FastAPI
from server.routes import init as init_routes
from starlette.testclient import TestClient


def _create_test_app(backend=None, fido2_manager=None):
    """Create a minimal test app with init routes."""
    from starlette.middleware.base import BaseHTTPMiddleware
    from starlette.requests import Request

    app = FastAPI()
    if backend is not None:
        app.state.backend = backend
    if fido2_manager is not None:
        app.state.fido2_manager = fido2_manager

    app.include_router(init_routes.router, prefix="/api/v1")

    class AuthMiddleware(BaseHTTPMiddleware):
        async def dispatch(self, request: Request, call_next):
            response = await call_next(request)
            if hasattr(request.state, "http_exception"):
                raise request.state.http_exception
            return response

    app.add_middleware(AuthMiddleware)
    return app


def _make_user(user_id="alice", enrolled_at=None, recovery_code_hash=None):
    return SimpleNamespace(
        user_id=user_id,
        enrolled_at=enrolled_at,
        recovery_code_hash=recovery_code_hash,
    )


def _make_role(role_id=1, name="admin"):
    return SimpleNamespace(id=role_id, name=name)


def _make_membership(user_id="alice", role_id=1):
    return SimpleNamespace(user_id=user_id, role_id=role_id)


class MockFido2Manager:
    def __init__(self):
        self._challenges = {}

    def start_registration(self, user_id, username, existing_credential_ids=None):
        challenge_id = "test-challenge-id"
        self._challenges[challenge_id] = {"user_id": user_id}
        options = {
            "challenge": "dGVzdC1jaGFsbGVuZ2U",
            "rp": {"id": "localhost", "name": "Venya"},
            "user": {"id": "YWxpY2U", "name": "alice", "displayName": "alice"},
            "pubKeyCredParams": [{"type": "public-key", "alg": -7}],
            "timeout": 60000,
            "excludeCredentials": [],
            "attestation": "none",
        }
        return challenge_id, options

    def finish_registration(self, challenge_id, response):
        stored = self._challenges.pop(challenge_id, None)
        if stored is None:
            raise ValueError("Challenge not found or expired")
        from server.fido2.manager import StoredCredential

        return StoredCredential(
            user_id=stored["user_id"],
            credential_id=b"test-cred-id",
            public_key=b"test-public-key",
            sign_count=0,
        )


class TestInitCore:
    """Tests for POST /init endpoint."""

    def test_init_fresh(self):
        """Fresh init creates admin role, user, and returns FIDO2 challenge."""
        db = MagicMock()
        db.query.return_value.filter.return_value.first.return_value = None
        db.query.return_value.join.return_value.filter.return_value.count.return_value = 0

        backend = MagicMock()
        backend.get_session.return_value = db

        fido2 = MockFido2Manager()
        app = _create_test_app(backend=backend, fido2_manager=fido2)

        client = TestClient(app, raise_server_exceptions=False)
        resp = client.post(
            "/api/v1/init",
            json={"user_id": "alice"},
        )
        assert resp.status_code == 201
        data = resp.json()
        assert data["user_id"] == "alice"
        assert "challenge_id" in data
        assert "options" in data
        assert db.add.called

    def test_init_already_initialized(self):
        """Init on fully initialized core returns 409."""
        admin_role = _make_role()
        admin_user = _make_user("alice", enrolled_at="2026-01-01")
        _make_membership()

        class MockQuery:
            def __init__(self, model):
                self._model = model
                self._call_count = 0

            def filter(self, *args, **kwargs):
                return self

            def join(self, *model):
                return self

            def first(self):
                self._call_count += 1
                if self._call_count == 1:
                    return admin_role
                return admin_user

            def count(self):
                return 1

        db = MagicMock()
        db.query.return_value = MockQuery(None)

        backend = MagicMock()
        backend.get_session.return_value = db
        app = _create_test_app(backend=backend, fido2_manager=MockFido2Manager())

        client = TestClient(app, raise_server_exceptions=False)
        resp = client.post(
            "/api/v1/init",
            json={"user_id": "bob"},
        )
        assert resp.status_code == 409
        assert "already initialized" in resp.json()["detail"]

    def test_init_pending_enrollment_rejected(self):
        """Init with pending enrollment returns 409, forces reset."""
        admin_role = _make_role()
        pending_user = _make_user("alice", enrolled_at=None)

        class MockQuery:
            def __init__(self, model):
                self._model = model
                self._call_count = 0

            def filter(self, *args, **kwargs):
                return self

            def join(self, *model):
                return self

            def first(self):
                self._call_count += 1
                if self._call_count == 1:
                    return admin_role
                return pending_user

            def count(self):
                return 0

        db = MagicMock()
        db.query.return_value = MockQuery(None)

        backend = MagicMock()
        backend.get_session.return_value = db
        app = _create_test_app(backend=backend, fido2_manager=MockFido2Manager())

        client = TestClient(app, raise_server_exceptions=False)
        resp = client.post(
            "/api/v1/init",
            json={"user_id": "alice"},
        )
        assert resp.status_code == 409
        data = resp.json()
        assert "pending enrollment exists" in data["detail"].lower()


class TestInitComplete:
    """Tests for POST /init/complete endpoint."""

    def test_complete_success(self):
        """Complete verifies attestation and returns recovery code."""
        pending_user = _make_user("alice", enrolled_at=None)

        # Set up the challenge first (simulating that /init was called)
        fido2 = MockFido2Manager()
        fido2.start_registration("alice", "alice")

        admin_role = _make_role(role_id=1, name="admin")
        pending_user = _make_user("alice", enrolled_at=None)

        class MockQuery:
            def __init__(self, model):
                self._model = model

            def join(self, *args, **kwargs):
                return self

            def filter(self, *args, **kwargs):
                return self

            def first(self):
                if self._model is not None and "Role" in str(self._model):
                    return admin_role
                return pending_user

        db = MagicMock()
        db.query.side_effect = lambda model: MockQuery(model)

        backend = MagicMock()
        backend.get_session.return_value = db

        app = _create_test_app(backend=backend, fido2_manager=fido2)

        client = TestClient(app, raise_server_exceptions=False)
        resp = client.post(
            "/api/v1/init/complete",
            json={
                "user_id": "alice",
                "challenge_id": "test-challenge-id",
                "response": {"id": "test-cred-id", "rawId": "dGVzdC1jcmVk"},
            },
        )
        assert resp.status_code == 201
        data = resp.json()
        assert data["success"] is True
        assert "recovery_code" in data
        assert data["user_id"] == "alice"

    def test_complete_invalid_challenge(self):
        """Complete with invalid challenge returns 400."""
        db = MagicMock()

        backend = MagicMock()
        backend.get_session.return_value = db
        app = _create_test_app(backend=backend, fido2_manager=MockFido2Manager())

        client = TestClient(app, raise_server_exceptions=False)
        resp = client.post(
            "/api/v1/init/complete",
            json={
                "user_id": "alice",
                "challenge_id": "nonexistent-challenge",
                "response": {"id": "test-cred-id"},
            },
        )
        assert resp.status_code == 400
        assert "Challenge not found" in resp.json()["detail"]

    def test_complete_no_pending_enrollment(self):
        """Complete when no pending enrollment returns 400."""
        # Set up the challenge first
        fido2 = MockFido2Manager()
        fido2.start_registration("alice", "alice")

        # Mock query returns None (no pending user found because user is already enrolled)
        # The code does: db.query(User).join(RoleMember).filter(...).filter(...).filter(...).first()
        db = MagicMock()
        db.query.return_value.join.return_value.filter.return_value.filter.return_value.filter.return_value.first.return_value = (
            None
        )

        backend = MagicMock()
        backend.get_session.return_value = db
        app = _create_test_app(backend=backend, fido2_manager=fido2)

        client = TestClient(app, raise_server_exceptions=False)
        resp = client.post(
            "/api/v1/init/complete",
            json={
                "user_id": "alice",
                "challenge_id": "test-challenge-id",
                "response": {"id": "test-cred-id", "rawId": "dGVzdC1jcmVk"},
            },
        )
        assert resp.status_code == 400
        assert "No pending enrollment" in resp.json()["detail"]


class TestRecoveryCodeHelpers:
    """Tests for recovery code generation and hashing."""

    def test_recovery_code_format(self):
        """Recovery code is 8 groups of 6 characters."""
        code = init_routes._generate_recovery_code()
        groups = code.split("-")
        assert len(groups) == 8
        for group in groups:
            assert len(group) == 6
            assert group.isalnum()

    def test_recovery_code_uniqueness(self):
        """Two recovery codes should be different."""
        code1 = init_routes._generate_recovery_code()
        code2 = init_routes._generate_recovery_code()
        assert code1 != code2

    def test_recovery_code_hash(self):
        """Hashing is deterministic."""
        pepper = "my-pepper"
        code = "ABCDEF-GHIJKL-MNOPQR-STUVWX-YZABCD-EFGHIJ-KLMNOP-QRSTUV"
        hash1 = init_routes._hash_recovery_code(code, pepper)
        hash2 = init_routes._hash_recovery_code(code, pepper)
        assert hash1 == hash2
        assert len(hash1) == 64  # SHA-256 hex digest

    def test_recovery_code_hash_differs_with_different_pepper(self):
        """Different peppers produce different hashes."""
        code = "ABCDEF-GHIJKL-MNOPQR-STUVWX-YZABCD-EFGHIJ-KLMNOP-QRSTUV"
        hash1 = init_routes._hash_recovery_code(code, "pepper1")
        hash2 = init_routes._hash_recovery_code(code, "pepper2")
        assert hash1 != hash2
