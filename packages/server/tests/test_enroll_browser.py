# Copyright (c) 2026 Tabith LLC.
# Use of this source code is governed by the Business Source License 1.1
# included in the LICENSE file at the root of this repository. As of the
# Change Date listed there, the work is available under MPL 2.0.
# SPDX-License-Identifier: BUSL-1.1

"""Tests for browser WebAuthn enrollment endpoints (Phase 2)."""

from datetime import UTC, datetime, timedelta
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

from core.iam.enrollment_manager import EnrollmentManager
from fastapi import FastAPI
from server.routes import enroll
from starlette.testclient import TestClient


def _create_test_app(fido2_manager=None, backend=None, config=None):
    """Create a minimal test app with browser enrollment routes."""
    from starlette.middleware.base import BaseHTTPMiddleware
    from starlette.requests import Request

    app = FastAPI()
    if fido2_manager is None:
        fido2_manager = MagicMock()
    app.state.fido2_manager = fido2_manager
    if backend is not None:
        app.state.backend = backend
    if config is not None:
        app.state.config = config
    app.include_router(enroll.router, prefix="/api/v1")

    class AuthMiddleware(BaseHTTPMiddleware):
        async def dispatch(self, request: Request, call_next):
            return await call_next(request)

    app.add_middleware(AuthMiddleware)
    return app


def _run_enroll_complete(session, token_state="in_progress", real_completer=False):
    """Drive POST /enroll/browser/complete to the session-creation step with a
    fully mocked fido2/enrollment/db stack. ``session`` is the session config
    namespace (session_timeout/access_token_ttl/max_session_duration). Returns
    (response, the patched SessionManager class-mock, the fido2 mock, the db
    mock) so callers can assert how the session was built and whether the
    ceremony ran. With ``real_completer=True`` the real
    ``EnrollmentManager.complete_enrollment`` executes (state-checked against
    the mock token) instead of the no-op stub."""
    from core.iam.enrollment_manager import EnrollmentManager

    mock_token = SimpleNamespace(
        user_id=1,
        state=token_state,
        token_hash="test-token-hash-00000000000000000000000000000000000000000000000000000000",
        binding_hash="test-binding-hash-000000000000000000000000000000000000000000000000000000000000000000000000000",
        expires_at=datetime.now(UTC) + timedelta(minutes=10),
    )
    mock_user = SimpleNamespace(
        id=1,
        user_id="newuser",
        status="pending_enrollment",
        display_name="New User",
        roles=[],
    )
    mock_cred = SimpleNamespace(
        user_id="1",
        credential_id=b"cred-123",
        public_key=b"pub-key",
        sign_count=0,
        # leg-1 capture fields: shape fidelity only, not under test here.
        attestation_fmt=None,
        aaguid=None,
        attestation_object=None,
    )
    mock_session = SimpleNamespace(id=1)
    mock_access_token = SimpleNamespace(token="access-token-xyz")

    mock_em = MagicMock()
    mock_em.get_token_by_plaintext.return_value = mock_token
    mock_em.complete_enrollment.return_value = None
    mock_sm = MagicMock()
    mock_sm.create_session.return_value = (mock_session, mock_access_token)

    mock_filter = MagicMock()
    mock_filter.first.return_value = mock_user
    mock_filter.filter.return_value.first.return_value = mock_user
    db = MagicMock()
    db.query.return_value = mock_filter

    backend = MagicMock()
    backend.get_session.return_value = db

    fido2 = MagicMock()
    fido2.finish_registration.return_value = mock_cred

    # A real ServerConfig always carries a fido2 section (enrollment TTL); the
    # enrollment_manager dependency reads config.fido2 directly, so the test
    # config must too.
    config = SimpleNamespace(
        session=session,
        fido2=SimpleNamespace(enrollment_token_ttl=15),
    )
    app = _create_test_app(fido2_manager=fido2, backend=backend, config=config)

    completer = EnrollmentManager.complete_enrollment if real_completer else mock_em.complete_enrollment
    with patch("server.routes.enroll.verify_binding_hash", return_value=True):
        with patch.object(EnrollmentManager, "__init__", lambda self, db, config=None: None):
            with patch.object(EnrollmentManager, "get_token_by_plaintext", mock_em.get_token_by_plaintext):
                with patch.object(EnrollmentManager, "complete_enrollment", completer):
                    with patch("core.iam.session_manager.SessionManager", return_value=mock_sm) as sm_cls:
                        client = TestClient(app, raise_server_exceptions=False)
                        resp = client.post(
                            "/api/v1/enroll/browser/complete",
                            json={
                                "enrollment_token": "test-token",
                                "challenge_id": "challenge-123",
                                "response": {"id": "dGVzdA==", "response": {}},
                                "label": "Primary key",
                            },
                        )
    return resp, sm_cls, fido2, db


class TestBrowserEnrollStart:
    """Tests for POST /enroll/browser/start."""

    def test_enroll_start_success(self):
        """Should return WebAuthn challenge for valid token."""
        from core.iam.enrollment_manager import EnrollmentManager

        # Mock token lookup
        mock_token = SimpleNamespace(
            user_id=1,
            state="created",
            token_hash="test-token-hash-00000000000000000000000000000000000000000000000000000000",
            binding_hash="test-binding-hash-0000000000000000000000000000000000000000000000000000000000000000",
            expires_at=datetime.now(UTC) + timedelta(minutes=10),
        )
        mock_user = SimpleNamespace(id=1, user_id="newuser", display_name="New User")

        mock_em = MagicMock()
        mock_em.validate_token_for_start.return_value = mock_token
        mock_em.mark_token_in_progress.return_value = mock_token

        mock_filter = MagicMock()
        mock_filter.first.return_value = mock_user
        db = MagicMock()
        db.query.return_value = mock_filter

        backend = MagicMock()
        backend.get_session.return_value = db

        fido2 = MagicMock()
        fido2.start_registration.return_value = (
            "challenge-123",
            {
                "challenge": "dGVzdA==",
                "rp": {"id": "localhost", "name": "Venya"},
                "user": {"id": "dW5pdA==", "name": "New User", "displayName": "New User"},
                "pubKeyCredParams": [{"type": "public-key", "alg": -7}],
                "timeout": 60000,
                "excludeCredentials": [],
                "attestation": "none",
            },
        )

        app = _create_test_app(fido2_manager=fido2, backend=backend)

        with patch("server.routes.enroll.verify_binding_hash", return_value=True):
            with patch.object(EnrollmentManager, "__init__", lambda self, db, config=None: None):
                with patch.object(EnrollmentManager, "validate_token_for_start", mock_em.validate_token_for_start):
                    with patch.object(EnrollmentManager, "mark_token_in_progress", mock_em.mark_token_in_progress):
                        client = TestClient(app, raise_server_exceptions=False)
                        resp = client.post(
                            "/api/v1/enroll/browser/start",
                            json={"enrollment_token": "test-token"},
                        )
                        assert resp.status_code == 200
                        data = resp.json()
                        assert data["challenge_id"] == "challenge-123"
                        assert "challenge" in data["options"]
                        assert "rp" in data["options"]

    def test_enroll_start_invalid_token(self):
        """Should return 400 for invalid token."""
        from core.iam.enrollment_manager import EnrollmentError

        mock_em = MagicMock()
        mock_em.validate_token_for_start.side_effect = EnrollmentError("Invalid enrollment token")

        db = MagicMock()
        backend = MagicMock()
        backend.get_session.return_value = db

        fido2 = MagicMock()
        app = _create_test_app(fido2_manager=fido2, backend=backend)

        with patch.object(EnrollmentManager, "__init__", lambda self, db, config=None: None):
            with patch.object(EnrollmentManager, "validate_token_for_start", mock_em.validate_token_for_start):
                client = TestClient(app, raise_server_exceptions=False)
                resp = client.post(
                    "/api/v1/enroll/browser/start",
                    json={"enrollment_token": "bad-token"},
                )
                assert resp.status_code == 400

    def test_enroll_start_no_fido2(self):
        """Should return 503 if FIDO2 not initialized."""
        mock_token = SimpleNamespace(
            user_id=1,
            state="created",
            token_hash="test-token-hash-00000000000000000000000000000000000000000000000000000000000000000000000",
            binding_hash="test-binding-hash-0000000000000000000000000000000000000000000000000000000000000000",
            expires_at=datetime.now(UTC) + timedelta(minutes=10),
        )

        mock_em = MagicMock()
        mock_em.validate_token_for_start.return_value = mock_token
        mock_em.mark_token_in_progress.return_value = mock_token

        db = MagicMock()
        backend = MagicMock()
        backend.get_session.return_value = db

        app = _create_test_app(backend=backend)
        del app.state.fido2_manager

        with patch("server.routes.enroll.verify_binding_hash", return_value=True):
            with patch.object(EnrollmentManager, "__init__", lambda self, db, config=None: None):
                with patch.object(EnrollmentManager, "validate_token_for_start", mock_em.validate_token_for_start):
                    with patch.object(EnrollmentManager, "mark_token_in_progress", mock_em.mark_token_in_progress):
                        client = TestClient(app, raise_server_exceptions=False)
                        resp = client.post(
                            "/api/v1/enroll/browser/start",
                            json={"enrollment_token": "test-token"},
                        )
                    assert resp.status_code == 503


class TestBrowserEnrollComplete:
    """Tests for POST /enroll/browser/complete."""

    def test_enroll_complete_success(self):
        """Should store credential, activate user, create session."""
        resp, _sm, _fido2, _db = _run_enroll_complete(
            SimpleNamespace(
                session_timeout=900,
                access_token_ttl=300,
                max_session_duration=14400,
            )
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] == "ok"
        # Check session cookie was set
        set_cookie = resp.headers.get("set-cookie", "")
        assert "venya_access_token" in set_cookie

    def test_enroll_complete_uses_configured_session_expiry(self):
        """#291 (enroll-session-config-bypass): the enroll-complete session must
        be built from the operator's configured session settings
        (request.app.state.config.session), not the core defaults. The
        SessionManager is handed a config carrying the configured expiry."""
        resp, sm_cls, _fido2, _db = _run_enroll_complete(
            SimpleNamespace(
                session_timeout=600,
                access_token_ttl=240,
                max_session_duration=7200,
            )
        )
        assert resp.status_code == 200
        args, _kwargs = sm_cls.call_args
        cfg = args[1]
        assert cfg.session_timeout == timedelta(seconds=600)
        assert cfg.access_token_ttl == timedelta(seconds=240)
        assert cfg.max_session_duration == timedelta(seconds=7200)

    def test_enroll_complete_default_config_preserves_core_defaults(self):
        """#291 T-neg2: server session config at defaults -> the session config
        handed to SessionManager equals the core defaults (900 s / 300 s / 4 h)."""
        from core.iam.session_manager import SessionConfig as CoreSessionConfig

        resp, sm_cls, _fido2, _db = _run_enroll_complete(
            SimpleNamespace(
                session_timeout=900,
                access_token_ttl=300,
                max_session_duration=14400,
            )
        )
        assert resp.status_code == 200
        args, _kwargs = sm_cls.call_args
        cfg = args[1]
        core = CoreSessionConfig()
        assert cfg.session_timeout == core.session_timeout
        assert cfg.access_token_ttl == core.access_token_ttl
        assert cfg.max_session_duration == core.max_session_duration

    def test_enroll_complete_cross_user_challenge_rejected(self):
        """Binding guard (sec-auth-elevation-authz-hardening #4): challenge_id
        issued for user A completed with user B's enrollment token -> 400,
        no credential stored, user not activated."""
        from core.iam.enrollment_manager import EnrollmentManager

        mock_token = SimpleNamespace(
            user_id=1,
            state="in_progress",
            token_hash="test-token-hash-00000000000000000000000000000000000000000000000000000000000000000000000",
            binding_hash="test-binding-hash-0000000000000000000000000000000000000000000000000000000000000000",
            expires_at=datetime.now(UTC) + timedelta(minutes=10),
        )
        mock_user = SimpleNamespace(
            id=1,
            user_id="newuser",
            status="pending_enrollment",
            display_name="New User",
            roles=[],
        )
        mock_cred = SimpleNamespace(
            user_id="999",  # challenge was issued for a DIFFERENT user
            credential_id=b"cred-123",
            public_key=b"pub-key",
            sign_count=0,
        )

        mock_em = MagicMock()
        mock_em.get_token_by_plaintext.return_value = mock_token
        mock_em.complete_enrollment.return_value = None

        mock_filter = MagicMock()
        mock_filter.first.return_value = mock_user
        mock_filter.filter.return_value.first.return_value = mock_user
        db = MagicMock()
        db.query.return_value = mock_filter

        backend = MagicMock()
        backend.get_session.return_value = db

        fido2 = MagicMock()
        fido2.finish_registration.return_value = mock_cred

        app = _create_test_app(fido2_manager=fido2, backend=backend)

        with patch("server.routes.enroll.verify_binding_hash", return_value=True):
            with patch.object(EnrollmentManager, "__init__", lambda self, db, config=None: None):
                with patch.object(EnrollmentManager, "get_token_by_plaintext", mock_em.get_token_by_plaintext):
                    with patch.object(EnrollmentManager, "complete_enrollment", mock_em.complete_enrollment):
                        client = TestClient(app, raise_server_exceptions=False)
                        resp = client.post(
                            "/api/v1/enroll/browser/complete",
                            json={
                                "enrollment_token": "test-token",
                                "challenge_id": "challenge-123",
                                "response": {"id": "dGVzdA==", "response": {}},
                                "label": "Primary key",
                            },
                        )
                        assert resp.status_code == 400
                        assert "different user" in resp.json()["detail"]
                        db.add.assert_not_called()
                        assert mock_user.status == "pending_enrollment"  # never activated
                        mock_em.complete_enrollment.assert_not_called()

    def test_enroll_complete_invalid_challenge(self):
        """Should return 400 for invalid WebAuthn challenge."""
        from core.iam.enrollment_manager import EnrollmentManager

        mock_token = SimpleNamespace(
            user_id=1,
            state="in_progress",
            token_hash="test-token-hash-00000000000000000000000000000000000000000000000000000000000000000000000",
            binding_hash="test-binding-hash-0000000000000000000000000000000000000000000000000000000000000000",
            expires_at=datetime.now(UTC) + timedelta(minutes=10),
        )

        mock_em = MagicMock()
        mock_em.get_token_by_plaintext.return_value = mock_token

        db = MagicMock()
        backend = MagicMock()
        backend.get_session.return_value = db

        fido2 = MagicMock()
        fido2.finish_registration.side_effect = ValueError("Challenge not found or expired")

        app = _create_test_app(fido2_manager=fido2, backend=backend)

        with patch("server.routes.enroll.verify_binding_hash", return_value=True):
            with patch.object(EnrollmentManager, "__init__", lambda self, db, config=None: None):
                with patch.object(EnrollmentManager, "get_token_by_plaintext", mock_em.get_token_by_plaintext):
                    client = TestClient(app, raise_server_exceptions=False)
                    resp = client.post(
                        "/api/v1/enroll/browser/complete",
                        json={
                            "enrollment_token": "test-token",
                            "challenge_id": "expired",
                            "response": {"id": "dGVzdA==", "response": {}},
                            "label": "Primary key",
                        },
                    )
                    assert resp.status_code == 400

    def test_enroll_complete_no_fido2(self):
        """Should return 503 if FIDO2 not initialized."""
        from core.iam.enrollment_manager import EnrollmentManager

        mock_token = SimpleNamespace(
            user_id=1,
            state="in_progress",
            token_hash="test-token-hash-00000000000000000000000000000000000000000000000000000000000000000000000",
            binding_hash="test-binding-hash-0000000000000000000000000000000000000000000000000000000000000000",
            expires_at=datetime.now(UTC) + timedelta(minutes=10),
        )

        mock_em = MagicMock()
        mock_em.get_token_by_plaintext.return_value = mock_token

        db = MagicMock()
        backend = MagicMock()
        backend.get_session.return_value = db

        app = _create_test_app(backend=backend)
        del app.state.fido2_manager

        with patch("server.routes.enroll.verify_binding_hash", return_value=True):
            with patch.object(EnrollmentManager, "__init__", lambda self, db, config=None: None):
                with patch.object(EnrollmentManager, "get_token_by_plaintext", mock_em.get_token_by_plaintext):
                    client = TestClient(app, raise_server_exceptions=False)
                    resp = client.post(
                        "/api/v1/enroll/browser/complete",
                        json={
                            "enrollment_token": "test-token",
                            "challenge_id": "challenge-123",
                            "response": {"id": "dGVzdA==", "response": {}},
                            "label": "Primary key",
                        },
                    )
                    assert resp.status_code == 503

    def test_enroll_complete_created_state_token_400_before_side_effects(self):
        """#412: complete over a token still in 'created' state must 400 before
        the ceremony. The route accepted ("in_progress", "created") while
        complete_enrollment enforces "in_progress" only, so a direct POST ran
        finish_registration + db.add and died in the completer (500 +
        store/DB divergence)."""
        resp, _sm, fido2, db = _run_enroll_complete(
            SimpleNamespace(
                session_timeout=900,
                access_token_ttl=300,
                max_session_duration=14400,
            ),
            token_state="created",
            real_completer=True,
        )
        assert resp.status_code == 400
        assert "not in progress" in resp.json()["detail"]
        fido2.finish_registration.assert_not_called()
        fido2.store.store_credential.assert_not_called()
        db.add.assert_not_called()

    def test_enroll_complete_completed_state_token_400(self):
        """Truth table: an already-'completed' token is rejected 400 too —
        pins the route check to exactly the completer's accepted state."""
        resp, _sm, fido2, db = _run_enroll_complete(
            SimpleNamespace(
                session_timeout=900,
                access_token_ttl=300,
                max_session_duration=14400,
            ),
            token_state="completed",
            real_completer=True,
        )
        assert resp.status_code == 400
        fido2.finish_registration.assert_not_called()
        fido2.store.store_credential.assert_not_called()
        db.add.assert_not_called()
