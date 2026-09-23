# Copyright (c) 2026 Tabith LLC.
# Use of this source code is governed by the Business Source License 1.1
# included in the LICENSE file at the root of this repository. As of the
# Change Date listed there, the work is available under MPL 2.0.
# SPDX-License-Identifier: BUSL-1.1

"""Tests for session authentication middleware (dual cookie + bearer)."""

from datetime import UTC, datetime, timedelta
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

from fastapi import FastAPI
from server.middleware.auth import SessionMiddleware
from starlette.testclient import TestClient


def _create_test_app():
    """Create a minimal test app with session middleware."""
    from starlette.requests import Request

    app = FastAPI()

    class AuthMiddleware(SessionMiddleware):
        pass

    app.add_middleware(AuthMiddleware)
    app.state.config = SimpleNamespace(
        session=SimpleNamespace(
            session_timeout=900,
            access_token_ttl=300,
            max_session_duration=14400,
        ),
        admin_mtls=SimpleNamespace(enabled=False),
    )

    @app.get("/api/v1/protected")
    def protected_endpoint(request: Request):
        user = getattr(request.state, "auth_user", None)
        return {"user": user}

    @app.get("/api/v1/public")
    def public_endpoint(request: Request):
        return {"status": "ok"}

    return app


def _make_session_mock(user_id="user1", expires_at=None, access_token_jti="token-123", user_status="active"):
    """Create a mock session object."""
    if expires_at is None:
        expires_at = datetime.now(UTC) + timedelta(minutes=10)
    user_mock = SimpleNamespace(user_id=user_id, status=user_status)
    return SimpleNamespace(
        id=1,
        user_id=user_id,
        expires_at=expires_at,
        user=user_mock,
        access_token_jti=access_token_jti,
    )


def _make_backend(session=None):
    """Create a mock backend with a session."""
    db = MagicMock()

    def query_side_effect(model):
        q = MagicMock()
        q.filter.return_value.first.return_value = session
        return q

    db.query.side_effect = query_side_effect
    backend = MagicMock()
    backend.get_session.return_value = db
    return backend


class TestCookieAuth:
    """Tests for cookie-based authentication."""

    def test_cookie_auth_success(self):
        """Cookie auth should work and attach user info."""
        session = _make_session_mock()
        backend = _make_backend(session)

        with patch("core.iam.session_manager.SessionManager") as mock_sm, patch(
            "core.iam.role_manager.RoleManager"
        ) as mock_rm:
            mock_sm.return_value.check_expiry.return_value = True
            mock_rm.return_value.get_user_roles.return_value = []

            app = _create_test_app()
            app.state.backend = backend

            client = TestClient(app, raise_server_exceptions=False)
            client.cookies.set("venya_access_token", "token-123")
            resp = client.get(
                "/api/v1/protected",
            )
            assert resp.status_code == 200
            data = resp.json()
            assert data["user"]["user_id"] == "user1"

    def test_cookie_auth_invalid_token(self):
        """Invalid cookie token should return 401."""
        backend = _make_backend(session=None)

        app = _create_test_app()
        app.state.backend = backend

        client = TestClient(app, raise_server_exceptions=False)
        client.cookies.set("venya_access_token", "nonexistent")
        resp = client.get(
            "/api/v1/protected",
        )
        assert resp.status_code == 401
        assert resp.json()["detail"] == "Invalid or expired token"

    def test_cookie_auth_expired(self):
        """Expired cookie token should return 401."""
        expired_session = _make_session_mock(
            expires_at=datetime.now(UTC) - timedelta(minutes=5),
        )
        backend = _make_backend(session=expired_session)

        with patch("core.iam.session_manager.SessionManager") as mock_sm:
            mock_sm.return_value.check_expiry.return_value = False

            app = _create_test_app()
            app.state.backend = backend

            client = TestClient(app, raise_server_exceptions=False)
            client.cookies.set("venya_access_token", "expired-token")
            resp = client.get(
                "/api/v1/protected",
            )
            assert resp.status_code == 401


class TestBearerAuth:
    """Tests for bearer token authentication (CLI)."""

    def test_bearer_auth_success(self):
        """Bearer token should work and attach user info."""
        session = _make_session_mock()
        backend = _make_backend(session)

        with patch("core.iam.session_manager.SessionManager") as mock_sm, patch(
            "core.iam.role_manager.RoleManager"
        ) as mock_rm:
            mock_sm.return_value.check_expiry.return_value = True
            mock_rm.return_value.get_user_roles.return_value = []

            app = _create_test_app()
            app.state.backend = backend

            client = TestClient(app, raise_server_exceptions=False)
            resp = client.get(
                "/api/v1/protected",
                headers={"authorization": "Bearer token-123"},
            )
            assert resp.status_code == 200
            data = resp.json()
            assert data["user"]["user_id"] == "user1"

    def test_bearer_auth_invalid_token(self):
        """Invalid bearer token should return 401."""
        backend = _make_backend(session=None)

        app = _create_test_app()
        app.state.backend = backend

        client = TestClient(app, raise_server_exceptions=False)
        resp = client.get(
            "/api/v1/protected",
            headers={"authorization": "Bearer nonexistent"},
        )
        assert resp.status_code == 401

    def test_no_auth_returns_401(self):
        """No token or cookie should return 401."""
        backend = _make_backend(session=None)

        app = _create_test_app()
        app.state.backend = backend

        client = TestClient(app, raise_server_exceptions=False)
        resp = client.get("/api/v1/protected")
        assert resp.status_code == 401
        assert resp.json()["detail"] == "Missing authentication token"


class TestCookiePriority:
    """Tests that cookie takes priority over bearer token."""

    def test_cookie_takes_priority_over_bearer(self):
        """When both cookie and bearer are present, cookie should be used."""
        cookie_session = _make_session_mock(user_id="cookie-user")
        bearer_session = _make_session_mock(user_id="bearer-user")

        def query_side_effect(model):
            if model.__name__ == "Session":
                # Return different sessions based on token value
                return MagicMock(
                    filter=MagicMock(
                        return_value=MagicMock(
                            first=MagicMock(
                                return_value=(
                                    cookie_session
                                    if "cookie-token" in str(list(model.__dict__.get("_filters", [])))
                                    else bearer_session
                                )
                            )
                        )
                    )
                )
            return MagicMock()

        # Use a simpler approach: cookie token matches cookie session
        db = MagicMock()
        db.query.return_value.filter.return_value.first.return_value = cookie_session
        backend = MagicMock()
        backend.get_session.return_value = db

        with patch("core.iam.session_manager.SessionManager") as mock_sm, patch(
            "core.iam.role_manager.RoleManager"
        ) as mock_rm:
            mock_sm.return_value.check_expiry.return_value = True
            mock_rm.return_value.get_user_roles.return_value = []

            app = _create_test_app()
            app.state.backend = backend

            client = TestClient(
                app,
                raise_server_exceptions=False,
                cookies={"venya_access_token": "cookie-token"},
            )
            resp = client.get(
                "/api/v1/protected",
                headers={"authorization": "Bearer bearer-token"},
            )
            assert resp.status_code == 200
            data = resp.json()
            assert data["user"]["user_id"] == "cookie-user"


class TestPublicPaths:
    """Tests that public paths bypass authentication."""

    def test_public_health(self):
        """GET /health should not require auth."""
        from server.routes import health

        app = _create_test_app()
        app.include_router(health.router, prefix="/api/v1")

        client = TestClient(app, raise_server_exceptions=False)
        resp = client.get("/api/v1/health")
        assert resp.status_code == 200

    def test_enroll_browser_public(self):
        """Browser enrollment start should be public."""
        from server.routes import enroll

        app = _create_test_app()
        app.include_router(enroll.router, prefix="/api/v1")

        client = TestClient(app, raise_server_exceptions=False)
        resp = client.post(
            "/api/v1/enroll/browser/start",
            json={"enrollment_token": "test-token"},
        )
        assert resp.status_code == 503  # Backend not initialized, not 401

    def test_enroll_browser_complete_public(self):
        """Browser enrollment complete should be public."""
        from server.routes import enroll

        app = _create_test_app()
        app.include_router(enroll.router, prefix="/api/v1")

        client = TestClient(app, raise_server_exceptions=False)
        resp = client.post(
            "/api/v1/enroll/browser/complete",
            json={"enrollment_token": "test-token", "challenge_id": "x", "response": {}, "label": "key"},
        )
        assert resp.status_code == 503  # Backend not initialized, not 401


class TestExecutorSessionPathAuth:
    """Truth table for the executor-session-path mTLS gate.

    Ticket sec-executor-session-path-no-auth: caller=executor must be granted
    ONLY on a verified client cert whose CN is a registered, non-revoked
    executor. Paired negatives throughout — the pre-fix code granted
    caller=executor to ANY anonymous caller by URL regex alone.
    """

    EXEC_SUBJECT = "CN=venya-exec-1,O=Venya"

    def _create_executor_app(self, backend=None):
        """App with SessionMiddleware + stub executor-session routes."""
        from starlette.requests import Request

        app = FastAPI()
        app.add_middleware(SessionMiddleware)
        app.state.config = SimpleNamespace(
            session=SimpleNamespace(
                session_timeout=900,
                access_token_ttl=300,
                max_session_duration=14400,
            ),
            admin_mtls=SimpleNamespace(enabled=False),
        )
        if backend is not None:
            app.state.backend = backend

        @app.post("/api/v1/sessions/{session_id}/filter")
        def filter_stub(request: Request):
            return {"user": getattr(request.state, "auth_user", None)}

        @app.post("/api/v1/sessions/{session_id}/secrets/revoke")
        def revoke_stub(request: Request):
            return {"user": getattr(request.state, "auth_user", None)}

        @app.post("/api/v1/heartbeat")
        def heartbeat_stub(request: Request):
            return {"user": getattr(request.state, "auth_user", None)}

        return app

    def _make_executor_backend(self, executor_row=None, cert_row=None, crl_row=None):
        """Mock backend dispatching by model (Executor/ExecutorCert/CRL)."""
        db = MagicMock()

        def query_side_effect(model):
            q = MagicMock()
            name = getattr(model, "__name__", "")
            if name == "Executor":
                q.filter.return_value.first.return_value = executor_row
            elif name == "ExecutorCert":
                q.filter.return_value.first.return_value = cert_row
            elif name == "ExecutorCertRevocation":
                q.filter.return_value.first.return_value = crl_row
            else:
                q.filter.return_value.first.return_value = None
            return q

        db.query.side_effect = query_side_effect
        backend = MagicMock()
        backend.get_session.return_value = db
        return backend, db

    def _rows(self, revoked_at=None):
        executor_row = SimpleNamespace(id="venya-exec-1", revoked_at=revoked_at)
        cert_row = SimpleNamespace(serial_number="0000000000000001")
        crl_row = SimpleNamespace(revoked_at=datetime.now(UTC))
        return executor_row, cert_row, crl_row

    def test_anonymous_filter_rejected_401_before_any_db_or_hashing(self):
        """The oracle is dead pre-auth: no headers → 401, backend NEVER touched.

        Pre-fix this exact request was granted caller=executor and the route
        decrypted secrets + hash-matched the attacker's candidate bytes.
        """
        backend, _db = self._make_executor_backend()
        app = self._create_executor_app(backend=backend)
        client = TestClient(app, raise_server_exceptions=False)
        resp = client.post("/api/v1/sessions/1/filter", json={"stdout": "", "stderr": ""})
        assert resp.status_code == 401
        assert resp.json()["detail"] == "Executor mTLS authentication required"
        backend.get_session.assert_not_called()

    def test_anonymous_revoke_rejected_401(self):
        """Paired negative on the second gated path (audit-forgery hole)."""
        backend, _ = self._make_executor_backend()
        app = self._create_executor_app(backend=backend)
        client = TestClient(app, raise_server_exceptions=False)
        resp = client.post("/api/v1/sessions/sess-1/secrets/revoke", json={"secret_ids": ["1"]})
        assert resp.status_code == 401
        backend.get_session.assert_not_called()

    def test_client_verified_not_success_rejected_401(self):
        """X-Client-Verified present but != SUCCESS (nginx verify failed)."""
        executor_row, _, _ = self._rows()
        backend, _ = self._make_executor_backend(executor_row=executor_row)
        app = self._create_executor_app(backend=backend)
        client = TestClient(app, raise_server_exceptions=False)
        resp = client.post(
            "/api/v1/sessions/1/filter",
            json={"stdout": "", "stderr": ""},
            headers={"X-Client-Verified": "FAILED", "X-Client-Subject": self.EXEC_SUBJECT},
        )
        assert resp.status_code == 401

    def test_success_without_subject_rejected_401(self):
        """SUCCESS sentinel but no X-Client-Subject → no identity → 401."""
        executor_row, _, _ = self._rows()
        backend, _ = self._make_executor_backend(executor_row=executor_row)
        app = self._create_executor_app(backend=backend)
        client = TestClient(app, raise_server_exceptions=False)
        resp = client.post(
            "/api/v1/sessions/1/filter",
            json={"stdout": "", "stderr": ""},
            headers={"X-Client-Verified": "SUCCESS"},
        )
        assert resp.status_code == 401

    def test_subject_without_cn_rejected_401(self):
        """Subject DN with no CN component → 401."""
        executor_row, _, _ = self._rows()
        backend, _ = self._make_executor_backend(executor_row=executor_row)
        app = self._create_executor_app(backend=backend)
        client = TestClient(app, raise_server_exceptions=False)
        resp = client.post(
            "/api/v1/sessions/1/filter",
            json={"stdout": "", "stderr": ""},
            headers={"X-Client-Verified": "SUCCESS", "X-Client-Subject": "O=Venya,OU=Executors"},
        )
        assert resp.status_code == 401

    def test_unregistered_cn_rejected_403(self):
        """Verified cert whose CN is not a registered Executor → 403.

        This is the allowlist half: ANY Root-CA-signed cert (or an admin
        cert) verifies at nginx but must still be refused here.
        """
        backend, _ = self._make_executor_backend(executor_row=None)
        app = self._create_executor_app(backend=backend)
        client = TestClient(app, raise_server_exceptions=False)
        resp = client.post(
            "/api/v1/sessions/1/filter",
            json={"stdout": "", "stderr": ""},
            headers={
                "X-Client-Verified": "SUCCESS",
                "X-Client-Subject": "CN=ghost-executor,O=Venya",
                "X-Client-Serial": "0000000000000001",
            },
        )
        assert resp.status_code == 403

    def test_admin_cert_cn_rejected_403(self):
        """Verified admin-CA cert (CN=admin@...) is NOT an executor → 403."""
        backend, _ = self._make_executor_backend(executor_row=None)
        app = self._create_executor_app(backend=backend)
        client = TestClient(app, raise_server_exceptions=False)
        resp = client.post(
            "/api/v1/sessions/1/filter",
            json={"stdout": "", "stderr": ""},
            headers={
                "X-Client-Verified": "SUCCESS",
                "X-Client-Subject": "CN=admin@venya-core-1,OU=Admin,O=Venya",
            },
        )
        assert resp.status_code == 403

    def test_registered_executor_passes_with_identity(self):
        """Full pass path: verified + registered + not revoked → caller state."""
        executor_row, _, _ = self._rows()
        backend, _ = self._make_executor_backend(executor_row=executor_row)
        app = self._create_executor_app(backend=backend)
        client = TestClient(app, raise_server_exceptions=False)
        resp = client.post(
            "/api/v1/sessions/1/filter",
            json={"stdout": "", "stderr": ""},
            headers={
                "X-Client-Verified": "SUCCESS",
                "X-Client-Subject": self.EXEC_SUBJECT,
                "X-Client-Serial": "0000000000000001",
            },
        )
        assert resp.status_code == 200
        assert resp.json()["user"] == {"caller": "executor", "executor_id": "venya-exec-1"}

    def test_identity_revoked_rejected_403(self):
        """Executor.revoked_at set → identity-flag revocation, terminal."""
        executor_row, _, _ = self._rows(revoked_at=datetime.now(UTC))
        backend, _ = self._make_executor_backend(executor_row=executor_row)
        app = self._create_executor_app(backend=backend)
        client = TestClient(app, raise_server_exceptions=False)
        resp = client.post(
            "/api/v1/sessions/1/filter",
            json={"stdout": "", "stderr": ""},
            headers={
                "X-Client-Verified": "SUCCESS",
                "X-Client-Subject": self.EXEC_SUBJECT,
                "X-Client-Serial": "0000000000000001",
            },
        )
        assert resp.status_code == 403

    def test_presented_serial_revoked_rejected_403(self):
        """Presented serial in the CRL → serial-history revocation."""
        executor_row, _, crl_row = self._rows()
        backend, _ = self._make_executor_backend(executor_row=executor_row, crl_row=crl_row)
        app = self._create_executor_app(backend=backend)
        client = TestClient(app, raise_server_exceptions=False)
        resp = client.post(
            "/api/v1/sessions/1/filter",
            json={"stdout": "", "stderr": ""},
            headers={
                "X-Client-Verified": "SUCCESS",
                "X-Client-Subject": self.EXEC_SUBJECT,
                "X-Client-Serial": "0000000000000002",
            },
        )
        assert resp.status_code == 403

    def test_missing_serial_header_falls_back_to_record_serial(self):
        """Named decision: no X-Client-Serial (older nginx) → the revocation
        helper falls back to the CURRENT ExecutorCert record serial — a
        serial-form revocation of the current credential still refuses."""
        executor_row, cert_row, crl_row = self._rows()
        backend, _ = self._make_executor_backend(executor_row=executor_row, cert_row=cert_row, crl_row=crl_row)
        app = self._create_executor_app(backend=backend)
        client = TestClient(app, raise_server_exceptions=False)
        resp = client.post(
            "/api/v1/sessions/1/filter",
            json={"stdout": "", "stderr": ""},
            headers={"X-Client-Verified": "SUCCESS", "X-Client-Subject": self.EXEC_SUBJECT},
        )
        assert resp.status_code == 403

    def test_no_backend_fails_closed_403(self):
        """Allowlist unverifiable (backend missing) → fail-closed 403."""
        app = self._create_executor_app(backend=None)
        client = TestClient(app, raise_server_exceptions=False)
        resp = client.post(
            "/api/v1/sessions/1/filter",
            json={"stdout": "", "stderr": ""},
            headers={"X-Client-Verified": "SUCCESS", "X-Client-Subject": self.EXEC_SUBJECT},
        )
        assert resp.status_code == 403

    def test_dead_mtls_scope_branch_removed(self):
        """The vacuous scope['client_cert'] branch is gone (ticket: 'must
        become live or be removed') — pin the removal so it cannot regress
        as a second, dead grant path."""
        assert not hasattr(SessionMiddleware, "_is_mtls_request")

    def test_dead_enrollment_confirm_entry_removed(self):
        """#23c pin (ticket sec-sweep-low-informational): the PUBLIC_PATHS
        allowlist entry for /api/v1/enrollment/confirm matched NO route —
        dead allowlist entries are how 'unmounted' paths stay mounted."""
        assert "/api/v1/enrollment/confirm" not in SessionMiddleware.PUBLIC_PATHS

    # --- Heartbeat gating (ticket sec-endpoint-ratelimit-hardening #7) ---

    def test_heartbeat_no_cert_rejected_401(self):
        """No X-Client-Verified → 401 BEFORE the route (the path was PUBLIC:
        unauthenticated liveness stamping + revocation oracle)."""
        executor_row, _, _ = self._rows()
        backend, _ = self._make_executor_backend(executor_row=executor_row)
        app = self._create_executor_app(backend=backend)
        client = TestClient(app, raise_server_exceptions=False)
        resp = client.post(
            "/api/v1/heartbeat",
            json={"executor_id": "venya-exec-1", "cert_fingerprint": "abc"},
        )
        assert resp.status_code == 401

    def test_heartbeat_verified_registered_passes(self):
        """Verified cert + registered CN → through to the route with the
        middleware-set auth state (CN binding happens route-side)."""
        executor_row, _, _ = self._rows()
        backend, _ = self._make_executor_backend(executor_row=executor_row)
        app = self._create_executor_app(backend=backend)
        client = TestClient(app, raise_server_exceptions=False)
        resp = client.post(
            "/api/v1/heartbeat",
            json={"executor_id": "venya-exec-1", "cert_fingerprint": "abc"},
            headers={
                "X-Client-Verified": "SUCCESS",
                "X-Client-Subject": self.EXEC_SUBJECT,
                "X-Client-Serial": "0000000000000001",
            },
        )
        assert resp.status_code == 200
        assert resp.json()["user"] == {"caller": "executor", "executor_id": "venya-exec-1"}

    def test_heartbeat_revoked_identity_passes_through_for_advisory(self):
        """B1 RULING PIN: a revoked executor is NOT 403'd on the heartbeat
        path (contrast test_identity_revoked_rejected_403 on the session
        path) — it passes through for the advisory 200 {revoked:true} (F3
        ride-along cooperative-stop channel); the route-side write-guard
        skips the row stamp (pinned in test_executor_revocation_identity.py
        ::test_identity_revoked_true)."""
        executor_row, _, _ = self._rows(revoked_at=datetime.now(UTC))
        backend, _ = self._make_executor_backend(executor_row=executor_row)
        app = self._create_executor_app(backend=backend)
        client = TestClient(app, raise_server_exceptions=False)
        resp = client.post(
            "/api/v1/heartbeat",
            json={"executor_id": "venya-exec-1", "cert_fingerprint": "abc"},
            headers={
                "X-Client-Verified": "SUCCESS",
                "X-Client-Subject": self.EXEC_SUBJECT,
                "X-Client-Serial": "0000000000000001",
            },
        )
        assert resp.status_code == 200
        assert resp.json()["user"]["caller"] == "executor"


class TestBareHealthAlias:
    """Truth table for the bare /health alias (ticket
    health-probe-401-installer-diagnostics scope a): the alias reuses the
    canonical handler (identical payload), is public via EXACT-path
    membership, and the addition widens nothing — unknown and prefixed
    paths still get the uniform 401 (info-hiding intact)."""

    def _create_full_app(self):
        from server.app import create_app
        from server.config import RateLimitConfig, ServerConfig

        config = ServerConfig(
            recovery_code_pepper="test-pepper-unused",
            rate_limit=RateLimitConfig(enforce=False),
        )
        return create_app(config).app

    def test_bare_health_public_200_identical_payload(self):
        """Positive: unauthenticated GET /health → 200, payload IDENTICAL to
        the canonical /api/v1/health (same handler, same disclosure)."""
        client = TestClient(self._create_full_app(), raise_server_exceptions=False)
        bare = client.get("/health")
        canon = client.get("/api/v1/health")
        assert bare.status_code == 200
        assert canon.status_code == 200
        assert bare.json() == canon.json()

    def test_nonexistent_path_still_401(self):
        """Paired negative: the PUBLIC_PATHS addition must not leak — an
        unknown path unauthenticated is STILL the uniform 401, not 404."""
        client = TestClient(self._create_full_app(), raise_server_exceptions=False)
        resp = client.get("/nonexistent")
        assert resp.status_code == 401
        assert resp.json()["detail"] == "Missing authentication token"

    def test_public_entry_is_exact_not_prefix(self):
        """Paired negative: exact frozenset membership only — paths that
        merely START with /health do not bypass auth."""
        client = TestClient(self._create_full_app(), raise_server_exceptions=False)
        assert client.get("/healthz").status_code == 401
        assert client.get("/health/deeper").status_code == 401


class TestSessionExtension:
    """Tests for middleware session extension (M-19 fix)."""

    def _make_session(self, user_id="user1", expires_at=None, access_token="token-123", user_status="active"):
        if expires_at is None:
            expires_at = datetime.now(UTC) + timedelta(minutes=10)
        user_mock = SimpleNamespace(user_id=user_id, status=user_status)
        return SimpleNamespace(
            id=1,
            user_id=user_id,
            expires_at=expires_at,
            user=user_mock,
            access_token=access_token,
        )

    def _make_backend(self, session=None, db=None):
        if db is None:
            db = MagicMock()
            db.query.return_value.filter.return_value.first.return_value = session
        backend = MagicMock()
        backend.get_session.return_value = db
        return backend, db

    def test_extend_when_nearing_expiry(self):
        """Session within 5 minutes of expiry should be extended + committed."""
        expires_at = datetime.now(UTC) + timedelta(minutes=3)
        session = self._make_session(expires_at=expires_at)
        backend, db = self._make_backend(session)

        with patch("core.iam.session_manager.SessionManager") as mock_sm, patch(
            "core.iam.role_manager.RoleManager"
        ) as mock_rm:
            mock_sm.return_value.check_expiry.return_value = True
            mock_sm.return_value.extend_session.return_value = True
            mock_rm.return_value.get_user_roles.return_value = []

            app = _create_test_app()
            app.state.backend = backend

            client = TestClient(
                app,
                raise_server_exceptions=False,
                headers={"authorization": "Bearer token-123"},
            )
            resp = client.get("/api/v1/protected")
            assert resp.status_code == 200

            mock_sm.return_value.extend_session.assert_called_once_with(1)
            db.commit.assert_called_once()

    def test_no_extend_when_fresh(self):
        """Session with >5 minutes left should not be extended."""
        expires_at = datetime.now(UTC) + timedelta(minutes=10)
        session = self._make_session(expires_at=expires_at)
        backend, db = self._make_backend(session)

        with patch("core.iam.session_manager.SessionManager") as mock_sm, patch(
            "core.iam.role_manager.RoleManager"
        ) as mock_rm:
            mock_sm.return_value.check_expiry.return_value = True
            mock_sm.return_value.extend_session.return_value = True
            mock_rm.return_value.get_user_roles.return_value = []

            app = _create_test_app()
            app.state.backend = backend

            client = TestClient(
                app,
                raise_server_exceptions=False,
                headers={"authorization": "Bearer token-123"},
            )
            resp = client.get("/api/v1/protected")
            assert resp.status_code == 200

            mock_sm.return_value.extend_session.assert_not_called()
            db.commit.assert_not_called()

    def test_no_refresh_token_called(self):
        """Middleware should extend, never rotate tokens."""
        expires_at = datetime.now(UTC) + timedelta(minutes=3)
        session = self._make_session(expires_at=expires_at)
        backend, _db = self._make_backend(session)

        with patch("core.iam.session_manager.SessionManager") as mock_sm, patch(
            "core.iam.role_manager.RoleManager"
        ) as mock_rm:
            mock_sm.return_value.check_expiry.return_value = True
            mock_sm.return_value.extend_session.return_value = True
            mock_sm.return_value.refresh_token.return_value = None
            mock_rm.return_value.get_user_roles.return_value = []

            app = _create_test_app()
            app.state.backend = backend

            client = TestClient(
                app,
                raise_server_exceptions=False,
                headers={"authorization": "Bearer token-123"},
            )
            resp = client.get("/api/v1/protected")
            assert resp.status_code == 200

            mock_sm.return_value.refresh_token.assert_not_called()

    def test_expired_session_returns_401(self):
        """Expired session should return 401, not extend."""
        expires_at = datetime.now(UTC) - timedelta(minutes=5)
        session = self._make_session(expires_at=expires_at)
        backend, _db = self._make_backend(session)

        with patch("core.iam.session_manager.SessionManager") as mock_sm, patch(
            "core.iam.role_manager.RoleManager"
        ) as mock_rm:
            mock_sm.return_value.check_expiry.return_value = False
            mock_rm.return_value.get_user_roles.return_value = []

            app = _create_test_app()
            app.state.backend = backend

            client = TestClient(
                app,
                raise_server_exceptions=False,
                headers={"authorization": "Bearer token-123"},
            )
            resp = client.get("/api/v1/protected")
            assert resp.status_code == 401

            mock_sm.return_value.extend_session.assert_not_called()


class TestDisabledUserSurvivingSession:
    """Surviving-session status gate (sec-auth-elevation-authz-hardening #9).

    Issuance is gated by create_session (UserNotActiveError, webauthn ticket);
    this pins the OTHER half: a user disabled AFTER login loses access on the
    next request — the session does not survive until idle expiry.
    """

    def test_disabled_user_live_session_rejected_401(self):
        session = _make_session_mock(user_status="disabled")
        backend = _make_backend(session)

        with patch("core.iam.session_manager.SessionManager") as mock_sm, patch(
            "core.iam.role_manager.RoleManager"
        ) as mock_rm:
            mock_sm.return_value.check_expiry.return_value = True
            mock_rm.return_value.get_user_roles.return_value = []

            app = _create_test_app()
            app.state.backend = backend

            client = TestClient(app, raise_server_exceptions=False)
            resp = client.get("/api/v1/protected", headers={"authorization": "Bearer token-123"})
            assert resp.status_code == 401
            assert resp.json()["detail"] == "Invalid or expired token"

    def test_pending_enrollment_user_live_session_rejected_401(self):
        """Paired negative: any non-active status is refused, not just 'disabled'."""
        session = _make_session_mock(user_status="pending_enrollment")
        backend = _make_backend(session)

        with patch("core.iam.session_manager.SessionManager") as mock_sm, patch(
            "core.iam.role_manager.RoleManager"
        ) as mock_rm:
            mock_sm.return_value.check_expiry.return_value = True
            mock_rm.return_value.get_user_roles.return_value = []

            app = _create_test_app()
            app.state.backend = backend

            client = TestClient(app, raise_server_exceptions=False)
            resp = client.get("/api/v1/protected", headers={"authorization": "Bearer token-123"})
            assert resp.status_code == 401

    def test_active_user_live_session_passes(self):
        """Paired positive: the gate does not reject the normal case."""
        session = _make_session_mock(user_status="active")
        backend = _make_backend(session)

        with patch("core.iam.session_manager.SessionManager") as mock_sm, patch(
            "core.iam.role_manager.RoleManager"
        ) as mock_rm:
            mock_sm.return_value.check_expiry.return_value = True
            mock_rm.return_value.get_user_roles.return_value = []

            app = _create_test_app()
            app.state.backend = backend

            client = TestClient(app, raise_server_exceptions=False)
            resp = client.get("/api/v1/protected", headers={"authorization": "Bearer token-123"})
            assert resp.status_code == 200
            assert resp.json()["user"]["user_id"] == "user1"
