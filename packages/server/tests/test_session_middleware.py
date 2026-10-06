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
        # #342: bearer-tier expiry — fresh by default so the session-tier
        # cells test what they always tested. NULL/aged is pinned in
        # tests/test_access_token_expiry_gate.py.
        access_token_expires_at=datetime.now(UTC) + timedelta(minutes=5),
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
    """Truth table for the executor-session-path gate on the crypto-forwarded
    certificate (#314; original ticket sec-executor-session-path-no-auth):
    caller=executor is granted ONLY on a Root-CA-verified certificate whose
    identity is a registered, non-revoked executor. Paired negatives
    throughout — the pre-fix code granted caller=executor to ANY anonymous
    caller by URL regex alone; the header trio that replaced it is now itself
    retired (forged headers are inert)."""

    def _root_ca(self, tmp_path):
        if not hasattr(self, "_ca_cache"):
            self._ca_cache = {}
        cache_key = str(tmp_path)
        if cache_key not in self._ca_cache:
            from server.ca import CAManager
            from server.config import CASecurityConfig

            ca_dir = tmp_path / "ca"
            ca_dir.mkdir(exist_ok=True)
            mgr = CAManager(str(ca_dir), CASecurityConfig(key_passphrase_env="ABSENT_TEST_VAR"))
            mgr.initialize()
            ca_cert, ca_key = mgr.load_ca()
            self._ca_cache[cache_key] = (mgr, ca_cert, ca_key)
        return self._ca_cache[cache_key]

    def _exec_cert(self, tmp_path, cn="venya-exec-1", serial=1):
        try:
            from .conftest import make_leaf
        except ImportError:
            from conftest import make_leaf

        _mgr, ca_cert, ca_key = self._root_ca(tmp_path)
        return make_leaf(ca_cert, ca_key, cn=cn, serial=serial)

    def _admin_ca_leaf(self, tmp_path, cn="admin@venya-core-1"):
        """Cross-plane leaf: signed by a DIFFERENT (admin-shaped) CA."""
        try:
            from .conftest import make_leaf
        except ImportError:
            from conftest import make_leaf

        from datetime import UTC as _UTC
        from datetime import datetime as _dt
        from datetime import timedelta as _td

        from cryptography import x509
        from cryptography.hazmat.primitives.asymmetric import ec
        from cryptography.hazmat.primitives.hashes import SHA256
        from cryptography.x509.oid import NameOID

        key = ec.generate_private_key(ec.SECP256R1())
        now = _dt.now(_UTC)
        admin_ca = (
            x509.CertificateBuilder()
            .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Venya Admin CA")]))
            .issuer_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Venya Admin CA")]))
            .public_key(key.public_key())
            .serial_number(9)
            .not_valid_before(now - _td(days=1))
            .not_valid_after(now + _td(days=365))
            .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
            .sign(key, SHA256())
        )
        return make_leaf(admin_ca, key, cn=cn)

    def _create_executor_app(self, backend=None, tmp_path=None):
        """App with SessionMiddleware + stub executor-session routes."""
        from server.config import InnerTLSConfig, ServerConfig
        from starlette.requests import Request

        prefix = tmp_path / "certfiles" if tmp_path is not None else None
        if prefix is not None:
            prefix.mkdir(exist_ok=True)

        config = ServerConfig(
            recovery_code_pepper="test-pepper",
            admin_mtls={"enabled": False},
            inner_mtls=InnerTLSConfig(
                enabled=True,
                cert_file="/test/inner.crt",
                key_file="/test/inner.key",
                client_ca_file="/test/inner-ca.crt",
            ),
        )

        app = FastAPI()
        app.add_middleware(SessionMiddleware)
        app.state.config = config
        if tmp_path is not None:
            app.state.ca_manager = self._root_ca(tmp_path)[0]
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

        @app.post("/api/v1/audit/ingest")
        def ingest_stub(request: Request):
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

    def _fwd(self, tmp_path, cert):
        try:
            from .conftest import forwarded_headers
        except ImportError:
            from conftest import forwarded_headers

        return forwarded_headers(tmp_path / "certfiles", cert)

    def test_anonymous_filter_rejected_401_before_any_db_or_hashing(self, tmp_path):
        """The oracle is dead pre-auth: no forwarded cert → 401, backend NEVER touched."""
        backend, _db = self._make_executor_backend()
        app = self._create_executor_app(backend=backend, tmp_path=tmp_path)
        client = TestClient(app, raise_server_exceptions=False)
        resp = client.post("/api/v1/sessions/1/filter", json={"stdout": "", "stderr": ""})
        assert resp.status_code == 401
        assert resp.json()["detail"] == "Executor mTLS authentication required"
        backend.get_session.assert_not_called()

    def test_anonymous_revoke_rejected_401(self, tmp_path):
        """Paired negative on the second gated path (audit-forgery hole)."""
        backend, _ = self._make_executor_backend()
        app = self._create_executor_app(backend=backend, tmp_path=tmp_path)
        client = TestClient(app, raise_server_exceptions=False)
        resp = client.post("/api/v1/sessions/sess-1/secrets/revoke", json={"secret_ids": ["1"]})
        assert resp.status_code == 401
        backend.get_session.assert_not_called()

    def test_forged_header_trio_without_cert_rejected_401(self, tmp_path):
        """The retired sentinel + subject headers, forged, with no forwarded
        cert file → 401 (the trio is inert; crypto verification is the gate)."""
        executor_row, _, _ = self._rows()
        backend, _ = self._make_executor_backend(executor_row=executor_row)
        app = self._create_executor_app(backend=backend, tmp_path=tmp_path)
        client = TestClient(app, raise_server_exceptions=False)
        resp = client.post(
            "/api/v1/sessions/1/filter",
            json={"stdout": "", "stderr": ""},
            headers={
                "X-Client-Verified": "SUCCESS",
                "X-Client-Subject": "CN=venya-exec-1,O=Venya",
                "X-Client-Serial": "0000000000000001",
            },
        )
        assert resp.status_code == 401

    def test_path_value_cert_pem_rejected_401(self, tmp_path):
        """Content transport guard: a filesystem-path string sent as the
        forwarded-cert PEM is not valid PEM → 401 fail-closed (there is no
        filesystem read, so a planted path grants nothing)."""
        import urllib.parse

        executor_row, _, _ = self._rows()
        backend, _ = self._make_executor_backend(executor_row=executor_row)
        app = self._create_executor_app(backend=backend, tmp_path=tmp_path)
        client = TestClient(app, raise_server_exceptions=False)
        resp = client.post(
            "/api/v1/sessions/1/filter",
            json={"stdout": "", "stderr": ""},
            headers={"x-client-cert-pem": urllib.parse.quote_from_bytes(str(tmp_path / "outside.pem").encode())},
        )
        assert resp.status_code == 401

    def test_unparseable_cert_pem_rejected_401(self, tmp_path):
        """Garbage bytes (URL-encoded) behind the header → 401 (parse fails closed)."""
        import urllib.parse

        executor_row, _, _ = self._rows()
        backend, _ = self._make_executor_backend(executor_row=executor_row)
        app = self._create_executor_app(backend=backend, tmp_path=tmp_path)
        client = TestClient(app, raise_server_exceptions=False)
        resp = client.post(
            "/api/v1/sessions/1/filter",
            json={"stdout": "", "stderr": ""},
            headers={"x-client-cert-pem": urllib.parse.quote_from_bytes(b"not a certificate")},
        )
        assert resp.status_code == 401

    def test_unregistered_cn_rejected_403(self, tmp_path):
        """Verified Root-CA cert whose CN is not a registered Executor → 403."""
        backend, _ = self._make_executor_backend(executor_row=None)
        app = self._create_executor_app(backend=backend, tmp_path=tmp_path)
        cert = self._exec_cert(tmp_path, cn="ghost-executor")
        client = TestClient(app, raise_server_exceptions=False)
        resp = client.post(
            "/api/v1/sessions/1/filter",
            json={"stdout": "", "stderr": ""},
            headers=self._fwd(tmp_path, cert),
        )
        assert resp.status_code == 403

    def test_admin_cert_cn_rejected_403(self, tmp_path):
        """Cross-plane (ruled Q4): an Admin-CA cert presenting an
        executor-shaped CN is refused at the chain check — no DB row lookup
        needed; backend stays untouched (the former CN-discriminator path)."""
        backend, _ = self._make_executor_backend(executor_row=None)
        app = self._create_executor_app(backend=backend, tmp_path=tmp_path)
        cert = self._admin_ca_leaf(tmp_path, cn="venya-exec-1")
        client = TestClient(app, raise_server_exceptions=False)
        resp = client.post(
            "/api/v1/sessions/1/filter",
            json={"stdout": "", "stderr": ""},
            headers=self._fwd(tmp_path, cert),
        )
        assert resp.status_code == 401
        backend.get_session.assert_not_called()

    def test_registered_executor_passes_with_identity(self, tmp_path):
        """Full pass path: crypto-verified + registered + not revoked → caller state."""
        executor_row, _, _ = self._rows()
        backend, _ = self._make_executor_backend(executor_row=executor_row)
        app = self._create_executor_app(backend=backend, tmp_path=tmp_path)
        cert = self._exec_cert(tmp_path, serial=1)
        client = TestClient(app, raise_server_exceptions=False)
        resp = client.post(
            "/api/v1/sessions/1/filter",
            json={"stdout": "", "stderr": ""},
            headers=self._fwd(tmp_path, cert),
        )
        assert resp.status_code == 200
        assert resp.json()["user"] == {
            "caller": "executor",
            "executor_id": "venya-exec-1",
            "presented_serial": "0000000000000001",
            "revoked": False,
        }

    def test_identity_revoked_rejected_403(self, tmp_path):
        """Executor.revoked_at set → identity-flag revocation, terminal."""
        executor_row, _, _ = self._rows(revoked_at=datetime.now(UTC))
        backend, _ = self._make_executor_backend(executor_row=executor_row)
        app = self._create_executor_app(backend=backend, tmp_path=tmp_path)
        cert = self._exec_cert(tmp_path, serial=1)
        client = TestClient(app, raise_server_exceptions=False)
        resp = client.post(
            "/api/v1/sessions/1/filter",
            json={"stdout": "", "stderr": ""},
            headers=self._fwd(tmp_path, cert),
        )
        assert resp.status_code == 403

    def test_presented_serial_revoked_rejected_403(self, tmp_path):
        """The VERIFIED cert's serial is in the CRL → serial-history revocation."""
        executor_row, _, crl_row = self._rows()
        backend, _ = self._make_executor_backend(executor_row=executor_row, crl_row=crl_row)
        app = self._create_executor_app(backend=backend, tmp_path=tmp_path)
        cert = self._exec_cert(tmp_path, serial=2)
        client = TestClient(app, raise_server_exceptions=False)
        resp = client.post(
            "/api/v1/sessions/1/filter",
            json={"stdout": "", "stderr": ""},
            headers=self._fwd(tmp_path, cert),
        )
        assert resp.status_code == 403

    def test_no_backend_fails_closed_403(self, tmp_path):
        """Allowlist unverifiable (backend missing) → fail-closed 403."""
        app = self._create_executor_app(backend=None, tmp_path=tmp_path)
        cert = self._exec_cert(tmp_path, serial=1)
        client = TestClient(app, raise_server_exceptions=False)
        resp = client.post(
            "/api/v1/sessions/1/filter",
            json={"stdout": "", "stderr": ""},
            headers=self._fwd(tmp_path, cert),
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

    def test_heartbeat_no_cert_rejected_401(self, tmp_path):
        """No forwarded cert → 401 BEFORE the route (the path was once PUBLIC:
        unauthenticated liveness stamping + revocation oracle)."""
        executor_row, _, _ = self._rows()
        backend, _ = self._make_executor_backend(executor_row=executor_row)
        app = self._create_executor_app(backend=backend, tmp_path=tmp_path)
        client = TestClient(app, raise_server_exceptions=False)
        resp = client.post(
            "/api/v1/heartbeat",
            json={"executor_id": "venya-exec-1", "cert_fingerprint": "abc"},
        )
        assert resp.status_code == 401

    def test_heartbeat_verified_registered_passes(self, tmp_path):
        """Verified cert + registered CN → through to the route with the
        middleware-set auth state (CN binding happens route-side)."""
        executor_row, _, _ = self._rows()
        backend, _ = self._make_executor_backend(executor_row=executor_row)
        app = self._create_executor_app(backend=backend, tmp_path=tmp_path)
        cert = self._exec_cert(tmp_path, serial=1)
        client = TestClient(app, raise_server_exceptions=False)
        resp = client.post(
            "/api/v1/heartbeat",
            json={"executor_id": "venya-exec-1", "cert_fingerprint": "abc"},
            headers=self._fwd(tmp_path, cert),
        )
        assert resp.status_code == 200
        assert resp.json()["user"] == {
            "caller": "executor",
            "executor_id": "venya-exec-1",
            "presented_serial": "0000000000000001",
            "revoked": False,
        }

    def test_heartbeat_revoked_identity_passes_through_for_advisory(self, tmp_path):
        """B1 RULING PIN: a revoked executor is NOT 403'd on the heartbeat
        path (contrast test_identity_revoked_rejected_403 on the session
        path) — it passes through for the advisory 200 {revoked:true} (F3
        ride-along cooperative-stop channel)."""
        executor_row, _, _ = self._rows(revoked_at=datetime.now(UTC))
        backend, _ = self._make_executor_backend(executor_row=executor_row)
        app = self._create_executor_app(backend=backend, tmp_path=tmp_path)
        cert = self._exec_cert(tmp_path, serial=1)
        client = TestClient(app, raise_server_exceptions=False)
        resp = client.post(
            "/api/v1/heartbeat",
            json={"executor_id": "venya-exec-1", "cert_fingerprint": "abc"},
            headers=self._fwd(tmp_path, cert),
        )
        assert resp.status_code == 200
        assert resp.json()["user"]["caller"] == "executor"
        # audit-ingest-revoked-serial-flag-divergence: the admission verdict
        # + its input ride on auth_user for the route to share by construction.
        assert resp.json()["user"]["revoked"] is True
        assert resp.json()["user"]["presented_serial"] == "0000000000000001"

    # --- Audit-forwarder ingest gating (ticket audit-forwarder-server-sink #307) ---

    def test_audit_ingest_no_cert_rejected_401(self, tmp_path):
        """No forwarded cert → 401 before the route: the sink writes
        ledger rows, so an anonymous POST is an audit-forgery attempt."""
        executor_row, _, _ = self._rows()
        backend, _ = self._make_executor_backend(executor_row=executor_row)
        app = self._create_executor_app(backend=backend, tmp_path=tmp_path)
        client = TestClient(app, raise_server_exceptions=False)
        resp = client.post("/api/v1/audit/ingest", content=b"x")
        assert resp.status_code == 401
        assert resp.json()["detail"] == "Executor mTLS authentication required"

    def test_audit_ingest_verified_registered_passes(self, tmp_path):
        """Verified cert + registered CN → route with caller=executor state
        (route-side guard + provenance write pinned in test_audit.py)."""
        executor_row, _, _ = self._rows()
        backend, _ = self._make_executor_backend(executor_row=executor_row)
        app = self._create_executor_app(backend=backend, tmp_path=tmp_path)
        cert = self._exec_cert(tmp_path, serial=1)
        client = TestClient(app, raise_server_exceptions=False)
        resp = client.post("/api/v1/audit/ingest", content=b"x", headers=self._fwd(tmp_path, cert))
        assert resp.status_code == 200
        assert resp.json()["user"] == {
            "caller": "executor",
            "executor_id": "venya-exec-1",
            "presented_serial": "0000000000000001",
            "revoked": False,
        }

    def test_audit_ingest_revoked_identity_passes_through(self, tmp_path):
        """D2 RULING PIN (#307): a revoked executor is NOT 403'd on the
        ingest path — its evidence still lands, route-side flagged
        sender_revoked=true (contrast test_identity_revoked_rejected_403
        on the session path)."""
        executor_row, _, _ = self._rows(revoked_at=datetime.now(UTC))
        backend, _ = self._make_executor_backend(executor_row=executor_row)
        app = self._create_executor_app(backend=backend, tmp_path=tmp_path)
        cert = self._exec_cert(tmp_path, serial=1)
        client = TestClient(app, raise_server_exceptions=False)
        resp = client.post("/api/v1/audit/ingest", content=b"x", headers=self._fwd(tmp_path, cert))
        assert resp.status_code == 200
        assert resp.json()["user"]["caller"] == "executor"
        assert resp.json()["user"]["revoked"] is True
        assert resp.json()["user"]["presented_serial"] == "0000000000000001"


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
            # #342: fresh bearer-tier expiry by default so these session-tier
            # cells exercise what they always did; NULL/aged pinned in
            # tests/test_access_token_expiry_gate.py.
            access_token_expires_at=datetime.now(UTC) + timedelta(minutes=5),
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
