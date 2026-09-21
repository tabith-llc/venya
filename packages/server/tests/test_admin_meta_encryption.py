# Copyright (c) 2026 Tabith LLC.
# Use of this source code is governed by the Business Source License 1.1
# included in the LICENSE file at the root of this repository. As of the
# Change Date listed there, the work is available under MPL 2.0.
# SPDX-License-Identifier: BUSL-1.1

"""Tests for admin metadata encryption in enrollment tokens."""

import json
from unittest.mock import MagicMock

from core.iam.models import ExecutorEnrollmentToken
from fastapi import FastAPI
from server.config import ServerConfig
from server.dependencies import get_current_user, require_admin
from server.routes import admin as admin_routes
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.testclient import TestClient


def _create_test_app_with_core(backend=None, auth_user=None, core_encrypt_side_effect=None):
    """Create a minimal test app with admin routes and a mock core."""
    app = FastAPI()
    if backend is None:
        backend = MagicMock()
        backend.get_session.return_value = MagicMock()
    app.state.backend = backend
    app.state.config = ServerConfig(recovery_code_pepper="test-pepper")

    mock_core = MagicMock()
    if core_encrypt_side_effect:
        mock_core.encrypt.side_effect = core_encrypt_side_effect
    else:
        mock_core.encrypt.return_value = (b"wrapped_dek", b"nonce", b"ciphertext")
    app.state.core = mock_core

    app.include_router(admin_routes.router, prefix="/api/v1")

    # Override auth deps so require_admin bypasses real auth
    TEST_USER = auth_user or {"user_id": "admin-1"}
    app.dependency_overrides[get_current_user] = lambda: TEST_USER
    app.dependency_overrides[require_admin] = lambda: TEST_USER

    class AuthMiddleware(BaseHTTPMiddleware):
        async def dispatch(self, request: Request, call_next):
            if auth_user is not None:
                request.state.auth_user = auth_user
            return await call_next(request)

    app.add_middleware(AuthMiddleware)
    return app, mock_core


class TestAdminMetaEncryption:
    """Tests for encrypted admin metadata on enrollment tokens."""

    def test_encrypt_called_on_token_creation(self):
        """core.encrypt() is called with JSON blob of forensic metadata."""
        mock_db = MagicMock()
        backend = MagicMock()
        backend.get_session.return_value = mock_db

        app, mock_core = _create_test_app_with_core(
            backend=backend,
            auth_user={"user_id": "admin-1", "session_id": "sess-123"},
        )

        client = TestClient(app, raise_server_exceptions=False)
        resp = client.post("/api/v1/admin/executors/test-exec/enroll")
        assert resp.status_code == 201

        # core.encrypt was called with JSON metadata
        mock_core.encrypt.assert_called_once()
        call_args = mock_core.encrypt.call_args[0][0]
        meta = json.loads(call_args)
        assert meta["sid"] == "sess-123"
        assert "ip" in meta
        assert "ua" in meta

    def test_encrypt_fails_gracefully_when_core_missing(self):
        """admin_enroll_executor raises clear error when core not initialized."""
        from server.dependencies import get_current_user, require_admin

        mock_db = MagicMock()
        backend = MagicMock()
        backend.get_session.return_value = mock_db

        app = FastAPI()
        app.state.backend = backend
        app.state.config = ServerConfig(recovery_code_pepper="test-pepper")
        # No core set — should cause clear error
        app.include_router(admin_routes.router, prefix="/api/v1")

        # Override auth deps
        _admin_user = {"user_id": "admin-1"}
        app.dependency_overrides[get_current_user] = lambda: _admin_user
        app.dependency_overrides[require_admin] = lambda: _admin_user

        client = TestClient(app, raise_server_exceptions=False)
        resp = client.post("/api/v1/admin/executors/test-exec/enroll")
        # Authored HTTPException passes through the generic handler → 503
        assert resp.status_code == 503
        assert "Core not initialized" in resp.json()["detail"]

    def test_encrypted_columns_set_on_token(self):
        """Encrypted metadata columns are set on the token before flush."""
        mock_db = MagicMock()
        mock_db.flush = MagicMock()
        mock_db.commit = MagicMock()
        mock_db.add = MagicMock()
        backend = MagicMock()
        backend.get_session.return_value = mock_db

        app, _mock_core = _create_test_app_with_core(backend=backend)

        client = TestClient(app, raise_server_exceptions=False)
        resp = client.post("/api/v1/admin/executors/test-exec/enroll")
        assert resp.status_code == 201

        # The token object was added to the DB session
        add_calls = mock_db.add.call_args_list
        assert len(add_calls) >= 1
        token = add_calls[0][0][0]
        assert isinstance(token, ExecutorEnrollmentToken)
        assert token.admin_meta_wrapped_dek == b"wrapped_dek"
        assert token.admin_meta_nonce == b"nonce"
        assert token.admin_meta_ciphertext == b"ciphertext"

    def test_null_metadata_handled(self):
        """Null session_id/UA produces valid JSON with null values."""
        mock_db = MagicMock()
        backend = MagicMock()
        backend.get_session.return_value = mock_db

        app, mock_core = _create_test_app_with_core(
            backend=backend,
            auth_user={"user_id": "admin-1"},  # No session_id
        )

        client = TestClient(app, raise_server_exceptions=False)
        resp = client.post("/api/v1/admin/executors/test-exec/enroll")
        assert resp.status_code == 201

        call_args = mock_core.encrypt.call_args[0][0]
        meta = json.loads(call_args)
        assert meta["sid"] is None
