# Copyright (c) 2026 Tabith LLC.
# Use of this source code is governed by the Business Source License 1.1
# included in the LICENSE file at the root of this repository. As of the
# Change Date listed there, the work is available under MPL 2.0.
# SPDX-License-Identifier: BUSL-1.1

"""Version-surface truth table (feature/version-surfaces, ruling 2026-09-20).

Single-source rule (condition 1): every surface reads
importlib.metadata.version(<dist>) — the tests compare against the SAME
call, so a literal anywhere would fail.

Heartbeat wire-compat (condition 2): the optional `version` field is
additive — the named negative pins a pre-change-shaped heartbeat to
200 + column untouched.
"""

from datetime import UTC, datetime, timedelta
from importlib.metadata import version as pkg_version
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

from fastapi import FastAPI
from starlette.testclient import TestClient

SERVER_VERSION = pkg_version("server")


# ---------------------------------------------------------------------------
# Health endpoint version field
# ---------------------------------------------------------------------------


class TestHealthVersion:
    def _app(self):
        from server.routes import health as health_routes

        health_routes._reset_health_cache()
        app = FastAPI()
        app.state.backend = MagicMock()
        app.include_router(health_routes.router, prefix="/api/v1")
        return app

    def test_health_carries_single_sourced_version(self):
        client = TestClient(self._app())
        resp = client.get("/api/v1/health")
        assert resp.status_code == 200
        assert resp.json()["version"] == SERVER_VERSION

    def test_health_docstring_fences_the_field(self):
        """Condition 5: the field's purpose is fenced in the route docstring."""
        from server.routes import health as health_routes

        doc = health_routes.health_check.__doc__ or ""
        assert "version" in doc
        assert "package version only" in doc


# ---------------------------------------------------------------------------
# FastAPI app version single-sourced
# ---------------------------------------------------------------------------


class TestAppVersion:
    def test_fastapi_version_matches_metadata(self):
        from server.app import create_app
        from server.config import ServerConfig

        outer = create_app(ServerConfig(recovery_code_pepper="test-pepper"))
        inner = outer
        while not hasattr(inner, "version"):  # unwrap middleware stack
            inner = inner.app
        assert inner.version == SERVER_VERSION


# ---------------------------------------------------------------------------
# Heartbeat additive version field (condition 2)
# ---------------------------------------------------------------------------


def _heartbeat_app(db, auth_executor_id="web-server-3"):
    from server.routes import executors as executors_routes
    from starlette.middleware.base import BaseHTTPMiddleware

    app = FastAPI()
    app.state.backend = MagicMock()
    app.state.backend.get_session.return_value = db
    app.state.ca_manager = MagicMock()
    app.include_router(executors_routes.router, prefix="/api/v1")

    # Middleware-shaped executor auth (ticket
    # sec-endpoint-ratelimit-hardening #7); every cell here beats as
    # web-server-3.
    class _ExecAuth(BaseHTTPMiddleware):
        async def dispatch(self, request, call_next):
            request.state.auth_user = {"caller": "executor", "executor_id": auth_executor_id}
            return await call_next(request)

    app.add_middleware(_ExecAuth)
    return app


def _db_with_executor(existing):
    db = MagicMock()

    def q(model):
        m = MagicMock()
        if model.__name__ == "Executor":
            m.filter = lambda *a, **k: MagicMock(first=lambda: existing)
        else:
            m.filter = lambda *a, **k: MagicMock(first=lambda: None)
            m.all = list
        return m

    db.query.side_effect = q
    return db


class TestHeartbeatVersionField:
    def _post(self, existing, body):
        db = _db_with_executor(existing)
        app = _heartbeat_app(db)
        with patch(
            "server.routes.executors.executor_revocation_state",
            return_value=SimpleNamespace(revoked=False),
        ):
            resp = TestClient(app).post("/api/v1/heartbeat", json=body)
        return resp, db

    def test_version_field_stored_on_row(self):
        from core.iam.models import Executor

        row = Executor(id="web-server-3", hostname="h", status="active")
        resp, db = self._post(row, {"executor_id": "web-server-3", "version": "9.9.9-test"})
        assert resp.status_code == 200
        assert row.version == "9.9.9-test"
        db.commit.assert_called()

    def test_heartbeat_pre_change_shape_leaves_version_null_and_returns_200(self):
        """NAMED NEGATIVE (condition 2): a heartbeat shaped EXACTLY like a
        pre-change daemon (no version key) must return 200 and leave the
        column untouched (NULL stays NULL — old daemons unaffected)."""
        from core.iam.models import Executor

        row = Executor(id="web-server-3", hostname="h", status="active")
        assert row.version is None
        resp, _ = self._post(row, {"executor_id": "web-server-3", "cert_fingerprint": "ab" * 32})
        assert resp.status_code == 200
        assert row.version is None

    def test_missing_version_leaves_existing_value_untouched(self):
        """Additive semantics: absence never NULLs out a previously reported version."""
        from core.iam.models import Executor

        row = Executor(id="web-server-3", hostname="h", status="active", version="1.2.3")
        resp, _ = self._post(row, {"executor_id": "web-server-3"})
        assert resp.status_code == 200
        assert row.version == "1.2.3"

    def test_empty_version_leaves_existing_value_untouched(self):
        """Empty string (metadata-missing daemon) is falsy — column untouched."""
        from core.iam.models import Executor

        row = Executor(id="web-server-3", hostname="h", status="active", version="1.2.3")
        resp, _ = self._post(row, {"executor_id": "web-server-3", "version": ""})
        assert resp.status_code == 200
        assert row.version == "1.2.3"


# ---------------------------------------------------------------------------
# Operator list surface: GET /api/v1/executors
# ---------------------------------------------------------------------------


class TestExecutorsListVersion:
    def test_list_surfaces_version(self):
        """Mirrors the test_executors.py harness: get_current_user override +
        MagicMock db whose query().all() yields the row."""
        from server.dependencies import get_current_user
        from server.routes import executors as executors_routes

        app = FastAPI()
        row = MagicMock()
        row.id = "web-server-3"
        row.hostname = "h"
        row.last_heartbeat = datetime.now(UTC) - timedelta(seconds=5)
        row.enrolled_at = datetime.now(UTC)
        row.revoked_at = None
        row.status = "active"
        row.version = "7.7.7"
        db = MagicMock()
        db.query.return_value.all.return_value = [row]
        app.state.backend = MagicMock()
        app.state.backend.get_session.return_value = db
        app.include_router(executors_routes.router, prefix="/api/v1")
        app.dependency_overrides[get_current_user] = lambda: {
            "user_id": "test-user",
            "roles": ["devops"],
            "caller": "human",
        }

        # Same RoleManager patch as test_executors.py's autouse fixture —
        # require_role("read") checks DB-derived permissions, not the token roles.
        rm = MagicMock()
        rm.get_user_permissions.side_effect = lambda uid: {1: "read"}
        with patch("server.dependencies.RoleManager", return_value=rm):
            resp = TestClient(app, raise_server_exceptions=False).get("/api/v1/executors")
        assert resp.status_code == 200
        assert resp.json()["executors"][0]["version"] == "7.7.7"


# ---------------------------------------------------------------------------
# Admin list surface: GET /api/v1/admin/executors
# ---------------------------------------------------------------------------


class TestAdminExecutorsListVersion:
    def test_admin_list_surfaces_version_with_null_passthrough(self):
        from server.routes import admin as admin_routes

        app = FastAPI()
        db = MagicMock()
        now = datetime.now(UTC)
        cert = SimpleNamespace(
            executor_id="e1",
            serial_number="aabb",
            fingerprint="ff",
            not_before=now,
            not_after=now + timedelta(days=30),
        )
        cert_query = MagicMock()
        cert_query.order_by.return_value.all.return_value = [cert]
        exec_row = SimpleNamespace(id="e1", version=None)
        exec_query = MagicMock()
        exec_query.all.return_value = [exec_row]

        def q(model):
            return cert_query if model.__name__ == "ExecutorCert" else exec_query

        db.query.side_effect = q
        app.state.backend = MagicMock()
        app.state.backend.get_session.return_value = db
        app.include_router(admin_routes.router, prefix="/api/v1")

        from server.dependencies import require_admin

        app.dependency_overrides[require_admin] = lambda: {"user_id": "admin"}

        with patch(
            # admin.py imports executor_revocation_state function-locally —
            # patch the SOURCE module the import resolves from at call time.
            "server.revocation.executor_revocation_state",
            return_value=SimpleNamespace(revoked=False),
        ):
            resp = TestClient(app).get("/api/v1/admin/executors")
        assert resp.status_code == 200
        body = resp.json()["executors"][0]
        assert "version" in body
        assert body["version"] is None  # NULL passthrough — CLI renders the label
