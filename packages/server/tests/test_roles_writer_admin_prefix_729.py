"""Leg 814 / #729 — the role writers under /api/v1/admin/, cell by cell.

Layer attribution per the leg-813 fixture law (every refusal cell names the
layer it is proven at, and every identity is an EXPLICIT per-cell argument —
no fixture in this file supplies an identity by default):

- TestRegistration          — Starlette route registration and verb matching.
                              NO middleware is mounted in these cells.
- TestPredicate             — the shipped predicate itself,
                              ``server.middleware.auth.SessionMiddleware._is_admin_route``.
- TestRealMiddlewareDenials — the REAL production ``SessionMiddleware`` with
                              ``admin_mtls`` enabled: the admin-mTLS branch is
                              the refusing layer.

Reader invariance (the #448 roster-scoping 404-shaped deny, member and
oversight reads) is proven by the five scoping cells already in
``test_roles.py`` — those GETs did not move, and the same suite run covers
them at this tip.
"""

from types import SimpleNamespace
from unittest.mock import MagicMock, patch

from fastapi import FastAPI
from fastapi.testclient import TestClient
from server.middleware.auth import SessionMiddleware
from server.routes import roles as roles_routes

# Explicit identities, one per cell — never a fixture default.
ADMIN_CELL_5 = {"user_id": "explicit-admin-cell-5", "caller": "admin", "plane": "machine"}
ADMIN_CELL_6 = {"user_id": "explicit-admin-cell-6", "caller": "admin", "plane": "machine"}


def _bare_app():
    """The real roles router at the real prefix, NO middleware — route-matching layer only."""
    app = FastAPI()
    app.include_router(roles_routes.router, prefix="/api/v1")
    return app


class TestRegistration:
    """Layer: Starlette route registration. Middleware is not mounted here."""

    def test_writers_registered_under_admin_prefix_readers_stayed(self):
        # Shape-agnostic read of the ACTUAL routed surface: app.openapi() reflects
        # exactly what routes resolve at runtime. (This FastAPI build defers
        # included routers via a private _IncludedRouter, so app.routes does NOT
        # flatten them — the wrong instrument; openapi() is the routed truth.)
        paths = _bare_app().openapi()["paths"]
        assert "post" in paths.get("/api/v1/admin/roles", {})
        assert "put" in paths.get("/api/v1/admin/roles/{role_id}", {})
        assert "delete" in paths.get("/api/v1/admin/roles/{role_id}", {})
        assert "post" in paths.get("/api/v1/admin/roles/{role_id}/members", {})
        assert "delete" in paths.get("/api/v1/admin/roles/{role_id}/members/{user_id}", {})
        # readers kept their exact paths
        for path in ("/api/v1/roles", "/api/v1/roles/{role_id}", "/api/v1/roles/{role_id}/members"):
            assert "get" in paths.get(path, {}), f"GET {path} missing"
        # and the old writer verbs are gone from the old paths (only GET remains there)
        assert "post" not in paths.get("/api/v1/roles", {})
        assert "put" not in paths.get("/api/v1/roles/{role_id}", {})
        assert "delete" not in paths.get("/api/v1/roles/{role_id}", {})
        assert "post" not in paths.get("/api/v1/roles/{role_id}/members", {})
        assert "/api/v1/roles/{role_id}/members/{user_id}" not in paths

    def test_stale_shared_path_writers_answer_405(self):
        """A stale CLI POSTs the OLD path; the reader keeps that path registered,
        so Starlette partial-matches and answers 405 — loud, not silent, and it
        cannot reach a wrong handler (R-2701 fact 2). Proof layer: route matching."""
        client = TestClient(_bare_app(), raise_server_exceptions=False)
        assert client.post("/api/v1/roles", json={"name": "x", "permissions": "read"}).status_code == 405
        assert client.put("/api/v1/roles/1", json={"description": "x"}).status_code == 405
        assert client.delete("/api/v1/roles/1").status_code == 405
        assert client.post("/api/v1/roles/1/members", json={"user_id": "u"}).status_code == 405

    def test_stale_unique_path_writer_answers_404(self):
        """DELETE …/members/{user_id} is path-UNIQUE — no reader stayed on it,
        so the stale call answers 404 (R-2701 fact 2). Proof layer: route matching."""
        client = TestClient(_bare_app(), raise_server_exceptions=False)
        assert client.delete("/api/v1/roles/1/members/user1").status_code == 404


class TestPredicate:
    """Layer: the shipped prefix predicate itself, not a copy of it."""

    def test_predicate_reaches_every_moved_writer_and_no_reader(self):
        mw = SessionMiddleware()
        assert mw._is_admin_route("/api/v1/admin/roles") is True
        assert mw._is_admin_route("/api/v1/admin/roles/1") is True
        assert mw._is_admin_route("/api/v1/admin/roles/1/members") is True
        assert mw._is_admin_route("/api/v1/admin/roles/1/members/user1") is True
        # Readers keep their exact paths, so the predicate still does NOT see them.
        assert mw._is_admin_route("/api/v1/roles") is False
        assert mw._is_admin_route("/api/v1/roles/1") is False
        assert mw._is_admin_route("/api/v1/roles/1/members") is False


def _middleware_app(seen_marker: dict):
    """Real production SessionMiddleware over the real roles router.

    ``require_admin`` is overridden with a MARKER that records entry: if a
    refusal happens at the middleware the marker stays unset, which is how
    each refusal cell below names its layer as MIDDLEWARE rather than route.
    """
    from server.dependencies import get_db, require_admin

    app = FastAPI()
    app.include_router(roles_routes.router, prefix="/api/v1")

    def _marker():
        seen_marker["entered_route_dependency"] = True
        return ADMIN_CELL_6

    app.dependency_overrides[require_admin] = _marker
    app.dependency_overrides[get_db] = lambda: MagicMock()
    # admin_mtls ENABLED: this is the posture the re-path exists to create.
    app.state.config = SimpleNamespace(admin_mtls=SimpleNamespace(enabled=True))
    app.state.backend = MagicMock()
    app.add_middleware(SessionMiddleware)
    return app


class TestRealMiddlewareDenials:
    """Layer: the REAL SessionMiddleware, admin-mTLS branch, at the moved paths."""

    def test_writer_without_cert_refused_at_middleware_cert_gate(self):
        """Proof layer: MIDDLEWARE (admin-mTLS branch of SessionMiddleware.dispatch
        -> _validate_admin_mtls, deny_on_missing_cert=True). Identity the code
        path received: NONE — the marker dependency never ran, so the route
        body was never reached and no auth_user was ever attached."""
        marker: dict = {}
        client = TestClient(_middleware_app(marker), raise_server_exceptions=False)
        resp = client.post("/api/v1/admin/roles", json={"name": "ops", "permissions": "read"})
        assert resp.status_code == 403, resp.text
        assert resp.json()["detail"] == "Admin access requires valid client certificate"
        assert marker.get("entered_route_dependency") is None  # refused BEFORE the router

    def test_writer_with_bearer_token_still_refused_at_cert_gate(self):
        """After the move a SESSION cannot stand in for a CERTIFICATE on the
        writer surface: the admin branch runs before session validation, so the
        403 names the certificate whatever the bearer header claims. Proof
        layer: MIDDLEWARE. This is the identity-reachability change #729
        creates, stated as a cell: ``caller: "admin"`` on these paths now comes
        ONLY from a cryptographically verified certificate
        (auth.py, the ``request.state.auth_user = {"caller": "admin", ...}``
        attach inside the admin-mTLS branch), never from a default."""
        marker: dict = {}
        client = TestClient(_middleware_app(marker), raise_server_exceptions=False)
        resp = client.post(
            "/api/v1/admin/roles",
            json={"name": "ops", "permissions": "read"},
            headers={"Authorization": "Bearer session-cannot-mint-a-cert"},
        )
        assert resp.status_code == 403, resp.text
        assert resp.json()["detail"] == "Admin access requires valid client certificate"
        assert marker.get("entered_route_dependency") is None

    def test_reader_past_the_same_cert_gate_pair_negative(self):
        """PAIRED NEGATIVE for both refusal cells above: the SAME middleware on
        the SAME app waves the READER past the cert gate — the predicate does
        not name it, so the request falls to the session branch and answers 401
        "Missing authentication token", not the 403 certificate sentence. The
        gate moved onto the writers only; the readers' surface is untouched."""
        marker: dict = {}
        client = TestClient(_middleware_app(marker), raise_server_exceptions=False)
        resp = client.get("/api/v1/roles")
        assert resp.status_code == 401, resp.text
        assert resp.json()["detail"] == "Missing authentication token"


class TestMovedWriterReachableWithExplicitIdentity:
    """The moved surface works: same handler, same require_admin dependency,
    reached at the new path with an identity this cell supplies EXPLICITLY."""

    def test_post_admin_roles_answers_twenty_one(self):
        from server.dependencies import get_db, require_admin

        rm = MagicMock()
        rm.create_role.return_value = SimpleNamespace(id=1, name="ops", permissions="read", description=None)
        app = FastAPI()
        app.include_router(roles_routes.router, prefix="/api/v1")
        app.dependency_overrides[require_admin] = lambda: ADMIN_CELL_5
        app.dependency_overrides[get_db] = lambda: MagicMock()
        app.state.backend = MagicMock()
        client = TestClient(app, raise_server_exceptions=False)
        with patch("server.dependencies.RoleManager", return_value=rm), patch(
            "core.iam.role_manager.RoleManager", return_value=rm
        ):
            resp = client.post("/api/v1/admin/roles", json={"name": "ops", "permissions": "read"})
        assert resp.status_code == 201, resp.text
        rm.create_role.assert_called_once()
