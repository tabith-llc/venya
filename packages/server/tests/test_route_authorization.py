# Copyright (c) 2026 Tabith LLC.
# Use of this source code is governed by the Business Source License 1.1
# included in the LICENSE file at the root of this repository. As of the
# Change Date listed there, the work is available under MPL 2.0.
# SPDX-License-Identifier: BUSL-1.1

"""Route-coverage net: every mounted endpoint must be guard-tagged or allowlisted,
AND every guard-tagged admin route must be REACHABLE to a caller the middleware can
actually produce.

This is the permanent control that replaced the retired RBACMiddleware path
matching. A privileged route that neither carries a _venya_guard
(require_admin / require_role / get_current_user) nor appears in NO_ROLE_ROUTES
fails the test — "did we forget a route?" can no longer ship silently.

The first assertion class answers "is a guard attached?". It cannot answer the
question #729 was filed on: a route can carry the real ``require_admin`` and still
be one the shipped ``SessionMiddleware`` can never hand an admin caller to, because
the middleware's own reach test is a prefix test plus a named bootstrap set. #730
AC4 therefore adds the second assertion class below (``TestAdminGuardedRoutesAreReachable``):
for every mounted route whose dependency tree carries the ``admin`` marker, state
whether the middleware can produce a caller that satisfies it — ``prefix-reachable``,
``bootstrap-reachable by name``, or ``neither`` — derived from the shipped objects
(``SessionMiddleware._is_admin_route``, ``SessionMiddleware.BOOTSTRAP_PATHS`` and the
paths ``server.app.create_app`` actually mounts), never from a hand-kept list. A route
in ``neither`` is a guard that can only ever answer for a caller who cannot arrive, and
that is the shape #729 shipped.

Each of the four new cells has a single-mutation red face, and leg 838 ran all four against a
throwaway copy of this file (`cp packages/server/tests/test_route_authorization.py
packages/server/tests/zz838b.py`, mutate one object, `uv run -p 3.14 --directory packages/server
pytest tests/zz838b.py -q -k <cell>`, then remove the copy and its `.pyc`): point `app` at an app
that mounts the real `require_admin` at `/api/v1/roles/{role_id}/members` and the census cell is red;
make `_reachability` skip the `BOOTSTRAP_PATHS` branch and the control cell is red (`init/reset`
reads `neither`); move that control writer under `/api/v1/admin/` and the sensitivity cell is red (the
predicate goes silent); name a route in the middleware's path sets that nothing mounts and the drift
cell is red. Logs: `/tabith/wave44-specs-20261101/838-logs/w4_*.txt` … `w7_*.txt`.
"""

from fastapi import Depends, FastAPI
from fastapi.routing import APIRoute
from server.app import create_app
from server.config import ServerConfig
from server.dependencies import require_admin
from server.middleware.auth import SessionMiddleware


def _norm(path: str) -> str:
    """Canonical form for allowlist matching: {param} segments -> * (positional)."""
    return "/".join("*" if seg.startswith("{") and seg.endswith("}") else seg for seg in path.split("/") if seg)


# Routes that intentionally rely on non-role authorization, grouped by model.
# (No _venya_guard present, so they MUST be allowlisted or the net fails.)
NO_ROLE_ROUTES = frozenset(
    _norm(p)
    for p in [
        # --- public / bootstrap: no authenticated session (or role) exists yet ---
        "/api/v1/health",  # liveness, no auth by design
        "/health",  # bare alias of /api/v1/health, same handler, no auth by design
        "/api/v1/ready",  # readiness, no auth by design
        "/api/v1/auth/login/start",
        "/api/v1/auth/login/complete",
        "/api/v1/auth/refresh",  # rotates the caller's own token
        "/api/v1/auth/login/browser/challenge",  # browser login challenge
        "/api/v1/auth/login/browser/assert",  # browser login assertion
        "/api/v1/auth/refresh/browser",  # browser token refresh
        "/api/v1/auth/logout/browser",  # browser logout
        "/api/v1/auth/elevate/browser/challenge",  # elevation challenge
        "/api/v1/auth/elevate/browser/assert",  # elevation assertion
        "/api/v1/auth/me",  # returns caller's own identity (bearer auth)
        "/api/v1/enroll/browser",  # alias for /enroll/browser/start
        "/api/v1/enroll/browser/start",  # self-registration via issuance token
        "/api/v1/enroll/browser/complete",
        "/api/v1/init",  # bootstrap (gated by FIDO2 / enrolled_count==0)
        # /api/v1/init/reset: removed from this allowlist (#450) — the route
        # now carries require_admin_when_initialized (_venya_guard = "admin"),
        # so the net above covers it.
        "/api/v1/init/complete",
        # --- break-glass: recovery code + FIDO2 assertion + 5/hr per-IP limit ---
        "/api/v1/recovery",
        # --- executor / mTLS: identity is the client cert, no user_id/role ---
        "/api/v1/executors/register",
        "/api/v1/executors/certs/revocation-list",  # CRL pulled by executors
        "/api/v1/executors/certs/crl",
        "/api/v1/heartbeat",
        "/api/v1/audit/ingest",  # executor mTLS audit-forwarder sink (#307)
        "/api/v1/sessions/{session_id}/secrets/revoke",  # executor mTLS
        "/api/v1/sessions/{session_id}/filter",  # executor mTLS
        # --- self-service, own-user scoped: bearer auth + ownership, not a role ---
        "/api/v1/credentials",  # lists caller's own credentials
        "/api/v1/credentials/{credential_id}",  # deletes caller's own credential
        "/api/v1/credentials/add/browser/start",  # add requires FIDO2 elevation token
        "/api/v1/credentials/add/browser/complete",
        # --- static HTML pages: no auth required ---
        "/",  # login page (public)
        "/enroll",  # user enrollment page (public)
        "/enroll-admin",  # admin enrollment page (public)
        "/dashboard",  # dashboard page (public)
        "/static/{file_path:path}",  # static assets (public)
    ]
)


def _guards(dependants) -> list[str]:
    """Collect _venya_guard marker values across a dependency tree (recursive)."""
    found: list[str] = []
    for d in dependants:
        marker = getattr(d.call, "_venya_guard", None)
        if marker:
            found.append(marker)
        found.extend(_guards(d.dependencies))
    return found


def _endpoints(app):
    """Yield (full_path, dependant, include_level_deps) for every APIRoute.

    shortcut: relies on FastAPI's lazy router-inclusion contract
    (_IncludedRouter.original_router + .include_context). If a FastAPI upgrade
    stops exposing .original_router, walk app.openapi() paths and re-resolve
    the dependants instead — the assertion below stays the same.
    """
    for r in app.routes:
        if isinstance(r, APIRoute):
            yield r.path, r.dependant, []
        elif hasattr(r, "original_router"):
            ctx = getattr(r, "include_context", None)
            prefix = (getattr(ctx, "prefix", "") or "") if ctx else ""
            include_deps = list(getattr(ctx, "dependencies", []) or []) if ctx else []
            for er in list(r.original_router.routes):
                if isinstance(er, APIRoute):
                    yield prefix + er.path, er.dependant, include_deps


# --- #730 AC4: the reachability class -------------------------------------------------

PREFIX_REACHABLE = "prefix-reachable"
BOOTSTRAP_REACHABLE = "bootstrap-reachable by name"
UNREACHABLE = "neither"


def _reachability(path: str) -> str:
    """What the shipped middleware can hand a request at this path, read off the shipped objects.

    ``_is_admin_route`` is called on the class with no instance: its body is
    ``path.startswith("/api/v1/admin/")`` and touches nothing but its argument, so an
    instance would add app state this predicate does not have and should not borrow.
    The bootstrap set is consulted BY NAME first, because that is the order
    ``dispatch`` enters them (the ``BOOTSTRAP_PATHS`` branch precedes the admin-mTLS
    branch) and a path in both sets is served by the bootstrap treatment.
    """
    if path in SessionMiddleware.BOOTSTRAP_PATHS:
        return BOOTSTRAP_REACHABLE
    if SessionMiddleware._is_admin_route(None, path):
        return PREFIX_REACHABLE
    return UNREACHABLE


def _admin_guarded(app) -> list[str]:
    """Every mounted path whose dependency tree carries the shipped ``admin`` marker."""
    out: list[str] = []
    for path, dependant, include_deps in _endpoints(app):
        if "admin" in _guards(include_deps + list(dependant.dependencies)):
            out.append(path)
    return out


def _mounted(app) -> list[str]:
    return [path for path, _dependant, _deps in _endpoints(app)]


def _unreachable_admin_routes(app) -> list[str]:
    return sorted({p for p in _admin_guarded(app) if _reachability(p) == UNREACHABLE})


def _declared_paths_with_no_route(app) -> list[str]:
    """Paths the middleware's own sets name but the app does not mount — a rename drift
    guard for the sets AC2's cells drive, derived from the same two objects."""
    mounted = set(_mounted(app))
    declared = set(SessionMiddleware.BOOTSTRAP_PATHS) | set(SessionMiddleware.SESSION_REQUIRED_ADMIN_PATHS)
    return sorted(declared - mounted)


class TestAdminGuardedRoutesAreReachable:
    """#730 AC4 — reachability, not marker presence."""

    def test_no_admin_guarded_route_is_unreachable(self):
        app = create_app(ServerConfig(recovery_code_pepper="test-pepper-unused")).app
        guarded = _admin_guarded(app)
        # Never pass vacuously: an empty census is a traversal failure, not a clean bill.
        assert guarded, "No admin-guarded route found — the census traversal is broken"
        violations = _unreachable_admin_routes(app)
        assert not violations, (
            f"{len(guarded)} admin-guarded routes censused; these carry require_admin where the "
            f"middleware can never produce an admin caller:\n" + "\n".join(violations)
        )

    def test_the_census_reports_the_roles_writers_and_init_reset_differently(self):
        """AC4's named control, and the proof the predicate is not one bucket: #729 moved the role
        WRITERS under the admin prefix, and ``/api/v1/init/reset`` was exempted there by NAME. Same
        marker, two different answers, and a census that returned one value for both would be blind.
        """
        assert _reachability("/api/v1/admin/roles/{role_id}/members") == PREFIX_REACHABLE
        assert _reachability("/api/v1/init/reset") == BOOTSTRAP_REACHABLE
        assert _reachability("/api/v1/init/reset") != _reachability("/api/v1/admin/roles")
        # init/reset is reachable ONLY because it is named: the prefix test says no.
        assert SessionMiddleware._is_admin_route(None, "/api/v1/init/reset") is False
        assert "/api/v1/init/reset" in SessionMiddleware.BOOTSTRAP_PATHS
        # And the pre-#729 writer shape is the UNREACHABLE one — the role readers still live here, so
        # the census has to be able to name it (asserted live in the next cell).
        assert _reachability("/api/v1/roles/{role_id}/members") == UNREACHABLE

    def test_the_census_fires_on_a_require_admin_writer_outside_the_admin_prefix(self):
        """Positive control for the cell above: this predicate can return nonzero, and it returns it on
        exactly the shape #729 shipped — the real ``require_admin`` mounted at a path that is neither
        under the admin prefix nor named in ``BOOTSTRAP_PATHS``.
        """
        app = FastAPI()

        @app.post("/api/v1/roles/{role_id}/members", dependencies=[Depends(require_admin)])
        def _writer(role_id: int) -> dict:
            return {"role_id": role_id}

        assert _admin_guarded(app) == ["/api/v1/roles/{role_id}/members"]
        assert _unreachable_admin_routes(app) == ["/api/v1/roles/{role_id}/members"]

    def test_the_app_mounts_every_path_the_middleware_sets_name(self):
        """The drift guard for AC2's two mint paths: ``BOOTSTRAP_PATHS`` and
        ``SESSION_REQUIRED_ADMIN_PATHS`` are consulted as exact strings, so a route rename that leaves
        a set entry behind turns a session-demanding path into an ordinary admin path with no cell
        failing anywhere else in this net.
        """
        app = create_app(ServerConfig(recovery_code_pepper="test-pepper-unused")).app
        orphans = _declared_paths_with_no_route(app)
        assert not orphans, f"middleware path sets name routes the app does not mount: {orphans}"
        # Positive control on that zero: the same helper flags a name that is not mounted.
        mounted = set(_mounted(app))
        assert "/api/v1/admin/recovery-code/reissue" in mounted
        assert "/api/v1/admin/not-a-real-route-730" not in mounted


def test_every_route_is_guarded_or_allowlisted():
    app = create_app(ServerConfig(recovery_code_pepper="test-pepper-unused")).app

    seen = 0
    violations: list[str] = []
    for path, dependant, include_deps in _endpoints(app):
        seen += 1
        guarded = _guards(include_deps + list(dependant.dependencies))
        if not guarded and _norm(path) not in NO_ROLE_ROUTES:
            violations.append(f"  {path} — no _venya_guard and not in NO_ROLE_ROUTES")

    # Never pass vacuously: if traversal silently yields nothing, fail loudly.
    assert seen > 0, "No endpoints found — app.routes traversal is broken"
    assert not violations, "Privileged route(s) missing a role/auth guard and not in the allowlist:\n" + "\n".join(
        violations
    )
