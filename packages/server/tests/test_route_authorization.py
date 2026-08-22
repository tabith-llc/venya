"""Route-coverage net: every mounted endpoint must be guard-tagged or allowlisted.

This is the permanent control that replaced the retired RBACMiddleware path
matching. A privileged route that neither carries a _venya_guard
(require_admin / require_role / get_current_user) nor appears in NO_ROLE_ROUTES
fails the test — "did we forget a route?" can no longer ship silently.
"""

from fastapi.routing import APIRoute
from server.app import create_app
from server.config import ServerConfig


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
        "/api/v1/ready",  # readiness, no auth by design
        "/api/v1/auth/registration/start",  # auth flow — user does not exist yet
        "/api/v1/auth/registration/complete",
        "/api/v1/auth/login/start",
        "/api/v1/auth/login/complete",
        "/api/v1/auth/refresh",  # rotates the caller's own token
        "/api/v1/enroll/browser/start",  # self-registration via issuance token
        "/api/v1/enroll/browser/complete",
        "/api/v1/init",  # bootstrap (gated by FIDO2 / enrolled_count==0)
        "/api/v1/init/reset",
        "/api/v1/init/complete",
        # --- break-glass: recovery code + FIDO2 assertion + 5/hr per-IP limit ---
        "/api/v1/recovery",
        # --- executor / mTLS: identity is the client cert, no user_id/role ---
        "/api/v1/executors/register",
        "/api/v1/executors/certs/revocation-list",  # CRL pulled by executors
        "/api/v1/executors/certs/crl",
        "/api/v1/heartbeat",
        "/api/v1/sessions/{session_id}/secrets/revoke",  # executor mTLS
        "/api/v1/sessions/{session_id}/filter",  # executor mTLS
        # --- self-service, own-user scoped: bearer auth + ownership, not a role ---
        "/api/v1/credentials",  # lists caller's own credentials
        "/api/v1/credentials/{credential_id}",  # deletes caller's own credential
        "/api/v1/credentials/add/browser/start",  # add requires FIDO2 elevation token
        "/api/v1/credentials/add/browser/complete",
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

    ponytail: relies on FastAPI's lazy router-inclusion contract
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
