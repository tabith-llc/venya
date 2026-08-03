"""Role-based access control middleware.

Enforces permission checks on protected endpoints.
"""

from __future__ import annotations

import logging

from fastapi import Request, status
from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint
from starlette.responses import JSONResponse, Response

logger = logging.getLogger("venya.server")

# Paths that require read-write permission
WRITE_PATHS = frozenset({
    "/api/v1/secrets",
    "/api/v1/roles",
    "/api/v1/enrollment",
    "/api/v1/admin",
})

# Paths that require admin permission
ADMIN_PATHS = frozenset({
    "/api/v1/admin",
})


class RBACMiddleware(BaseHTTPMiddleware):
    """Enforces role-based access control.

    Checks that authenticated users have the required permissions
    for the requested endpoint.
    """

    async def dispatch(
        self, request: Request, call_next: RequestResponseEndpoint
    ) -> Response:
        # Skip if no auth info (public endpoints handled by SessionMiddleware)
        user_info = getattr(request.state, "auth_user", None)
        if user_info is None:
            return await call_next(request)

        # Executor (mTLS) has full access — they need the secrets
        if user_info.get("caller") == "executor":
            return await call_next(request)

        path = request.url.path
        method = request.method

        # Admin paths require admin role
        if path.startswith("/api/v1/admin"):
            if not self._has_admin_role(user_info):
                return JSONResponse(
                    status_code=status.HTTP_403_FORBIDDEN,
                    content={"detail": "Admin permission required"},
                )

        # POST/PUT/DELETE on secrets/roles require read-write
        if method in ("POST", "PUT", "DELETE") and (
            path.startswith("/api/v1/secrets")
            or path.startswith("/api/v1/roles")
        ):
            if not self._has_write_permission(user_info):
                return JSONResponse(
                    status_code=status.HTTP_403_FORBIDDEN,
                    content={"detail": "Write permission required"},
                )

        return await call_next(request)

    def _has_admin_role(self, user_info: dict) -> bool:
        """Check if user has admin role."""
        # TODO: Check against actual admin role in DB
        # For now, check for "admin" in roles
        return "admin" in user_info.get("roles", [])

    def _has_write_permission(self, user_info: dict) -> bool:
        """Check if user has write permission on requested resources."""
        # TODO: Check role permissions in DB
        # For now, accept any authenticated user
        return True
