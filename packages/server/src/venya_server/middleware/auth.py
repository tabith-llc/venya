"""Session validation middleware.

Validates bearer tokens against active sessions and attaches
user info to request state.
"""

from __future__ import annotations

import logging
import time
from datetime import datetime, timezone
from typing import Any

from fastapi import Request, status
from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint
from starlette.responses import JSONResponse, Response

logger = logging.getLogger("venya.server")


class SessionMiddleware(BaseHTTPMiddleware):
    """Validates session tokens and manages token rotation.

    Extracts the Bearer token from the Authorization header,
    looks up the session, validates it's not expired, and attaches
    user info to request.state.auth_user.
    """

    # Paths that don't require authentication
    PUBLIC_PATHS = frozenset({
        "/api/v1/health",
        "/api/v1/ready",
        "/api/v1/auth/registration/start",
        "/api/v1/auth/registration/complete",
        "/api/v1/auth/login/start",
        "/api/v1/auth/login/complete",
        "/api/v1/auth/refresh",
        "/api/v1/enrollment/confirm",
        "/api/v1/init",
        "/api/v1/recovery",
        "/api/v1/executors/register",
        "/api/v1/executors/certs/revocation-list",
    })

    def __init__(self, app: Any = None, max_token_age: float = 300.0) -> None:
        """
        Args:
            app: The next ASGI app.
            max_token_age: Maximum age in seconds for a bearer token before
                requiring refresh.
        """
        super().__init__(app)
        self.max_token_age = max_token_age

    async def dispatch(
        self, request: Request, call_next: RequestResponseEndpoint
    ) -> Response:
        # Skip auth for public paths
        if request.url.path in self.PUBLIC_PATHS:
            return await call_next(request)

        # Skip mTLS paths (executor)
        if self._is_mtls_request(request):
            request.state.auth_user = {"caller": "executor"}  # type: ignore[attr-defined]
            return await call_next(request)

        # Skip executor session paths (mTLS auth, not bearer token)
        if self._is_executor_session_path(request.url.path):
            request.state.auth_user = {"caller": "executor"}  # type: ignore[attr-defined]
            return await call_next(request)

        # Extract bearer token
        auth_header = request.headers.get("authorization", "")
        if not auth_header.startswith("Bearer "):
            return JSONResponse(
                status_code=status.HTTP_401_UNAUTHORIZED,
                content={"detail": "Missing authentication token"},
            )

        token = auth_header[7:]

        # Validate token via backend
        user_info = await self._validate_token(request, token)
        if user_info is None:
            return JSONResponse(
                status_code=status.HTTP_401_UNAUTHORIZED,
                content={"detail": "Invalid or expired token"},
            )

        request.state.auth_user = user_info  # type: ignore[attr-defined]
        return await call_next(request)

    def _is_mtls_request(self, request: Request) -> bool:
        """Check if request was authenticated via mTLS."""
        # mTLS client cert info would be available via ASGI scope
        client_cert = request.scope.get("client_cert")
        return client_cert is not None

    def _is_executor_session_path(self, path: str) -> bool:
        """Check if path is an executor session endpoint.

        These paths use mTLS auth (not bearer tokens) and should
        bypass token-based authentication.

        Args:
            path: The request URL path.

        Returns:
            True if this is an executor session path.
        """
        import re

        return bool(re.match(r"^/api/v1/sessions/[^/]+/secrets/revoke$", path))

    async def _validate_token(
        self, request: Request, token: str
    ) -> dict | None:
        """Validate a bearer token and return user info.

        Args:
            request: The FastAPI request.
            token: The bearer token string.

        Returns:
            User info dict or None if invalid.
        """
        backend = getattr(request.app.state, "backend", None)
        if backend is None:
            return None

        db = backend.get_session()
        try:
            from ..iam.session_manager import SessionManager
            from ..iam.session_manager import SessionConfig as VaultSessionConfig
            from ..iam.models import Session as SessionModel
            from datetime import timedelta

            config = VaultSessionConfig(
                session_timeout=timedelta(minutes=15),
                access_token_ttl=timedelta(minutes=5),
                max_session_duration=timedelta(hours=4),
            )
            manager = SessionManager(db, config)

            # Find session by access token JTI
            session = (
                db.query(SessionModel)
                .filter(SessionModel.access_token_jti == token)
                .first()
            )

            if session is None:
                return None

            if not manager.check_expiry(session):
                return None

            # Get user info
            user = session.user
            user_info = {
                "user_id": user.user_id,
                "session_id": session.id,
                "roles": [],
                "exp": int(session.expires_at.timestamp()),
            }

            # Get role IDs for this user
            from ..iam.role_manager import RoleManager
            rm = RoleManager(db)
            user_roles = rm.get_user_roles(user.user_id)
            user_info["roles"] = [str(m.role_id) for m in user_roles]

            # Auto-refresh: if token is near expiry, create new token
            now = datetime.now(timezone.utc)
            if session.expires_at < now + timedelta(seconds=60):
                new_token = manager.refresh_token(token)
                if new_token:
                    user_info["session_id"] = session.id
                    # Token will be refreshed in response headers by a separate mechanism

            return user_info
        finally:
            db.close()
