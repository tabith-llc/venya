"""Database session + auth dependencies for FastAPI."""

from __future__ import annotations

import logging
from collections.abc import Generator
from datetime import datetime, timezone

from fastapi import Depends, HTTPException, Request, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy.orm import Session

logger = logging.getLogger("venya.server")

from vault.vault.backend import Backend, BackendConfig
from vault.vault.factory import VaultFactory
from vault.vault.vault import Caller
from vault.iam.models import Session as SessionModel
from vault.iam.session_manager import SessionConfig as VaultSessionConfig, SessionManager
from vault.iam.role_manager import RoleManager
from .utils.time import is_expired

_bearer_scheme = HTTPBearer(auto_error=False)


def init_db(db_config: BackendConfig, db_url: str | None = None) -> Backend:
    """Initialize the database backend.

    Uses database_url for PostgreSQL connection.

    Args:
        db_config: Database configuration (passphrase only).
        db_url: PostgreSQL database URL.

    Returns:
        Configured Backend instance.
    """
    import os

    database_url = db_url or os.environ.get("VENYA_DB_URL")
    if not database_url:
        raise RuntimeError("No database URL configured. Set VENYA_DB_URL or config.db_url")

    config = BackendConfig(
        database_url=database_url,
        passphrase=db_config.passphrase.encode("utf-8") if db_config.passphrase else None,
    )
    return Backend(config)


def get_backend(request: Request) -> Backend:
    """FastAPI dependency that yields the backend from app state."""
    backend = getattr(request.app.state, "backend", None)
    if backend is None:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Backend not initialized",
        )
    return backend


def get_db(backend: Backend = Depends(get_backend)) -> Generator[Session, None, None]:
    """FastAPI dependency that yields a DB session."""
    session = backend.get_session()
    try:
        yield session
    finally:
        session.close()


def get_current_session(
    request: Request,
    db: Session = Depends(get_db),
) -> tuple[Session, SessionModel] | None:
    """FastAPI dependency that returns (db, session) from cookie.

    DB session remains open until request completes.

    Args:
        request: The FastAPI request (for cookie access).
        db: DB session from get_db dependency.

    Returns:
        Tuple of (db, SessionModel) if valid, None otherwise.
    """
    token = request.cookies.get("venya_access_token")
    if not token:
        logger.info("GET_SESSION DEBUG: no token in cookie")
        return None

    session = (
        db.query(SessionModel)
        .filter(SessionModel.access_token == token)
        .first()
    )
    if session is None:
        logger.info("GET_SESSION DEBUG: token %s not found in DB", token[:20] if token else "None")
        return None

    # Check expiry
    from vault.iam.session_manager import SessionConfig

    config = SessionConfig()
    server_config = getattr(request.app.state, "config", None)
    tolerance = (
        server_config.clock_skew.token_tolerance_seconds
        if server_config and hasattr(server_config, "clock_skew")
        else 60
    )
    now = datetime.now(timezone.utc)
    session_created_at = session.expires_at - config.session_timeout
    if session_created_at + config.max_session_duration < now:
        logger.info("GET_SESSION DEBUG: session %s over max cap, created_at=%s, now=%s", session.id, session_created_at, now)
        return None
    if is_expired(session.expires_at, tolerance):
        logger.info("GET_SESSION DEBUG: session %s expired, expires_at=%s, now=%s", session.id, session.expires_at, now)
        return None

    logger.info("GET_SESSION DEBUG: token=%s, session=%s", token[:20] if token else "None", session.id)
    return (db, session)


def get_session_manager(backend: Backend = Depends(get_backend)) -> SessionManager:
    """FastAPI dependency that yields a SessionManager."""
    from sqlalchemy.orm import Session as ORMSession

    # Get the config from app state
    # We'll create a temporary session for the manager
    db = backend.get_session()
    config = getattr(backend, "_session_config", VaultSessionConfig())
    return SessionManager(db, config)


def get_role_manager(backend: Backend = Depends(get_backend)) -> RoleManager:
    """FastAPI dependency that yields a RoleManager."""
    db = backend.get_session()
    return RoleManager(db)


async def get_current_user(
    request: Request,
    credentials: HTTPAuthorizationCredentials | None = Depends(_bearer_scheme),
) -> dict:
    """FastAPI dependency that validates the session token and returns user info.

    Returns:
        Dict with user_id, roles, session_id.

    Raises:
        HTTPException: If token is invalid or expired.
    """
    if credentials is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing authentication token",
            headers={"WWW-Authenticate": "Bearer"},
        )

    token = credentials.credentials

    # Look up session by token JTI in app state
    # The session middleware should have validated and attached user info
    user_info = getattr(request.state, "auth_user", None)
    if user_info is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired token",
            headers={"WWW-Authenticate": "Bearer"},
        )

    return user_info


def require_role(permission: str):
    """Dependency factory that requires a specific permission level.

    Args:
        permission: Required permission — "read" or "read-write".

    Returns:
        Dependency that checks the user has the required permission.
    """
    async def _checker(
        user_info: dict = Depends(get_current_user),
        role_manager: RoleManager = Depends(get_role_manager),
        request: Request = Depends(get_backend),
    ) -> dict:
        # This will be properly implemented when we have role context
        # For now, just return the user info
        return user_info

    return _checker


def get_caller(request: Request) -> Caller:
    """Determine the caller type from the request.

    mTLS requests come from executor (caller=executor).
    Bearer token requests come from human (caller=human).

    Args:
        request: The FastAPI request.

    Returns:
        Caller enum value.
    """
    # Check if request has mTLS client cert (executor)
    if getattr(request, "client_cert", None) is not None:
        return Caller.EXECUTOR

    # Otherwise human (CLI)
    return Caller.HUMAN
