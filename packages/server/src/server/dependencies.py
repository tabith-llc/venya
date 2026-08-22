"""Database session + auth dependencies for FastAPI."""

import logging
from collections.abc import Generator
from datetime import UTC, datetime, timedelta

from fastapi import Depends, HTTPException, Request, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy.orm import Session

logger = logging.getLogger("venya.server")

from core.engine.backend import Backend, BackendConfig
from core.engine.core import Caller
from core.iam.models import Session as SessionModel
from core.iam.role_manager import RoleManager
from core.utils.sensitive_log import token as sensitive_token

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
        passphrase=db_config.passphrase if db_config.passphrase else None,
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


def get_db(backend: Backend = Depends(get_backend)) -> Generator[Session]:
    """FastAPI dependency that yields a DB session.

    Owns the session lifecycle for the route layer: rollback on any exception
    escaping the route, close on all paths. Routes must never call
    db.rollback() or db.close() on this session.
    """
    session = backend.get_session()
    try:
        yield session
    except Exception:
        session.rollback()
        raise
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

    session = db.query(SessionModel).filter(SessionModel.access_token == token).first()
    if session is None:
        logger.info(
            "GET_SESSION DEBUG: token %s not found in DB", sensitive_token(token, "ACCESS") if token else "None"
        )
        return None

    # Check expiry
    from core.iam.session_manager import SessionConfig

    server_config = getattr(request.app.state, "config", None)
    tolerance = (
        server_config.clock_skew.token_tolerance_seconds
        if server_config and hasattr(server_config, "clock_skew")
        else 60
    )
    # Operator-configured hard cap (seconds), core default (4h) if unset —
    # same source and fallback order as maintenance.py (M-28 class).
    operator_max = getattr(getattr(server_config, "session", None), "max_session_duration", None)
    max_session_duration = (
        timedelta(seconds=operator_max) if operator_max is not None else SessionConfig().max_session_duration
    )
    now = datetime.now(UTC)
    session_created_at = session.created_at
    if session_created_at + max_session_duration < now:
        logger.info(
            "GET_SESSION DEBUG: session %s over max cap, created_at=%s, now=%s", session.id, session_created_at, now
        )
        return None
    if is_expired(session.expires_at, tolerance):
        logger.info("GET_SESSION DEBUG: session %s expired, expires_at=%s, now=%s", session.id, session.expires_at, now)
        return None

    logger.info(
        "GET_SESSION DEBUG: token=%s, session=%s", sensitive_token(token, "ACCESS") if token else "None", session.id
    )
    return (db, session)


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


get_current_user._venya_guard = "auth"  # type: ignore[attr-defined]


def require_role(permission: str):
    """Dependency factory that requires a specific permission tier.

    Args:
        permission: Required permission — "read" or "read-write".

    Returns:
        Dependency that allows the request only when the authenticated
        user holds at least one role whose permission tier meets the
        required level. "read" passes with any role membership;
        "read-write" requires at least one read-write role. Executors
        (mTLS) always pass.

    Raises:
        ValueError: If permission is not "read" or "read-write".
            Raised at factory call time (app startup), not per request.
    """
    if permission not in ("read", "read-write"):
        raise ValueError(f"Invalid permission: {permission}. Must be 'read' or 'read-write'")

    async def _checker(
        user_info: dict = Depends(get_current_user),
        backend: Backend = Depends(get_backend),
    ) -> dict:
        # Executor (mTLS) has full access.
        # Their user_info carries no user_id, so a role lookup is impossible.
        if user_info.get("caller") == "executor":
            return user_info

        db = backend.get_session()
        try:
            rm = RoleManager(db)
            permissions = rm.get_user_permissions(user_info["user_id"])

            if permission == "read":
                if not permissions:
                    raise HTTPException(
                        status_code=status.HTTP_403_FORBIDDEN,
                        detail="Insufficient permissions",
                    )
            else:  # "read-write"
                if not any(p == "read-write" for p in permissions.values()):
                    raise HTTPException(
                        status_code=status.HTTP_403_FORBIDDEN,
                        detail="Read-write permission required",
                    )

            return user_info
        except HTTPException:
            raise
        except Exception:
            db.rollback()
            raise
        finally:
            db.close()

    _checker._venya_guard = permission  # type: ignore[attr-defined]
    return _checker


def get_caller(request: Request) -> str:
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


def require_admin(
    user_info: dict = Depends(get_current_user),
    backend: Backend = Depends(get_backend),
) -> dict:
    """FastAPI dependency that requires admin role.

    Checks that the authenticated user has the admin role by querying
    the database. Returns user info dict on success, raises HTTPException
    on failure.

    Raises:
        HTTPException 403: User lacks admin role. Executor (mTLS) callers
            are denied outright (they carry no user_id; admin routes are
            human-only).
    """
    # Executors (mTLS) carry no user_id; the role lookup below would raise
    # KeyError and surface as a 500. Admin routes are human-only, so deny
    # cleanly. Mirrors require_role's executor branch (dependencies.py:195),
    # which passes executors; here we deny them instead.
    if user_info.get("caller") == "executor":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Admin permission required",
        )

    db = backend.get_session()
    try:
        from core.iam.role_manager import RoleManager

        rm = RoleManager(db)
        admin_role = rm.get_role_by_name("admin")
        if admin_role is None:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Admin role not found",
            )
        has_admin = rm.has_permission(user_info["user_id"], admin_role.id, "read-write")
        if not has_admin:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Admin permission required",
            )
        return user_info
    except HTTPException:
        raise
    except Exception:
        db.rollback()
        raise
    finally:
        db.close()


require_admin._venya_guard = "admin"  # type: ignore[attr-defined]
