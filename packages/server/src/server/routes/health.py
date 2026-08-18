"""Health check endpoints."""

import logging
import time
from typing import Any

from fastapi import APIRouter, FastAPI, Request
from fastapi.responses import JSONResponse

logger = logging.getLogger(__name__)

router = APIRouter()

# Module-level cache for CA key checks — avoids decrypting passphrase-protected
# keys on every LB probe. 15s TTL balances freshness against disk I/O cost.
_health_cache: dict[str, dict[str, Any]] = {}
_HEALTH_CACHE_TTL = 15  # seconds


def _reset_health_cache() -> None:
    """Clear the health check cache. Exposed for testing."""
    _health_cache.clear()


def _get_cached_check(name: str, check_fn) -> str:
    """Return cached check result or re-run check_fn if cache expired."""
    now = time.time()
    cached = _health_cache.get(name)
    if cached and (now - cached["time"]) < _HEALTH_CACHE_TTL:
        return cached["result"]

    try:
        check_fn()
        result = "ok"
    except Exception as e:
        logger.error("Health check '%s' failed: %s", name, e)
        result = "check_failed"

    _health_cache[name] = {"time": now, "result": result}
    return result


def _check_ca(app: FastAPI) -> None:
    """Verify CA cert and key are loadable.

    Raises RuntimeError if the key cannot be decrypted.
    """
    ca_manager = getattr(app.state, "ca_manager", None)
    if ca_manager is None:
        raise RuntimeError("CA manager not configured")
    ca_manager.load_ca()


def _check_admin_ca(app: FastAPI) -> None:
    """Verify admin CA is loadable when admin_mtls is enabled.

    Raises RuntimeError("skipped") when admin_mtls is disabled.
    Raises RuntimeError("not_configured") when app not fully initialized.
    Raises RuntimeError with other message on actual failure.
    """
    config = getattr(app.state, "config", None)
    if config is None or not getattr(config, "admin_mtls", None):
        raise RuntimeError("not_configured")
    if not config.admin_mtls.enabled:
        raise RuntimeError("skipped")

    admin_ca_manager = getattr(app.state, "admin_ca_manager", None)
    if admin_ca_manager is None:
        raise RuntimeError("not_configured")
    admin_ca_manager._load_ca_key()


def _determine_status(checks: dict[str, str]) -> tuple[str, int]:
    """Determine overall status and HTTP status code from individual checks.

    - "ok" → HTTP 200 (all checks ok or skipped)
    - "degraded" → HTTP 200 (non-critical check failed, e.g. admin CA)
    - "error" → HTTP 503 (critical check failed, e.g. main CA)
    """
    critical_keys = {"ca"}
    values = list(checks.values())

    has_error = any(v in ("error", "check_failed") for v in values)
    has_critical_error = any(
        checks[k] in ("error", "check_failed") for k in critical_keys if k in checks
    )

    if has_critical_error:
        return "error", 503
    elif has_error:
        return "degraded", 200
    return "ok", 200


@router.get("/health")
async def health_check(request: Request) -> JSONResponse:
    """Liveness probe — is the server running and can it serve executor enrollments?

    Checks CA key loadability (critical) and admin CA when mTLS is enabled.
    Results are cached for 15 seconds to avoid decrypting passphrase-protected
    keys on every probe.

    No authentication required. Not rate-limited.
    """
    checks: dict[str, str] = {}

    # CA check — skip if app not fully initialized (no ca_manager on state)
    ca_manager = getattr(request.app.state, "ca_manager", None)
    if ca_manager is not None:
        checks["ca"] = _get_cached_check("ca", lambda: _check_ca(request.app))
    else:
        checks["ca"] = "skipped"

    # Admin CA check — only when config exists and admin_mtls is enabled
    config = getattr(request.app.state, "config", None)
    if config is not None and getattr(config, "admin_mtls", None) is not None:
        if config.admin_mtls.enabled:
            try:
                admin_ca_result = _get_cached_check(
                    "admin_ca", lambda: _check_admin_ca(request.app)
                )
                if admin_ca_result != "skipped":
                    checks["admin_ca"] = admin_ca_result
            except RuntimeError:
                pass  # admin_ca_manager not yet initialized

    status, http_status = _determine_status(checks)
    return JSONResponse(
        content={"status": status, "checks": checks},
        status_code=http_status,
    )


@router.get("/ready")
async def readiness_check(request: Request) -> dict:
    """Readiness probe — is the server ready to serve traffic?

    Checks database connectivity. No authentication required. Not rate-limited.
    """
    from sqlalchemy import text

    backend = getattr(request.app.state, "backend", None)
    if backend is None:
        return {"status": "degraded", "checks": {"database": "not_configured"}}

    db = backend.get_session()
    try:
        db.execute(text("SELECT 1"))
        db.commit()
        return {"status": "ok", "checks": {"database": "connected"}}
    except Exception as e:
        db.rollback()
        logger.error("Readiness check failed: %s", e)
        return {"status": "degraded", "checks": {"database": "not_ready"}}
    finally:
        db.close()
