# Copyright (c) 2026 Tabith LLC.
# Use of this source code is governed by the Business Source License 1.1
# included in the LICENSE file at the root of this repository. As of the
# Change Date listed there, the work is available under MPL 2.0.
# SPDX-License-Identifier: BUSL-1.1

"""Health check endpoints."""

import logging
import time
from importlib.metadata import PackageNotFoundError
from importlib.metadata import version as _pkg_version
from typing import Any

from fastapi import APIRouter, FastAPI, Request
from fastapi.responses import JSONResponse

logger = logging.getLogger(__name__)

router = APIRouter()


def _dist_version() -> str:
    """Single-sourced version (feature/version-surfaces condition 1): dist
    metadata (pyproject) is the only truth — never a string literal. Missing
    metadata yields the honest signal "unknown", never a guessed value."""
    try:
        return _pkg_version("server")
    except PackageNotFoundError:
        return "unknown"


_SERVER_VERSION = _dist_version()

# Module-level cache for CA key checks — avoids decrypting passphrase-protected
# keys on every LB probe. 15s TTL balances freshness against disk I/O cost.
#
# #464: the age is measured on ``time.monotonic()``, not the wall clock. This
# cache is per-process memory (a module dict, never persisted, never shared
# across workers), and the thing being measured is elapsed real time since the
# entry was written — exactly what a monotonic clock answers. Reading
# ``time.time()`` here let a BACKWARD clock step (NTP correction, snapshot
# restore) make the age negative, and a negative age is always "young", so a
# cached ``ok`` kept answering the readiness probe for the whole skew interval
# even after the CA key became unreadable (fail-open on the signal a load
# balancer acts on). A backward step can no longer resurrect a dead entry, and
# a forward step cannot make a live one look stale.
#
# The wall stamp is still recorded (``"time"``) for log/diagnostic readers; the
# guard itself never consults it.
_health_cache: dict[str, dict[str, Any]] = {}
_HEALTH_CACHE_TTL = 15  # seconds


def _reset_health_cache() -> None:
    """Clear the health check cache. Exposed for testing."""
    _health_cache.clear()


def _get_cached_check(name: str, check_fn) -> str:
    """Return cached check result or re-run check_fn if cache expired."""
    now_mono = time.monotonic()
    cached = _health_cache.get(name)
    if cached and (now_mono - cached["mono"]) < _HEALTH_CACHE_TTL:
        return cached["result"]

    try:
        check_fn()
        result = "ok"
    except Exception as e:
        logger.error("Health check '%s' failed: %s", name, e)
        result = "check_failed"

    _health_cache[name] = {"mono": now_mono, "time": time.time(), "result": result}
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

    Failure values counted toward "degraded": "error", "check_failed" and
    "uninitialized" (refs #455 — a component whose probe could not be wired
    yet reads degraded, not "ok": an unchecked state is never proof of
    health). HTTP codes are unchanged from the pre-#455 contract: only the
    ``checks`` value distinguishes "not initialized yet" from "probe broke".
    """
    critical_keys = {"ca"}
    values = list(checks.values())

    has_error = any(v in ("error", "check_failed", "uninitialized") for v in values)
    has_critical_error = any(checks[k] in ("error", "check_failed") for k in critical_keys if k in checks)

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

    The ``version`` field is fenced to the server package version only
    (single-sourced from dist metadata) — it must never grow into an
    environment/config dump on this unauthenticated surface.

    No authentication required. Rate-limited under the generic per-IP tier
    (no health exemption in RateLimitMiddleware — same tier as any non-auth
    route; the bare /health alias shares the same bucket).
    """
    checks: dict[str, str] = {}

    # CA check — skip if app not fully initialized (no ca_manager on state)
    ca_manager = getattr(request.app.state, "ca_manager", None)
    if ca_manager is not None:
        checks["ca"] = _get_cached_check("ca", lambda: _check_ca(request.app))
    else:
        checks["ca"] = "skipped"

    # Admin CA check — only when config exists and admin_mtls is enabled.
    #
    # #455: admin_mtls enabled but the manager not yet on state is its OWN
    # state ("uninitialized", logged at WARNING), not a silent pass and not
    # the "check_failed" answer a broken probe yields. The old
    # ``except RuntimeError: pass`` never fired — _get_cached_check already
    # swallows every exception into "check_failed" — so an uninitialized
    # manager and a broken one returned byte-identical bodies. Presence of
    # the manager is inspected directly (mirroring the honest "skipped"
    # vocabulary the main CA check uses above) so the two states read
    # differently.
    config = getattr(request.app.state, "config", None)
    admin_mtls = getattr(config, "admin_mtls", None) if config is not None else None
    if admin_mtls is not None and admin_mtls.enabled:
        if getattr(request.app.state, "admin_ca_manager", None) is None:
            checks["admin_ca"] = "uninitialized"
            logger.warning(
                "admin CA readiness probe NOT RUN: admin_mtls is enabled but "
                "admin_ca_manager is not initialized yet — reporting "
                "'uninitialized' (degraded), not 'ok'"
            )
        else:
            admin_ca_result = _get_cached_check("admin_ca", lambda: _check_admin_ca(request.app))
            if admin_ca_result != "skipped":
                checks["admin_ca"] = admin_ca_result

    status, http_status = _determine_status(checks)
    return JSONResponse(
        content={"status": status, "version": _SERVER_VERSION, "checks": checks},
        status_code=http_status,
    )


@router.get("/ready")
async def readiness_check(request: Request) -> dict:
    """Readiness probe — is the server ready to serve traffic?

    Checks database connectivity. No authentication required. Rate-limited
    under the generic per-IP tier (no /ready exemption in RateLimitMiddleware —
    same bucket as any non-auth route).
    """
    from sqlalchemy import text

    backend = getattr(request.app.state, "backend", None)
    if backend is None:
        return {"status": "degraded", "checks": {"database": "not_configured"}}

    # #603 AC2 (residual): the readiness read takes the RESERVED liveness capacity
    # when the backend supplies it, so /ready keeps answering while ordinary
    # request traffic holds every slot of the shared pool. Before this it grabbed a
    # shared-pool slot like any business query and, when it won one, reported
    # itself healthy on a starved path.
    #
    # The discriminator is the CLASS, copied from the shipped guard at
    # ``middleware/auth.py`` (``_liveness`` below): ``getattr(backend, ...)`` on a
    # MagicMock answers any attribute name, and ~60 server test files wire mock
    # backends, so an instance lookup would silently move those cells onto a second
    # mock session. ``type(backend)`` carries only real implementations.
    #
    # The acquire sits INSIDE the try because ``Backend.get_liveness_session`` is
    # fail-closed and RAISES when no reserved connection can be checked out within
    # ``LIVENESS_POOL_TIMEOUT``: on this probe that is a ``degraded`` answer, never
    # an unhandled 500 escaping a health endpoint. A capacity event stays a capacity
    # event here — the body names the database state and asserts no security fact.
    liveness_capable = callable(getattr(type(backend), "get_liveness_session", None))
    db = None
    try:
        db = backend.get_liveness_session() if liveness_capable else backend.get_session()
        db.execute(text("SELECT 1"))
        db.commit()
        return {"status": "ok", "checks": {"database": "connected"}}
    except Exception as e:
        if db is not None:
            db.rollback()
        logger.error("Readiness check failed: %s", e)
        return {"status": "degraded", "checks": {"database": "not_ready"}}
    finally:
        if db is not None:
            db.close()
