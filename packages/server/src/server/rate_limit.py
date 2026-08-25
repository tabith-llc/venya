"""Rate limit dependencies for executor registration endpoints.

Provides FastAPI dependencies that enforce per-admin and per-executor
rate limits using atomic multi-key sliding window check-and-consume.
"""

import logging
from datetime import UTC, datetime

from fastapi import HTTPException, Request, status

from .utils.rate_limiter import SlidingWindowRateLimiter

logger = logging.getLogger("venya.server")


_LIMITERS: dict[str, SlidingWindowRateLimiter] = {}


def _get_limiter(config, limit_name: str) -> SlidingWindowRateLimiter | None:
    """Get or create a rate limiter from config."""
    cfg = getattr(config, limit_name, None)
    if cfg is None:
        return None
    key = f"limiter_{limit_name}"
    if key not in _LIMITERS:
        _LIMITERS[key] = SlidingWindowRateLimiter(
            max_requests=cfg,
            window_seconds=60,
        )
    return _LIMITERS[key]


async def rate_limit_admin_token_gen(request: Request) -> None:
    """Rate limit token generation per admin user.

    Checks admin session identity and enforces per-user limit.
    Attaches rate limit info to request.state for header middleware.
    """
    config = getattr(request.app.state, "config", None)
    if config is None or not config.executor_enrollment.enabled:
        return

    caller = getattr(request.state, "auth_user", {})
    admin_user_id = caller.get("user_id", None)
    if not admin_user_id:
        return

    limiter = _get_limiter(config.executor_enrollment, "token_generation_per_minute")
    if limiter is None:
        return

    key = f"admin:{admin_user_id}"
    allowed, retry_after = await limiter.check_and_consume([key])

    remaining = await limiter.get_remaining(key)
    reset_time = await limiter.get_reset_time(key)

    request.state.rate_limit_info = {  # type: ignore[attr-defined]
        "limit": config.executor_enrollment.token_generation_per_minute,
        "remaining": remaining,
        "reset": int(datetime.now(UTC).timestamp()) + reset_time,
    }

    if not allowed:
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Too many token generation attempts",
            headers={"Retry-After": str(retry_after)},
        )


async def rate_limit_registration(request: Request) -> None:
    """Rate limit executor registration with dual-key atomic check.

    Checks both per-IP and per-executor_id limits atomically.
    Both must pass (AND logic). First registration uses stricter limit.

    Attaches rate limit info to request.state for header middleware.
    """
    config = getattr(request.app.state, "config", None)
    if config is None or not config.executor_enrollment.enabled:
        return

    client_ip = request.client.host if request.client else "unknown"

    # Try to extract executor_id from request body for dual-keying
    executor_id = None
    try:
        body = await request.json()
        executor_id = body.get("executor_id")
    except Exception:  # nosec B110 — best-effort JSON parse, None falls through  # noqa: S110
        pass

    # Check global emergency limit first (configurable backstop, default 100/min).
    # M-62: must be a PERSISTENT limiter (via the _LIMITERS cache) — an inline
    # SlidingWindowRateLimiter() is recreated per request, so its counter never
    # accumulates across requests and the 429 below was unreachable.
    global_limiter = _get_limiter(config.executor_enrollment, "registration_global_per_minute")
    if global_limiter is not None:
        global_key = f"global:{client_ip}"
        allowed, retry_after = await global_limiter.check_and_consume([global_key])
        if not allowed:
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail="Server rate limit exceeded",
                headers={"Retry-After": str(retry_after)},
            )

    # Determine per-IP limit (stricter for first registration).
    # M-63: first_attempt_limiter must be a PERSISTENT limiter (via the
    # _LIMITERS cache) — an inline SlidingWindowRateLimiter() is recreated per
    # request, so the 3/min first-attempt counter never accumulated and the cap
    # was inert (the 3 was also hardcoded, not operator-configurable).
    ip_limiter = _get_limiter(config.executor_enrollment, "registration_ip_per_minute")
    first_attempt_limiter = _get_limiter(config.executor_enrollment, "registration_first_attempt_per_minute")

    # Per-executor limit. M-61: the reg_exec: key must be enforced on its OWN
    # persistent limiter — the old code checked it against the *IP* limiter's
    # cap, so the executor cap never applied (an executor rotating IPs could
    # register without bound).
    exec_limiter = _get_limiter(config.executor_enrollment, "registration_attempts_per_minute")

    # Check if this is a first registration (no existing cert).
    # M-63 (second root cause): this probe used `from ..dependencies import
    # get_backend` — one dot too deep for a server/*.py module — which raised
    # ImportError, swallowed by the blanket except below, so is_first was ALWAYS
    # False and the first-attempt path was dead. Correct depth is `.dependencies`.
    # (Making the limiter persistent alone would not have made it live.)
    is_first = False
    if executor_id and ip_limiter is not None:
        try:
            from .dependencies import get_backend

            backend = get_backend(request)
            db = backend.get_session()
            try:
                from core.iam.models import ExecutorCert

                cert = db.query(ExecutorCert).filter(ExecutorCert.executor_id == executor_id).first()
                is_first = cert is None
            finally:
                db.close()
        except Exception:  # nosec B110 — best-effort DB query, None falls through  # noqa: S110
            pass

    # Dual-key AND check. Every key is guarded by ITS OWN dedicated limiter, so
    # per-IP and per-executor throttle independently. Both must pass: a request
    # is allowed only after each limiter confirms a free slot under its own cap,
    # so neither limit can be exceeded. A request denied by one limiter still
    # holds the slot it consumed on the limiters that passed (at most one per
    # denied request) — fail-safe: it only ever tightens the effective limit.
    ip_limiter = first_attempt_limiter if (is_first and first_attempt_limiter is not None) else ip_limiter
    checks: list[tuple[SlidingWindowRateLimiter, str]] = []
    if ip_limiter is not None:
        checks.append((ip_limiter, f"reg_ip:{client_ip}"))
    if executor_id and exec_limiter is not None:
        checks.append((exec_limiter, f"reg_exec:{executor_id}"))

    allowed = True
    retry_after = 0
    for limiter, key in checks:
        ok, ra = await limiter.check_and_consume([key])
        if ok:
            continue
        allowed = False
        retry_after = ra
        break

    # Headers reflect the tighter (smallest remaining) of the checked limits.
    tight_remaining: int | None = None
    tight_reset = 0
    tight_limit: int | None = None
    for limiter, key in checks:
        remaining = await limiter.get_remaining(key)
        reset = await limiter.get_reset_time(key)
        if tight_remaining is None or remaining < tight_remaining:
            tight_remaining, tight_reset, tight_limit = remaining, reset, limiter.max_requests
    if tight_remaining is None:
        tight_remaining, tight_reset, tight_limit = 0, 0, 0

    request.state.rate_limit_info = {  # type: ignore[attr-defined]
        "limit": tight_limit,
        "remaining": max(0, tight_remaining),
        "reset": int(datetime.now(UTC).timestamp()) + tight_reset,
    }

    if not allowed:
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Too many registration attempts",
            headers={"Retry-After": str(retry_after)},
        )
