"""Rate limit dependencies for executor registration endpoints.

Provides FastAPI dependencies that enforce per-admin and per-executor
rate limits using atomic multi-key sliding window check-and-consume.
"""


import logging
from datetime import datetime, timezone

from fastapi import HTTPException, Request, status

from .utils.rate_limiter import SlidingWindowRateLimiter

logger = logging.getLogger("venya.server")


def _get_limiter(config, limit_name: str) -> SlidingWindowRateLimiter:
    """Get or create a rate limiter from config."""
    cfg = getattr(config, limit_name, None)
    if cfg is None:
        return None
    key = f"limiter_{limit_name}"
    if not hasattr(_get_limiter, "_limiters"):
        _get_limiter._limiters = {}  # type: ignore[attr-defined]
    if key not in _get_limiter._limiters:
        _get_limiter._limiters[key] = SlidingWindowRateLimiter(
            max_requests=cfg,
            window_seconds=60,
        )
    return _get_limiter._limiters[key]  # type: ignore[return-value]


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
        "reset": int(datetime.now(timezone.utc).timestamp()) + reset_time,
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
    except Exception:  # nosec B110 — best-effort JSON parse, None falls through
        pass

    # Check global emergency limit first (100/min)
    global_limiter = SlidingWindowRateLimiter(max_requests=100, window_seconds=60)
    global_key = f"global:{client_ip}"
    allowed, retry_after = await global_limiter.check_and_consume([global_key])
    if not allowed:
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Server rate limit exceeded",
            headers={"Retry-After": str(retry_after)},
        )

    # Determine per-IP limit (stricter for first registration)
    ip_limiter = _get_limiter(config.executor_enrollment, "registration_ip_per_minute")
    first_attempt_limiter = SlidingWindowRateLimiter(max_requests=3, window_seconds=60)

    # Check if this is a first registration (no existing cert)
    is_first = False
    if executor_id and ip_limiter is not None:
        try:
            from ..dependencies import get_backend
            backend = get_backend(request)
            db = backend.get_session()
            try:
                from core.iam.models import ExecutorCert
                cert = db.query(ExecutorCert).filter(ExecutorCert.executor_id == executor_id).first()
                is_first = cert is None
            finally:
                db.close()
        except Exception:  # nosec B110 — best-effort DB query, None falls through
            pass

    # Build keys for atomic check-and-consume
    keys: list[str] = []

    ip_key = f"reg_ip:{client_ip}"
    keys.append(ip_key)
    if is_first:
        ip_limiter = first_attempt_limiter

    if executor_id:
        exec_key = f"reg_exec:{executor_id}"
        keys.append(exec_key)
        exec_limiter = _get_limiter(config.executor_enrollment, "registration_attempts_per_minute")

    # Atomic check-and-consume
    limiter = ip_limiter
    if not keys:
        keys = [ip_key]

    allowed, retry_after = await limiter.check_and_consume(keys)

    # Calculate most restrictive remaining
    remaining_values = []
    reset_values = []
    for key in keys:
        lim = None
        if key.startswith("reg_ip:"):
            lim = ip_limiter
        elif key.startswith("reg_exec:"):
            lim = _get_limiter(config.executor_enrollment, "registration_attempts_per_minute")
        if lim:
            remaining_values.append(await lim.get_remaining(key))
            reset_values.append(await lim.get_reset_time(key))

    most_restrictive_remaining = min(remaining_values) if remaining_values else 0
    max_reset = max(reset_values) if reset_values else 0

    request.state.rate_limit_info = {  # type: ignore[attr-defined]
        "limit": most_restrictive_remaining + (1 if allowed else 0),
        "remaining": max(0, most_restrictive_remaining - (0 if allowed else 1)),
        "reset": int(datetime.now(timezone.utc).timestamp()) + max_reset,
    }

    if not allowed:
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Too many registration attempts",
            headers={"Retry-After": str(retry_after)},
        )
