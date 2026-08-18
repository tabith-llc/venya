"""Time utilities with clock skew tolerance.

Provides centralized helpers for token/session expiration checks
with configurable clock skew tolerance. Prevents drift across
call sites by using a single source of truth.
"""


import logging
from datetime import datetime, timedelta, timezone

logger = logging.getLogger("venya")


def is_expired(expires_at: datetime | None, tolerance_seconds: int = 60) -> bool:
    """Check if a timestamp has expired, with clock skew tolerance.

    Args:
        expires_at: The expiration timestamp to check.
        tolerance_seconds: Clock skew tolerance in seconds.

    Returns:
        True if the timestamp has expired beyond tolerance.
        False if not expired, None, or within tolerance.
    """
    if expires_at is None:
        return False

    now = datetime.now(timezone.utc)

    # Handle timezone-naive datetimes (defensive — all models should be aware)
    if expires_at.tzinfo is None:
        expires_at = expires_at.replace(tzinfo=timezone.utc)

    expired = expires_at <= now - timedelta(seconds=tolerance_seconds)

    if not expired and expires_at <= now:
        # Technically expired but within tolerance — log for observability
        seconds_past = int((now - expires_at).total_seconds())
        logger.debug(
            "Token accepted within clock skew tolerance "
            "(expired %ds ago, tolerance=%ds)",
            seconds_past,
            tolerance_seconds,
        )

    return expired


def effective_expiry_check_time(tolerance_seconds: int) -> datetime:
    """Return now minus tolerance for use in SQL comparisons.

    Used when building SQL queries that filter on expires_at.
    Ensures Python and DB logic are perfectly aligned.

    Args:
        tolerance_seconds: Clock skew tolerance in seconds.

    Returns:
        datetime representing now - tolerance.
    """
    return datetime.now(timezone.utc) - timedelta(seconds=tolerance_seconds)


def has_not_yet_started(valid_from: datetime, tolerance_seconds: int = 60) -> bool:
    """Check if a 'not before' time hasn't arrived yet, with clock skew tolerance.

    Args:
        valid_from: The timestamp when the item becomes valid.
        tolerance_seconds: Clock skew tolerance in seconds.

    Returns:
        True if valid_from is still in the future (beyond tolerance).
    """
    now = datetime.now(timezone.utc)

    if valid_from.tzinfo is None:
        valid_from = valid_from.replace(tzinfo=timezone.utc)

    return valid_from > now + timedelta(seconds=tolerance_seconds)
