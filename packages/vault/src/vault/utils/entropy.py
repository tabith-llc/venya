"""Cryptographic token generation and CSPRNG self-test.

All token generation in the Venya codebase should flow through
get_secure_token() to provide a single audit point for entropy usage.
"""

from __future__ import annotations

import os
import secrets
import logging

logger = logging.getLogger(__name__)

_SELF_TEST_BYTES = 32


def get_secure_token(length: int = 32) -> str:
    """Generate a cryptographically secure URL-safe token.

    Args:
        length: Number of random bytes to use (default 32 = 256 bits).

    Returns:
        A URL-safe random string. Length=0 returns empty string.

    Note:
        secrets.token_urlsafe(0) returns "". If length comes from
        config and defaults to 0, the token will be empty — a silent
        security failure. Validate length > 0 at the config boundary.
    """
    return secrets.token_urlsafe(length)


def csprng_self_test() -> None:
    """Verify the CSPRNG is functional at startup.

    Confirms that os.urandom() returns the requested number of bytes
    within a reasonable time. Does NOT verify cryptographic quality —
    that's the kernel's responsibility.

    On modern Linux, os.urandom() blocks via getrandom() until the
    CRNG is initialized, so if this returns, the CSPRNG is ready.
    """
    try:
        data = os.urandom(_SELF_TEST_BYTES)
        if len(data) != _SELF_TEST_BYTES:
            raise RuntimeError(
                f"CSPRNG returned {len(data)} bytes, expected {_SELF_TEST_BYTES}"
            )
        if data == b'\x00' * _SELF_TEST_BYTES:
            raise RuntimeError("CSPRNG returned all-zero output — possible failure")
        logger.info("CSPRNG self-test passed")
    except BlockingIOError:
        logger.warning(
            "CSPRNG not yet initialized (getrandom returned EAGAIN). "
            "Token generation may block until the kernel CRNG is ready."
        )
    except OSError as e:
        logger.error("CSPRNG self-test failed: %s", e)
        raise RuntimeError(f"Cannot start server: CSPRNG unavailable — {e}")
