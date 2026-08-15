"""Logging filter that redacts sensitive data from log messages.

Redacts patterns like::

    enrollment_token=abc123  →  enrollment_token=[REDACTED]
    password="secret"        →  password=[REDACTED]
    token: enrl_exec_...     →  token: [REDACTED]
    Bearer eyJ...             →  Bearer [REDACTED]
    recovery_code=xyz        →  recovery_code=[REDACTED]

Usage::

    import logging
    from executor.sensitive_log_filter import SensitiveFieldFilter

    logging.basicConfig(
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )
    for handler in logging.root.handlers:
        handler.addFilter(SensitiveFieldFilter())
"""

from __future__ import annotations

import logging
import re


_SENSITIVE_KEYS = [
    "enrollment_token",
    "recovery_code",
    "access_token",
    "refresh_token",
    "client_secret",
    "api_key",
    "private_key",
    "ca_key",
    "secret_key",
    "password",
    "passwd",
    "secret",
    "token",
    "bearer",
    "key",
]


def _build_patterns() -> list[tuple[re.Pattern[str], str]]:
    """Build (compiled_regex, replacement) pairs for redaction."""
    result: list[tuple[re.Pattern[str], str]] = []
    for key in _SENSITIVE_KEYS:
        pat = re.compile(
            rf"""(\b{key}(?:_\w+)*\s*(?:=|:)\s*)(?:"([^"]*)"|'([^']*)'|([^\s"']+))""",
            re.IGNORECASE,
        )
        result.append((pat, r"\1[REDACTED]"))

        pat2 = re.compile(
            rf"(\b{key}(?:_\w+)*\s+)([A-Za-z0-9_\-./+=]{{8,}})",
            re.IGNORECASE,
        )
        result.append((pat2, r"\1[REDACTED]"))
    return result


_PATTERNS = _build_patterns()


class SensitiveFieldFilter(logging.Filter):
    """A logging filter that redacts sensitive field values from log records."""

    def filter(self, record: logging.LogRecord) -> bool:
        original_msg = record.getMessage()
        record.msg = _redact(original_msg)
        return True


def _redact(message: str) -> str:
    """Redact sensitive values from a single string."""
    if not message:
        return message
    for pat, repl in _PATTERNS:
        message = pat.sub(repl, message)
    return message
