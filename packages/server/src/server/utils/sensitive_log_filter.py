"""Logging filter that redacts sensitive data from log messages.

Redacts patterns like::

    enrollment_token=abc123  →  enrollment_token=[REDACTED]
    password="secret"        →  password=[REDACTED]
    token: enrl_exec_...     →  token: [REDACTED]
    Bearer eyJ...             →  Bearer [REDACTED]
    recovery_code=xyz        →  recovery_code=[REDACTED]

Usage::

    import logging
    from server.utils.sensitive_log_filter import SensitiveFieldFilter

    logging.basicConfig(
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )
    for handler in logging.root.handlers:
        handler.addFilter(SensitiveFieldFilter())
"""

from __future__ import annotations

import logging
import re


# Sensitive key names, ordered longest-first so specific patterns match
# before shorter generic ones (e.g. "enrollment_token" before "token").
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
        # Match: key=<val>  key="val"  key='val'  key: <val>  key <val>
        # Group 1 = prefix (key + operator), rest = value alternatives
        # Handles quoted and unquoted values, colon, equals, and space separators.
        # Unquoted values stop at whitespace or quotes to avoid over-matching.
        # (?:_\w+)* allows matching compound names like private_key_path.
        pat = re.compile(
            rf"""(\b{key}(?:_\w+)*\s*(?:=|:)\s*)(?:"([^"]*)"|'([^']*)'|([^\s"']+))""",
            re.IGNORECASE,
        )
        result.append((pat, r"\1[REDACTED]"))

        # Space-separated form for log-style output: "token enrl_exec_abc123"
        pat2 = re.compile(
            rf"(\b{key}(?:_\w+)*\s+)([A-Za-z0-9_\-./+=]{{8,}})",
            re.IGNORECASE,
        )
        result.append((pat2, r"\1[REDACTED]"))
    return result


# Module-level cache — compiled once at import time.
_PATTERNS = _build_patterns()


class SensitiveFieldFilter(logging.Filter):
    """A logging filter that redacts sensitive field values from log records.

    This filter modifies the log message *in-place* before emission, replacing
    sensitive values with ``[REDACTED]``.  It operates on the fully-formatted
    message (after %-substitution), so it catches values even when they were
    passed as ``logger.info("token=%s", value)``.
    """

    def filter(self, record: logging.LogRecord) -> bool:
        # getMessage() does %-substitution; we redact the *formatted* message.
        # Then clear args so a second getMessage() call doesn't re-substitute.
        formatted = record.getMessage()
        record.msg = _redact(formatted)
        record.args = ()
        return True


def _redact(message: str) -> str:
    """Redact sensitive values from a single string."""
    if not message:
        return message
    for pat, repl in _PATTERNS:
        message = pat.sub(repl, message)
    return message
