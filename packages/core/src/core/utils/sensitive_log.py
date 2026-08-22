"""Sensitive value logging with automatic redaction.

Two-layer protection against credential leakage in logs:

1. Wrapper types (primary): Mark sensitive values explicitly at call sites.
   Wrappers override ``__str__`` so that when the logging formatter calls
   ``str()`` during ``%s`` interpolation, the redaction marker is emitted.

2. Regex fallback (defense-in-depth): Pattern matching for legacy or
   third-party log lines that don't use wrappers.

Usage::

    from core.utils.sensitive_log import token, secret, RedactingFormatter

    logger.info("Using token %s", token("enrl_exec_abc123", "enrollment"))
    # Output: "Using token [REDACTED:ENROLLMENT]"

    logger.info("Password: %s", secret("hunter2"))
    # Output: "Password: [REDACTED]"

Wrappers are lightweight dataclasses — the original value is preserved
on ``.value`` for non-log use (e.g. passing the actual token to an API).
"""

import logging
import re
from dataclasses import dataclass
from typing import Any, ClassVar, Literal

# ---------------------------------------------------------------------------
# Wrapper types
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class Secret:
    """Marks a value as sensitive for log redaction.

    ``str(Secret(...))`` returns ``"[REDACTED]"``.
    The original value is accessible via ``.value``.
    """

    value: Any

    def __str__(self) -> str:
        return "[REDACTED]"


@dataclass(frozen=True)
class Token:
    """Marks a token value for log redaction with type metadata.

    ``str(Token(...))`` returns ``"[REDACTED:<TYPE>]"``.
    The original value is accessible via ``.value``.
    """

    value: Any
    token_type: str = "UNKNOWN"

    def __str__(self) -> str:
        return f"[REDACTED:{self.token_type.upper()}]"


def secret(value: Any) -> Secret:
    """Wrap a sensitive value."""
    return Secret(value)


def token(value: Any, token_type: str = "UNKNOWN") -> Token:  # nosec B107 — not a password, just a type label
    """Wrap a token value with a type identifier."""
    return Token(value, token_type)


# ---------------------------------------------------------------------------
# RedactingFormatter
# ---------------------------------------------------------------------------


class RedactingFormatter(logging.Formatter):
    """Logging formatter with two-layer credential redaction.

    Layer 1 — Wrapper detection (primary):
        Before formatting, inspect ``LogRecord.args`` for ``Secret`` /
        ``Token`` instances.  Because these classes override ``__str__``,
        the normal ``%s`` interpolation will emit the redaction marker.

    Layer 2 — Regex safety-net (fallback):
        After formatting, apply compiled regex patterns to catch unwrapped
        credentials in legacy ``%s`` messages or third-party library logs.

    Attributes:
        REGEX_PATTERNS: Compiled patterns for common Venya credential formats.
    """

    REGEX_PATTERNS: ClassVar[list[re.Pattern[str]]] = [
        # Enrollment tokens
        re.compile(r"enrl_exec_[a-zA-Z0-9_\-]+"),
        re.compile(r"enrl_[a-zA-Z0-9_\-]+"),
        # Bearer tokens
        re.compile(r"Bearer [a-zA-Z0-9._\-]+"),
        # URL query parameters
        re.compile(r"password=[^\s&]+", re.IGNORECASE),
        re.compile(r"token=[^\s&]+", re.IGNORECASE),
        re.compile(r"api[-_]?key=[^\s&]+", re.IGNORECASE),
    ]

    def __init__(
        self,
        fmt: str | None = None,
        datefmt: str | None = None,
        style: Literal["%", "{", "$"] = "%",
        validate: bool = True,
        *,
        use_regex_fallback: bool = True,
    ) -> None:
        super().__init__(fmt, datefmt, style, validate)
        self.use_regex_fallback = use_regex_fallback

    # -- public API --------------------------------------------------------

    @classmethod
    def get_patterns(cls) -> list[re.Pattern[str]]:
        """Return a shallow copy of the compiled regex patterns."""
        return cls.REGEX_PATTERNS.copy()

    @classmethod
    def add_pattern(cls, pattern: str) -> None:
        """Add a new regex pattern at runtime.

        Warning: modifies the class attribute — all instances are affected.
        """
        cls.REGEX_PATTERNS.append(re.compile(pattern))

    # -- Formatter override ------------------------------------------------

    def format(self, record: logging.LogRecord) -> str:
        # Layer 1: replace wrappers in args so %s interpolation emits markers
        original_args = record.args
        try:
            if original_args:
                record.args = self._redact_args(original_args)
            message = super().format(record)
        finally:
            record.args = original_args

        # Layer 2: regex safety-net on the final message
        if self.use_regex_fallback:
            # Protect already-redacted markers from regex over-matching
            import re as _re

            # Collect (start, end, original_text) for each marker
            markers: list[tuple[int, int, str]] = []
            for m in _re.finditer(r"\[REDACTED(?::[A-Z_]+)?\]", message):
                markers.append((m.start(), m.end(), m.group()))
            # Build cleaned message with markers removed
            cleaned_parts: list[str] = []
            prev = 0
            for start, end, _ in markers:
                cleaned_parts.append(message[prev:start])
                prev = end
            cleaned_parts.append(message[prev:])
            cleaned = "".join(cleaned_parts)
            # Apply regex to cleaned message
            for pattern in self.REGEX_PATTERNS:
                cleaned = pattern.sub("[REDACTED]", cleaned)
            # Rebuild message: insert original marker text at each position
            result_parts: list[str] = []
            ci = 0
            for start, end, orig_text in markers:
                result_parts.append(cleaned[ci:start])
                result_parts.append(orig_text)  # preserve original marker
                ci = start
            result_parts.append(cleaned[ci:])
            message = "".join(result_parts)

        return message

    # -- Internal helpers --------------------------------------------------

    def _redact_args(self, args: Any) -> Any:
        if isinstance(args, dict):
            return {k: self._redact_value(v) for k, v in args.items()}
        if isinstance(args, tuple):
            return tuple(self._redact_value(v) for v in args)
        return self._redact_value(args)

    def _redact_value(self, value: Any) -> Any:
        if isinstance(value, (Secret, Token)):
            return value  # __str__ returns the redaction marker
        if isinstance(value, dict):
            return {k: self._redact_value(v) for k, v in value.items()}
        if isinstance(value, (list, tuple)):
            result = [self._redact_value(v) for v in value]
            return type(value)(result)
        return value
