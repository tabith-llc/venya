"""Tests for sensitive value logging with automatic redaction.

Covers:
- Wrapper types (Secret, Token)
- RedactingFormatter (layer 1: wrappers, layer 2: regex)
- Edge cases (nested args, empty values, non-wrapped strings)

See: Issue #16 (Environment Variable Leakage in Logs)
"""


import logging
from io import StringIO

import pytest

from core.utils.sensitive_log import (
    RedactingFormatter,
    Secret,
    Token,
    secret,
    token,
)


# ============================================================================
# Wrapper Type Tests
# ============================================================================


class TestSecret:
    """Tests for Secret wrapper class."""

    def test_secret_str_returns_marker(self):
        s = Secret("sensitive_value")
        assert str(s) == "[REDACTED]"

    def test_secret_preserves_value(self):
        s = Secret("actual_secret")
        assert s.value == "actual_secret"

    def test_secret_immutable(self):
        s = Secret("value")
        with pytest.raises(Exception):
            s.value = "modified"  # type: ignore

    def test_secret_with_different_types(self):
        assert str(Secret("string")) == "[REDACTED]"
        assert str(Secret(123)) == "[REDACTED]"
        assert str(Secret(None)) == "[REDACTED]"
        assert str(Secret({"nested": "dict"})) == "[REDACTED]"


class TestToken:
    """Tests for Token wrapper class."""

    def test_token_str_with_type(self):
        t = Token("token_value", "enrollment")
        assert str(t) == "[REDACTED:ENROLLMENT]"

    def test_token_default_type_unknown(self):
        t = Token("value")
        assert str(t) == "[REDACTED:UNKNOWN]"

    def test_token_preserves_value(self):
        t = Token("enrl_exec_abc123", "enrollment")
        assert t.value == "enrl_exec_abc123"
        assert t.token_type == "enrollment"

    def test_token_case_normalization(self):
        t1 = Token("value", "ENROLLMENT")
        t2 = Token("value", "enrollment")
        t3 = Token("value", "Enrollment")
        assert str(t1) == "[REDACTED:ENROLLMENT]"
        assert str(t2) == "[REDACTED:ENROLLMENT]"
        assert str(t3) == "[REDACTED:ENROLLMENT]"


class TestHelperFunctions:
    """Tests for secret() and token() helpers."""

    def test_secret_helper(self):
        s = secret("value")
        assert isinstance(s, Secret)
        assert s.value == "value"

    def test_token_helper(self):
        t = token("value", "enrollment")
        assert isinstance(t, Token)
        assert t.value == "value"
        assert t.token_type == "enrollment"

    def test_token_helper_default_type(self):
        t = token("value")
        assert t.token_type == "UNKNOWN"


# ============================================================================
# RedactingFormatter Tests — Wrapper Layer
# ============================================================================


class TestRedactingFormatterWrapperLayer:
    """Tests for Layer 1: Wrapper-based redaction."""

    @pytest.fixture
    def logger_with_formatter(self):
        buffer = StringIO()
        handler = logging.StreamHandler(buffer)
        handler.setFormatter(RedactingFormatter("%(message)s"))

        logger = logging.getLogger(f"test_{id(buffer)}")
        logger.handlers = [handler]
        logger.setLevel(logging.INFO)
        logger.propagate = False

        return logger, buffer

    def test_secret_wrapped_value_redacted(self, logger_with_formatter):
        logger, buffer = logger_with_formatter
        logger.info("Password: %s", secret("hunter2"))
        output = buffer.getvalue()
        assert "[REDACTED]" in output
        assert "hunter2" not in output

    def test_token_wrapped_value_redacted_with_type(self, logger_with_formatter):
        logger, buffer = logger_with_formatter
        logger.info("Token: %s", token("enrl_exec_abc123", "enrollment"))
        output = buffer.getvalue()
        assert "[REDACTED:ENROLLMENT]" in output
        assert "enrl_exec_abc123" not in output

    def test_multiple_wrapped_values_same_message(self, logger_with_formatter):
        logger, buffer = logger_with_formatter
        logger.info(
            "Auth with token %s and secret %s",
            token("enrl_exec_x", "enrollment"),
            secret("password"),
        )
        output = buffer.getvalue()
        assert "[REDACTED:ENROLLMENT]" in output
        assert "[REDACTED]" in output
        assert "enrl_exec_x" not in output
        assert "password" not in output

    def test_non_wrapped_values_passed_through(self, logger_with_formatter):
        logger, buffer = logger_with_formatter
        logger.info("Executor ID: %s", "exec-001")
        output = buffer.getvalue()
        assert "exec-001" in output

    def test_tuple_args_with_wrappers(self, logger_with_formatter):
        logger, buffer = logger_with_formatter
        logger.info("A: %s, B: %s", secret("s1"), token("t1", "test"))
        output = buffer.getvalue()
        assert "[REDACTED]" in output
        assert "[REDACTED:TEST]" in output


# ============================================================================
# RedactingFormatter Tests — Regex Layer
# ============================================================================


class TestRedactingFormatterRegexLayer:
    """Tests for Layer 2: Regex fallback redaction."""

    @pytest.fixture
    def logger_with_regex(self):
        buffer = StringIO()
        handler = logging.StreamHandler(buffer)
        handler.setFormatter(RedactingFormatter("%(message)s", use_regex_fallback=True))

        logger = logging.getLogger(f"test_regex_{id(buffer)}")
        logger.handlers = [handler]
        logger.setLevel(logging.INFO)
        logger.propagate = False

        return logger, buffer

    def test_enrollment_token_pattern(self, logger_with_regex):
        logger, buffer = logger_with_regex
        logger.info("Token: enrl_exec_abc123")
        output = buffer.getvalue()
        assert "[REDACTED]" in output
        assert "enrl_exec_abc123" not in output

    def test_enrl_prefix_pattern(self, logger_with_regex):
        logger, buffer = logger_with_regex
        logger.info("Token: enrl_abc123")
        output = buffer.getvalue()
        assert "[REDACTED]" in output
        assert "enrl_abc123" not in output

    def test_bearer_token_pattern(self, logger_with_regex):
        logger, buffer = logger_with_regex
        logger.info("Auth: Bearer eyJhbGciOiJIUzI1NiJ9")
        output = buffer.getvalue()
        assert "[REDACTED]" in output
        assert "eyJhbGciOiJIUzI1NiJ9" not in output

    def test_password_query_param(self, logger_with_regex):
        logger, buffer = logger_with_regex
        logger.info("URL: https://api.example.com?password=hunter2")
        output = buffer.getvalue()
        assert "[REDACTED]" in output
        assert "hunter2" not in output

    def test_token_query_param(self, logger_with_regex):
        logger, buffer = logger_with_regex
        logger.info("URL: https://api.example.com?token=abc123")
        output = buffer.getvalue()
        assert "[REDACTED]" in output
        assert "abc123" not in output

    def test_regex_disabled_no_redaction(self):
        buffer = StringIO()
        handler = logging.StreamHandler(buffer)
        handler.setFormatter(RedactingFormatter("%(message)s", use_regex_fallback=False))

        logger = logging.getLogger("test_no_regex")
        logger.handlers = [handler]
        logger.setLevel(logging.INFO)
        logger.propagate = False

        logger.info("Token: enrl_exec_abc123")
        output = buffer.getvalue()
        assert "enrl_exec_abc123" in output

    def test_legacy_unwrapped_token_still_caught(self, logger_with_regex):
        logger, buffer = logger_with_regex
        logger.info("Legacy token value: enrl_exec_xyz789")
        output = buffer.getvalue()
        assert "[REDACTED]" in output
        assert "enrl_exec_xyz789" not in output

    def test_api_key_pattern(self, logger_with_regex):
        logger, buffer = logger_with_regex
        logger.info("Key: api_key=sk-12345")
        output = buffer.getvalue()
        assert "[REDACTED]" in output
        assert "sk-12345" not in output


# ============================================================================
# RedactingFormatter Tests — Edge Cases
# ============================================================================


class TestRedactingFormatterEdgeCases:
    """Tests for edge cases and error handling."""

    def test_empty_string_value(self):
        buffer = StringIO()
        handler = logging.StreamHandler(buffer)
        handler.setFormatter(RedactingFormatter("%(message)s"))

        logger = logging.getLogger("test_empty")
        logger.handlers = [handler]
        logger.setLevel(logging.INFO)
        logger.propagate = False

        logger.info("Token: %s", token("", "test"))
        output = buffer.getvalue()
        assert "[REDACTED:TEST]" in output

    def test_none_value(self):
        buffer = StringIO()
        handler = logging.StreamHandler(buffer)
        handler.setFormatter(RedactingFormatter("%(message)s"))

        logger = logging.getLogger("test_none")
        logger.handlers = [handler]
        logger.setLevel(logging.INFO)
        logger.propagate = False

        logger.info("Value: %s", None)
        output = buffer.getvalue()
        assert "None" in output

    def test_special_characters_in_token(self):
        buffer = StringIO()
        handler = logging.StreamHandler(buffer)
        handler.setFormatter(RedactingFormatter("%(message)s"))

        logger = logging.getLogger("test_special")
        logger.handlers = [handler]
        logger.setLevel(logging.INFO)
        logger.propagate = False

        logger.info("Token: %s", token("enrl_exec_abc-123_XYZ", "enrollment"))
        output = buffer.getvalue()
        assert "[REDACTED:ENROLLMENT]" in output
        assert "enrl_exec_abc-123_XYZ" not in output

    def test_no_args_proceeds_normally(self):
        buffer = StringIO()
        handler = logging.StreamHandler(buffer)
        handler.setFormatter(RedactingFormatter("%(message)s"))

        logger = logging.getLogger("test_no_args")
        logger.handlers = [handler]
        logger.setLevel(logging.INFO)
        logger.propagate = False

        logger.info("Simple message without args")
        output = buffer.getvalue()
        assert "Simple message without args" in output


# ============================================================================
# Pattern Management Tests
# ============================================================================


class TestPatternManagement:
    """Tests for regex pattern management."""

    def test_get_patterns_returns_copy(self):
        patterns = RedactingFormatter.get_patterns()
        original_count = len(patterns)
        patterns.append(__import__("re").compile(r"test"))
        assert len(RedactingFormatter.get_patterns()) == original_count

    def test_add_pattern_dynamically(self):
        original_count = len(RedactingFormatter.get_patterns())
        try:
            RedactingFormatter.add_pattern(r"custom_secret_\d+")
            new_patterns = RedactingFormatter.get_patterns()
            assert len(new_patterns) == original_count + 1

            buffer = StringIO()
            handler = logging.StreamHandler(buffer)
            handler.setFormatter(RedactingFormatter("%(message)s"))

            logger = logging.getLogger("test_custom")
            logger.handlers = [handler]
            logger.setLevel(logging.INFO)
            logger.propagate = False

            logger.info("Secret: custom_secret_12345")
            output = buffer.getvalue()
            assert "[REDACTED]" in output
            assert "custom_secret_12345" not in output
        finally:
            RedactingFormatter.REGEX_PATTERNS.pop()


# ============================================================================
# Integration Tests
# ============================================================================


class TestIntegrationScenarios:
    """Integration tests for real-world usage patterns."""

    def test_http_request_logging_safe(self):
        buffer = StringIO()
        handler = logging.StreamHandler(buffer)
        handler.setFormatter(RedactingFormatter("%(message)s"))

        logger = logging.getLogger("test_http")
        logger.handlers = [handler]
        logger.setLevel(logging.INFO)
        logger.propagate = False

        auth_header = f"Bearer {token('eyJhbGciOiJIUzI1NiJ9', 'bearer')}"
        logger.info("Request auth: %s", auth_header)
        output = buffer.getvalue()
        assert "eyJhbGciOiJIUzI1NiJ9" not in output

    def test_database_connection_string_safe(self):
        buffer = StringIO()
        handler = logging.StreamHandler(buffer)
        handler.setFormatter(RedactingFormatter("%(message)s"))

        logger = logging.getLogger("test_db")
        logger.handlers = [handler]
        logger.setLevel(logging.INFO)
        logger.propagate = False

        conn_string = "postgresql://user:hunter2@db.example.com/prod"
        logger.info("Connecting: %s", secret(conn_string))
        output = buffer.getvalue()
        assert "[REDACTED]" in output
        assert "hunter2" not in output

    def test_third_party_library_logs_filtered(self):
        buffer = StringIO()
        handler = logging.StreamHandler(buffer)
        handler.setFormatter(RedactingFormatter("%(levelname)s %(name)s %(message)s"))

        logger = logging.getLogger("thirdparty.lib")
        logger.handlers = [handler]
        logger.setLevel(logging.DEBUG)
        logger.propagate = False

        logger.debug("Failed auth with token enrl_exec_xyz")
        output = buffer.getvalue()
        assert "[REDACTED]" in output
        assert "enrl_exec_xyz" not in output

    def test_debug_logging_with_wrappers(self):
        buffer = StringIO()
        handler = logging.StreamHandler(buffer)
        handler.setFormatter(RedactingFormatter("%(message)s"))

        logger = logging.getLogger("test_debug")
        logger.handlers = [handler]
        logger.setLevel(logging.DEBUG)
        logger.propagate = False

        token_value = "enrl_exec_debug_token_123"
        logger.debug("AUTH DEBUG: token=%s", token(token_value, "ACCESS"))
        output = buffer.getvalue()
        # Token wrapper redacts via __str__; regex layer preserves the marker
        assert "[REDACTED:ACCESS]" in output
        assert token_value not in output

    def test_cookie_dict_repr_caught_by_regex(self):
        """Dict repr values are handled by regex fallback (Layer 2).

        Python's str(dict) calls repr() on values, not str(), so wrapper
        __str__ is not invoked for nested values. The regex fallback catches
        token-like values in dict reprs as a defense-in-depth measure.
        """
        buffer = StringIO()
        handler = logging.StreamHandler(buffer)
        handler.setFormatter(RedactingFormatter("%(message)s"))

        logger = logging.getLogger("test_cookie_dict")
        logger.handlers = [handler]
        logger.setLevel(logging.INFO)
        logger.propagate = False

        # Simulate: logger.info("DEBUG: cookies=%s", dict(request.cookies))
        # where cookies contains a token value
        logger.info("DEBUG: cookies={'venya_access_token': 'enrl_exec_secret123'}")
        output = buffer.getvalue()
        assert "enrl_exec_secret123" not in output
