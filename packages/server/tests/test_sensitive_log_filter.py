"""Tests for the sensitive log redaction filter."""

from __future__ import annotations

import io
import logging as _logging

import pytest

from server.utils.sensitive_log_filter import (
    SensitiveFieldFilter,
    _redact,
)


class TestRedact:
    """Tests for the _redact function."""

    def test_enrollment_token_equals(self):
        assert _redact("enrollment_token=abc123") == "enrollment_token=[REDACTED]"

    def test_enrollment_token_colon(self):
        assert _redact("token: enrl_exec_abc123") == "token: [REDACTED]"

    def test_password_quoted(self):
        assert _redact('password="secret123"') == "password=[REDACTED]"

    def test_password_single_quoted(self):
        assert _redact("password='secret123'") == "password=[REDACTED]"

    def test_bearer_token(self):
        jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"
        assert _redact(f"Bearer {jwt}") == "Bearer [REDACTED]"

    def test_recovery_code(self):
        assert _redact("recovery_code=XYZ123") == "recovery_code=[REDACTED]"

    def test_api_key(self):
        assert _redact("api_key=sk-12345") == "api_key=[REDACTED]"

    def test_secret(self):
        assert _redact("secret=mysecretvalue") == "secret=[REDACTED]"

    def test_private_key_path(self):
        assert _redact("private_key_path=/etc/venya/ca.key") == "private_key_path=[REDACTED]"

    def test_client_secret(self):
        assert _redact("client_secret=abc") == "client_secret=[REDACTED]"

    def test_access_token(self):
        assert _redact("access_token=xyz") == "access_token=[REDACTED]"

    def test_refresh_token(self):
        assert _redact("refresh_token=def") == "refresh_token=[REDACTED]"

    def test_passwd(self):
        assert _redact("passwd=hunter2") == "passwd=[REDACTED]"

    def test_key_equals(self):
        assert _redact("key=mysecretkey") == "key=[REDACTED]"

    def test_ca_key_env(self):
        assert _redact("ca_key_env=VENYA_CA_KEY_PASSPHRASE") == "ca_key_env=[REDACTED]"

    def test_no_sensitive_data(self):
        assert _redact("no sensitive data here") == "no sensitive data here"

    def test_ca_key_warning_not_redacted(self):
        # "CA key" is not a sensitive key name — only "ca_key=" or "ca_key:" patterns
        assert _redact("CA key will be stored UNENCRYPTED") == (
            "CA key will be stored UNENCRYPTED"
        )

    def test_password_in_quotes_in_sentence(self):
        assert _redact('logging "password=hunter2" in config') == (
            'logging "password=[REDACTED]" in config'
        )

    def test_empty_string(self):
        assert _redact("") == ""

    def test_none_handled(self):
        assert _redact(None) is None

    def test_multiple_sensitive_values(self):
        msg = "password=foo and token=bar"
        result = _redact(msg)
        assert "password=[REDACTED]" in result
        assert "token=[REDACTED]" in result
        assert "foo" not in result
        assert "bar" not in result

    def test_token_with_space_separator(self):
        assert _redact("token enrl_exec_abc123def456") == "token [REDACTED]"

    def test_bearer_space_separator(self):
        jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"
        assert _redact(f"bearer {jwt}") == "bearer [REDACTED]"

    def test_case_insensitive(self):
        assert _redact("PASSWORD=upper") == "PASSWORD=[REDACTED]"
        assert _redact("Token=mixed") == "Token=[REDACTED]"


class TestSensitiveFieldFilter:
    """Tests for the SensitiveFieldFilter logging filter."""

    def test_filter_redacts_message(self):
        out = io.StringIO()
        handler = _logging.StreamHandler(out)
        handler.setFormatter(_logging.Formatter("%(message)s"))
        handler.addFilter(SensitiveFieldFilter())

        logger = _logging.getLogger("test_redact")
        logger.setLevel(_logging.INFO)
        logger.handlers.clear()
        logger.addHandler(handler)
        logger.propagate = False

        logger.info("password=secret123")
        logger.removeHandler(handler)

        output = out.getvalue()
        assert "secret123" not in output
        assert "[REDACTED]" in output

    def test_filter_preserves_non_sensitive(self):
        out = io.StringIO()
        handler = _logging.StreamHandler(out)
        handler.setFormatter(_logging.Formatter("%(message)s"))
        handler.addFilter(SensitiveFieldFilter())

        logger = _logging.getLogger("test_noredact")
        logger.setLevel(_logging.INFO)
        logger.handlers.clear()
        logger.addHandler(handler)
        logger.propagate = False

        logger.info("normal log message")
        logger.removeHandler(handler)

        output = out.getvalue()
        assert "normal log message" in output

    def test_filter_with_percent_formatting(self):
        out = io.StringIO()
        handler = _logging.StreamHandler(out)
        handler.setFormatter(_logging.Formatter("%(message)s"))
        handler.addFilter(SensitiveFieldFilter())

        logger = _logging.getLogger("test_percent")
        logger.setLevel(_logging.INFO)
        logger.handlers.clear()
        logger.addHandler(handler)
        logger.propagate = False

        logger.info("token=%s", "abc123")
        logger.removeHandler(handler)

        output = out.getvalue()
        assert "abc123" not in output
        assert "[REDACTED]" in output
