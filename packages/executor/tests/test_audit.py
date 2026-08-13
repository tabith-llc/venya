"""Tests for AuditLogger."""

from __future__ import annotations

import threading
from unittest.mock import MagicMock, patch

import pytest

from executor.audit import AuditEvent, AuditLogger
from executor.config import AuditForwarderConfig


@pytest.fixture()
def audit_config() -> AuditForwarderConfig:
    return AuditForwarderConfig(
        remote_url="http://localhost:8080/audit",
        max_buffer_size=100,
        alert_threshold=0.8,
        retry_base_delay=0.1,
        retry_max_delay=1.0,
        local_retention_days=90,
    )


@pytest.fixture()
def logger(audit_config: AuditForwarderConfig) -> AuditLogger:
    return AuditLogger(audit_config, session_id="test-session-1")


@pytest.fixture()
def success_mock() -> MagicMock:
    """Create a properly configured httpx2.Client mock that returns 200."""
    mock_client = MagicMock()
    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_client.__enter__.return_value.post.return_value = mock_response
    return mock_client


class TestAuditEvent:
    """Tests for AuditEvent dataclass."""

    def test_to_dict_basic(self):
        event = AuditEvent(event_type="credential_injected", session_id="s1")
        d = event.to_dict()
        assert d["event_type"] == "credential_injected"
        assert d["session_id"] == "s1"
        assert "timestamp" in d

    def test_to_dict_with_extra(self):
        event = AuditEvent(
            event_type="command_executed",
            session_id="s1",
            extra={"exit_code": 0, "duration_ms": 42.5},
        )
        d = event.to_dict()
        assert d["exit_code"] == 0
        assert d["duration_ms"] == 42.5

    def test_to_json(self):
        import json

        event = AuditEvent(event_type="credential_injected", session_id="s1")
        data = json.loads(event.to_json())
        assert data["event_type"] == "credential_injected"
        assert data["session_id"] == "s1"


class TestAuditLoggerEmit:
    """Tests for AuditLogger.emit()."""

    def test_emit_buffers_event(self, logger: AuditLogger):
        logger.emit("credential_injected", strategy="memfd", fd_count=2)
        assert len(logger._buffer) == 1

    def test_emit_multiple_events(self, logger: AuditLogger):
        logger.emit("credential_injected", strategy="memfd", fd_count=1)
        logger.emit("credential_injected", strategy="memfd", fd_count=2)
        assert len(logger._buffer) == 2

    def test_emit_command_executed(self, logger: AuditLogger):
        logger.emit("command_executed", command="ls -la", exit_code=0, duration_ms=15.3)
        event = logger._buffer[0]
        assert event.event_type == "command_executed"
        assert event.extra["exit_code"] == 0

    def test_emit_command_rejected(self, logger: AuditLogger):
        logger.emit("command_rejected", command="rm -rf /", reason="blocked")
        event = logger._buffer[0]
        assert event.event_type == "command_rejected"
        assert event.extra["reason"] == "blocked"

    def test_emit_unknown_event_type_logged(self, logger: AuditLogger, caplog):
        with caplog.at_level("WARNING"):
            logger.emit("unknown_type")
        assert "Unknown audit event type" in caplog.text
        assert len(logger._buffer) == 0

    def test_emit_includes_session_id(self, logger: AuditLogger):
        logger.emit("credential_injected", strategy="memfd")
        event = logger._buffer[0]
        assert event.session_id == "test-session-1"


class TestAuditLoggerFlush:
    """Tests for AuditLogger.flush()."""

    def test_flush_sends_events(self, audit_config: AuditForwarderConfig, success_mock: MagicMock):
        audit_config.remote_url = "http://localhost:8080/audit"
        log = AuditLogger(audit_config, session_id="s1")
        log.emit("credential_injected", strategy="memfd", fd_count=1)

        with patch("httpx2.Client", return_value=success_mock) as mock_client_cls:
            log.flush()

        mock_client_cls.return_value.__enter__.return_value.post.assert_called_once()
        call_args = mock_client_cls.return_value.__enter__.return_value.post.call_args
        assert call_args[1]["headers"] == {"Content-Type": "application/x-ndjson"}

    def test_flush_clears_buffer(self, audit_config: AuditForwarderConfig, success_mock: MagicMock):
        audit_config.remote_url = "http://localhost:9999/audit"
        log = AuditLogger(audit_config, session_id="s1")
        log.emit("credential_injected", strategy="memfd")

        with patch("httpx2.Client", return_value=success_mock):
            log.flush()

        assert len(log._buffer) == 0

    def test_flush_noop_without_remote_url(self, audit_config: AuditForwarderConfig):
        audit_config.remote_url = None
        log = AuditLogger(audit_config, session_id="s1")
        log.emit("credential_injected", strategy="memfd")
        log.flush()
        # Buffer should still have events (not flushed)
        assert len(log._buffer) == 1

    def test_flush_noop_with_empty_buffer(self, audit_config: AuditForwarderConfig):
        audit_config.remote_url = "http://localhost:9999/audit"
        log = AuditLogger(audit_config, session_id="s1")
        log.flush()  # Should not raise

    def test_auto_flush_on_buffer_full(self, audit_config: AuditForwarderConfig, success_mock: MagicMock):
        audit_config.remote_url = "http://localhost:9999/audit"
        audit_config.max_buffer_size = 5
        log = AuditLogger(audit_config, session_id="s1")

        with patch("httpx2.Client", return_value=success_mock):
            for i in range(5):
                log.emit("credential_injected", strategy="memfd", fd_count=i + 1)

        assert len(log._buffer) == 0

    def test_alert_threshold_warning(self, audit_config: AuditForwarderConfig, caplog):
        audit_config.max_buffer_size = 100
        audit_config.alert_threshold = 0.5
        log = AuditLogger(audit_config, session_id="s1")

        with caplog.at_level("WARNING"):
            for i in range(50):
                log.emit("credential_injected", strategy="memfd", fd_count=i)
            # 51st event should trigger alert
            log.emit("credential_injected", strategy="memfd", fd_count=51)

        assert "Audit buffer at" in caplog.text


class TestAuditLoggerShutdown:
    """Tests for AuditLogger.shutdown()."""

    def test_shutdown_flushes_remaining(self, audit_config: AuditForwarderConfig, success_mock: MagicMock):
        audit_config.remote_url = "http://localhost:9999/audit"
        log = AuditLogger(audit_config, session_id="s1")
        log.emit("credential_injected", strategy="memfd")

        with patch("httpx2.Client", return_value=success_mock):
            log.shutdown()

        assert len(log._buffer) == 0

    def test_shutdown_clears_shutdown_flag(self, audit_config: AuditForwarderConfig):
        log = AuditLogger(audit_config, session_id="s1")
        log.shutdown()
        assert log._shutdown is True
