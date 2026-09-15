"""Tests for AuditLogger (durable spool + asynchronous forwarder)."""

import json
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from executor.audit import AuditEvent, AuditLogger
from executor.config import AuditForwarderConfig


def make_config(spool_dir: Path, **overrides) -> AuditForwarderConfig:
    base = {
        "remote_url": None,
        "max_buffer_size": 100,
        "alert_threshold": 0.8,
        "retry_base_delay": 60.0,
        "retry_max_delay": 120.0,
        "max_retries": 3,
        "spool_path": str(spool_dir / "spool.jsonl"),
    }
    base.update(overrides)
    return AuditForwarderConfig(**base)


def read_spool(spool_dir: Path) -> list[dict]:
    p = spool_dir / "spool.jsonl"
    if not p.exists():
        return []
    return [json.loads(line) for line in p.read_text().splitlines() if line]


@pytest.fixture()
def spool_dir(tmp_path: Path) -> Path:
    return tmp_path


@pytest.fixture()
def audit_logger(spool_dir: Path):
    log = AuditLogger(make_config(spool_dir), session_id="test-session-1")
    yield log
    log.shutdown()


@pytest.fixture()
def success_mock() -> MagicMock:
    """Create a properly configured httpx2.Client mock that returns 200."""
    mock_response = MagicMock()
    mock_response.status_code = 200

    mock_client = MagicMock()
    mock_client.post.return_value = mock_response
    mock_client.__enter__ = MagicMock(return_value=mock_client)
    mock_client.__exit__ = MagicMock(return_value=False)

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
        event = AuditEvent(event_type="credential_injected", session_id="s1")
        data = json.loads(event.to_json())
        assert data["event_type"] == "credential_injected"
        assert data["session_id"] == "s1"


class TestEmitDurable:
    """emit() must be durable (spool file) and never touch the network."""

    def test_emit_writes_spool_line(self, audit_logger: AuditLogger, spool_dir: Path):
        audit_logger.emit("credential_injected", strategy="memfd", fd_count=2)
        lines = read_spool(spool_dir)
        assert len(lines) == 1
        assert lines[0]["event_type"] == "credential_injected"
        assert lines[0]["session_id"] == "test-session-1"
        assert lines[0]["strategy"] == "memfd"
        assert lines[0]["fd_count"] == 2

    def test_emit_multiple_events(self, audit_logger: AuditLogger, spool_dir: Path):
        audit_logger.emit("credential_injected", strategy="memfd", fd_count=1)
        audit_logger.emit("credential_injected", strategy="memfd", fd_count=2)
        assert len(read_spool(spool_dir)) == 2

    def test_emit_command_executed(self, audit_logger: AuditLogger, spool_dir: Path):
        audit_logger.emit("command_executed", command="ls -la", exit_code=0, duration_ms=15.3)
        line = read_spool(spool_dir)[0]
        assert line["event_type"] == "command_executed"
        assert line["exit_code"] == 0

    def test_emit_command_rejected(self, audit_logger: AuditLogger, spool_dir: Path):
        audit_logger.emit("command_rejected", command="rm -rf /", reason="blocked")
        line = read_spool(spool_dir)[0]
        assert line["event_type"] == "command_rejected"
        assert line["reason"] == "blocked"

    def test_emit_unknown_event_type_not_written(self, audit_logger: AuditLogger, spool_dir: Path, caplog):
        with caplog.at_level("WARNING"):
            audit_logger.emit("unknown_type")
        assert "Unknown audit event type" in caplog.text
        assert read_spool(spool_dir) == []

    def test_emit_survives_without_flush_or_shutdown(self, spool_dir: Path):
        log = AuditLogger(make_config(spool_dir), session_id="s1")
        log.emit("credential_injected", strategy="memfd")
        # No flush/shutdown — the event must already be on disk.
        del log
        assert len(read_spool(spool_dir)) == 1

    def test_emit_serialization_failure_writes_marker_line(self, audit_logger: AuditLogger, spool_dir: Path):
        audit_logger.emit("command_executed", broken=object())
        lines = read_spool(spool_dir)
        assert len(lines) == 1
        assert lines[0]["event_type"] == "command_executed"
        assert "serialization_error" in lines[0]

    def test_emit_never_touches_network(self, spool_dir: Path):
        log = AuditLogger(make_config(spool_dir), session_id="s1")
        try:
            with patch("executor.audit.httpx2.Client") as cls:
                log.emit("credential_injected", strategy="memfd")
                assert cls.call_count == 0
            assert len(read_spool(spool_dir)) == 1
        finally:
            log.shutdown()


class TestForward:
    """_forward_once(): spool → remote, truncate on success, keep on failure.

    Unit tests stop the background forwarder before exercising the direct
    path so exactly the test drives the (mocked) transport.
    """

    @staticmethod
    def _stop_forwarder(log: AuditLogger) -> None:
        log._shutdown = True
        log._wakeup.set()
        log._forwarder.join(timeout=2.0)

    def _logger_prepped(self, spool_dir: Path, **overrides) -> AuditLogger:
        log = AuditLogger(make_config(spool_dir, **overrides), session_id="s1")
        self._stop_forwarder(log)
        log._config.remote_url = "http://127.0.0.1:1/audit"
        return log

    def test_forward_sends_zstd_ndjson_and_truncates(self, spool_dir: Path, success_mock: MagicMock):
        log = self._logger_prepped(spool_dir)
        log.emit("credential_injected", strategy="memfd", fd_count=1)
        with patch("executor.audit.httpx2.Client", return_value=success_mock) as cls:
            assert log._forward_once() is True
        post = cls.return_value.__enter__.return_value.post
        post.assert_called_once()
        kwargs = post.call_args[1]
        assert kwargs["headers"] == {
            "Content-Type": "application/x-ndjson",
            "Content-Encoding": "zstd",
        }
        import compression.zstd

        assert b"credential_injected" in compression.zstd.decompress(kwargs["content"])
        assert read_spool(spool_dir) == []

    def test_forward_failure_keeps_lines(self, spool_dir: Path):
        log = self._logger_prepped(spool_dir)
        log.emit("credential_injected", strategy="memfd")
        fail_response = MagicMock()
        fail_response.status_code = 500
        fail_response.text = "boom"
        mock_client = MagicMock()
        mock_client.post.return_value = fail_response
        mock_client.__enter__ = MagicMock(return_value=mock_client)
        mock_client.__exit__ = MagicMock(return_value=False)
        with patch("executor.audit.httpx2.Client", return_value=mock_client):
            assert log._forward_once() is False
        assert len(read_spool(spool_dir)) == 1

    def test_forward_connection_error_keeps_lines(self, spool_dir: Path):
        import httpx2

        log = self._logger_prepped(spool_dir)
        log.emit("credential_injected", strategy="memfd")
        with patch(
            "executor.audit.httpx2.Client",
            side_effect=httpx2.ConnectError("refused"),
        ):
            assert log._forward_once() is False
        assert len(read_spool(spool_dir)) == 1

    def test_forward_verifies_with_ca_cert_path(self, spool_dir: Path, success_mock: MagicMock):
        """Positive: valid config forwards with verify=<ca_cert_path>."""
        ca = spool_dir / "ca.crt"
        ca.write_text("dummy")
        log = AuditLogger(
            make_config(spool_dir, remote_url="https://sink.invalid/audit", ca_cert_path=str(ca)),
            session_id="s1",
        )
        self._stop_forwarder(log)
        log.emit("credential_injected", strategy="memfd")
        try:
            with patch("executor.audit.httpx2.Client", return_value=success_mock) as cls:
                assert log._forward_once() is True
            assert cls.call_args.kwargs["verify"] == str(ca)
        finally:
            log.shutdown()

    def test_bypassed_validator_never_disables_verify(self, spool_dir: Path, success_mock: MagicMock):
        """Negative guard: direct mutation bypasses pydantic validation —
        the call site must fall back to True (system trust), never False
        (regression guard for verify=False fallback)."""
        log = self._logger_prepped(spool_dir)
        log.emit("credential_injected", strategy="memfd")
        with patch("executor.audit.httpx2.Client", return_value=success_mock) as cls:
            assert log._forward_once() is True
        assert cls.call_args.kwargs["verify"] is True

    def test_forward_noop_without_remote_url(self, spool_dir: Path):
        log = AuditLogger(make_config(spool_dir), session_id="s1")
        log.emit("credential_injected", strategy="memfd")
        try:
            assert log._forward_once() is True
        finally:
            log.shutdown()
        assert len(read_spool(spool_dir)) == 1

    def test_forward_empty_spool_no_post(self, spool_dir: Path, success_mock: MagicMock):
        log = self._logger_prepped(spool_dir)
        with patch("executor.audit.httpx2.Client", return_value=success_mock) as cls:
            assert log._forward_once() is True
        cls.assert_not_called()

    def test_flush_drains_spool(self, spool_dir: Path, success_mock: MagicMock):
        log = self._logger_prepped(spool_dir)
        log.emit("credential_injected", strategy="memfd")
        with patch("executor.audit.httpx2.Client", return_value=success_mock) as cls:
            log.flush()
        cls.return_value.__enter__.return_value.post.assert_called_once()
        assert read_spool(spool_dir) == []

    def test_compression_reduces_size(self, spool_dir: Path, success_mock: MagicMock):
        log = self._logger_prepped(spool_dir, max_buffer_size=10_000)
        for i in range(100):
            log.emit("command_executed", command=f"ls -la /path/to/dir_{i}", exit_code=0, duration_ms=42.5)
        with patch("executor.audit.httpx2.Client", return_value=success_mock) as cls:
            log._forward_once()
        content = cls.return_value.__enter__.return_value.post.call_args[1]["content"]
        import compression.zstd

        assert len(content) < len(compression.zstd.decompress(content))


class TestSpoolBounds:
    """Capacity alerts and drop-oldest keep the spool bounded."""

    def test_alert_threshold_warning(self, spool_dir: Path, caplog):
        log = AuditLogger(
            make_config(spool_dir, max_buffer_size=10, alert_threshold=0.5),
            session_id="s1",
        )
        try:
            with caplog.at_level("WARNING"):
                for i in range(5):
                    log.emit("credential_injected", n=i)
            assert "Audit buffer at" in caplog.text
        finally:
            log.shutdown()

    def test_drop_oldest_at_capacity(self, spool_dir: Path):
        log = AuditLogger(make_config(spool_dir, max_buffer_size=3), session_id="s1")
        try:
            for i in range(5):
                log.emit("credential_injected", n=i)
            lines = read_spool(spool_dir)
            assert len(lines) == 3
            # oldest (n=0, n=1) dropped; newest three kept, in order
            assert [l["n"] for l in lines] == [2, 3, 4]
        finally:
            log.shutdown()


class TestShutdown:
    """shutdown(): bounded final drain + flag."""

    def test_shutdown_flushes_remaining(self, spool_dir: Path, success_mock: MagicMock):
        log = AuditLogger(make_config(spool_dir), session_id="s1")
        log.emit("credential_injected", strategy="memfd")
        log._config.remote_url = "http://127.0.0.1:1/audit"
        with patch("executor.audit.httpx2.Client", return_value=success_mock) as cls:
            log.shutdown()
        cls.return_value.__enter__.return_value.post.assert_called()
        assert read_spool(spool_dir) == []
        assert log._shutdown is True

    def test_shutdown_sets_flag(self, spool_dir: Path):
        log = AuditLogger(make_config(spool_dir), session_id="s1")
        log.shutdown()
        assert log._shutdown is True


class TestForwarderThread:
    """The background thread drains the spool without explicit flush."""

    def test_background_forward_drains_spool(self, spool_dir: Path, success_mock: MagicMock):
        import time

        ca = spool_dir / "ca.crt"
        ca.write_text("dummy")
        log = AuditLogger(
            make_config(
                spool_dir,
                remote_url="https://127.0.0.1:1/audit",
                ca_cert_path=str(ca),
                retry_base_delay=0.05,
                retry_max_delay=0.1,
            ),
            session_id="s1",
        )
        log.emit("credential_injected", strategy="memfd")
        try:
            # The forwarder polls ≤ 1s; give it generous slack.
            deadline = time.monotonic() + 10.0
            with patch("executor.audit.httpx2.Client", return_value=success_mock):
                while time.monotonic() < deadline and read_spool(spool_dir):
                    time.sleep(0.05)
        finally:
            log.shutdown()
        assert read_spool(spool_dir) == []
