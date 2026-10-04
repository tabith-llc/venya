# Copyright (c) 2026 Tabith LLC.
# Use of this source code is governed by the Business Source License 1.1
# included in the LICENSE file at the root of this repository. As of the
# Change Date listed there, the work is available under MPL 2.0.
# SPDX-License-Identifier: BUSL-1.1

"""Tests for AuditLogger (durable spool + asynchronous forwarder)."""

import json
import os
import ssl
from datetime import UTC, datetime, timedelta
from pathlib import Path
from unittest.mock import MagicMock, patch

import httpx2
import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from executor.audit import AuditEvent, AuditLogger
from executor.config import AuditForwarderConfig


def make_cert_pair(dir_: Path) -> tuple[str, str]:
    """Write a MATCHING self-signed cert/key PEM pair into dir_, return paths.

    #432: the forwarder now loads client_cert through
    ssl.SSLContext.load_cert_chain(certfile, keyfile), which needs a real
    parseable matching pair — the /tmp/c.crt placeholder paths never loaded,
    they only ever reached a MagicMock. (The conftest cert_files fixture is
    NOT usable: its cert embeds a different key than its key file.)
    """
    key = ec.generate_private_key(ec.SECP256R1())
    now = datetime.now(UTC)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "audit-test-executor")])
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(days=1))
        .not_valid_after(now + timedelta(days=1))
        .sign(key, hashes.SHA256())
    )
    cert_path = dir_ / "client.crt"
    key_path = dir_ / "client.key"
    cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    key_path.write_bytes(
        key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
    )
    return str(cert_path), str(key_path)


@pytest.fixture()
def cert_pair(tmp_path: Path) -> tuple[str, str]:
    """Matching client cert/key pair paths for forward cells that really load."""
    return make_cert_pair(tmp_path)


def make_config(spool_dir: Path, **overrides) -> AuditForwarderConfig:
    base = {
        "remote_url": None,
        "max_buffer_size": 100,
        "max_batch_lines": 50,
        "alert_threshold": 0.8,
        "retry_base_delay": 60.0,
        "retry_max_delay": 120.0,
        "max_retries": 3,
        "spool_path": str(spool_dir / "spool.jsonl"),
    }
    base.update(overrides)
    # keep the harness valid under the #307 D3 validator (batch <= buffer)
    base["max_batch_lines"] = min(base["max_batch_lines"], base["max_buffer_size"])
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

    def _logger_prepped(self, spool_dir: Path, cert_pair: tuple[str, str], **overrides) -> AuditLogger:
        # client_cert present because these cells exercise the POST path;
        # _forward_once fail-closes without it (#307 D1, T2 pins that).
        # The pair is REAL files since #432: _forward_once loads it through
        # ssl.SSLContext.load_cert_chain before constructing the client.
        log = AuditLogger(
            make_config(spool_dir, **overrides),
            session_id="s1",
            client_cert=cert_pair,
        )
        self._stop_forwarder(log)
        log._config.remote_url = "http://127.0.0.1:1/audit"
        return log

    def test_forward_sends_zstd_ndjson_and_truncates(
        self, spool_dir: Path, cert_pair: tuple[str, str], success_mock: MagicMock
    ):
        log = self._logger_prepped(spool_dir, cert_pair)
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

    def test_forward_failure_keeps_lines(self, spool_dir: Path, cert_pair: tuple[str, str]):
        log = self._logger_prepped(spool_dir, cert_pair)
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

    def test_forward_connection_error_keeps_lines(self, spool_dir: Path, cert_pair: tuple[str, str]):
        import httpx2

        log = self._logger_prepped(spool_dir, cert_pair)
        log.emit("credential_injected", strategy="memfd")
        with patch(
            "executor.audit.httpx2.Client",
            side_effect=httpx2.ConnectError("refused"),
        ):
            assert log._forward_once() is False
        assert len(read_spool(spool_dir)) == 1

    def test_forward_verifies_with_ca_cert_path(
        self, spool_dir: Path, cert_pair: tuple[str, str], tmp_ca_dir: Path, success_mock: MagicMock
    ):
        """Positive (#432 rework): configured CA forwards with
        verify=<ssl.SSLContext built from the CA file> and NO cert= kwarg —
        the old verify=<str CA path> + cert= shape TypeErrors under the
        pinned httpx2 2.12 (the #432 defect the string-assert hid)."""
        ca = str(tmp_ca_dir / "ca.crt")
        log = AuditLogger(
            make_config(spool_dir, remote_url="https://sink.invalid/audit", ca_cert_path=ca),
            session_id="s1",
            client_cert=cert_pair,
        )
        self._stop_forwarder(log)
        log.emit("credential_injected", strategy="memfd")
        try:
            with patch("executor.audit.httpx2.Client", return_value=success_mock) as cls:
                assert log._forward_once() is True
            assert isinstance(cls.call_args.kwargs["verify"], ssl.SSLContext)
            assert "cert" not in cls.call_args.kwargs
        finally:
            log.shutdown()

    def test_bypassed_validator_never_disables_verify(
        self, spool_dir: Path, cert_pair: tuple[str, str], success_mock: MagicMock
    ):
        """Negative guard: direct mutation bypasses pydantic validation —
        the call site must fall back to a system-trust SSLContext, never
        False (regression guard for verify=False fallback; #432 retires the
        old verify=True shape into load_default_certs())."""
        log = self._logger_prepped(spool_dir, cert_pair)
        log.emit("credential_injected", strategy="memfd")
        with patch("executor.audit.httpx2.Client", return_value=success_mock) as cls:
            assert log._forward_once() is True
        verify = cls.call_args.kwargs["verify"]
        assert isinstance(verify, ssl.SSLContext)
        assert verify is not False

    def test_forward_noop_without_remote_url(self, spool_dir: Path, success_mock: MagicMock):
        """T5 pin (#307): no remote_url ⇒ inert-by-absence — True, spool
        kept, and NO transport ever constructed (early-return half of the
        #307 truth table; do not regress into the fail-loud branch)."""
        log = AuditLogger(make_config(spool_dir), session_id="s1")
        log.emit("credential_injected", strategy="memfd")
        try:
            with patch("executor.audit.httpx2.Client", return_value=success_mock) as cls:
                assert log._forward_once() is True
            cls.assert_not_called()
        finally:
            log.shutdown()
        assert len(read_spool(spool_dir)) == 1

    def test_forward_empty_spool_no_post(self, spool_dir: Path, cert_pair: tuple[str, str], success_mock: MagicMock):
        log = self._logger_prepped(spool_dir, cert_pair)
        with patch("executor.audit.httpx2.Client", return_value=success_mock) as cls:
            assert log._forward_once() is True
        cls.assert_not_called()

    def test_flush_drains_spool(self, spool_dir: Path, cert_pair: tuple[str, str], success_mock: MagicMock):
        log = self._logger_prepped(spool_dir, cert_pair)
        log.emit("credential_injected", strategy="memfd")
        with patch("executor.audit.httpx2.Client", return_value=success_mock) as cls:
            log.flush()
        cls.return_value.__enter__.return_value.post.assert_called_once()
        assert read_spool(spool_dir) == []

    def test_compression_reduces_size(self, spool_dir: Path, cert_pair: tuple[str, str], success_mock: MagicMock):
        log = self._logger_prepped(spool_dir, cert_pair, max_buffer_size=10_000)
        for i in range(100):
            log.emit("command_executed", command=f"ls -la /path/to/dir_{i}", exit_code=0, duration_ms=42.5)
        with patch("executor.audit.httpx2.Client", return_value=success_mock) as cls:
            log._forward_once()
        content = cls.return_value.__enter__.return_value.post.call_args[1]["content"]
        import compression.zstd

        assert len(content) < len(compression.zstd.decompress(content))


class TestForwarderClientCert:
    """#307 D1: the forwarder must present the executor mTLS client cert —
    the sink is executor-mTLS-gated, so a cert-less forwarder is a deaf
    dead-knob (401 retry loop). Configured remote WITHOUT client cert is a
    loud fail-closed refusal, never a silent POST."""

    @staticmethod
    def _stop(log: AuditLogger) -> None:
        log._shutdown = True
        log._wakeup.set()
        log._forwarder.join(timeout=2.0)

    def test_T1_client_cert_passed_to_httpx(self, spool_dir: Path, cert_pair: tuple[str, str], success_mock: MagicMock):
        """T1 (#432 rework): client_cert set → it reaches the transport as a
        loaded ssl.SSLContext (verify=), NOT the httpx2 2.12-rejected
        cert= kwarg. The cert/key pair loads for real (make_cert_pair), so
        an empty/unloaded context would fail the chain check below."""
        log = AuditLogger(
            make_config(spool_dir),
            session_id="s1",
            client_cert=cert_pair,
        )
        self._stop(log)
        log._config.remote_url = "https://sink.invalid/audit"
        log.emit("credential_injected", strategy="memfd")
        with patch("executor.audit.httpx2.Client", return_value=success_mock) as cls:
            assert log._forward_once() is True
        assert "cert" not in cls.call_args.kwargs
        assert isinstance(cls.call_args.kwargs["verify"], ssl.SSLContext)
        assert read_spool(spool_dir) == []

    def test_T2_remote_without_client_cert_fails_loud_no_post(self, spool_dir: Path, caplog):
        """T2: remote_url set, client_cert None → ERROR log, NO POST,
        False (lines kept). The loud-deaf-boot class must not regress."""
        log = AuditLogger(make_config(spool_dir), session_id="s1")
        self._stop(log)
        log._config.remote_url = "https://sink.invalid/audit"
        log.emit("credential_injected", strategy="memfd")
        with (
            caplog.at_level("ERROR", logger="venya.executor.audit"),
            patch("executor.audit.httpx2.Client") as cls,
        ):
            assert log._forward_once() is False
        cls.assert_not_called()
        assert "without client certificate" in caplog.text
        assert len(read_spool(spool_dir)) == 1

    def test_T3_batch_cap_drains_max_batch_lines_only(
        self, spool_dir: Path, cert_pair: tuple[str, str], success_mock: MagicMock
    ):
        """T3 (D3): >max_batch_lines spool lines → exactly max_batch_lines
        per POST, remainder kept in the spool."""
        log = AuditLogger(
            make_config(spool_dir, max_buffer_size=1000, max_batch_lines=500),
            session_id="s1",
            client_cert=cert_pair,
        )
        self._stop(log)
        log._config.remote_url = "https://sink.invalid/audit"
        for i in range(600):
            log.emit("command_executed", command=f"echo {i}", exit_code=0, duration_ms=1.0)
        with patch("executor.audit.httpx2.Client", return_value=success_mock) as cls:
            assert log._forward_once() is True
        import compression.zstd

        content = cls.return_value.__enter__.return_value.post.call_args[1]["content"]
        posted = compression.zstd.decompress(content).decode().splitlines()
        assert len(posted) == 500
        assert len(read_spool(spool_dir)) == 100

    def test_T4_max_batch_lines_validator(self):
        """T4: max_batch_lines bounded to 1..max_buffer_size at config load."""
        from pydantic import ValidationError

        with pytest.raises(ValidationError):
            AuditForwarderConfig(max_batch_lines=0)
        with pytest.raises(ValidationError):
            AuditForwarderConfig(max_buffer_size=100, max_batch_lines=101)
        # positive twin: valid values load
        cfg = AuditForwarderConfig(max_buffer_size=100, max_batch_lines=50)
        assert cfg.max_batch_lines == 50


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

    def test_shutdown_flushes_remaining(self, spool_dir: Path, cert_pair: tuple[str, str], success_mock: MagicMock):
        log = AuditLogger(make_config(spool_dir), session_id="s1", client_cert=cert_pair)
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

    def test_background_forward_drains_spool(
        self, spool_dir: Path, cert_pair: tuple[str, str], tmp_ca_dir: Path, success_mock: MagicMock
    ):
        import time

        # real CA file since #432: the forwarder load_verify_locations()s it
        ca = tmp_ca_dir / "ca.crt"
        log = AuditLogger(
            make_config(
                spool_dir,
                remote_url="https://127.0.0.1:1/audit",
                ca_cert_path=str(ca),
                retry_base_delay=0.05,
                retry_max_delay=0.1,
            ),
            session_id="s1",
            client_cert=cert_pair,
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


class TestSpoolPermissions:
    """Spool must be 0600 (ticket sec-secret-redaction-log-leaks #19): it
    holds FULL command lines; pre-fix .open("a") inherited the umask
    (typically 0644 = world-readable audit trail)."""

    def test_spool_created_0600_on_init(self, spool_dir: Path):
        AuditLogger(make_config(spool_dir), session_id="perm-test")
        mode = (spool_dir / "spool.jsonl").stat().st_mode & 0o777
        assert mode == 0o600

    def test_legacy_world_readable_spool_repaired_on_init(self, spool_dir: Path):
        p = spool_dir / "spool.jsonl"
        p.write_text('{"event_type": "legacy"}\n', encoding="utf-8")
        os.chmod(p, 0o644)
        log = AuditLogger(make_config(spool_dir), session_id="perm-test")
        assert (p.stat().st_mode & 0o777) == 0o600
        # legacy content preserved, appends still work post-repair
        log.emit("credential_injected", strategy="memfd", fd_count=1)
        lines = read_spool(spool_dir)
        assert lines[0]["event_type"] == "legacy"
        assert len(lines) == 2


class TestForwarderIntegrity:
    """#310 (owner ruling 2026-10-01, most-secure layered): content-addressed
    success truncation (a line leaves the spool only if it was sent or
    explicitly warned-dropped), 0600 on every create path, and the layered
    batch-cap interlock (boot clamp <= server cap + in-cycle 413 halve-and-
    retry). Mechanism record: defect-hunt-20261001-ultra.md UH4-01/4-02/1-03."""

    @staticmethod
    def _stop(log: AuditLogger) -> None:
        log._shutdown = True
        log._wakeup.set()
        log._forwarder.join(timeout=2.0)

    def _mock_client(self, side_effect) -> MagicMock:
        client = MagicMock()
        client.post.side_effect = side_effect
        client.__enter__ = MagicMock(return_value=client)
        client.__exit__ = MagicMock(return_value=False)
        return client

    def test_TA_interleaved_drop_loses_nothing_unsent(self, spool_dir: Path, cert_pair: tuple[str, str], caplog):
        """T-A (UH4-01, RED pre-fix): emit crosses capacity DURING an
        in-flight POST — the in-batch head is warned-dropped by emit's
        drop-oldest, and count-truncation on success would blind-delete an
        equal count of the NEWER, never-sent lines. Final rule under test:
        every line is either sent, warned-dropped, or still in the spool."""
        import threading

        log = AuditLogger(
            make_config(spool_dir, max_buffer_size=100, max_batch_lines=50),
            session_id="s1",
            client_cert=cert_pair,
        )
        self._stop(log)
        log._config.remote_url = "https://sink.invalid/audit"
        for i in range(50):
            log.emit("command_executed", command=f"sent {i}", exit_code=0, duration_ms=1.0)

        posted = threading.Event()
        release = threading.Event()
        ok_response = MagicMock()
        ok_response.status_code = 200

        def blocking_post(*_args, **_kwargs):
            posted.set()
            assert release.wait(timeout=10), "fixture released the POST"
            return ok_response

        client = self._mock_client(blocking_post)
        outcome: dict = {}

        def run() -> None:
            with patch("executor.audit.httpx2.Client", return_value=client):
                outcome["ok"] = log._forward_once()

        thread = threading.Thread(target=run)
        thread.start()
        try:
            assert posted.wait(timeout=10), "forwarder read the batch and entered POST"
            # 60 appends cross the 100-line capacity: drop-oldest evicts 10
            # of the IN-FLIGHT batch lines (each warned), then all stop.
            with caplog.at_level("WARNING", logger="venya.executor.audit"):
                for i in range(60):
                    log.emit("command_executed", command=f"new {i}", exit_code=0, duration_ms=1.0)
        finally:
            release.set()
            thread.join(timeout=30)
        try:
            assert not thread.is_alive(), "forwarder thread hung — STOP condition"
            assert outcome["ok"] is True
            lines = read_spool(spool_dir)
            # The 50 sent lines are gone; the 10 warned-dropped are gone;
            # ALL 60 never-sent appended lines survive, in order.
            assert [l["command"] for l in lines] == [f"new {i}" for i in range(60)]
            assert "dropped" in caplog.text
        finally:
            log.shutdown()

    def test_TB_recreate_after_full_drain_is_0600(
        self, spool_dir: Path, cert_pair: tuple[str, str], success_mock: MagicMock
    ):
        """T-B (UH4-02, RED pre-fix): drain-to-empty then re-emit — the
        re-created spool must be 0600, not umask-born world-readable."""
        old_umask = os.umask(0o022)
        try:
            log = AuditLogger(
                make_config(spool_dir),
                session_id="s1",
                client_cert=cert_pair,
            )
            try:
                self._stop(log)
                log._config.remote_url = "http://127.0.0.1:1/audit"
                log.emit("credential_injected", strategy="memfd")
                with patch("executor.audit.httpx2.Client", return_value=success_mock):
                    assert log._forward_once() is True
                assert read_spool(spool_dir) == []
                log.emit("credential_injected", strategy="memfd")
                mode = (spool_dir / "spool.jsonl").stat().st_mode & 0o777
                assert mode == 0o600
            finally:
                log.shutdown()
        finally:
            os.umask(old_umask)

    def test_TC_validator_clamps_batch_to_server_cap(self):
        """T-C: the boot clamp refuses > SERVER cap (2000), accepts 2000/500."""
        from pydantic import ValidationError

        from executor.config import SERVER_INGEST_MAX_LINES

        assert SERVER_INGEST_MAX_LINES == 2000
        with pytest.raises(ValidationError):
            AuditForwarderConfig(max_buffer_size=10_000, max_batch_lines=2001)
        assert AuditForwarderConfig(max_buffer_size=10_000, max_batch_lines=2000).max_batch_lines == 2000
        assert AuditForwarderConfig(max_buffer_size=10_000, max_batch_lines=500).max_batch_lines == 500
        # buffer bound still applies below the server cap
        with pytest.raises(ValidationError):
            AuditForwarderConfig(max_buffer_size=100, max_batch_lines=101)

    def test_TD_413_halves_batch_and_retries_in_cycle(self, spool_dir: Path, cert_pair: tuple[str, str], caplog):
        """T-D (UH1-03/UH4-03 brace b): 413 → halve (floor) and re-POST in
        the SAME drain cycle: two POSTs, second batch 1000 lines, accepted
        prefix removed, remainder kept."""
        import compression.zstd

        log = AuditLogger(
            make_config(spool_dir, max_buffer_size=10_000, max_batch_lines=2000),
            session_id="s1",
            client_cert=cert_pair,
        )
        try:
            self._stop(log)
            log._config.remote_url = "https://sink.invalid/audit"
            for i in range(2000):
                log.emit("command_executed", command=f"echo {i}", exit_code=0, duration_ms=1.0)
            r413 = MagicMock()
            r413.status_code = 413
            r413.text = "cap"
            r200 = MagicMock()
            r200.status_code = 200
            client = self._mock_client([r413, r200])
            with caplog.at_level("WARNING", logger="venya.executor.audit"):
                with patch("executor.audit.httpx2.Client", return_value=client):
                    assert log._forward_once() is True
            assert client.post.call_count == 2
            second = compression.zstd.decompress(client.post.call_args_list[1][1]["content"]).decode()
            assert len(second.splitlines()) == 1000
            assert "splitting" in caplog.text
            # accepted 1000 removed by content; the other 1000 kept
            assert len(read_spool(spool_dir)) == 1000
        finally:
            log.shutdown()

    def test_TE_content_truncate_head_moved_warns_no_count_delete(self, spool_dir: Path, caplog):
        """T-E: success-truncation with the head already moved (two sent
        lines warned-dropped in flight) → WARNING with counts, the REMAINING
        sent content removed, every unsent line kept — never a blind
        count-based delete."""
        log = AuditLogger(make_config(spool_dir), session_id="s1")
        self._stop(log)
        try:
            batch = [
                json.dumps({"event_type": "command_executed", "session_id": "s1", "n": i}) + "\n" for i in range(5)
            ]
            # sent 0,1 already warned-dropped; sent 2,3,4 still at the head;
            # two NEVER-SENT lines appended during the POST.
            (spool_dir / "spool.jsonl").write_text(
                "".join(batch[2:]) + '{"marker": "unsent-1"}\n{"marker": "unsent-2"}\n',
                encoding="utf-8",
            )
            with caplog.at_level("WARNING", logger="venya.executor.audit"):
                log._remove_sent_lines(batch)
            assert "head moved" in caplog.text
            kept = (spool_dir / "spool.jsonl").read_text(encoding="utf-8")
            assert kept == '{"marker": "unsent-1"}\n{"marker": "unsent-2"}\n'
        finally:
            log.shutdown()

    def test_TF_server_cap_interlock(self):
        """T-F: the executor mirror constant MUST equal the server file's
        INGEST_MAX_LINES (text-parsed — no cross-package import)."""
        import re

        from executor.config import SERVER_INGEST_MAX_LINES

        server_audit = (
            Path(__file__).resolve().parents[3] / "packages" / "server" / "src" / "server" / "routes" / "audit.py"
        )
        match = re.search(r"^INGEST_MAX_LINES\s*=\s*(\d+)", server_audit.read_text(encoding="utf-8"), re.MULTILINE)
        assert match is not None, "server INGEST_MAX_LINES symbol not found — interlock is the check"
        assert SERVER_INGEST_MAX_LINES == int(match.group(1))


class TestForwardSSLContext:
    """#432 (audit-forwarder-httpx-cert-verify-conflict): httpx2 >= 2.12
    rejects verify=<str> combined with cert= — every forward cycle
    TypeErrored while the spool grew fail-safe. The forwarder now ports the
    cli-admin-mtls-verify-cert-conflict precedent: ONE ssl.SSLContext
    (PROTOCOL_TLS_CLIENT) carries CA anchors (or the system store) and the
    client chain; verify=<ctx>, no cert= kwarg."""

    @staticmethod
    def _stop(log: AuditLogger) -> None:
        log._shutdown = True
        log._wakeup.set()
        log._forwarder.join(timeout=2.0)

    def test_real_httpx_constructor_accepts_forward_kwargs(
        self, spool_dir: Path, cert_pair: tuple[str, str], tmp_ca_dir: Path, success_mock: MagicMock
    ):
        """AC2 positive: the kwargs handed to httpx2.Client are fed to the
        REAL constructor (then closed). The old verify=<str CA path> +
        cert=<tuple> shape TypeErrors HERE — this is the cell the
        mock-everything posture structurally could not see (#432 shipped
        green because MagicMock accepts ANY kwargs)."""
        log = AuditLogger(
            make_config(spool_dir, ca_cert_path=str(tmp_ca_dir / "ca.crt")),
            session_id="s1",
            client_cert=cert_pair,
        )
        self._stop(log)
        log._config.remote_url = "https://sink.invalid/audit"
        log.emit("credential_injected", strategy="memfd")
        real_client = httpx2.Client  # capture BEFORE patch: the patch is on the httpx2 module attribute

        def real_ctor_spy(**kwargs):
            client = real_client(**kwargs)  # raises TypeError on the old shape
            client.close()
            return success_mock

        with patch("executor.audit.httpx2.Client", side_effect=real_ctor_spy) as cls:
            assert log._forward_once() is True
        verify = cls.call_args.kwargs["verify"]
        assert isinstance(verify, ssl.SSLContext)
        assert "cert" not in cls.call_args.kwargs
        assert read_spool(spool_dir) == []

    def test_old_verify_str_plus_cert_shape_typeerrors(self, cert_pair: tuple[str, str], tmp_ca_dir: Path):
        """AC2 premise pin: under the pinned httpx2, the RETIRED shape
        (string verify + cert=) still raises TypeError at construction —
        proves the real-constructor cell above has teeth, not a happy
        mock."""
        with pytest.raises(TypeError):
            httpx2.Client(verify=str(tmp_ca_dir / "ca.crt"), cert=cert_pair, timeout=10)

    def test_no_ca_configured_falls_back_to_system_store(
        self, spool_dir: Path, cert_pair: tuple[str, str], success_mock: MagicMock
    ):
        """AC3 half (no-CA): ca_cert_path unset → context carries the SYSTEM
        trust store (load_default_certs), never False. Direct mutation
        bypasses the validator to simulate the fail-closed fallback branch.
        The wiring is pinned via the load_default_certs call — OpenSSL counts
        capath-dir anchors lazily, so cert_store_stats stays 0 even with the
        system store loaded."""
        log = AuditLogger(make_config(spool_dir), session_id="s1", client_cert=cert_pair)
        self._stop(log)
        log._config.remote_url = "http://127.0.0.1:1/audit"
        log.emit("credential_injected", strategy="memfd")
        with (
            patch.object(ssl.SSLContext, "load_default_certs", autospec=True) as ldc,
            patch("executor.audit.httpx2.Client", return_value=success_mock) as cls,
        ):
            assert log._forward_once() is True
        verify = cls.call_args.kwargs["verify"]
        assert isinstance(verify, ssl.SSLContext)
        ldc.assert_called_once_with(verify)
        assert read_spool(spool_dir) == []

    def test_missing_cert_files_keep_lines_and_log_loud(self, spool_dir: Path, caplog):
        """AC3 negative half (cert files): paths that fail load_cert_chain
        (missing) → per-cycle catch: WARNING, lines KEPT, False — degrades,
        never crash-loops (#307 D1 retention semantics unchanged)."""
        log = AuditLogger(
            make_config(spool_dir),
            session_id="s1",
            client_cert=(str(spool_dir / "nope.crt"), str(spool_dir / "nope.key")),
        )
        self._stop(log)
        log._config.remote_url = "https://sink.invalid/audit"
        log.emit("credential_injected", strategy="memfd")
        with caplog.at_level("WARNING", logger="venya.executor.audit"):
            assert log._forward_once() is False
        assert "Audit forward error" in caplog.text
        assert len(read_spool(spool_dir)) == 1

    def test_garbage_ca_file_keeps_lines_and_log_loud(self, spool_dir: Path, cert_pair: tuple[str, str], caplog):
        """AC3 negative half (CA file): garbage ca_cert_path →
        load_verify_locations raises into the per-cycle catch: WARNING,
        lines KEPT, False."""
        bad_ca = spool_dir / "bad-ca.crt"
        bad_ca.write_text("not a pem")
        log = AuditLogger(
            make_config(spool_dir, remote_url="https://sink.invalid/audit", ca_cert_path=str(bad_ca)),
            session_id="s1",
            client_cert=cert_pair,
        )
        self._stop(log)
        log.emit("credential_injected", strategy="memfd")
        with caplog.at_level("WARNING", logger="venya.executor.audit"):
            assert log._forward_once() is False
        assert "Audit forward error" in caplog.text
        assert len(read_spool(spool_dir)) == 1

    def test_missing_ca_file_keeps_lines_and_log_loud(self, spool_dir: Path, cert_pair: tuple[str, str], caplog):
        """AC3 negative half (CA file, missing): same fail-safe via a path
        that does not exist (validator bypassed by direct mutation)."""
        log = AuditLogger(make_config(spool_dir), session_id="s1", client_cert=cert_pair)
        self._stop(log)
        log._config.remote_url = "https://sink.invalid/audit"
        log._config.ca_cert_path = str(spool_dir / "gone-ca.crt")
        log.emit("credential_injected", strategy="memfd")
        with caplog.at_level("WARNING", logger="venya.executor.audit"):
            assert log._forward_once() is False
        assert "Audit forward error" in caplog.text
        assert len(read_spool(spool_dir)) == 1
