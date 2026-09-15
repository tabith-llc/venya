# Copyright (c) 2026 Tabith LLC.
# Use of this source code is governed by the Business Source License 1.1
# included in the LICENSE file at the root of this repository. As of the
# Change Date listed there, the work is available under MPL 2.0.
# SPDX-License-Identifier: BUSL-1.1

"""Tests for ReaperLoop thread lifecycle and ExecutorDaemon signal handling.

Tests ReaperLoop.start()/stop(), _run() loop behavior, and ExecutorDaemon
methods: _main_loop(), _send_heartbeat(), _handle_signal(), stop(),
_write_pidfile(), _remove_pidfile().
"""

import os
import signal
import time
from datetime import UTC
from pathlib import Path
from unittest.mock import MagicMock, patch

import httpx2
import pytest
from cryptography.hazmat.primitives import hashes

from executor.config import ExecutorConfig, ReaperConfig
from executor.daemon import DaemonState, ExecutorDaemon, ReaperLoop

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture()
def config() -> ExecutorConfig:
    return ExecutorConfig(
        server_url="https://example.com",
        executor_id="test-executor",
        reaper=ReaperConfig(check_interval=0.1, secret_ttl_seconds=1),
    )


@pytest.fixture()
def state() -> DaemonState:
    return DaemonState()


@pytest.fixture()
def tmpfs_dir(tmp_path: Path) -> Path:
    d = tmp_path / "venya-secrets"
    d.mkdir()
    return d


# ---------------------------------------------------------------------------
# ReaperLoop thread lifecycle
# ---------------------------------------------------------------------------


class TestReaperLoopLifecycle:
    """Tests for ReaperLoop.start() and stop()."""

    def test_start_creates_and_starts_thread(self, config: ExecutorConfig, state: DaemonState, tmpfs_dir: Path):
        """start() creates a daemon thread and starts it."""
        reaper = ReaperLoop(config, state, tmpfs_dir=str(tmpfs_dir))

        reaper.start()
        time.sleep(0.2)  # Give thread time to start

        assert reaper._thread is not None
        assert reaper._thread.is_alive()
        assert reaper._thread.daemon is True
        assert reaper._thread.name == "venya-reaper"

        reaper.stop()

    def test_stop_terminates_thread(self, config: ExecutorConfig, state: DaemonState, tmpfs_dir: Path):
        """stop() sets the stop event and joins the thread."""
        reaper = ReaperLoop(config, state, tmpfs_dir=str(tmpfs_dir))

        reaper.start()
        time.sleep(0.2)
        assert reaper._thread.is_alive()

        reaper.stop()
        assert not reaper._thread.is_alive()

    def test_stop_without_start(self, config: ExecutorConfig, state: DaemonState, tmpfs_dir: Path):
        """stop() without start() does not raise."""
        reaper = ReaperLoop(config, state, tmpfs_dir=str(tmpfs_dir))

        reaper.stop()  # Should not raise

    def test_start_clears_stop_event(self, config: ExecutorConfig, state: DaemonState, tmpfs_dir: Path):
        """start() clears the stop event for restart."""
        reaper = ReaperLoop(config, state, tmpfs_dir=str(tmpfs_dir))

        reaper.start()
        time.sleep(0.2)
        reaper.stop()

        # Restart should work
        reaper.start()
        time.sleep(0.2)
        assert reaper._thread.is_alive()
        reaper.stop()

    def test_run_loop_checks_orphaned_each_iteration(self, config: ExecutorConfig, state: DaemonState, tmpfs_dir: Path):
        """_run() calls _check_orphaned on each iteration."""
        reaper = ReaperLoop(config, state, tmpfs_dir=str(tmpfs_dir))

        with patch.object(reaper, "_check_orphaned") as mock_check:
            reaper.start()
            time.sleep(0.5)  # Should run at least a couple iterations (interval=0.1)
            reaper.stop()

            assert mock_check.call_count >= 1

    def test_run_loop_exits_on_stop_event(self, config: ExecutorConfig, state: DaemonState, tmpfs_dir: Path):
        """_run() exits when stop event is set."""
        reaper = ReaperLoop(config, state, tmpfs_dir=str(tmpfs_dir))

        reaper.start()
        time.sleep(0.15)
        reaper.stop()

        # Thread should have exited
        assert not reaper._thread.is_alive()

    def test_run_loop_catches_exceptions(self, config: ExecutorConfig, state: DaemonState, tmpfs_dir: Path):
        """_run() catches exceptions in _check_orphaned and continues."""
        reaper = ReaperLoop(config, state, tmpfs_dir=str(tmpfs_dir))

        call_count = [0]

        def fail_once():
            call_count[0] += 1
            if call_count[0] == 1:
                raise RuntimeError("Test error")

        with patch.object(reaper, "_check_orphaned", side_effect=fail_once):
            reaper.start()
            time.sleep(0.5)  # Should continue after exception
            reaper.stop()

            # Should have been called at least twice (exception + recovery)
            assert call_count[0] >= 2


# ---------------------------------------------------------------------------
# ExecutorDaemon._send_heartbeat
# ---------------------------------------------------------------------------


class TestSendHeartbeat:
    """Tests for ExecutorDaemon._send_heartbeat()."""

    def test_heartbeat_sends_fingerprint(self, config: ExecutorConfig, tmp_path: Path):
        """_send_heartbeat posts fingerprint to server."""

        # Create a real cert so get_fingerprint returns non-empty
        from executor.daemon import _create_csr, _generate_ecdsa_p256_keypair

        key = _generate_ecdsa_p256_keypair()
        _create_csr(key, "test-exec")

        # Create a self-signed cert for testing
        from datetime import datetime, timedelta

        from cryptography import x509
        from cryptography.x509.oid import NameOID

        now = datetime.now(UTC)
        subject = x509.Name(
            [
                x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Venya"),
                x509.NameAttribute(NameOID.COMMON_NAME, "test-exec"),
            ]
        )
        test_cert = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(subject)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now)
            .not_valid_after(now + timedelta(days=30))
            .sign(key, hashes.SHA256())
        )

        cert_path = str(tmp_path / "executor.crt")
        key_path = str(tmp_path / "executor.key")
        ca_path = str(tmp_path / "ca.crt")

        from cryptography.hazmat.primitives import serialization

        Path(cert_path).write_bytes(test_cert.public_bytes(serialization.Encoding.PEM))
        Path(key_path).write_bytes(
            key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption(),
            )
        )
        Path(ca_path).write_bytes(test_cert.public_bytes(serialization.Encoding.PEM))

        config.mtls.cert = cert_path
        config.mtls.key = key_path
        config.mtls.ca_cert = ca_path

        daemon = ExecutorDaemon(config)
        daemon.client = MagicMock(spec=httpx2.Client)

        daemon._send_heartbeat()

        daemon.client.post.assert_called_once()
        call_args = daemon.client.post.call_args
        assert call_args[0][0] == "/api/v1/heartbeat"
        payload = call_args[1]["json"]
        assert payload["executor_id"] == "test-executor"
        assert len(payload["cert_fingerprint"]) == 64  # SHA-256 hex

    def test_heartbeat_handles_connection_error(self, config: ExecutorConfig):
        """_send_heartbeat logs debug on connection error, does not raise."""
        daemon = ExecutorDaemon(config)
        daemon.client = MagicMock(spec=httpx2.Client)
        daemon.client.post.side_effect = httpx2.RequestError("Connection refused", request=MagicMock())

        # Should not raise
        daemon._send_heartbeat()

    def test_heartbeat_with_no_cert(self, config: ExecutorConfig):
        """_send_heartbeat sends empty fingerprint when no cert exists."""
        daemon = ExecutorDaemon(config)
        daemon.client = MagicMock(spec=httpx2.Client)

        daemon._send_heartbeat()

        daemon.client.post.assert_called_once()
        payload = daemon.client.post.call_args[1]["json"]
        assert payload["cert_fingerprint"] == ""


# ---------------------------------------------------------------------------
# ExecutorDaemon._handle_signal
# ---------------------------------------------------------------------------


class TestHandleSignal:
    """Tests for ExecutorDaemon._handle_signal()."""

    def test_handle_signal_sets_running_false(self, config: ExecutorConfig):
        """_handle_signal sets state.running to False."""
        daemon = ExecutorDaemon(config)
        daemon.state.running = True

        daemon._handle_signal(signal.SIGTERM, None)

        assert daemon.state.running is False

    def test_handle_signal_sets_shutdown_event(self, config: ExecutorConfig):
        """_handle_signal sets the shutdown event."""
        daemon = ExecutorDaemon(config)
        daemon._shutdown_event.clear()

        daemon._handle_signal(signal.SIGTERM, None)

        assert daemon._shutdown_event.is_set()

    def test_handle_signal_logs(self, config: ExecutorConfig, caplog):
        """_handle_signal logs the received signal."""
        caplog.set_level("INFO", logger="venya.executor.daemon")

        daemon = ExecutorDaemon(config)
        daemon._handle_signal(signal.SIGTERM, None)

        assert "SIGTERM" in caplog.text
        assert "shutdown" in caplog.text.lower()

    def test_handle_signal_sigint(self, config: ExecutorConfig):
        """_handle_signal works with SIGINT."""
        daemon = ExecutorDaemon(config)
        daemon.state.running = True

        daemon._handle_signal(signal.SIGINT, None)

        assert daemon.state.running is False
        assert daemon._shutdown_event.is_set()


# ---------------------------------------------------------------------------
# ExecutorDaemon._write_pidfile / _remove_pidfile
# ---------------------------------------------------------------------------


class TestPidfile:
    """Tests for PID file management."""

    def test_write_pidfile(self, tmp_path: Path, config: ExecutorConfig):
        """_write_pidfile creates PID file with current PID."""
        daemon = ExecutorDaemon(config)
        daemon.config.pid_file = str(tmp_path / "executor.pid")

        daemon._write_pidfile()

        pid_file = Path(daemon.config.pid_file)
        assert pid_file.exists()
        assert pid_file.read_text() == str(os.getpid())

    def test_write_pidfile_creates_parent_dirs(self, tmp_path: Path, config: ExecutorConfig):
        """_write_pidfile creates parent directories if needed."""
        daemon = ExecutorDaemon(config)
        daemon.config.pid_file = str(tmp_path / "nested" / "deep" / "executor.pid")

        daemon._write_pidfile()

        assert Path(daemon.config.pid_file).exists()

    def test_remove_pidfile(self, tmp_path: Path, config: ExecutorConfig):
        """_remove_pidfile removes the PID file."""
        daemon = ExecutorDaemon(config)
        daemon.config.pid_file = str(tmp_path / "executor.pid")

        daemon._write_pidfile()
        assert Path(daemon.config.pid_file).exists()

        daemon._remove_pidfile()
        assert not Path(daemon.config.pid_file).exists()

    def test_remove_pidfile_missing(self, config: ExecutorConfig):
        """_remove_pidfile does not raise if file doesn't exist."""
        daemon = ExecutorDaemon(config)
        daemon.config.pid_file = "/tmp/nonexistent-venya-pid-12345.pid"

        daemon._remove_pidfile()  # Should not raise

    def test_remove_pidfile_nonexistent(self, tmp_path: Path, config: ExecutorConfig):
        """_remove_pidfile does not raise for already-deleted file."""
        daemon = ExecutorDaemon(config)
        daemon.config.pid_file = str(tmp_path / "executor.pid")

        daemon._write_pidfile()
        os.unlink(daemon.config.pid_file)

        daemon._remove_pidfile()  # Should not raise


# ---------------------------------------------------------------------------
# ExecutorDaemon.stop()
# ---------------------------------------------------------------------------


class TestDaemonStop:
    """Tests for ExecutorDaemon.stop()."""

    def test_stop_stops_reaper(self, config: ExecutorConfig, tmpfs_dir: Path):
        """stop() stops the reaper loop."""
        daemon = ExecutorDaemon(config)
        daemon.reaper.tmpfs_dir = str(tmpfs_dir)
        daemon.client = MagicMock(spec=httpx2.Client)
        daemon.reaper.start()
        time.sleep(0.2)
        assert daemon.reaper._thread.is_alive()

        daemon.stop()

        assert not daemon.reaper._thread.is_alive()

    def test_stop_closes_client(self, config: ExecutorConfig):
        """stop() closes the HTTP client."""
        daemon = ExecutorDaemon(config)
        daemon.client = MagicMock(spec=httpx2.Client)

        daemon.stop()

        daemon.client.close.assert_called_once()

    def test_stop_removes_pidfile(self, tmp_path: Path, config: ExecutorConfig):
        """stop() removes the PID file."""
        daemon = ExecutorDaemon(config)
        daemon.config.pid_file = str(tmp_path / "executor.pid")
        daemon.client = MagicMock(spec=httpx2.Client)

        daemon._write_pidfile()
        daemon.stop()

        assert not Path(daemon.config.pid_file).exists()

    def test_stop_logs(self, config: ExecutorConfig, caplog):
        """stop() logs start and completion."""
        caplog.set_level("INFO", logger="venya.executor.daemon")

        daemon = ExecutorDaemon(config)
        daemon.client = MagicMock(spec=httpx2.Client)

        daemon.stop()

        assert "Stopping executor daemon" in caplog.text
        assert "Executor daemon stopped" in caplog.text


# ---------------------------------------------------------------------------
# ExecutorDaemon._main_loop
# ---------------------------------------------------------------------------


class TestMainLoop:
    """Tests for ExecutorDaemon._main_loop()."""

    def test_main_loop_exits_when_revoked(self, config: ExecutorConfig):
        """_main_loop() exits when check_revocation returns True."""
        daemon = ExecutorDaemon(config)
        daemon.client = MagicMock(spec=httpx2.Client)
        daemon.state.running = True

        with patch.object(daemon.cert_manager, "needs_rotation", return_value=False):
            with patch.object(daemon.cert_manager, "check_revocation", return_value=True):
                with patch.object(daemon, "_send_heartbeat"):
                    with patch.object(daemon._shutdown_event, "wait", return_value=False):
                        daemon._main_loop()

        assert daemon.state.revoked is True

    def test_main_loop_exits_when_stopped(self, config: ExecutorConfig):
        """_main_loop() exits when state.running is False."""
        daemon = ExecutorDaemon(config)
        daemon.client = MagicMock(spec=httpx2.Client)

        # Set running to False immediately — loop should not enter
        with patch.object(daemon.cert_manager, "needs_rotation", return_value=False):
            with patch.object(daemon.cert_manager, "check_revocation", return_value=False):
                with patch.object(daemon._shutdown_event, "wait", return_value=False):
                    daemon._main_loop()

        # Loop should exit immediately without calling heartbeat
        with patch.object(daemon, "_send_heartbeat") as mock_hb:
            daemon.state.running = False
            daemon._main_loop()
        mock_hb.assert_not_called()

    def test_main_loop_sends_heartbeat(self, config: ExecutorConfig):
        """_main_loop() calls _send_heartbeat each iteration."""
        daemon = ExecutorDaemon(config)
        daemon.client = MagicMock(spec=httpx2.Client)
        daemon.state.running = True

        call_count = [0]

        def set_running_false():
            call_count[0] += 1
            if call_count[0] >= 2:
                daemon.state.running = False

        with patch.object(daemon.cert_manager, "needs_rotation", return_value=False):
            with patch.object(daemon.cert_manager, "check_revocation", return_value=False):
                with patch.object(daemon, "_send_heartbeat", side_effect=set_running_false):
                    with patch.object(daemon._shutdown_event, "wait", return_value=False):
                        daemon._main_loop()

        assert call_count[0] >= 2

    def test_main_loop_rotates_cert_when_needed(self, config: ExecutorConfig):
        """_main_loop() rotates certificate when needs_rotation returns True."""
        daemon = ExecutorDaemon(config)
        daemon.client = MagicMock(spec=httpx2.Client)
        daemon.state.running = True

        rotate_called = [False]

        def do_rotate():
            rotate_called[0] = True
            daemon.state.running = False

        with patch.object(daemon.cert_manager, "needs_rotation", return_value=True):
            with patch.object(daemon.cert_manager, "rotate", side_effect=do_rotate):
                with patch.object(daemon.cert_manager, "check_revocation", return_value=False):
                    with patch.object(daemon, "_send_heartbeat"):
                        with patch.object(daemon._shutdown_event, "wait", return_value=False):
                            daemon._main_loop()

        assert rotate_called[0] is True
