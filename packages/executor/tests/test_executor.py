# Copyright (c) 2026 Tabith LLC.
# Use of this source code is governed by the Business Source License 1.1
# included in the LICENSE file at the root of this repository. As of the
# Change Date listed there, the work is available under MPL 2.0.
# SPDX-License-Identifier: BUSL-1.1

"""Tests for Executor.revoke_tokens(), _send_to_stage2(), and create_executor()."""

import os
import time
from pathlib import Path
from unittest.mock import MagicMock, patch

import httpx2
import pytest

from executor.command_validator import CommandValidator
from executor.config import CertificateRotationConfig, ExecutorConfig, MtlsConfig, ReaperConfig
from executor.daemon import DaemonState, ExecutorDaemon, ReaperLoop
from executor.executor import Executor

# --- Fixtures ---


@pytest.fixture()
def validator() -> CommandValidator:
    """Create a CommandValidator instance."""
    return CommandValidator()


@pytest.fixture()
def executor(validator: CommandValidator) -> Executor:
    """Create an Executor instance."""
    return Executor(
        command_validator=validator,
        session_id="test-session-123",
    )


@pytest.fixture()
def mock_http_client() -> httpx2.Client:
    """Create a mock httpx client."""
    client = MagicMock(spec=httpx2.Client)
    response = MagicMock(spec=httpx2.Response)
    response.status_code = 200
    response.json.return_value = {"revoked": True, "count": 2, "session_id": "test-session-123"}
    response.raise_for_status.return_value = None
    client.post.return_value = response
    return client


# --- Tests: revoke_tokens ---


class TestRevokeTokens:
    """Tests for Executor.revoke_tokens()."""

    def test_revoke_tokens_calls_server_api(self, executor: Executor, mock_http_client: httpx2.Client):
        """revoke_tokens calls POST /sessions/{session_id}/secrets/revoke."""
        executor.http_client = mock_http_client
        secret_ids = ["secret-1", "secret-2"]

        executor.revoke_tokens(secret_ids)

        mock_http_client.post.assert_called_once_with(
            "/api/v1/sessions/test-session-123/secrets/revoke",
            json={"secret_ids": secret_ids},
            timeout=10.0,
        )

    def test_revoke_tokens_logs_success(self, executor: Executor, mock_http_client: httpx2.Client, caplog):
        """revoke_tokens logs success on successful API call."""
        executor.http_client = mock_http_client
        caplog.set_level("INFO", logger="venya.executor")

        executor.revoke_tokens(["secret-1"])

        assert "Revoked tokens for 1 secrets" in caplog.text
        assert "test-session-123" in caplog.text

    def test_revoke_tokens_empty_list(self, executor: Executor, mock_http_client: httpx2.Client):
        """revoke_tokens does nothing with empty list."""
        executor.http_client = mock_http_client

        executor.revoke_tokens([])

        mock_http_client.post.assert_not_called()

    def test_revoke_tokens_no_client(self, executor: Executor, caplog):
        """revoke_tokens logs warning when no HTTP client is available."""
        executor.http_client = None
        caplog.set_level("WARNING", logger="venya.executor")

        executor.revoke_tokens(["secret-1"])

        assert "No HTTP client available" in caplog.text
        assert "skipping server token revocation" in caplog.text

    def test_revoke_tokens_server_error(self, executor: Executor, mock_http_client: httpx2.Client, caplog):
        """revoke_tokens logs error but doesn't raise on server failure."""
        mock_http_client.post.side_effect = httpx2.RequestError("Connection refused", request=MagicMock())
        executor.http_client = mock_http_client
        caplog.set_level("ERROR", logger="venya.executor")

        executor.revoke_tokens(["secret-1"])

        assert "Failed to revoke tokens" in caplog.text

    def test_revoke_tokens_emits_audit_event_on_failure(self, executor: Executor, mock_http_client: httpx2.Client):
        """revoke_tokens emits token_revocation_failed audit event on failure."""
        mock_http_client.post.side_effect = httpx2.RequestError("Connection refused", request=MagicMock())
        executor.http_client = mock_http_client

        # Create a mock audit logger
        mock_audit = MagicMock()
        executor.audit_logger = mock_audit

        executor.revoke_tokens(["secret-1", "secret-2"])

        # Verify audit event was emitted
        mock_audit.emit.assert_called_once_with(
            "token_revocation_failed",
            session_id="test-session-123",
            secret_ids=["secret-1", "secret-2"],
        )

    def test_revoke_tokens_no_audit_logger(self, executor: Executor, mock_http_client: httpx2.Client):
        """revoke_tokens handles missing audit logger gracefully."""
        mock_http_client.post.side_effect = httpx2.RequestError("Connection refused", request=MagicMock())
        executor.http_client = mock_http_client
        executor.audit_logger = None

        # Should not raise
        executor.revoke_tokens(["secret-1"])


# --- Tests: create_executor ---


class TestCreateExecutor:
    """Tests for ExecutorDaemon.create_executor()."""

    def test_create_executor_includes_http_client(self):
        """create_executor passes the mTLS client to Executor."""
        config = ExecutorConfig(
            server_url="https://example.com",
            executor_id="test-executor",
            mtls=MtlsConfig(
                ca_cert="/tmp/ca.crt",
                cert="/tmp/executor.crt",
                key="/tmp/executor.key",
            ),
            cert_rotation=CertificateRotationConfig(rotation_days=30),
        )

        daemon = ExecutorDaemon(config)

        # Manually set a mock client (simulating what start() does)
        daemon.client = MagicMock(spec=httpx2.Client)

        exec_instance = daemon.create_executor("session-abc")

        assert isinstance(exec_instance, Executor)
        assert exec_instance.session_id == "session-abc"
        assert exec_instance.http_client is daemon.client


# --- Tests: ReaperLoop ---


class TestReaperLoop:
    """Tests for ReaperLoop._check_orphaned()."""

    def _create_reaper(
        self,
        tmp_path: Path,
        secret_ttl_seconds: int = 300,
        check_interval: float = 1.0,
    ) -> ReaperLoop:
        """Create a ReaperLoop instance with a temporary tmpfs_dir."""
        tmpfs_dir = tmp_path / "venya-secrets"
        tmpfs_dir.mkdir()

        config = ExecutorConfig(
            reaper=ReaperConfig(
                secret_ttl_seconds=secret_ttl_seconds,
                check_interval=check_interval,
            ),
        )
        state = DaemonState()
        return ReaperLoop(config, state, tmpfs_dir=str(tmpfs_dir))

    def test_check_orphaned_no_files(self, tmp_path: Path):
        """Does nothing when no secret files exist."""
        reaper = self._create_reaper(tmp_path)

        reaper._check_orphaned()  # Should not raise

    def test_check_orphaned_new_files_not_orphaned(self, tmp_path: Path):
        """Does not delete files newer than TTL."""
        reaper = self._create_reaper(tmp_path, secret_ttl_seconds=300)
        tmpfs_dir = Path(reaper.tmpfs_dir)

        # Create a new file
        secret_file = tmpfs_dir / "venya_db-password_abc123.secret"
        secret_file.write_bytes(b"secret-value")

        reaper._check_orphaned()

        # File should still exist
        assert secret_file.exists()

    def test_check_orphaned_old_files_deleted(self, tmp_path: Path):
        """Deletes files older than TTL."""
        reaper = self._create_reaper(tmp_path, secret_ttl_seconds=1)
        tmpfs_dir = Path(reaper.tmpfs_dir)

        # Create an old file by backdating its mtime
        secret_file = tmpfs_dir / "venya_api-key_xyz789.secret"
        secret_file.write_bytes(b"secret-value")
        old_time = time.time() - 10  # 10 seconds ago
        os.utime(secret_file, (old_time, old_time))

        reaper._check_orphaned()

        # File should be deleted
        assert not secret_file.exists()

    def test_check_orphaned_non_venya_files_ignored(self, tmp_path: Path):
        """Does not touch files that don't match venya pattern."""
        reaper = self._create_reaper(tmp_path, secret_ttl_seconds=1)
        tmpfs_dir = Path(reaper.tmpfs_dir)

        # Create a non-venya file
        other_file = tmpfs_dir / "some_other_file.txt"
        other_file.write_bytes(b"not a secret")
        old_time = time.time() - 10
        os.utime(other_file, (old_time, old_time))

        reaper._check_orphaned()

        # File should still exist
        assert other_file.exists()

    def test_check_orphaned_revokes_tokens(self, tmp_path: Path):
        """Revokes tokens for orphaned secrets via server API."""
        mock_client = MagicMock(spec=httpx2.Client)
        response = MagicMock(spec=httpx2.Response)
        response.status_code = 200
        mock_client.post.return_value = response

        reaper = self._create_reaper(tmp_path, secret_ttl_seconds=1)
        reaper.http_client = mock_client
        reaper.session_id = "test-session-123"
        tmpfs_dir = Path(reaper.tmpfs_dir)

        # Create an old file
        secret_file = tmpfs_dir / "venya_db-password_abc123.secret"
        secret_file.write_bytes(b"secret-value")
        old_time = time.time() - 10
        os.utime(secret_file, (old_time, old_time))

        reaper._check_orphaned()

        # Should have called revoke endpoint
        mock_client.post.assert_called_once()
        call_args = mock_client.post.call_args
        assert "/api/v1/sessions/test-session-123/secrets/revoke" in call_args[0][0]
        # Secret ID extracted as parts[1] from "venya_db-password_abc123.secret"
        assert call_args[1]["json"]["secret_ids"] == ["db-password"]

    def test_check_orphaned_no_revocation_without_client(self, tmp_path: Path):
        """Does not attempt revocation when no HTTP client is available."""
        reaper = self._create_reaper(tmp_path, secret_ttl_seconds=1)
        reaper.http_client = None
        tmpfs_dir = Path(reaper.tmpfs_dir)

        secret_file = tmpfs_dir / "venya_api-key_xyz789.secret"
        secret_file.write_bytes(b"secret-value")
        old_time = time.time() - 10
        os.utime(secret_file, (old_time, old_time))

        reaper._check_orphaned()  # Should not raise

        # File should still be deleted
        assert not secret_file.exists()

    def test_check_orphaned_nonexistent_tmpfs_dir(self):
        """Does nothing when tmpfs_dir does not exist."""
        config = ExecutorConfig()
        state = DaemonState()
        reaper = ReaperLoop(config, state, tmpfs_dir="/tmp/nonexistent-venya-dir-12345")

        reaper._check_orphaned()  # Should not raise

    def test_check_orphaned_multiple_orphaned_files(self, tmp_path: Path):
        """Handles multiple orphaned files correctly."""
        mock_client = MagicMock(spec=httpx2.Client)
        response = MagicMock(spec=httpx2.Response)
        response.status_code = 200
        mock_client.post.return_value = response

        reaper = self._create_reaper(tmp_path, secret_ttl_seconds=1)
        reaper.http_client = mock_client
        reaper.session_id = "test-session"
        tmpfs_dir = Path(reaper.tmpfs_dir)

        # Create multiple old files
        for name in ["venya_secret1_abc.secret", "venya_secret2_def.secret", "venya_secret3_ghi.secret"]:
            f = tmpfs_dir / name
            f.write_bytes(b"data")
            old_time = time.time() - 10
            os.utime(f, (old_time, old_time))

        # Create one new file
        new_file = tmpfs_dir / "venya_secret4_jkl.secret"
        new_file.write_bytes(b"data")

        reaper._check_orphaned()

        # All old files should be deleted
        assert not (tmpfs_dir / "venya_secret1_abc.secret").exists()
        assert not (tmpfs_dir / "venya_secret2_def.secret").exists()
        assert not (tmpfs_dir / "venya_secret3_ghi.secret").exists()
        # New file should still exist
        assert new_file.exists()

        # Should have revoked tokens for 3 orphaned secrets
        call_args = mock_client.post.call_args
        assert len(call_args[1]["json"]["secret_ids"]) == 3


# --- Tests: _send_to_stage2 ---


class TestSendToStage2:
    """Tests for Executor._send_to_stage2()."""

    def _create_mock_response(
        self, stdout_data: bytes = b"filtered output", stderr_data: bytes = b"", masked_hashes: list[str] | None = None
    ):
        """Create a mock httpx response for Stage 2."""
        import base64

        response = MagicMock()
        response.status_code = 200
        response.json.return_value = {
            "stdout": base64.b64encode(stdout_data).decode(),
            "stderr": base64.b64encode(stderr_data).decode(),
            "masked_count": len(masked_hashes or []),
            "masked_hashes": masked_hashes or [],
        }
        response.raise_for_status.return_value = None
        return response

    def test_send_to_stage2_success(self, executor: Executor, mock_http_client: httpx2.Client):
        """_send_to_stage2 sends base64-encoded output and returns filtered result."""
        import base64

        executor.http_client = mock_http_client

        stdout = b"hello secret_value world"
        stderr = b""
        secret_entries = [{"secret_id": "test-secret", "value": b"secret_value"}]

        mock_response = self._create_mock_response(
            stdout_data=b"hello [REDACTED] world",
            stderr_data=b"",
            masked_hashes=["a1b2c3d4"],
        )
        mock_http_client.post.return_value = mock_response

        result_stdout, result_stderr, masked_ids = executor._send_to_stage2(stdout, stderr, secret_entries)

        # Verify payload sent to server
        call_args = mock_http_client.post.call_args
        assert call_args[0][0] == "/api/v1/sessions/test-session-123/filter"
        payload = call_args[1]["json"]
        assert payload["stdout"] == base64.b64encode(stdout).decode()
        assert payload["stderr"] == base64.b64encode(stderr).decode()
        assert payload["secrets"] == secret_entries
        assert call_args[1]["timeout"] == 30.0

        # Verify returned data
        assert result_stdout == b"hello [REDACTED] world"
        assert result_stderr == b""
        assert masked_ids == ["a1b2c3d4"]

    def test_send_to_stage2_parses_masked_hashes(self, executor: Executor, mock_http_client: httpx2.Client):
        """_send_to_stage2 deduplicates and sorts masked hashes."""
        executor.http_client = mock_http_client

        import base64

        mock_response = MagicMock()
        mock_response.json.return_value = {
            "stdout": base64.b64encode(b"output").decode(),
            "stderr": base64.b64encode(b"error").decode(),
            "masked_count": 3,
            "masked_hashes": ["c3d4e5f6", "a1b2c3d4", "a1b2c3d4"],
        }
        mock_http_client.post.return_value = mock_response

        _, _, masked_ids = executor._send_to_stage2(b"out", b"err", [])

        assert masked_ids == ["a1b2c3d4", "c3d4e5f6"]

    def test_send_to_stage2_empty_masked_hashes(self, executor: Executor, mock_http_client: httpx2.Client):
        """_send_to_stage2 handles missing masked_hashes gracefully."""
        executor.http_client = mock_http_client

        import base64

        mock_response = MagicMock()
        mock_response.json.return_value = {
            "stdout": base64.b64encode(b"output").decode(),
            "stderr": base64.b64encode(b"").decode(),
            "masked_count": 0,
            "masked_hashes": [],
        }
        mock_http_client.post.return_value = mock_response

        _, _, masked_ids = executor._send_to_stage2(b"out", b"", [])

        assert masked_ids == []

    def test_send_to_stage2_server_error_raises(self, executor: Executor, mock_http_client: httpx2.Client):
        """_send_to_stage2 raises on server connection failure."""
        executor.http_client = mock_http_client
        mock_http_client.post.side_effect = httpx2.RequestError("Connection refused", request=MagicMock())

        with pytest.raises(httpx2.RequestError):
            executor._send_to_stage2(b"out", b"err", [])


# --- Tests: _run_command Stage 2 integration ---


class TestRunCommandStage2:
    """Tests for Stage 2 integration in _run_command()."""

    def test_run_command_uses_stage2_results(self, executor: Executor):
        """_run_command uses Stage 2 output when server is available."""
        import base64

        # Mock subprocess
        mock_process = MagicMock()
        mock_process.stdin = MagicMock()
        mock_process.stdout = MagicMock()
        mock_process.stderr = MagicMock()
        mock_process.stdin.fileno.return_value = 3
        mock_process.stdout.fileno.return_value = 4
        mock_process.stderr.fileno.return_value = 5
        mock_process.stdin.__enter__ = MagicMock(return_value=mock_process.stdin)
        mock_process.stdin.__exit__ = MagicMock(return_value=False)
        mock_process.stdout.__enter__ = MagicMock(return_value=mock_process.stdout)
        mock_process.stdout.__exit__ = MagicMock(return_value=False)
        mock_process.stderr.__enter__ = MagicMock(return_value=mock_process.stderr)
        mock_process.stderr.__exit__ = MagicMock(return_value=False)

        # Stage 1 says 1 secret masked, Stage 2 says 2 secrets masked
        stage1_stdout = b"hello [REDACTED:x1x1x1x1] world"
        stage2_stdout = b"hello [REDACTED:x1x1x1x1] and [REDACTED:y2y2y2y2] world"

        with patch("executor.executor.subprocess.Popen", return_value=mock_process):
            with patch("executor.executor.filter_and_redact", return_value=(stage1_stdout, b"", ["x1x1x1x1"], [])):
                with patch("executor.executor.scan_open_fds", return_value=[0, 1, 2, 3, 4, 5]):
                    with patch("executor.executor.set_cloexec"):
                        with patch("executor.executor.verify_fd_whitelist", return_value=[]):
                            mock_response = MagicMock()
                            mock_response.json.return_value = {
                                "stdout": base64.b64encode(stage2_stdout).decode(),
                                "stderr": base64.b64encode(b"").decode(),
                                "masked_count": 2,
                                "masked_hashes": ["y2y2y2y2", "x1x1x1x1"],
                            }
                            executor.http_client = MagicMock()
                            executor.http_client.post.return_value = mock_response

                            injections = [
                                MagicMock(secret_id="s1", value=b"secret1"),
                                MagicMock(secret_id="s2", value=b"secret2"),
                            ]
                            result = executor._run_command_direct("echo test", injections, None, None)

        # Stage 2 output should be used
        assert result.stdout == stage2_stdout
        assert result.masked_secret_ids == ["x1x1x1x1", "y2y2y2y2"]

    def test_run_command_falls_back_to_stage1_on_stage2_failure(self, executor: Executor):
        """_run_command falls back to Stage 1 when Stage 2 fails."""
        stage1_stdout = b"hello [REDACTED:z1z1z1z1] world"

        mock_process = MagicMock()
        mock_process.stdin = MagicMock()
        mock_process.stdout = MagicMock()
        mock_process.stderr = MagicMock()
        mock_process.stdin.fileno.return_value = 3
        mock_process.stdout.fileno.return_value = 4
        mock_process.stderr.fileno.return_value = 5
        mock_process.stdin.__enter__ = MagicMock(return_value=mock_process.stdin)
        mock_process.stdin.__exit__ = MagicMock(return_value=False)
        mock_process.stdout.__enter__ = MagicMock(return_value=mock_process.stdout)
        mock_process.stdout.__exit__ = MagicMock(return_value=False)
        mock_process.stderr.__enter__ = MagicMock(return_value=mock_process.stderr)
        mock_process.stderr.__exit__ = MagicMock(return_value=False)

        with patch("executor.executor.subprocess.Popen", return_value=mock_process):
            with patch("executor.executor.filter_and_redact", return_value=(stage1_stdout, b"", ["z1z1z1z1"], [])):
                with patch("executor.executor.scan_open_fds", return_value=[0, 1, 2, 3, 4, 5]):
                    with patch("executor.executor.set_cloexec"):
                        with patch("executor.executor.verify_fd_whitelist", return_value=[]):
                            executor.http_client = MagicMock()
                            executor.http_client.post.side_effect = httpx2.RequestError(
                                "Connection refused", request=MagicMock()
                            )

                            injections = [MagicMock(secret_id="s1", value=b"secret1")]
                            result = executor._run_command_direct("echo test", injections, None, None)

        # Should fall back to Stage 1
        assert result.stdout == stage1_stdout
        assert result.masked_secret_ids == ["z1z1z1z1"]

    def test_run_command_skips_stage2_without_http_client(self, executor: Executor):
        """_run_command skips Stage 2 when no HTTP client is available."""
        stage1_stdout = b"hello [REDACTED:a1a1a1a1] world"

        mock_process = MagicMock()
        mock_process.stdin = MagicMock()
        mock_process.stdout = MagicMock()
        mock_process.stderr = MagicMock()
        mock_process.stdin.fileno.return_value = 3
        mock_process.stdout.fileno.return_value = 4
        mock_process.stderr.fileno.return_value = 5
        mock_process.stdin.__enter__ = MagicMock(return_value=mock_process.stdin)
        mock_process.stdin.__exit__ = MagicMock(return_value=False)
        mock_process.stdout.__enter__ = MagicMock(return_value=mock_process.stdout)
        mock_process.stdout.__exit__ = MagicMock(return_value=False)
        mock_process.stderr.__enter__ = MagicMock(return_value=mock_process.stderr)
        mock_process.stderr.__exit__ = MagicMock(return_value=False)

        with patch("executor.executor.subprocess.Popen", return_value=mock_process):
            with patch("executor.executor.filter_and_redact", return_value=(stage1_stdout, b"", ["a1a1a1a1"], [])):
                with patch("executor.executor.scan_open_fds", return_value=[0, 1, 2, 3, 4, 5]):
                    with patch("executor.executor.set_cloexec"):
                        with patch("executor.executor.verify_fd_whitelist", return_value=[]):
                            executor.http_client = None

                            injections = [MagicMock(secret_id="s1", value=b"secret1")]
                            result = executor._run_command_direct("echo test", injections, None, None)

        # Should use Stage 1 results directly
        assert result.stdout == stage1_stdout
        assert result.masked_secret_ids == ["a1a1a1a1"]
