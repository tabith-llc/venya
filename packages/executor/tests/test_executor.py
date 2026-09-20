# Copyright (c) 2026 Tabith LLC.
# Use of this source code is governed by the Business Source License 1.1
# included in the LICENSE file at the root of this repository. As of the
# Change Date listed there, the work is available under MPL 2.0.
# SPDX-License-Identifier: BUSL-1.1

"""Tests for Executor.revoke_tokens(), _send_to_stage2(), and create_executor()."""

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
            cert_rotation=CertificateRotationConfig(rotate_before_days=3),
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
    """Tests for ReaperLoop._check_orphaned() — layout-independent edges only.

    The sbx-layout orphan behavior (session_<id>_<rand> dirs: aged deletion,
    per-session revocation, TTL, foreign entries, failure tolerance) lives in
    test_daemon_loop.py::TestReaperOrphanCleanup. The legacy flat
    venya_*.secret file tests were removed together with the layout they
    pinned — that scan matched nothing under the sbx writer (ticket
    daemon-reaper-phantom-session).
    """

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
        """Does nothing when the base dir is empty."""
        reaper = self._create_reaper(tmp_path)

        reaper._check_orphaned()  # Should not raise

    def test_check_orphaned_nonexistent_tmpfs_dir(self):
        """Does nothing when the base dir does not exist."""
        config = ExecutorConfig(reaper=ReaperConfig(secret_ttl_seconds=1))
        state = DaemonState()
        reaper = ReaperLoop(config, state, tmpfs_dir="/nonexistent/venya-secrets-test")

        reaper._check_orphaned()  # Should not raise


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

        mock_response = self._create_mock_response(
            stdout_data=b"hello [REDACTED] world",
            stderr_data=b"",
            masked_hashes=["a1b2c3d4"],
        )
        mock_http_client.post.return_value = mock_response

        result_stdout, result_stderr, masked_ids = executor._send_to_stage2(stdout, stderr)

        # Verify payload sent to server
        call_args = mock_http_client.post.call_args
        assert call_args[0][0] == "/api/v1/sessions/test-session-123/filter"
        payload = call_args[1]["json"]
        assert payload["stdout"] == base64.b64encode(stdout).decode()
        assert payload["stderr"] == base64.b64encode(stderr).decode()
        # dead `secrets` field deleted (ticket executor-stage2-plaintext-signoff)
        assert "secrets" not in payload
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

        _, _, masked_ids = executor._send_to_stage2(b"out", b"err")

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

        _, _, masked_ids = executor._send_to_stage2(b"out", b"")

        assert masked_ids == []

    def test_send_to_stage2_server_error_raises(self, executor: Executor, mock_http_client: httpx2.Client):
        """_send_to_stage2 raises on server connection failure."""
        executor.http_client = mock_http_client
        mock_http_client.post.side_effect = httpx2.RequestError("Connection refused", request=MagicMock())

        with pytest.raises(httpx2.RequestError):
            executor._send_to_stage2(b"out", b"err")


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


class TestEnvCwdThreadThrough:
    """Executor-level matrix for env_override/cwd (ticket
    executor-env-override-cwd-sbx-noop): the sbx path must forward both to
    the strategy, and the direct path must keep honoring them — consistent,
    documented behavior on both paths, not works-on-one/no-ops-on-other."""

    def _executor_with_mock_sbx(self):
        from executor.executor import Executor
        from executor.strategies.sbx_strategy import SbxStrategy

        strategy = MagicMock(spec=SbxStrategy)
        strategy.name.return_value = "sbx"
        strategy.execute_command.return_value = MagicMock(returncode=0, stdout=b"ok", stderr=b"")
        ex = Executor(command_validator=MagicMock(), session_id="s-thread", injection_strategy=strategy)
        ex.http_client = None
        return ex, strategy

    def test_sbx_path_forwards_env_and_cwd(self):
        ex, strategy = self._executor_with_mock_sbx()
        with patch("executor.executor.filter_and_redact", side_effect=lambda o, e, s: (o, e, [], [])):
            ex._run_command_sbx("cmd", [], env_override={"A": "1"}, cwd="/work")
        kwargs = strategy.execute_command.call_args
        assert kwargs[0][0] == "cmd"
        assert kwargs[1]["env_override"] == {"A": "1"}
        assert kwargs[1]["cwd"] == "/work"
        # cwd also feeds the workspace mount at create time (coherent dual role)
        assert strategy.create_sandbox.call_args[0][1] == "/work"

    def test_sbx_path_defaults_none(self):
        ex, strategy = self._executor_with_mock_sbx()
        with patch("executor.executor.filter_and_redact", side_effect=lambda o, e, s: (o, e, [], [])):
            ex._run_command_sbx("cmd", [], None, None)
        kwargs = strategy.execute_command.call_args
        assert kwargs[1]["env_override"] is None
        assert kwargs[1]["cwd"] is None

    def test_direct_path_honors_env_and_cwd(self):
        """Matrix other half: direct/memfd path passes env + cwd to Popen."""
        from executor.executor import Executor

        ex = Executor(command_validator=MagicMock(), session_id="s-direct")
        ex.http_client = None
        ex._injection_result = None
        mock_process = MagicMock()
        mock_process.stdin.fileno.return_value = 3
        mock_process.stdout.fileno.return_value = 4
        mock_process.stderr.fileno.return_value = 5
        mock_process.wait.return_value = 0
        mock_process.returncode = 0
        with patch("executor.executor.subprocess.Popen", return_value=mock_process) as popen:
            with patch("executor.executor.select.select", return_value=([], [], [])):
                with patch("executor.executor.scan_open_fds", return_value=[0, 1, 2]):
                    with patch("executor.executor.set_cloexec"):
                        with patch("executor.executor.verify_fd_whitelist", return_value=[]):
                            with patch(
                                "executor.executor.filter_and_redact", side_effect=lambda o, e, s: (o, e, [], [])
                            ):
                                ex._run_command_direct("ls", [], env_override={"FOO": "bar"}, cwd="/tmp")
        env = popen.call_args[1]["env"]
        assert env["FOO"] == "bar"
        assert popen.call_args[1]["cwd"] == "/tmp"


class TestSbxTruncationAccounting:
    """Ticket executor-sbx-truncation-accounting-wrong: oversized sandbox
    output must report output_truncated=True and the true pre-slice sizes.
    Previously both were derived from the already-sliced payload, so the sbx
    path structurally always reported False / post-slice sizes."""

    def _executor_with_output(self, stdout: bytes, stderr: bytes = b""):
        from executor.strategies.sbx_strategy import SbxStrategy

        strategy = MagicMock(spec=SbxStrategy)
        strategy.execute_command.return_value = MagicMock(returncode=0, stdout=stdout, stderr=stderr)
        ex = Executor(command_validator=MagicMock(), session_id="s-trunc", injection_strategy=strategy)
        ex.http_client = None
        return ex

    def _run_sbx(self, ex: Executor):
        with patch("executor.executor.filter_and_redact", side_effect=lambda o, e, s: (o, e, [], [])):
            return ex._run_command_sbx("cmd", [], None, None)

    def test_oversized_stdout_reports_truncated_and_true_size(self):
        from executor.executor import MAX_OUTPUT_BYTES

        true_size = MAX_OUTPUT_BYTES + 4096
        result = self._run_sbx(self._executor_with_output(b"x" * true_size))

        assert result.output_truncated is True
        assert result.original_stdout_size == true_size
        assert len(result.stdout) == MAX_OUTPUT_BYTES

    def test_oversized_stderr_reports_truncated_and_true_size(self):
        from executor.executor import MAX_OUTPUT_BYTES

        true_size = MAX_OUTPUT_BYTES + 1
        result = self._run_sbx(self._executor_with_output(b"out", b"e" * true_size))

        assert result.output_truncated is True
        assert result.original_stderr_size == true_size
        assert result.original_stdout_size == 3
        assert len(result.stderr) == MAX_OUTPUT_BYTES

    def test_under_limit_not_truncated_true_sizes(self):
        """Negative half: under-cap output keeps False flag and exact sizes."""
        result = self._run_sbx(self._executor_with_output(b"x" * 100, b"y" * 50))

        assert result.output_truncated is False
        assert result.original_stdout_size == 100
        assert result.original_stderr_size == 50

    def test_direct_path_threads_capture_totals(self):
        """_run_command_direct wiring: the true totals from _capture_output
        reach CommandResult, not the post-slice payload lengths."""
        from executor.executor import MAX_OUTPUT_BYTES

        ex = Executor(command_validator=MagicMock(), session_id="s-direct-trunc")
        ex.http_client = None
        ex._injection_result = None
        mock_process = MagicMock()
        mock_process.stdin.fileno.return_value = 3
        mock_process.stdout.fileno.return_value = 4
        mock_process.stderr.fileno.return_value = 5
        mock_process.wait.return_value = 0
        with patch("executor.executor.subprocess.Popen", return_value=mock_process):
            with patch.object(Executor, "_capture_output", return_value=(b"x" * 1000, b"", MAX_OUTPUT_BYTES + 999, 0)):
                with patch("executor.executor.scan_open_fds", return_value=[0, 1, 2]):
                    with patch("executor.executor.set_cloexec"):
                        with patch("executor.executor.verify_fd_whitelist", return_value=[]):
                            with patch(
                                "executor.executor.filter_and_redact", side_effect=lambda o, e, s: (o, e, [], [])
                            ):
                                result = ex._run_command_direct("ls", [], None, None)

        assert result.output_truncated is True
        assert result.original_stdout_size == MAX_OUTPUT_BYTES + 999
        assert result.original_stderr_size == 0
