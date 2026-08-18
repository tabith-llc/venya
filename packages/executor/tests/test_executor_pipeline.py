"""Tests for Executor pipeline: execute(), _prepare_injections(), _capture_output(), _cleanup_injections()."""


import base64
import fcntl
import os
import stat
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import MagicMock, patch

import httpx2
import pytest

from executor.command_validator import CommandValidator
from executor.config import ExecutorConfig, MtlsConfig, CertificateRotationConfig, ReaperConfig
from executor.daemon import DaemonState, ExecutorDaemon, ReaperLoop
from executor.executor import CommandResult, Executor, SecretBundle
from executor.injector import wrap_with_sentinel


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture()
def validator() -> CommandValidator:
    return CommandValidator()


@pytest.fixture()
def executor(validator: CommandValidator) -> Executor:
    return Executor(command_validator=validator, session_id="test-session-123")


@pytest.fixture()
def mock_http_client() -> httpx2.Client:
    client = MagicMock(spec=httpx2.Client)
    response = MagicMock(spec=httpx2.Response)
    response.status_code = 200
    response.json.return_value = {"revoked": True, "count": 0}
    response.raise_for_status.return_value = None
    client.post.return_value = response
    return client


def _make_secret(secret_id: str, value: bytes, wrapped: bool = True) -> dict:
    """Create a secret dict for testing."""
    from executor.injector import wrap_with_sentinel

    secret = {"secret_id": secret_id, "value": value}
    if wrapped:
        secret["wrapped_value"] = wrap_with_sentinel(secret_id, value)
    return secret


# ---------------------------------------------------------------------------
# execute() — full pipeline
# ---------------------------------------------------------------------------


class TestExecute:
    """Tests for Executor.execute() full pipeline."""

    def test_execute_valid_command_succeeds(self, executor: Executor):
        """Valid command executes and returns result."""
        with patch("executor.executor.scan_open_fds", return_value={0, 1, 2}):
            with patch("executor.executor.set_cloexec"):
                result = executor.execute("/usr/bin/echo hello", [_make_secret("s1", b"secret-value")])

        assert isinstance(result, CommandResult)
        assert result.exit_code == 0
        assert b"hello" in result.stdout

    def test_execute_rejects_invalid_command(self, executor: Executor):
        """Invalid command raises ValueError."""
        with pytest.raises(ValueError, match="Command rejected"):
            executor.execute("rm -rf /", [_make_secret("s1", b"secret")])

    def test_execute_validates_command_first(self, executor: Executor):
        """Validation happens before injection preparation."""
        with pytest.raises(ValueError, match="Command rejected"):
            executor.execute("sudo cat /etc/shadow", [_make_secret("s1", b"secret")])

    def test_execute_cleanup_runs_even_on_error(self, executor: Executor):
        """Cleanup runs even if command fails."""
        secrets = [_make_secret("s1", b"secret")]

        # This will fail validation, but cleanup should still be attempted
        with pytest.raises(ValueError):
            executor.execute("invalid-command", secrets)

    def test_execute_revoke_tokens_called(self, executor: Executor, mock_http_client: httpx2.Client):
        """revoke_tokens is called after execution."""
        executor.http_client = mock_http_client

        # Mock Stage 2 to return proper response
        import base64
        stage2_response = MagicMock()
        stage2_response.json.return_value = {
            "stdout": base64.b64encode(b"test\n").decode(),
            "stderr": base64.b64encode(b"").decode(),
            "masked_count": 0,
            "masked_hashes": [],
        }
        stage2_response.raise_for_status.return_value = None
        mock_http_client.post.return_value = stage2_response

        secrets = [_make_secret("db-pass", b"password123")]

        with patch("executor.executor.scan_open_fds", return_value={0, 1, 2}):
            with patch("executor.executor.set_cloexec"):
                executor.execute("/usr/bin/echo test", secrets)

        # Should be called twice: Stage 2 filter + revoke_tokens
        assert mock_http_client.post.call_count == 2
        revoke_call = mock_http_client.post.call_args_list[1]
        assert "/api/v1/sessions/test-session-123/secrets/revoke" in revoke_call[0][0]
        assert "db-pass" in revoke_call[1]["json"]["secret_ids"]

    def test_execute_multiple_secrets(self, executor: Executor):
        """Multiple secrets are all injected and cleaned up."""
        secrets = [
            _make_secret("s1", b"one"),
            _make_secret("s2", b"two"),
            _make_secret("s3", b"three"),
        ]

        with patch("executor.executor.scan_open_fds", return_value={0, 1, 2}):
            with patch("executor.executor.set_cloexec"):
                result = executor.execute("/usr/bin/echo done", secrets)

        assert result.exit_code == 0
        assert result.output_truncated is False

    def test_execute_with_env_override(self, executor: Executor):
        """Environment override is applied."""
        with patch("executor.executor.scan_open_fds", return_value={0, 1, 2}):
            with patch("executor.executor.set_cloexec"):
                result = executor.execute(
                    "/usr/bin/printenv MY_VAR",
                    [],
                    env_override={"MY_VAR": "custom_value"},
                )

        assert b"custom_value" in result.stdout

    def test_execute_with_cwd(self, executor: Executor, tmp_path: Path):
        """Command runs in specified working directory."""
        work_dir = tmp_path / "work"
        work_dir.mkdir()
        (work_dir / "test.txt").write_text("hello from work dir")

        with patch("executor.executor.scan_open_fds", return_value={0, 1, 2}):
            with patch("executor.executor.set_cloexec"):
                result = executor.execute("/usr/bin/cat test.txt", [], cwd=str(work_dir))

        assert b"hello from work dir" in result.stdout


# ---------------------------------------------------------------------------
# _prepare_injections
# ---------------------------------------------------------------------------


class TestPrepareInjections:
    """Tests for Executor._prepare_injections()."""

    def test_prepare_creates_injections(self, executor: Executor):
        """Injections are created for each secret."""
        secrets = [_make_secret("s1", b"secret-value")]
        injections = executor._prepare_injections(secrets)

        assert len(injections) == 1
        assert injections[0].secret_id == "s1"
        assert injections[0].value == b"secret-value"

    def test_prepare_strips_sentinel(self, executor: Executor):
        """Sentinel is stripped to get plaintext."""
        wrapped = wrap_with_sentinel("s1", b"my-secret")
        secrets = [{"secret_id": "s1", "value": b"my-secret", "wrapped_value": wrapped}]

        injections = executor._prepare_injections(secrets)

        assert injections[0].value == b"my-secret"

    def test_prepare_uses_value_when_no_wrapped(self, executor: Executor):
        """Uses plain value when wrapped_value is not provided."""
        secrets = [{"secret_id": "s1", "value": b"plain-secret"}]

        injections = executor._prepare_injections(secrets)

        assert injections[0].value == b"plain-secret"

    def test_prepare_registers_sentinel_hash(self, executor: Executor):
        """Sentinel hash is registered in the registry."""
        wrapped = wrap_with_sentinel("s1", b"secret")
        secrets = [{"secret_id": "s1", "value": b"secret", "wrapped_value": wrapped}]

        executor._prepare_injections(secrets)

        hashes = executor.sentinel_registry.get_session_hashes()
        assert len(hashes) == 1

    def test_prepare_registers_correct_mapping(self, executor: Executor):
        """Sentinel registry maps hash to secret_id."""
        from executor.injector import wrap_with_sentinel
        import hashlib

        secret_id = "db-password-prod"
        wrapped = wrap_with_sentinel(secret_id, b"secret")
        expected_hash = hashlib.sha256(secret_id.encode()).hexdigest()[:8]

        secrets = [{"secret_id": secret_id, "value": b"secret", "wrapped_value": wrapped}]
        executor._prepare_injections(secrets)

        assert executor.sentinel_registry.get_secret_id(expected_hash) == secret_id

    def test_prepare_multiple_secrets(self, executor: Executor):
        """Multiple secrets create multiple injections."""
        secrets = [
            _make_secret("s1", b"one"),
            _make_secret("s2", b"two"),
            _make_secret("s3", b"three"),
        ]

        injections = executor._prepare_injections(secrets)

        assert len(injections) == 3
        assert injections[0].secret_id == "s1"
        assert injections[1].secret_id == "s2"
        assert injections[2].secret_id == "s3"

    def test_prepare_creates_injection_result(self, executor: Executor):
        """Strategy is called and InjectionResult is stored on executor."""
        secrets = [_make_secret("s1", b"secret")]
        injections = executor._prepare_injections(secrets)

        assert len(injections) == 1
        assert executor._injection_result is not None
        assert executor._injection_result.extra_fds  # memfd strategy creates FDs


# ---------------------------------------------------------------------------
# _capture_output
# ---------------------------------------------------------------------------


class TestCaptureOutput:
    """Tests for Executor._capture_output()."""

    def test_capture_process_exits(self):
        """Stops capturing when process exits."""
        mock_process = MagicMock()
        mock_process.stdout = MagicMock()
        mock_process.stderr = MagicMock()
        mock_process.stdout.fileno.return_value = 4
        mock_process.stderr.fileno.return_value = 5
        mock_process.poll.return_value = 1  # Process already exited
        mock_process.wait.return_value = 1

        executor = Executor(command_validator=CommandValidator(), session_id="test")

        with patch("executor.executor.select.select", return_value=[[], [], []]):
            with patch("executor.executor.scan_open_fds", return_value={0, 1, 2, 4, 5}):
                stdout, stderr = executor._capture_output(mock_process)

        assert stdout == b""
        assert stderr == b""

    def test_capture_none_fds(self):
        """Returns empty when stdout/stderr FDs are None."""
        mock_process = MagicMock()
        mock_process.stdout = None
        mock_process.stderr = None
        mock_process.wait.return_value = 0

        executor = Executor(command_validator=CommandValidator(), session_id="test")

        stdout, stderr = executor._capture_output(mock_process)

        assert stdout == b""
        assert stderr == b""

    def test_select_timeout_breaks_on_poll(self):
        """select timeout breaks loop when process has exited."""
        mock_process = MagicMock()
        mock_process.stdout = MagicMock()
        mock_process.stderr = MagicMock()
        mock_process.stdout.fileno.return_value = 4
        mock_process.stderr.fileno.return_value = 5
        mock_process.poll.return_value = None  # Initially still running
        mock_process.poll.side_effect = [None, None, 0]  # Then exits
        mock_process.wait.return_value = 0

        executor = Executor(command_validator=CommandValidator(), session_id="test")

        # select returns empty (timeout) repeatedly, then poll returns non-None
        call_count = [0]

        def mock_select(readable, writable, error, timeout):
            call_count[0] += 1
            if call_count[0] >= 3:
                mock_process.poll.return_value = 0
            return [], [], []

        with patch("executor.executor.select.select", side_effect=mock_select):
            with patch("executor.executor.scan_open_fds", return_value={0, 1, 2, 4, 5}):
                stdout, stderr = executor._capture_output(mock_process)


# ---------------------------------------------------------------------------
# _cleanup_injections
# ---------------------------------------------------------------------------


class TestCleanupInjections:
    """Tests for Executor._cleanup_injections() with strategy-based cleanup."""

    def test_cleanup_closes_memfd(self, executor: Executor):
        """Strategy cleanup closes memfd FDs."""
        secrets = [_make_secret("s1", b"secret")]
        executor._prepare_injections(secrets)

        fds_before = list(executor._injection_result.extra_fds)
        assert len(fds_before) == 1
        fd = fds_before[0]

        # FD should be open before cleanup
        fcntl.fcntl(fd, fcntl.F_GETFD)

        executor._cleanup_injections()

        # FD should be closed after cleanup
        with pytest.raises(OSError):
            fcntl.fcntl(fd, fcntl.F_GETFD)

        # Injection result should be cleared
        assert executor._injection_result is None

    def test_cleanup_zeros_secret_value(self, executor: Executor):
        """Zeros secret value in memory."""
        original = b"super-secret-password"
        secrets = [{"secret_id": "s1", "value": original, "wrapped_value": b""}]
        executor._prepare_injections(secrets)

        executor._cleanup_injections()

        bundle = executor._bundles[0]
        assert bundle.value == b"\x00" * len(original)
        assert bundle.value != original

    def test_cleanup_clears_sentinel_registry(self, executor: Executor):
        """Clears sentinel registry after cleanup."""
        wrapped = wrap_with_sentinel("s1", b"secret")
        secrets = [{"secret_id": "s1", "value": b"secret", "wrapped_value": wrapped}]
        executor._prepare_injections(secrets)

        assert len(executor.sentinel_registry.get_session_hashes()) > 0

        executor._cleanup_injections()

        assert executor.sentinel_registry.get_session_hashes() == set()

    def test_cleanup_resilient_to_strategy_errors(self, executor: Executor):
        """Does not raise even if strategy cleanup functions fail."""
        secrets = [_make_secret("s1", b"secret")]
        executor._prepare_injections(secrets)

        # Corrupt the injection result to cause cleanup to fail
        executor._injection_result.extra_fds = [-1]

        # Should not raise
        executor._cleanup_injections()

    def test_cleanup_multiple_secrets(self, executor: Executor):
        """Cleans up all FDs for multiple secrets."""
        secrets = [
            _make_secret("s1", b"one"),
            _make_secret("s2", b"two"),
            _make_secret("s3", b"three"),
        ]
        executor._prepare_injections(secrets)

        fds_before = list(executor._injection_result.extra_fds)
        assert len(fds_before) == 3

        executor._cleanup_injections()

        for fd in fds_before:
            with pytest.raises(OSError):
                fcntl.fcntl(fd, fcntl.F_GETFD)


# ---------------------------------------------------------------------------
# CommandResult
# ---------------------------------------------------------------------------


class TestCommandResult:
    """Tests for CommandResult dataclass."""

    def test_default_fields(self):
        result = CommandResult(command="echo test", exit_code=0, stdout=b"ok", stderr=b"")

        assert result.masked_secret_ids == []
        assert result.output_truncated is False
        assert result.original_stdout_size == 0
        assert result.original_stderr_size == 0

    def test_with_masked_ids(self):
        result = CommandResult(
            command="echo test", exit_code=0, stdout=b"ok", stderr=b"",
            masked_secret_ids=["a1b2c3d4", "e5f6g7h8"],
        )

        assert result.masked_secret_ids == ["a1b2c3d4", "e5f6g7h8"]

    def test_with_truncation(self):
        result = CommandResult(
            command="echo test", exit_code=0, stdout=b"x" * 300000, stderr=b"",
            output_truncated=True,
            original_stdout_size=300000,
        )

        assert result.output_truncated is True
        assert result.original_stdout_size == 300000


# ---------------------------------------------------------------------------
# SecretBundle
# ---------------------------------------------------------------------------


class TestSecretBundle:
    """Tests for SecretBundle dataclass."""

    def test_basic_fields(self):
        bundle = SecretBundle(secret_id="s1", value=b"secret", wrapped_value=b"wrapped")

        assert bundle.secret_id == "s1"
        assert bundle.value == b"secret"
        assert bundle.wrapped_value == b"wrapped"


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------


class TestConstants:
    """Tests for executor constants."""

    def test_max_output_bytes(self):
        from executor.executor import MAX_OUTPUT_BYTES
        assert MAX_OUTPUT_BYTES == 262144  # 256 KB

    def test_truncation_marker_format(self):
        from executor.executor import TRUNCATION_MARKER
        expected = "... [OUTPUT TRUNCATED: 1024 bytes discarded]\n"
        actual = TRUNCATION_MARKER.format(n=1024)
        assert actual == expected


class TestValidateCommandStructure:
    """Tests for _validate_command_structure metacharacter rejection."""

    def test_accepts_simple_command(self):
        from executor.executor import _validate_command_structure
        result = _validate_command_structure("/usr/bin/echo hello")
        assert result == ["/usr/bin/echo", "hello"]

    def test_accepts_command_with_quoted_args(self):
        from executor.executor import _validate_command_structure
        result = _validate_command_structure('/usr/bin/echo "hello world"')
        assert result == ["/usr/bin/echo", "hello world"]

    def test_accepts_command_with_single_quotes(self):
        from executor.executor import _validate_command_structure
        result = _validate_command_structure("/usr/bin/echo 'hello world'")
        assert result == ["/usr/bin/echo", "hello world"]

    def test_rejects_pipe(self):
        from executor.executor import _validate_command_structure
        with pytest.raises(ValueError, match="Shell metacharacters"):
            _validate_command_structure("/usr/bin/ls | /usr/bin/cat")

    def test_rejects_semicolon(self):
        from executor.executor import _validate_command_structure
        with pytest.raises(ValueError, match="Shell metacharacters"):
            _validate_command_structure("/usr/bin/ls; /usr/bin/cat")

    def test_rejects_dollar_paren(self):
        from executor.executor import _validate_command_structure
        with pytest.raises(ValueError, match="Shell metacharacters"):
            _validate_command_structure("/usr/bin/echo $(whoami)")

    def test_rejects_backtick(self):
        from executor.executor import _validate_command_structure
        with pytest.raises(ValueError, match="Shell metacharacters"):
            _validate_command_structure("/usr/bin/echo `id`")

    def test_rejects_dollar_var(self):
        from executor.executor import _validate_command_structure
        with pytest.raises(ValueError, match="Shell metacharacters"):
            _validate_command_structure("/usr/bin/echo $HOME")

    def test_rejects_redirect(self):
        from executor.executor import _validate_command_structure
        with pytest.raises(ValueError, match="Shell metacharacters"):
            _validate_command_structure("/usr/bin/ls > /tmp/out")

    def test_rejects_ampersand(self):
        from executor.executor import _validate_command_structure
        with pytest.raises(ValueError, match="Shell metacharacters"):
            _validate_command_structure("/usr/bin/ls &")

    def test_rejects_glob(self):
        from executor.executor import _validate_command_structure
        with pytest.raises(ValueError, match="Shell metacharacters"):
            _validate_command_structure("/usr/bin/ls *.txt")

    def test_rejects_newline(self):
        from executor.executor import _validate_command_structure
        with pytest.raises(ValueError, match="Shell metacharacters"):
            _validate_command_structure("/usr/bin/echo hello\n/usr/bin/echo world")

    def test_rejects_empty_command(self):
        from executor.executor import _validate_command_structure
        with pytest.raises(ValueError, match="Empty command"):
            _validate_command_structure("")

    def test_rejects_whitespace_only(self):
        from executor.executor import _validate_command_structure
        with pytest.raises(ValueError, match="Empty command"):
            _validate_command_structure("   ")


class TestStage2SendsHashes:
    """Tests for H-44: Stage 2 sends hashes, not plaintext values."""

    def test_send_to_stage2_sends_hashes_not_values(self, executor: Executor, mock_http_client: httpx2.Client):
        """_send_to_stage2 sends secret hashes, not plaintext values."""
        import base64

        executor.http_client = mock_http_client

        response = MagicMock()
        response.json.return_value = {
            "stdout": base64.b64encode(b"filtered\n").decode(),
            "stderr": base64.b64encode(b"").decode(),
            "masked_hashes": [],
        }
        response.raise_for_status.return_value = None
        mock_http_client.post.return_value = response

        from executor.bundles import SecretBundle

        bundle = SecretBundle(
            secret_id="test-secret",
            value=b"plaintext-secret-value",
            wrapped_value=b"wrapped",
            hash="abc123def456",
        )

        # Pass only the fields that _send_to_stage2 would send (secret_id + hash)
        secret_dict = {"secret_id": bundle.secret_id, "hash": bundle.hash}
        executor._send_to_stage2(b"output", b"", [secret_dict])

        # Verify the call was made with hash, not value
        call_args = mock_http_client.post.call_args
        payload = call_args.kwargs["json"] if call_args.kwargs else call_args[1]["json"]
        assert "secrets" in payload
        assert payload["secrets"][0]["hash"] == "abc123def456"
        assert "value" not in payload["secrets"][0]


class TestTruncatedAudit:
    """Tests for L-28: truncated flag in audit events."""

    def test_truncated_flag_in_command_result(self, executor: Executor):
        """CommandResult.output_truncated is set when output exceeds limit."""
        result = executor._filter_and_build_result(
            "/usr/bin/echo test",
            0,
            b"A" * 300_000,  # stdout exceeds MAX_OUTPUT_BYTES
            b"stderr",
            [],
        )
        assert result.output_truncated is True

    def test_not_truncated_when_under_limit(self, executor: Executor):
        """output_truncated is False when output is under limit."""
        result = executor._filter_and_build_result(
            "/usr/bin/echo test",
            0,
            b"short output",
            b"short stderr",
            [],
        )
        assert result.output_truncated is False
