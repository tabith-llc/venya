# Copyright (c) 2026 Tabith LLC.
# Use of this source code is governed by the Business Source License 1.1
# included in the LICENSE file at the root of this repository. As of the
# Change Date listed there, the work is available under MPL 2.0.
# SPDX-License-Identifier: BUSL-1.1

"""Tests for Executor pipeline: execute(), _prepare_injections(), _capture_output(), _cleanup_injections()."""

import base64
import inspect
import shlex
from pathlib import Path
from unittest.mock import MagicMock, patch

import httpx2
import pytest

from executor.command_validator import CommandValidator
from executor.executor import (
    SHELL_METACHARS,
    CommandResult,
    Executor,
    SecretBundle,
    _validate_command_structure,
    render_command,
)
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


def mock_sbx_run(self, command, injections, env_override, cwd, askpass_helper=False, argv: list[str] | None = None):
    """Stand-in for Executor._run_command_sbx: runs the rendered command via
    subprocess directly (module-level so the signature-compat cell can
    inspect it; #378). Ignores argv by design — the real function's argv
    behavior is pinned by the #322 cells in test_sbx_strategy.py."""
    import os
    import subprocess as _real_subprocess

    try:
        env = os.environ.copy()
        if env_override:
            env.update(env_override)
        result = _real_subprocess.run(
            command,
            shell=True,
            capture_output=True,
            timeout=5,
            check=False,
            env=env,
            cwd=cwd,
        )
        return CommandResult(
            command=command,
            exit_code=result.returncode,
            stdout=result.stdout,
            stderr=result.stderr,
        )
    except Exception:
        return CommandResult(command=command, exit_code=1, stdout=b"", stderr=b"mock error")


def test_mock_sbx_run_signature_is_call_compatible():
    """#378 truth-table half: the pipeline calls _run_command_sbx with keyword
    arguments (argv included, #322 LEG B) and the fixture mock replaces the
    method wholesale. If the mock's parameter set ever falls behind the real
    signature the swap dies TypeError ONLY on sbx-present hosts — an sbx-absent
    dev box errors earlier at the strategy boundary and never reaches the mock. Pin
    the mock to accept every parameter the real method declares (values may
    be ignored; argv behavior itself stays pinned by the #322 cells).
    Module-level: inside TestExecute the autouse patch would make the
    comparison self-referential."""
    real_params = inspect.signature(Executor._run_command_sbx).parameters
    mock_params = inspect.signature(mock_sbx_run).parameters
    missing = [name for name in real_params if name not in mock_params]
    assert (
        not missing
    ), f"mock_sbx_run misses real-parameter(s) {missing} — pipeline call sites TypeError on sbx-present runs"


class TestExecute:
    """Tests for Executor.execute() full pipeline."""

    @pytest.fixture(autouse=True)
    def _mock_sbx(self):
        """Mock _run_command_sbx to return a basic CommandResult."""
        with patch.object(Executor, "_run_command_sbx", mock_sbx_run):
            yield

    def test_execute_valid_command_succeeds(self, executor: Executor):
        """Valid command executes and returns result."""
        result = executor.execute(["/usr/bin/echo", "hello"], [_make_secret("s1", b"secret-value")])

        assert isinstance(result, CommandResult)
        assert result.exit_code == 0
        assert b"hello" in result.stdout

    def test_execute_rejects_invalid_command(self, executor: Executor):
        """Invalid command raises ValueError."""
        with pytest.raises(ValueError, match="Command rejected"):
            executor.execute(["rm", "-rf", "/"], [_make_secret("s1", b"secret")])

    def test_execute_validates_command_first(self, executor: Executor):
        """Validation happens before injection preparation."""
        with pytest.raises(ValueError, match="Command rejected"):
            executor.execute(["sudo", "cat", "/etc/shadow"], [_make_secret("s1", b"secret")])

    def test_execute_cleanup_runs_even_on_error(self, executor: Executor):
        """Cleanup runs even if command fails."""
        secrets = [_make_secret("s1", b"secret")]

        # This will fail validation, but cleanup should still be attempted
        with pytest.raises(ValueError):
            executor.execute(["invalid-command"], secrets)

    def test_execute_revoke_tokens_called(self, executor: Executor, mock_http_client: httpx2.Client):
        """revoke_tokens is called after execution."""
        executor.http_client = mock_http_client

        secrets = [_make_secret("db-pass", b"password123")]

        executor.execute(["/usr/bin/echo", "test"], secrets)

        # revoke_tokens is called once after execution
        assert mock_http_client.post.call_count == 1
        revoke_call = mock_http_client.post.call_args_list[0]
        assert "/api/v1/sessions/test-session-123/secrets/revoke" in revoke_call[0][0]
        assert "db-pass" in revoke_call[1]["json"]["secret_ids"]

    def test_execute_multiple_secrets(self, executor: Executor):
        """Multiple secrets are all injected and cleaned up."""
        secrets = [
            _make_secret("s1", b"one"),
            _make_secret("s2", b"two"),
            _make_secret("s3", b"three"),
        ]

        result = executor.execute(["/usr/bin/echo", "done"], secrets)

        assert result.exit_code == 0
        assert result.output_truncated is False

    def test_execute_with_env_override(self, executor: Executor):
        """Environment override is applied."""
        result = executor.execute(
            ["/usr/bin/printenv", "MY_VAR"],
            [],
            env_override={"MY_VAR": "custom_value"},
        )

        assert b"custom_value" in result.stdout

    def test_execute_with_cwd(self, executor: Executor, tmp_path: Path):
        """Command runs in specified working directory."""
        work_dir = tmp_path / "work"
        work_dir.mkdir()
        (work_dir / "test.txt").write_text("hello from work dir")

        result = executor.execute(["/usr/bin/cat", "test.txt"], [], cwd=str(work_dir))

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

    def test_prepare_normalizes_int_secret_id(self, executor: Executor):
        """DB secret PKs are Integer and arrive via the relay payload as JSON
        ints; the engine contract is str (SecretBundle, Stage-1 Rust filter,
        revoke). Before normalization an int id raised
        TypeError: 'int' object cannot be converted to 'PyString' in the
        filter (physical e2e, 2026-09-03)."""
        value = b"secret-value-12345"
        wrapped = wrap_with_sentinel("1", value)
        secrets = [{"secret_id": 1, "value": value, "wrapped_value": wrapped}]

        injections = executor._prepare_injections(secrets)

        assert injections[0].secret_id == "1"
        assert isinstance(injections[0].secret_id, str)

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
        import hashlib

        from executor.injector import wrap_with_sentinel

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
        assert len(executor._injection_result.secret_mounts) == 1  # sbx strategy creates mounts


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
                stdout, stderr, stdout_total, stderr_total = executor._capture_output(mock_process)

        assert stdout == b""
        assert stderr == b""
        assert stdout_total == 0
        assert stderr_total == 0

    def test_capture_none_fds(self):
        """Returns empty when stdout/stderr FDs are None."""
        mock_process = MagicMock()
        mock_process.stdout = None
        mock_process.stderr = None
        mock_process.wait.return_value = 0

        executor = Executor(command_validator=CommandValidator(), session_id="test")

        stdout, stderr, stdout_total, stderr_total = executor._capture_output(mock_process)

        assert stdout == b""
        assert stderr == b""
        assert stdout_total == 0
        assert stderr_total == 0

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
                _stdout, _stderr, _stdout_total, _stderr_total = executor._capture_output(mock_process)

    def test_truncation_totals_exact_and_marker_fits_cap(self):
        """Mocked feed: totals are true observed bytes; truncated payload is
        exactly MAX_OUTPUT_BYTES (marker carved out of the cap) — ticket
        executor-sbx-truncation-accounting-wrong issue 3."""
        from executor.executor import MAX_OUTPUT_BYTES

        mock_process = MagicMock()
        mock_process.stdout = MagicMock()
        mock_process.stderr = MagicMock()
        mock_process.stdout.fileno.return_value = 4
        mock_process.stderr.fileno.return_value = 5

        chunk = b"A" * 65536
        reads = {4: [chunk, chunk, chunk, chunk, chunk], 5: [b""]}

        def mock_read(fd, n):
            return reads[fd].pop(0)

        executor = Executor(command_validator=CommandValidator(), session_id="test")

        with patch("executor.executor.select.select", side_effect=lambda r, w, e, t: (list(r), [], [])):
            with patch("executor.executor.os.read", side_effect=mock_read):
                stdout, stderr, stdout_total, stderr_total = executor._capture_output(mock_process)

        assert stdout_total == 327680
        assert stderr_total == 0
        assert len(stdout) == MAX_OUTPUT_BYTES
        assert b"65536 bytes discarded" in stdout
        assert stderr == b""

    def test_truncation_physical_subprocess_over_cap(self):
        """Physical feed (real pipe + select/os.read): output over the cap
        truncates to exactly the cap with true observed totals."""
        import subprocess

        from executor.executor import MAX_OUTPUT_BYTES

        executor = Executor(command_validator=CommandValidator(), session_id="test")

        with subprocess.Popen(
            ["/usr/bin/head", "-c", "300000", "/dev/zero"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        ) as proc:
            stdout, stderr, stdout_total, stderr_total = executor._capture_output(proc)

        assert MAX_OUTPUT_BYTES < stdout_total <= 300000
        assert len(stdout) == MAX_OUTPUT_BYTES
        assert stderr_total == 0
        assert stderr == b""


# ---------------------------------------------------------------------------
# _cleanup_injections
# ---------------------------------------------------------------------------


class TestCleanupInjections:
    """Tests for Executor._cleanup_injections() with strategy-based cleanup."""

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
        """Cleans up all mounts for multiple secrets."""
        secrets = [
            _make_secret("s1", b"one"),
            _make_secret("s2", b"two"),
            _make_secret("s3", b"three"),
        ]
        executor._prepare_injections(secrets)

        assert len(executor._injection_result.secret_mounts) == 3

        executor._cleanup_injections()

        # Injection result should be cleared
        assert executor._injection_result is None


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
            command="echo test",
            exit_code=0,
            stdout=b"ok",
            stderr=b"",
            masked_secret_ids=["a1b2c3d4", "e5f6g7h8"],
        )

        assert result.masked_secret_ids == ["a1b2c3d4", "e5f6g7h8"]

    def test_with_truncation(self):
        result = CommandResult(
            command="echo test",
            exit_code=0,
            stdout=b"x" * 300000,
            stderr=b"",
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
    """Per-element metacharacter rejection for _validate_command_structure over
    argv lists (ticket execution-command-wire-unstructured-string #322, ruling
    Q2-B1: the gate checks INSIDE every element — stricter than the old
    whole-string scan; a metachar packed into ONE argument dies there)."""

    def test_accepts_simple_argv(self):
        from executor.executor import _validate_command_structure

        result = _validate_command_structure(["/usr/bin/echo", "hello"])
        assert result == ["/usr/bin/echo", "hello"]

    def test_accepts_arg_with_spaces(self):
        """#322 headline: whitespace inside ONE argument is data, not a
        separator — the arg survives as one token (positive pair of the
        per-element rejection cells)."""
        from executor.executor import _validate_command_structure

        result = _validate_command_structure(["grep", "error message", "app.log"])
        assert result == ["grep", "error message", "app.log"]

    def test_accepts_args_containing_quotes(self):
        from executor.executor import _validate_command_structure

        result = _validate_command_structure(["/usr/bin/echo", "it's", '"quoted "'])
        assert result == ["/usr/bin/echo", "it's", '"quoted "']

    @pytest.mark.parametrize(
        "metachar_arg", ["a|b", "a;b", "a$(whoami)", "a`id`", "a$HOME", "a>b", "a&b", "a*.txt", "a|;b", "x\ny"]
    )
    def test_rejects_metachar_inside_single_element(self, metachar_arg):
        """Negative half of the truth table: |/;/$()/backtick/&/>/glob/newline
        INSIDE a single argv element are all rejected."""
        from executor.executor import _validate_command_structure

        with pytest.raises(ValueError, match="Shell metacharacters"):
            _validate_command_structure(["/usr/bin/echo", metachar_arg])

    def test_rejects_metachar_in_program_element(self):
        from executor.executor import _validate_command_structure

        with pytest.raises(ValueError, match="Shell metacharacters"):
            _validate_command_structure(["/usr/bin/ls|cat"])

    def test_rejects_fused_less_than_element(self):
        from executor.executor import _validate_command_structure

        with pytest.raises(ValueError, match="Shell metacharacters"):
            _validate_command_structure(["a<b"])

    def test_rejects_empty_command(self):
        from executor.executor import _validate_command_structure

        with pytest.raises(ValueError, match="Empty command"):
            _validate_command_structure([])

    def test_rejects_metachar_only_element(self):
        from executor.executor import _validate_command_structure

        with pytest.raises(ValueError, match="Shell metacharacters"):
            _validate_command_structure(["|"])


class TestStage2NoSecretMaterial:
    """Stage-2 payload carries NO secret material at all.

    Supersedes TestStage2SendsHashes (H-44): the `secrets` field (ids +
    sha256 hashes) was DEAD WIRE — server FilterRequest never declared it
    and pydantic dropped it. Ruling 2026-09-20 (ticket
    executor-stage2-plaintext-signoff): deleted; hashes of low-entropy
    secrets no longer cross the wire for no consumer.
    """

    def test_send_to_stage2_payload_has_no_secrets_field(self, executor: Executor, mock_http_client: httpx2.Client):
        executor.http_client = mock_http_client

        response = MagicMock()
        response.status_code = 200
        response.json.return_value = {
            "stdout": base64.b64encode(b"filtered\n").decode(),
            "stderr": base64.b64encode(b"").decode(),
            "masked_hashes": [],
        }
        response.raise_for_status.return_value = None
        mock_http_client.post.return_value = response

        executor._send_to_stage2(b"output", b"")

        call_args = mock_http_client.post.call_args
        payload = call_args.kwargs["json"] if call_args.kwargs else call_args[1]["json"]
        # Truth table (ruling): payload keys are EXACTLY the output pair —
        # no secrets field, no hashes, no values.
        assert set(payload) == {"stdout", "stderr"}


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


class TestStructuralGate:
    """Solution A (ruled 2026-09-16, ticket executor-sbx-skips-shell-metachar-validation):
    unconditional PER-ELEMENT structural gate in execute() step 1a (argv list, ticket #322 Q2-B1) — before
    the policy gate, before any strategy dispatch. The production sbx path
    hands the command string to `sh -c` inside the sandbox; metacharacters
    must never reach it. Truth table: alphabet rejection through production
    execute() + audit, quoted-metachar tradeoff, gate ordering, permissive-
    policy invariance, both-paths parity, clean-pass control."""

    def _executor(self, audit=None, preset=None):
        import dataclasses

        from executor.strategies.sbx_strategy import SbxStrategy

        strategy = MagicMock(spec=SbxStrategy)
        cv = CommandValidator()
        if preset is not None:
            cv.policy = dataclasses.replace(cv.policy, preset=preset)
        ex = Executor(
            command_validator=cv,
            session_id="s-struct",
            injection_strategy=strategy,
            audit_logger=audit,
        )
        ex.http_client = None
        return ex, strategy

    @pytest.mark.parametrize("ch", sorted(SHELL_METACHARS))
    def test_metachar_alphabet_rejected_via_production_execute(self, ch):
        """Every SHELL_METACHARS member through production execute() →
        rejected BEFORE any strategy call (acceptance: sbx path guarded)."""
        ex, strategy = self._executor()
        with pytest.raises(ValueError, match="Command rejected: Shell metacharacters"):
            ex.execute(["/usr/bin/echo", f"hi{ch}tail"], [])
        strategy.create_sandbox.assert_not_called()
        strategy.execute_command.assert_not_called()

    def test_quoted_metachar_rejected_documented_tradeoff(self):
        """ACCEPTED TRADEOFF (ruling condition 1, recorded in ticket +
        plan-9 Deviations row 6): `echo "a; b"` is safe to a shell but
        rejected whole-string — quote-scoped parsing cannot soundly
        distinguish local vs remote interpretation here."""
        ex, _strategy = self._executor()
        with pytest.raises(ValueError, match="Command rejected: Shell metacharacters"):
            ex.execute(["/usr/bin/echo", "a; b"], [])

    def test_structural_gate_precedes_policy(self):
        """Ordering ruling: the reason string proves the structural gate got
        the first word — `;` is caught structurally, not as a policy
        'Dangerous pattern' (sudo sits in the same command)."""
        ex, _strategy = self._executor()
        with pytest.raises(ValueError) as exc:
            ex.execute(["/usr/bin/sudo", "ls;", "rm", "x"], [])
        assert "metacharacters" in str(exc.value)
        assert "Dangerous pattern" not in str(exc.value)

    def test_gate_unconditional_under_permissive_policy(self):
        """The invariant is not config-dependent: `permissive` preset returns
        True early in the policy layer, yet metachars are still rejected."""
        ex, strategy = self._executor(preset="permissive")
        with pytest.raises(ValueError, match="Command rejected: Shell metacharacters"):
            ex.execute(["/usr/bin/echo", "hi;", "rm", "x"], [])
        strategy.execute_command.assert_not_called()

    def test_structural_rejection_is_command_rejected_class(self):
        """#410: the structural gate raises the dedicated CommandRejected
        class — the single marker the relay listener uses for its 4xx lane.
        ValueError subclass, so pre-#410 ValueError catchers (and the
        match="Command rejected" cells above) stay green unchanged."""
        from executor.executor import CommandRejected

        ex, _strategy = self._executor()
        with pytest.raises(CommandRejected, match="Command rejected: Shell metacharacters"):
            ex.execute(["/usr/bin/echo", "hi;", "tail"], [])

    def test_policy_rejection_is_command_rejected_class(self):
        """#410 paired positive: the policy gate's Dangerous-pattern veto
        carries the SAME class — both pre-run gates share the 4xx lane,
        nothing else does."""
        from executor.executor import CommandRejected

        ex, _strategy = self._executor()
        with pytest.raises(CommandRejected, match="Command rejected: Dangerous pattern"):
            ex.execute(["/usr/bin/sudo", "ls"], [])

    def test_structural_rejection_emits_command_rejected_audit(self):
        """Ruling condition 2: explicit audit assertion, not an assumption —
        silent structural rejection = F11-class bug."""
        audit = MagicMock()
        ex, _strategy = self._executor(audit=audit)
        cmd = ["/usr/bin/echo", "hi;", "tail"]
        with pytest.raises(ValueError):
            ex.execute(cmd, [])
        audit.emit.assert_called_once()
        args, kwargs = audit.emit.call_args
        assert args == ("command_rejected",)
        assert kwargs["command"] == shlex.join(cmd)
        assert "metacharacters" in kwargs["reason"]

    def test_policy_rejection_audits_with_distinct_reason(self):
        """Both rejection classes emit command_rejected with DISTINCT reason
        strings (ordering rationale, ruling 2026-09-16)."""
        audit = MagicMock()
        ex, _strategy = self._executor(audit=audit)
        with pytest.raises(ValueError, match="Dangerous pattern"):
            ex.execute(["/usr/bin/sudo", "ls"], [])
        args, kwargs = audit.emit.call_args
        assert args == ("command_rejected",)
        assert "metacharacters" not in kwargs["reason"]

    def test_direct_path_rejects_identically(self):
        """Both-paths parity (acceptance): _run_command_direct keeps its own
        call (redundancy comment per ruling; refactor-5 coexistence
        guardrail) and rejects the same shapes."""
        ex, _strategy = self._executor()
        with pytest.raises(ValueError, match="Shell metacharacters"):
            ex._run_command_direct(["/usr/bin/echo", "hi;", "tail"], [], None, None)

    def test_clean_command_passes_structural_gate(self):
        """Control: a metachar-free command flows through execute() to the
        strategy untouched."""
        ex, strategy = self._executor()
        strategy.execute_command.return_value = MagicMock(returncode=0, stdout=b"ok", stderr=b"")
        with patch("executor.executor.filter_and_redact", side_effect=lambda o, e, s: (o, e, [], [])):
            result = ex.execute(["/usr/bin/echo", "hello"], [])
        assert result.exit_code == 0
        strategy.execute_command.assert_called_once()

    @pytest.mark.parametrize("elem", ["\x00start", "hi\x00middle", "tail\x00"])
    def test_nul_element_rejected_audited_before_side_effects(self, elem):
        """Ticket argv-nul-gate-reject (#333): NUL is never valid in argv
        (execve contract). Negative half — NUL at start/middle/end of one
        element takes the standard rejection path: ValueError before the
        policy gate, BEFORE any sandbox touch (strategy spy uncalled) and
        before secret materialization (step 2, unreached), with one
        command_rejected audit whose reason is the fixed message (value-
        free)."""
        audit = MagicMock()
        ex, strategy = self._executor(audit=audit)
        with pytest.raises(ValueError, match="Command rejected: Shell metacharacters"):
            ex.execute(["/usr/bin/echo", elem], [{"secret_id": "00000000-0000-0000-0000-000000000001"}])
        strategy.create_sandbox.assert_not_called()
        strategy.execute_command.assert_not_called()
        audit.emit.assert_called_once()
        args, kwargs = audit.emit.call_args
        assert args == ("command_rejected",)
        assert "metacharacters" in kwargs["reason"]
        assert "\x00" not in kwargs["reason"]

    def test_nul_paired_positive_unicode_and_normal_pass(self):
        """Paired positive (truth-table rule): emoji/unicode/normal elements
        are not collaterally rejected by the NUL class-member."""
        ex, strategy = self._executor()
        strategy.execute_command.return_value = MagicMock(returncode=0, stdout=b"ok", stderr=b"")
        with patch("executor.executor.filter_and_redact", side_effect=lambda o, e, s: (o, e, [], [])):
            result = ex.execute(["/usr/bin/echo", "emoji😀🚀", "naïve-café", "plain-arg"], [])
        assert result.exit_code == 0
        strategy.execute_command.assert_called_once()


class TestRedirectAllowance:
    """Narrow redirect allowance (ticket secret-shape-sudo-remote, option (a),
    user ruling 2026-09-21 — corporate targets almost never grant NOPASSWD
    sudo): a STANDALONE '<' immediately followed by an exactly-matching
    SESSION-BOUND secret path is the only tolerated metachar form. Paired
    cells per the truth-table rule; the TestStructuralGate alphabet cells stay
    green (fused '<' forms die with the same whole-string message)."""

    def _executor(self, audit=None):
        from executor.strategies.sbx_strategy import SbxStrategy

        strategy = MagicMock(spec=SbxStrategy)
        ex = Executor(
            command_validator=CommandValidator(),
            session_id="s-sudo",
            injection_strategy=strategy,
            audit_logger=audit,
        )
        ex.http_client = None
        return ex, strategy

    def test_canonical_sudo_shape_passes_full_pipeline(self):
        ex, _strategy = self._executor()
        secrets = [_make_secret("1", b"ssh-pass"), _make_secret("2", b"sudo-pass")]
        # Canonical templates must NOT carry `sudo -S -p ''`: ssh joins remote
        # argv with spaces WITHOUT re-quoting, the empty arg vanishes, and the
        # remote sudo swallows the next token as its prompt string (misparse →
        # usage error, exit 1). Field-proven 2026-09-25 on tvc/tve; the sudo
        # prompt text appearing in stderr is harmless (carries no secret).
        cmd = [
            "/usr/bin/sshpass",
            "-f",
            "/run/secrets/venya/1",
            "/usr/bin/ssh",
            "bot@target-1",
            "/usr/bin/sudo",
            "-S",
            "systemctl",
            "restart",
            "httpd",
            "<",
            "/run/secrets/venya/2",
        ]
        canned = CommandResult(command=shlex.join(cmd), exit_code=0, stdout=b"ok", stderr=b"")
        with patch.object(Executor, "_run_command_sbx", return_value=canned) as m:
            result = ex.execute(cmd, secrets)
        assert result.exit_code == 0
        m.assert_called_once()

    def test_unbound_secret_path_redirect_rejected(self):
        ex, strategy = self._executor()
        secrets = [_make_secret("1", b"ssh-pass")]
        cmd = [
            "/usr/bin/sshpass",
            "-f",
            "/run/secrets/venya/1",
            "/usr/bin/ssh",
            "bot@t",
            "/usr/bin/sudo",
            "-S",
            "id",
            "<",
            "/run/secrets/venya/2",
        ]
        with pytest.raises(ValueError, match="SESSION-BOUND"):
            ex.execute(cmd, secrets)
        strategy.create_sandbox.assert_not_called()

    def test_nonsecret_path_redirect_rejected(self):
        ex, _strategy = self._executor()
        with pytest.raises(ValueError, match="SESSION-BOUND"):
            ex.execute(["/usr/bin/sort", "<", "/etc/passwd"], [_make_secret("1", b"x")])

    def test_prefix_trick_and_relative_paths_rejected(self):
        ex, _strategy = self._executor()
        secrets = [_make_secret("4", b"x")]
        for target in (
            "/run/secrets/venya/4x",
            "/run/secrets/venya/../4",
            "run/secrets/venya/4",
            "/run/secrets/venya/",
        ):
            with pytest.raises(ValueError, match="SESSION-BOUND"):
                ex.execute(["/usr/bin/cat", "x", "<", target], secrets)

    def test_fused_and_heredoc_forms_rejected_with_metachar_message(self):
        ex, _strategy = self._executor()
        secrets = [_make_secret("4", b"x")]
        for form in ("<<", "<>", "<&3", "a<b"):
            with pytest.raises(ValueError, match="Shell metacharacters"):
                ex.execute(["/usr/bin/echo", "hi", form, "/run/secrets/venya/4"], secrets)

    def test_trailing_redirect_rejected(self):
        ex, _strategy = self._executor()
        with pytest.raises(ValueError, match="SESSION-BOUND"):
            ex.execute(["/usr/bin/sort", "<"], [_make_secret("4", b"x")])

    def test_output_redirect_still_rejected(self):
        ex, _strategy = self._executor()
        with pytest.raises(ValueError, match="Shell metacharacters"):
            ex.execute(["/usr/bin/echo", "hi", ">", "/tmp/x"], [_make_secret("4", b"x")])

    def test_multiple_redirects_all_must_be_bound(self):
        both = ["/usr/bin/cmd1", "<", "/run/secrets/venya/1", "<", "/run/secrets/venya/2"]
        toks = _validate_command_structure(both, frozenset({"/run/secrets/venya/1", "/run/secrets/venya/2"}))
        assert "<" in toks
        mixed = ["/usr/bin/cmd1", "<", "/run/secrets/venya/1", "<", "/run/secrets/venya/9"]
        with pytest.raises(ValueError, match="SESSION-BOUND"):
            _validate_command_structure(mixed, frozenset({"/run/secrets/venya/1"}))

    def test_no_secrets_means_no_redirect_ever(self):
        ex, _strategy = self._executor()
        with pytest.raises(ValueError, match="SESSION-BOUND"):
            ex.execute(["/usr/bin/sort", "<", "/run/secrets/venya/4"], [])

    def test_rejection_audits_command_rejected(self):
        audit = MagicMock()
        ex, _strategy = self._executor(audit=audit)
        with pytest.raises(ValueError):
            ex.execute(["/usr/bin/sort", "<", "/etc/passwd"], [])
        args, kwargs = audit.emit.call_args
        assert args == ("command_rejected",)
        assert "SESSION-BOUND" in kwargs["reason"]


class TestRedirectReRender332:
    """Ruled pair re-emission (ticket redirect-allowance-neutralized-by-quoting
    #332, hunt-wave2 FIND-1): the gate accepts the session-bound '<' pair but
    the plain shlex.join re-quoted it into inertness — sudo-remote option (a)
    was silently dead at tip. render_command re-emits accepted pairs RAW and
    must agree with the gate via the ONE shared _redirect_pair helper."""

    def _executor(self, audit=None):
        from executor.strategies.sbx_strategy import SbxStrategy

        strategy = MagicMock(spec=SbxStrategy)
        ex = Executor(
            command_validator=CommandValidator(),
            session_id="s-332",
            injection_strategy=strategy,
            audit_logger=audit,
        )
        ex.http_client = None
        return ex, strategy

    def test_accepted_pair_renders_raw_string(self):
        # Cell (a): string-level assert — the ruled pair crosses UNQUOTED.
        bound = "/run/secrets/venya/2"
        rendered = render_command(["/usr/bin/sort", "<", bound], frozenset({bound}))
        assert rendered == "/usr/bin/sort < /run/secrets/venya/2"
        assert "'<'" not in rendered

    def test_real_shell_executes_restored_redirect(self, tmp_path):
        # Cell (b) positive: honest simulation — a tmp_path file is SUBSTITUTED
        # for the in-sandbox secret path (same bytes on both sides of render).
        import subprocess

        secret = tmp_path / "2"
        secret.write_text("s3cr3t\n")
        bound = str(secret)
        rendered = render_command(["cat", "<", bound], frozenset({bound}))
        out = subprocess.run(["sh", "-c", rendered], capture_output=True, text=True, check=False)
        assert out.returncode == 0
        assert out.stdout == "s3cr3t\n"

    def test_inert_join_form_is_the_regression_pin(self, tmp_path):
        # Cell (b) paired negative: the pre-#332 rendering (plain shlex.join)
        # is INERT — '<' arrives as a literal ARGUMENT and cat fails to open
        # a file named '<'. This is exactly the dead-feature shape #332 fixes.
        import subprocess

        secret = tmp_path / "2"
        secret.write_text("s3cr3t\n")
        inert = shlex.join(["cat", "<", str(secret)])
        out = subprocess.run(["sh", "-c", inert], capture_output=True, text=True, check=False)
        assert out.returncode != 0

    @pytest.mark.parametrize(
        "argv",
        [
            ["ls", "-la", "/tmp"],
            ["echo", "a b"],
            ["echo", "a'b"],
            ["echo", 'a"b'],
            ["echo", "a\\b"],
            ["echo", ""],
            ["prog", "--flag=x"],
            ["echo", "é"],
            ["echo", "a\tb"],
            ["cat", "/run/secrets/venya/9", "<"],  # bound-ish names WITHOUT a pair: still quoted
        ],
    )
    def test_non_allowance_input_matches_shlex_join(self, argv):
        # Cell (c): common path zero-drift — byte-identical to shlex.join for
        # every input without an accepted pair, with or without a bound set.
        assert render_command(argv) == shlex.join(argv)
        assert render_command(argv, frozenset({"/run/secrets/venya/9"})) == shlex.join(argv)

    def test_gate_rejects_unbound_pair_before_render(self):
        # Cell (d): order is gate-then-render — a '<' NOT followed by a bound
        # path raises with NO audit of execution and render never invoked.
        audit = MagicMock()
        ex, strategy = self._executor(audit=audit)
        with patch("executor.executor.render_command") as render:
            with pytest.raises(ValueError, match="SESSION-BOUND"):
                ex.execute(["/usr/bin/sort", "<", "/etc/passwd"], [_make_secret("1", b"x")])
        render.assert_not_called()
        strategy.create_sandbox.assert_not_called()
        args, _kwargs = audit.emit.call_args
        assert args == ("command_rejected",)

    def test_single_source_condition_drift_guard(self):
        # Cell (e): the pair condition lives ONCE — in _redirect_pair. The
        # gate and the renderer must not re-grow their own copies (#332's
        # second-order bug class). Source-text grep assertion, stable per-def.
        import inspect

        src = inspect.getsource(inspect.getmodule(render_command))
        # the pair MEMBERSHIP condition exists exactly once (in _redirect_pair);
        # the renderer may READ command[i+1] raw but only after the helper says
        # so — a second bounds-checked lookup means a copy of the condition grew.
        assert src.count("in allowed_redirect_paths") == 1
        assert src.count("if i + 1 < len(command)") == 1


class TestArgvDirectPosture322:
    """C3 hybrid posture (ticket execution-command-wire-unstructured-string
    #322, owner ruling 2026-10-02 Q3=C3; fleet C5 probe grounded): execute()
    hands the gate-validated argv list DIRECT to the strategy for the common
    case (no shell re-parses it); a command carrying the ruled session-bound
    `<` pair keeps the rendered `sh -c` form (argv=None) because the guest
    shell must perform the redirect. Truth table: both positives plus the
    paired gate-negatives — dispatch happens ONLY after the per-element gate
    has passed, and the gate is never weakened by the switch."""

    def _executor(self):
        from executor.strategies.sbx_strategy import SbxStrategy

        strategy = MagicMock(spec=SbxStrategy)
        strategy.execute_command.return_value = MagicMock(returncode=0, stdout=b"ok", stderr=b"")
        ex = Executor(
            command_validator=CommandValidator(),
            session_id="s-argv322",
            injection_strategy=strategy,
        )
        ex.http_client = None
        return ex, strategy

    def _execute(self, ex, cmd, secrets=None):
        with patch("executor.executor.filter_and_redact", side_effect=lambda o, e, s: (o, e, [], [])):
            return ex.execute(cmd, secrets or [])

    def test_plain_command_dispatched_argv_direct(self):
        """Positive: metachar-free argv arrives at the strategy as the SAME
        list (boundaries intact, element-for-element); the positional payload
        stays the shlex.join display string (audit/response shape unchanged)."""
        ex, strategy = self._executor()
        cmd = ["/usr/bin/echo", "two words", "quote'd"]
        result = self._execute(ex, cmd)
        assert result.exit_code == 0
        args, kwargs = strategy.execute_command.call_args
        assert kwargs["argv"] == cmd
        assert args[0] == shlex.join(cmd)

    def test_ruled_redirect_pair_keeps_shell_path(self):
        """`<`-case regression pin (the ruled exception must keep WORKING):
        a command with a session-bound pair dispatches with argv=None and the
        pair RAW in the sh -c payload — identical bytes to the pre-switch
        posture for this case (#332 re-emission preserved)."""
        ex, strategy = self._executor()
        bound = "/run/secrets/venya/2"
        cmd = [
            "/usr/bin/sshpass",
            "-f",
            "/run/secrets/venya/1",
            "/usr/bin/ssh",
            "bot@target-1",
            "/usr/bin/sudo",
            "-S",
            "id",
            "<",
            bound,
        ]
        self._execute(ex, cmd, [_make_secret("1", b"ssh-pass"), _make_secret("2", b"sudo-pass")])
        args, kwargs = strategy.execute_command.call_args
        assert kwargs["argv"] is None
        assert args[0].endswith(f"< {bound}")
        assert "'<'" not in args[0]

    def test_metachar_element_rejected_before_any_dispatch(self):
        """Paired negative: a per-element metachar dies at the gate BEFORE the
        strategy sees it — the argv-direct switch adds no path around the
        gate (relay maps this class to the existing 503 idiom, unchanged)."""
        ex, strategy = self._executor()
        with pytest.raises(ValueError, match="Command rejected: Shell metacharacters"):
            self._execute(ex, ["/usr/bin/echo", "hi; touch /tmp/pwned"])
        strategy.execute_command.assert_not_called()
        strategy.create_sandbox.assert_not_called()

    def test_unbound_redirect_rejected_before_any_dispatch(self):
        """Paired negative on the new branch's condition: a '<' NOT followed
        by a bound path never reaches the posture decision — rejected with
        SESSION-BOUND, zero dispatch."""
        ex, strategy = self._executor()
        with pytest.raises(ValueError, match="SESSION-BOUND"):
            self._execute(ex, ["/usr/bin/cat", "<", "/etc/shadow"], [_make_secret("2", b"pw")])
        strategy.execute_command.assert_not_called()
        strategy.create_sandbox.assert_not_called()

    def test_policy_rejection_still_precedes_dispatch(self):
        """Gate ordering unchanged by the switch: the policy gate still sees
        the rendered string and still vetoes dispatch (sudo + Dangerous
        pattern shape from the policy preset)."""
        ex, strategy = self._executor()
        with pytest.raises(ValueError, match="Dangerous pattern"):
            self._execute(ex, ["/usr/bin/sudo", "ls"])
        strategy.execute_command.assert_not_called()


class TestDirectPathGuardParity374:
    """Ticket direct-path-inner-guard-drift-trap (#374, ruling ALIGN
    2026-10-02): the redundant inner guard in _run_command_direct must
    compute the IDENTICAL ruled decision as execute() step 1a — derived from
    this path's own injections via the shared bound-path helper. The bound
    pair ACCEPTS (under shell=False the pair never reaches a shell: the '<'
    and the path are separate inert argv elements); every other metachar /
    '<' shape still rejects BEFORE any Popen. The guard stays (fail-closed
    redundancy per the 2026-09-16 ruling) — it may no longer contradict the
    ruled '<` posture."""

    BOUND = "/run/secrets/venya/2"

    def _executor(self):
        from executor.strategies.sbx_strategy import SbxStrategy

        strategy = MagicMock(spec=SbxStrategy)
        ex = Executor(
            command_validator=CommandValidator(),
            session_id="s-374",
            injection_strategy=strategy,
        )
        ex.http_client = None
        ex._injection_result = None
        return ex

    def _proc(self):
        proc = MagicMock()
        proc.stdin.fileno.return_value = 3
        proc.stdout.fileno.return_value = 4
        proc.stderr.fileno.return_value = 5
        proc.wait.return_value = 0
        proc.returncode = 0
        return proc

    def _bundle(self):
        return [MagicMock(secret_id="2", value=b"pw")]

    def _direct(self, ex, cmd, popen):
        """Existing direct-path test idiom: process machinery mocked, Popen
        recorded."""
        with patch("executor.executor.subprocess.Popen", popen):
            with patch("executor.executor.select.select", return_value=([], [], [])):
                with patch("executor.executor.scan_open_fds", return_value=[0, 1, 2]):
                    with patch("executor.executor.set_cloexec"):
                        with patch("executor.executor.verify_fd_whitelist", return_value=[]):
                            with patch(
                                "executor.executor.filter_and_redact",
                                side_effect=lambda o, e, s: (o, e, [], []),
                            ):
                                ex._run_command_direct(cmd, self._bundle(), None, None)

    def test_bound_pair_accepts_as_inert_argv(self):
        """RED at base (the drift itself): the ruled posture accepts the
        standalone '<' followed by the bound path this session's bundles
        name — both arrive at execve as SEPARATE literal argv elements
        (inert data, shell=False)."""
        popen = MagicMock(return_value=self._proc())
        cmd = ["/bin/cat", "<", self.BOUND]
        self._direct(self._executor(), cmd, popen)
        popen.assert_called_once()
        assert popen.call_args[0][0] == cmd  # '<' and path stay distinct elements
        assert popen.call_args[1]["shell"] is False

    def test_metachar_element_rejected_before_popen(self):
        popen = MagicMock(return_value=self._proc())
        with pytest.raises(ValueError, match="Shell metacharacters"):
            self._direct(self._executor(), ["/bin/echo", "hi;tail"], popen)
        popen.assert_not_called()

    def test_unbound_redirect_rejected_before_popen(self):
        """Same '<`-plus-path shape, path NOT named by any bundle: SESSION-BOUND
        rejection — the guard's allowance is data-derived, never free-standing."""
        popen = MagicMock(return_value=self._proc())
        with pytest.raises(ValueError, match="SESSION-BOUND"):
            self._direct(self._executor(), ["/bin/cat", "<", "/etc/shadow"], popen)
        popen.assert_not_called()

    def test_lone_trailing_redirect_rejected_before_popen(self):
        popen = MagicMock(return_value=self._proc())
        with pytest.raises(ValueError, match="SESSION-BOUND"):
            self._direct(self._executor(), ["/bin/cat", "<"], popen)
        popen.assert_not_called()

    def test_gate_call_count_drift_guard(self):
        """#332 single-source idiom: the structural gate exists at exactly
        def + the two aligned sites (execute() step 1a, direct inner). A
        fourth hit means a third gate — or a stray call — grew; a third
        would mean the aligned inner guard was removed without a ruling."""
        import inspect

        src = inspect.getsource(inspect.getmodule(Executor))
        assert src.count("_validate_command_structure(") == 3


class TestValidateCommandStructureStrictUtf8:
    """Gate layer for ticket argv-surrogate-executes-then-crashes-audit-write
    (#334, posture B): a lone surrogate cannot be executed faithfully nor
    audited losslessly — the per-element gate rejects it with the same
    ValueError -> command_rejected path that carries every other structural
    rejection (including #333's NUL set-entry, now landed), before any
    strategy dispatch."""

    def test_rejects_lone_surrogate_element(self):
        with pytest.raises(ValueError, match="not valid strict UTF-8"):
            _validate_command_structure(["/usr/bin/touch", "bad\ud800name"])

    def test_error_names_index_never_echoes_value(self):
        """Actionable (index) without echoing argv content (#325-class hygiene:
        the element may carry user-sensitive text)."""
        with pytest.raises(ValueError) as exc:
            _validate_command_structure(["ls", "\udfff"])
        assert "Argument 1" in str(exc.value)
        assert "\udfff" not in str(exc.value)

    def test_accepts_full_unicode_positive(self):
        """Paired positive: astral-plane text (emoji, CJK, accents) is strict-
        encodable and must sail through the gate unchanged."""
        argv = ["/usr/bin/echo", "héllo", "🔐🚀", "日本", "\u00e9\u00e8"]
        assert _validate_command_structure(argv) == argv
