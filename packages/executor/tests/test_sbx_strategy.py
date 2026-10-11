# Copyright (c) 2026 Tabith LLC.
# Use of this source code is governed by the Business Source License 1.1
# included in the LICENSE file at the root of this repository. As of the
# Change Date listed there, the work is available under MPL 2.0.
# SPDX-License-Identifier: BUSL-1.1

"""Tests for Docker Sandboxes (sbx) injection strategy."""

import logging
import os
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
from venya_contract import ASKPASS_HELPER_PATH

from executor.bundles import SecretBundle
from executor.config import ExecutorConfig, host_total_memory_mib
from executor.egress_filter import DEFAULT_ALLOWLIST_PATH
from executor.strategies.sbx_strategy import (
    ASKPASS_HELPER_CONTENT,
    SBX_CREATE_TIMEOUT,
    SbxStrategy,
    sweep_workspace_base,
)


class TestSbxStrategyName:
    def test_returns_sbx(self):
        strategy = SbxStrategy()
        assert strategy.name() == "sbx"


class TestSbxStrategyValidate:
    def test_raises_when_sbx_not_found(self):
        with patch("shutil.which", return_value=None), pytest.raises(RuntimeError, match="sbx CLI not found"):
            strategy = SbxStrategy()
            strategy.validate()

    def test_passes_when_sbx_found(self):
        with patch("shutil.which", return_value="/usr/bin/sbx"):
            strategy = SbxStrategy()
            strategy.validate()  # Should not raise


class TestSbxStrategyPrepare:
    @pytest.fixture
    def strategy(self):
        return SbxStrategy()

    @pytest.fixture
    def secrets(self):
        return [
            SecretBundle(secret_id="sudo-pass", value=b"password123", wrapped_value=b""),
            SecretBundle(secret_id="api-key", value=b"sk-abc123", wrapped_value=b""),
        ]

    @pytest.fixture
    def tmpfs_dir(self, monkeypatch, tmp_path):
        """Mock SECRET_TMPFS_BASE to use tmp_path for testing."""
        monkeypatch.setattr("executor.strategies.sbx_strategy.SECRET_TMPFS_BASE", str(tmp_path))
        return tmp_path

    def test_prepare_creates_tmpfs_dir(self, strategy, secrets, tmpfs_dir):
        strategy.prepare(secrets, "11111111-2222-3333-4444-555555555555")
        assert strategy._session_dir is not None
        assert os.path.isdir(strategy._session_dir)
        assert str(tmpfs_dir) in strategy._session_dir

    def test_prepare_dir_embeds_session_id(self, strategy, secrets, tmpfs_dir):
        """Reaper contract: dir name = session_<server-session-id>_<rand>.

        The reaper parses parts[1] as the session id (UUIDs carry no
        underscores; the mkdtemp rand tail CAN — [a-z0-9_] charset).
        """
        sid = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
        strategy.prepare(secrets, sid)
        dirname = os.path.basename(strategy._session_dir)
        assert dirname.startswith(f"session_{sid}_")
        parts = dirname.split("_")
        assert parts[1] == sid

    def test_prepare_creates_missing_base(self, strategy, secrets, monkeypatch, tmp_path):
        """Fresh installs have no /dev/shm/venya-secrets — prepare() must
        self-provision it instead of raising FileNotFoundError."""
        base = tmp_path / "not-yet-created"
        monkeypatch.setattr("executor.strategies.sbx_strategy.SECRET_TMPFS_BASE", str(base))
        strategy.prepare(secrets, "11111111-2222-3333-4444-555555555555")
        assert base.is_dir()
        assert os.path.isdir(strategy._session_dir)

    def test_prepare_writes_secret_files(self, strategy, secrets, tmpfs_dir):
        result = strategy.prepare(secrets, "11111111-2222-3333-4444-555555555555")
        for mount in result.secret_mounts:
            assert os.path.isfile(mount.path)

    def test_prepare_sets_secret_permissions(self, strategy, secrets, tmpfs_dir):
        result = strategy.prepare(secrets, "11111111-2222-3333-4444-555555555555")
        for mount in result.secret_mounts:
            mode = os.stat(mount.path).st_mode & 0o777
            assert mode == 0o400

    def test_prepare_returns_correct_mounts(self, strategy, secrets, tmpfs_dir):
        result = strategy.prepare(secrets, "11111111-2222-3333-4444-555555555555")
        assert len(result.secret_mounts) == 2
        for mount in result.secret_mounts:
            assert mount.container_path.startswith("/run/secrets/venya/")
            assert mount.secret_id in mount.path

    def test_prepare_empty_secrets(self, strategy, tmpfs_dir):
        result = strategy.prepare([], "11111111-2222-3333-4444-555555555555")
        assert len(result.secret_mounts) == 0
        assert result.extra_fds == []

    def test_prepare_no_extra_fds(self, strategy, secrets, tmpfs_dir):
        result = strategy.prepare(secrets, "11111111-2222-3333-4444-555555555555")
        assert result.extra_fds == []

    def test_prepare_cleanup_removes_dir(self, strategy, secrets, tmpfs_dir):
        result = strategy.prepare(secrets, "11111111-2222-3333-4444-555555555555")
        session_dir = strategy._session_dir
        assert os.path.isdir(session_dir)
        result.cleanup()
        assert not os.path.exists(session_dir)

    def test_prepare_cleanup_is_idempotent(self, strategy, secrets, tmpfs_dir):
        result = strategy.prepare(secrets, "11111111-2222-3333-4444-555555555555")
        result.cleanup()
        result.cleanup()  # Should not raise


class TestSbxStrategyPrepareSecretIdValidation:
    """Ticket #320: server-issued secret_id lands in the host tmpfs join and
    the container_path f-string — reject traversal/absolute/dot-only ids at
    the boundary with nothing written (validation precedes any os.open).

    Uses the conftest autouse base: SECRET_TMPFS_BASE = tmp_path/"shm".
    """

    SESSION_ID = "11111111-2222-3333-4444-555555555555"

    @pytest.fixture
    def strategy(self):
        return SbxStrategy()

    def test_traversal_id_rejected(self, strategy, tmp_path):
        bundles = [SecretBundle(secret_id="../../escape", value=b"x", wrapped_value=b"")]
        with pytest.raises(ValueError, match="unsafe secret_id"):
            strategy.prepare(bundles, self.SESSION_ID)
        # tmpfs base untouched (no session dir, no file) and nothing escaped
        assert list((tmp_path / "shm").iterdir()) == []
        assert not (tmp_path / "escape").exists()

    def test_absolute_id_rejected(self, strategy, tmp_path):
        bundles = [SecretBundle(secret_id="/tmp/venya320-pwn", value=b"x", wrapped_value=b"")]
        with pytest.raises(ValueError, match="unsafe secret_id"):
            strategy.prepare(bundles, self.SESSION_ID)
        assert list((tmp_path / "shm").iterdir()) == []
        assert not Path("/tmp/venya320-pwn").exists()

    def test_dot_only_id_rejected(self, strategy, tmp_path):
        """'.'/'..' are charset-legal but are traversal segments — must be
        rejected so the id stays one plain file name."""
        for bad in (".", ".."):
            bundles = [SecretBundle(secret_id=bad, value=b"x", wrapped_value=b"")]
            with pytest.raises(ValueError, match="unsafe secret_id"):
                strategy.prepare(bundles, self.SESSION_ID)
        assert list((tmp_path / "shm").iterdir()) == []

    def test_rejection_after_valid_bundle_writes_nothing(self, strategy, tmp_path):
        """No partial writes: first bundle is fine, second is malicious —
        the pre-loop validation aborts before any os.open."""
        bundles = [
            SecretBundle(secret_id="42", value=b"good", wrapped_value=b""),
            SecretBundle(secret_id="../bad", value=b"evil", wrapped_value=b""),
        ]
        with pytest.raises(ValueError, match="unsafe secret_id"):
            strategy.prepare(bundles, self.SESSION_ID)
        assert list((tmp_path / "shm").iterdir()) == []
        assert strategy._session_dir is None

    def test_int_shaped_id_accepted_unchanged(self, strategy, tmp_path):
        """Server truth: ids are Integer PKs str()-cast by the daemon —
        the canonical decimal form must pass both sinks untouched."""
        bundles = [SecretBundle(secret_id="42", value=b"x", wrapped_value=b"")]
        result = strategy.prepare(bundles, self.SESSION_ID)
        mount = result.secret_mounts[0]
        assert mount.secret_id == "42"
        assert os.path.basename(mount.path) == "42"
        assert mount.container_path == "/run/secrets/venya/42"


class TestSbxStrategyCreateSandbox:
    """#578: the create path carries an explicit --memory. Every cell here pins
    a cap because the shipped posture is refuse-without-one; the refusal and
    the config-load bounds are the paired negatives at the end of this class.
    """

    MEMORY_MB = 1024

    @pytest.fixture
    def ws_base(self, monkeypatch, tmp_path):
        """Point WORKSPACE_BASE at tmp_path (hermetic; not real /dev/shm)."""
        base = tmp_path / "wsbase"
        monkeypatch.setattr("executor.strategies.sbx_strategy.WORKSPACE_BASE", str(base))
        return base

    def test_create_sandbox_calls_sbx_create(self):
        strategy = SbxStrategy(sandbox_memory_mb=self.MEMORY_MB)
        with patch("subprocess.run") as mock_run, patch("shutil.which", return_value=None):
            mock_run.return_value = MagicMock(returncode=0, stderr="")
            strategy.create_sandbox("venya-test123", "/workspace")
            mock_run.assert_called_once()
            call_args = mock_run.call_args[0][0]
            assert call_args == [
                "sbx",
                "create",
                "--name",
                "venya-test123",
                "--memory",
                f"{self.MEMORY_MB}m",
                "shell",
                "/workspace",
            ]
            assert strategy._sandbox_name == "venya-test123"

    def test_create_sandbox_raises_on_failure(self, ws_base):
        strategy = SbxStrategy(sandbox_memory_mb=self.MEMORY_MB)
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=1, stderr="image not found")
            with pytest.raises(RuntimeError, match="Failed to create sandbox"):
                strategy.create_sandbox("venya-test123")

    def test_create_sandbox_without_workspace_creates_existing_tmpfs_dir(self, ws_base):
        """No workspace -> strategy creates a per-run dir and always passes it
        as the last argv element (omission was the bug: sbx create prompts on a
        missing path and fails with "user cancelled operation" under non-TTY)."""
        strategy = SbxStrategy(sandbox_memory_mb=self.MEMORY_MB)
        with patch("subprocess.run") as mock_run, patch("shutil.which", return_value=None):
            mock_run.return_value = MagicMock(returncode=0, stderr="")
            strategy.create_sandbox("venya-test123")
            call_args = mock_run.call_args_list[0][0][0]
            # #578 shifted this window: --memory sits between --name and shell,
            # so the first seven tokens are the pinned prefix.
            assert call_args[:7] == [
                "sbx",
                "create",
                "--name",
                "venya-test123",
                "--memory",
                f"{self.MEMORY_MB}m",
                "shell",
            ]
            workspace = call_args[len(call_args) - 1]
            assert os.path.isdir(workspace)
            assert workspace.startswith(str(ws_base) + os.sep)
            assert os.path.basename(workspace).startswith("ws_")
            assert strategy._workspace_dir == workspace

    def test_create_sandbox_failure_cleans_created_workspace(self, ws_base):
        strategy = SbxStrategy(sandbox_memory_mb=self.MEMORY_MB)
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=1, stderr="boom")
            with pytest.raises(RuntimeError, match="Failed to create sandbox"):
                strategy.create_sandbox("venya-test123")
        assert strategy._workspace_dir is None
        remaining = [p.name for p in ws_base.iterdir()] if ws_base.exists() else []
        assert not any(name.startswith("ws_") for name in remaining)

    def test_create_sandbox_uses_configured_timeout(self):
        strategy = SbxStrategy(sandbox_memory_mb=self.MEMORY_MB)
        with patch("subprocess.run") as mock_run, patch("shutil.which", return_value=None):
            mock_run.return_value = MagicMock(returncode=0, stderr="")
            strategy.create_sandbox("venya-test123", "/workspace")
            used = mock_run.call_args_list[0].kwargs["timeout"]
            expected = int(os.environ.get("VENYA_SBX_CREATE_TIMEOUT", SBX_CREATE_TIMEOUT))
            assert used == expected

    def test_create_sandbox_timeout_env_override(self, monkeypatch):
        strategy = SbxStrategy(sandbox_memory_mb=self.MEMORY_MB)
        monkeypatch.setenv("VENYA_SBX_CREATE_TIMEOUT", "777")
        with patch("subprocess.run") as mock_run, patch("shutil.which", return_value=None):
            mock_run.return_value = MagicMock(returncode=0, stderr="")
            strategy.create_sandbox("venya-test123", "/workspace")
            assert mock_run.call_args_list[0].kwargs["timeout"] == 777

    def test_sbx_create_refuses_when_memory_unset(self, ws_base):
        """NEGATIVE PAIR to the pinned argv above: with the knob unset (the
        shipped default), create_sandbox refuses and never spawns sbx — so no
        sandbox ever inherits the vendor's 50%-of-guest default."""
        strategy = SbxStrategy(sandbox_memory_mb=None)
        with patch("subprocess.run") as mock_run, patch("shutil.which", return_value="/usr/bin/sbx"):
            with pytest.raises(RuntimeError, match="sandbox_memory_mb is not configured"):
                strategy.create_sandbox("test-negative-578", "/workspace")
            mock_run.assert_not_called()
        # The refusal lands before any workspace is created: nothing to clean.
        assert strategy._workspace_dir is None
        assert not os.path.isdir(ws_base) or not any(name.startswith("ws_") for name in os.listdir(ws_base))

    def test_config_rejects_memory_below_vendor_min(self) -> None:
        """Config load refuses 511 MiB with a named reason (vendor minimum is 512 MiB)."""
        with pytest.raises(ValueError, match="512"):
            ExecutorConfig(sandbox_memory_mb=511, executor_id="test-exec-578")

    def test_config_rejects_memory_above_vendor_max(self) -> None:
        """NEGATIVE half of the cap: a value above 75% of this machine's memory is
        one the vendor would clamp silently, so config load refuses it."""
        absurd = host_total_memory_mib() * 2
        with pytest.raises(ValueError, match="75%"):
            ExecutorConfig(sandbox_memory_mb=absurd, executor_id="test-exec-578")

    def test_config_accepts_memory_at_vendor_min(self) -> None:
        """The boundary itself loads, and unset stays loadable — a host that never
        runs a sandbox must still start (the create path owns that refusal)."""
        assert ExecutorConfig(sandbox_memory_mb=512, executor_id="test-exec-578").sandbox_memory_mb == 512
        assert ExecutorConfig(executor_id="test-exec-578").sandbox_memory_mb is None


class TestSbxStrategyRemoveSandboxWorkspace:
    @pytest.fixture
    def ws_base(self, monkeypatch, tmp_path):
        base = tmp_path / "wsbase"
        monkeypatch.setattr("executor.strategies.sbx_strategy.WORKSPACE_BASE", str(base))
        return base

    def test_remove_sandbox_deletes_created_workspace_and_keeps_base(self, ws_base):
        strategy = SbxStrategy(sandbox_memory_mb=1024)
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=0, stderr="")
            strategy.create_sandbox("venya-test123")
            workspace = strategy._workspace_dir
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=0, stderr="")
            strategy.remove_sandbox()
        assert not os.path.exists(workspace)
        assert os.path.isdir(ws_base)  # base survives rmtree — next session needs it
        assert strategy._workspace_dir is None

    def test_remove_sandbox_keeps_caller_workspace(self, tmp_path):
        caller_ws = tmp_path / "caller-owned"
        caller_ws.mkdir()
        strategy = SbxStrategy(sandbox_memory_mb=1024)
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=0, stderr="")
            strategy.create_sandbox("venya-test123", str(caller_ws))
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=0, stderr="")
            strategy.remove_sandbox()
        assert os.path.isdir(caller_ws)  # ownership: only what the strategy created
        assert strategy._workspace_dir is None

    def test_remove_sandbox_no_sandbox_no_workspace_is_noop(self, ws_base):
        strategy = SbxStrategy()
        with patch("subprocess.run") as mock_run:
            strategy.remove_sandbox()
            mock_run.assert_not_called()


class TestSweepWorkspaceBase:
    def test_sweep_removes_only_ws_dirs(self, tmp_path):
        base = tmp_path / "base"
        (base / "ws_dead").mkdir(parents=True)
        (base / "ws_stale").mkdir(parents=True)
        (base / "session_survives").mkdir()
        (base / "ws_file").write_text("not a dir")
        swept = sweep_workspace_base(str(base))
        assert swept == 2
        assert not (base / "ws_dead").exists()
        assert not (base / "ws_stale").exists()
        assert (base / "session_survives").exists()
        assert (base / "ws_file").exists()

    def test_sweep_creates_missing_base(self, tmp_path):
        base = tmp_path / "missing"
        assert sweep_workspace_base(str(base)) == 0
        assert base.is_dir()


class TestSbxStrategyCopySecrets:
    def test_copy_secrets_creates_dir_and_copies(self, tmp_path):
        strategy = SbxStrategy()
        strategy._sandbox_name = "venya-test123"
        secret_file = tmp_path / "secret"
        secret_file.write_bytes(b"supersecret")
        mounts = [
            MagicMock(secret_id="pass", path=str(secret_file), container_path="/run/secrets/venya/pass"),
        ]
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=0, stderr=b"")
            strategy.copy_secrets_into_sandbox(mounts)
            # mkdir + tee(inject) + chmod = 3 calls
            assert mock_run.call_count == 3
            # the inject call pipes the raw secret over stdin to tee
            tee_call = mock_run.call_args_list[1]
            assert "tee" in tee_call.args[0]
            assert "-i" in tee_call.args[0]
            assert "/run/secrets/venya/pass" in tee_call.args[0]
            assert tee_call.kwargs["input"] == b"supersecret"

    def test_copy_secrets_raises_on_failure(self, tmp_path):
        strategy = SbxStrategy()
        strategy._sandbox_name = "venya-test123"
        secret_file = tmp_path / "secret"
        secret_file.write_bytes(b"supersecret")
        mounts = [
            MagicMock(secret_id="pass", path=str(secret_file), container_path="/run/secrets/venya/pass"),
        ]
        with patch("subprocess.run") as mock_run:
            mock_run.side_effect = [
                MagicMock(returncode=0, stderr=b""),  # mkdir
                MagicMock(returncode=1, stderr=b"copy failed"),  # tee inject
                MagicMock(returncode=0, stderr=b""),  # rollback rm -f
            ]
            with pytest.raises(RuntimeError, match="Failed to copy secret"):
                strategy.copy_secrets_into_sandbox(mounts)

    def test_copy_secrets_raises_on_mkdir_failure(self):
        """Fail-closed: a failed mkdir must raise before the secret is
        injected (a swallowed mkdir once surfaced as an opaque tar error)."""
        strategy = SbxStrategy()
        strategy._sandbox_name = "venya-test123"
        mounts = [
            MagicMock(secret_id="pass", path="/tmp/secret", container_path="/run/secrets/venya/pass"),
        ]
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=1, stderr="Permission denied")
            with pytest.raises(RuntimeError, match="Failed to create secrets directory"):
                strategy.copy_secrets_into_sandbox(mounts)
            assert mock_run.call_count == 1  # mkdir only — no inject/chmod attempted

    def test_copy_secrets_raises_on_chmod_failure(self, tmp_path):
        """L-65: a failed chmod 400 must fail closed, not leave the secret at
        default perms. mkdir + inject succeed, chmod fails -> raise + rollback."""
        strategy = SbxStrategy()
        strategy._sandbox_name = "venya-test123"
        secret_file = tmp_path / "secret"
        secret_file.write_bytes(b"supersecret")
        mounts = [
            MagicMock(secret_id="pass", path=str(secret_file), container_path="/run/secrets/venya/pass"),
        ]
        with patch("subprocess.run") as mock_run:
            mock_run.side_effect = [
                MagicMock(returncode=0, stderr=b""),  # mkdir
                MagicMock(returncode=0, stderr=b""),  # tee inject
                MagicMock(returncode=1, stderr=b"chmod failed"),  # chmod
                MagicMock(returncode=0, stderr=b""),  # rollback rm -f
            ]
            with pytest.raises(RuntimeError, match="Failed to set read-only permissions"):
                strategy.copy_secrets_into_sandbox(mounts)

            # rollback rm -f ran for the already-copied path
            rollback_calls = [c for c in mock_run.call_args_list if "rm" in c.args[0]]
            assert rollback_calls, "expected a rollback rm -f after chmod failure"

    def test_inject_secret_is_passed_via_stdin_not_argv(self, tmp_path):
        """Security: the secret travels over stdin (tee input), never argv —
        argv would surface in the sandbox process listings."""
        strategy = SbxStrategy()
        strategy._sandbox_name = "venya-test123"
        secret_bytes = b"super-secret-value-12345"
        secret_file = tmp_path / "secret"
        secret_file.write_bytes(secret_bytes)
        mounts = [
            MagicMock(secret_id="pass", path=str(secret_file), container_path="/run/secrets/venya/pass"),
        ]
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=0, stderr=b"")
            strategy.copy_secrets_into_sandbox(mounts)
            tee_calls = [c for c in mock_run.call_args_list if "tee" in c.args[0]]
            assert len(tee_calls) == 1
            assert tee_calls[0].kwargs["input"] == secret_bytes
            assert all(secret_bytes.decode() not in a for a in tee_calls[0].args[0])

    def test_copy_secrets_raises_without_sandbox(self):
        strategy = SbxStrategy()
        strategy._sandbox_name = None
        with pytest.raises(RuntimeError, match="Sandbox not created yet"):
            strategy.copy_secrets_into_sandbox([])


class TestSbxStrategyNetworkPolicy:
    def test_apply_network_policy_adds_allow_rules(self, tmp_path: Path):
        strategy = SbxStrategy(dns_resolver="192.0.2.53")
        strategy._sandbox_name = "venya-test123"
        allowlist = tmp_path / "egress-allowlist.txt"
        allowlist.write_text("198.51.100.50\n198.51.100.100\n")

        mock_egress = MagicMock()
        mock_egress.get_allowed_hosts.return_value = ["198.51.100.50", "198.51.100.100", "192.0.2.1"]

        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=0, stderr="", stdout="")
            with patch("executor.egress_filter.EgressFilter", return_value=mock_egress):
                strategy.apply_network_policy("venya-test123")
            # 2 allowlist entries + 1 DNS resolver
            assert mock_run.call_count == 3
            # Pin the exact argv: no sudo (daemon-user context), --sandbox
            # scoping (sbx 0.38 rejects --name).
            calls = [c[0][0] for c in mock_run.call_args_list]
            expected = [
                ["sbx", "policy", "allow", "network", host, "--sandbox", "venya-test123"]
                for host in ["198.51.100.50", "198.51.100.100", "192.0.2.1"]
            ]
            assert calls == expected

    def test_apply_network_policy_raises_on_registration_failure(self, tmp_path: Path):
        """A registration failure must raise, not log-and-continue: a
        swallowed failure leaves the sandbox under deny-all and the command
        dies later with an opaque network error (F11)."""
        strategy = SbxStrategy(dns_resolver="192.0.2.53")
        strategy._sandbox_name = "venya-test123"

        mock_egress = MagicMock()
        mock_egress.get_allowed_hosts.return_value = ["192.0.2.22"]

        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=1, stderr="unknown flag: --name", stdout="")
            with patch("executor.egress_filter.EgressFilter", return_value=mock_egress):
                with pytest.raises(RuntimeError, match="Failed to register egress allow 192.0.2.22"):
                    strategy.apply_network_policy("venya-test123")

    def test_apply_network_policy_rejects_empty_host(self, tmp_path: Path):
        strategy = SbxStrategy(dns_resolver="192.0.2.53")
        strategy._sandbox_name = "venya-test123"

        mock_egress = MagicMock()
        mock_egress.get_allowed_hosts.return_value = [""]

        with patch("subprocess.run") as mock_run:
            with patch("executor.egress_filter.EgressFilter", return_value=mock_egress):
                with pytest.raises(RuntimeError, match="empty entry"):
                    strategy.apply_network_policy("venya-test123")
            mock_run.assert_not_called()

    def test_apply_network_policy_dns_always_allowed(self, tmp_path: Path):
        strategy = SbxStrategy(dns_resolver="192.0.2.53")
        strategy._sandbox_name = "venya-test123"

        mock_egress = MagicMock()
        mock_egress.get_allowed_hosts.return_value = ["192.0.2.1"]

        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=0, stderr="", stdout="")
            with patch("executor.egress_filter.EgressFilter", return_value=mock_egress):
                strategy.apply_network_policy("venya-test123")
            # Only DNS resolver should be allowed
            assert mock_run.call_count == 1
            call_args = mock_run.call_args[0][0]
            assert "192.0.2.1" in call_args

    def test_apply_network_policy_missing_allowlist(self):
        strategy = SbxStrategy(dns_resolver="192.0.2.53")
        strategy._sandbox_name = "venya-test123"

        mock_egress = MagicMock()
        mock_egress.get_allowed_hosts.return_value = ["192.0.2.1"]

        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=0, stderr="", stdout="")
            with patch("executor.egress_filter.EgressFilter", return_value=mock_egress):
                strategy.apply_network_policy("venya-test123")
            # Only DNS resolver should be allowed
            assert mock_run.call_count == 1


class TestConfigPlumbing:
    """Ticket executor-dns-resolver-config-inert: the dns_resolver /
    egress_allowlist_path config knobs must reach EgressFilter. Pre-fix they
    were loadable into ExecutorConfig but had zero readers —
    apply_network_policy hardcoded both values."""

    def test_constructor_defaults_mirror_module_constants(self):
        strategy = SbxStrategy()
        # Ruling D1 option (a): no built-in resolver — the constant is gone,
        # so the default is None (the daemon refuses to start without one).
        assert strategy.dns_resolver is None
        assert strategy.egress_allowlist_path == DEFAULT_ALLOWLIST_PATH

    def test_explicit_values_carried_on_attrs(self):
        strategy = SbxStrategy(dns_resolver="203.0.113.53", egress_allowlist_path="/tmp/venya-t2.txt")
        assert strategy.dns_resolver == "203.0.113.53"
        assert strategy.egress_allowlist_path == "/tmp/venya-t2.txt"

    def test_apply_network_policy_uses_wired_values(self):
        strategy = SbxStrategy(dns_resolver="203.0.113.53", egress_allowlist_path="/tmp/venya-t2.txt")
        strategy._sandbox_name = "venya-test123"

        mock_egress = MagicMock()
        mock_egress.get_allowed_hosts.return_value = ["203.0.113.53"]

        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=0, stderr="", stdout="")
            with patch("executor.egress_filter.EgressFilter", return_value=mock_egress) as mock_cls:
                strategy.apply_network_policy("venya-test123")
            mock_cls.assert_called_once_with(
                allowlist_path=Path("/tmp/venya-t2.txt"),
                dns_resolver="203.0.113.53",
            )

    def test_apply_network_policy_none_resolver_raises(self):
        """Replaces the stage-1 behavior-preservation pin, which dies BY
        RULING (ticket private-infra-product-defaults-and-fixtures, ruling D1
        option (a)): a default-constructed strategy has no resolver, so
        building the egress policy must fail loudly instead of using a
        guessed IP."""
        strategy = SbxStrategy()
        with pytest.raises(RuntimeError, match="dns_resolver"):
            strategy.apply_network_policy("venya-test123")


class TestSbxStrategyExecuteCommand:
    def test_execute_command_runs_in_sandbox(self):
        strategy = SbxStrategy()
        strategy._sandbox_name = "venya-test123"
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(
                returncode=0,
                stdout=b"hello",
                stderr=b"",
            )
            result = strategy.execute_command("echo hello")
            mock_run.assert_called_once()
            call_args = mock_run.call_args[0][0]
            assert call_args == ["sbx", "exec", "venya-test123", "sh", "-c", "echo hello"]
            assert result.stdout == b"hello"

    def test_execute_command_without_sandbox(self):
        strategy = SbxStrategy()
        strategy._sandbox_name = None
        with pytest.raises(RuntimeError, match="Sandbox not created yet"):
            strategy.execute_command("echo hello")


class TestSbxStrategyArgvDirect322:
    """C3 execution posture (ticket execution-command-wire-unstructured-string
    #322, owner ruling 2026-10-02; fleet C5 probe grounded: argv boundaries
    survive render->sh, direct-argv PATH-resolves bare names). When the caller
    passes `argv`, the guest runs those tokens DIRECT (no `sh -c` wrapper) —
    boundaries are the list's, nothing re-parses them. `sh -c` remains ONLY for
    the ruled session-bound `<` sudo-redirect case, which is exactly when the
    caller omits argv (the guest shell must perform the redirect)."""

    def _strategy(self):
        strategy = SbxStrategy()
        strategy._sandbox_name = "venya-test123"
        return strategy

    def _run(self, strategy, **kwargs):
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=0, stdout=b"out", stderr=b"")
            strategy.execute_command("display string", **kwargs)
            return mock_run.call_args[0][0]

    def test_argv_tokens_run_direct_no_shell(self):
        """Positive: argv present -> sbx receives the tokens verbatim after the
        sandbox name; NO 'sh'/'-c' wrapper anywhere in the command."""
        argv = self._run(self._strategy(), argv=["/usr/bin/echo", "hello"])
        assert argv == ["sbx", "exec", "venya-test123", "/usr/bin/echo", "hello"]
        assert "sh" not in argv and "-c" not in argv

    def test_argv_boundaries_survive_as_single_tokens(self):
        """C5 fixtures (space/tab/quote forms that passed the probe): each
        element stays ONE token in the sbx command — no quoting, no splitting."""
        tricky = ["two words", "ta\tb", "quote'd", 'double"d']
        argv = self._run(self._strategy(), argv=["/bin/echo", *tricky])
        assert argv[-4:] == tricky
        assert argv[:3] == ["sbx", "exec", "venya-test123"]

    def test_argv_none_keeps_shell_path_for_redirect_case(self):
        """Ruled exception regression pin: the `<` sudo-redirect command
        (caller omits argv) still crosses as `sh -c <rendered>` with the pair
        RAW — the guest shell performs the redirect (#332 posture)."""
        rendered = "cat < /run/secrets/venya/2"
        strategy = self._strategy()
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=0, stdout=b"", stderr=b"")
            strategy.execute_command(rendered)
        assert mock_run.call_args[0][0] == ["sbx", "exec", "venya-test123", "sh", "-c", rendered]

    def test_empty_argv_rejected_before_exec(self):
        """Empty list is a caller bug, not an exec: fail loud BEFORE any sbx
        call (an empty token list would leave sbx exec with no command)."""
        strategy = self._strategy()
        with patch("subprocess.run") as mock_run:
            with pytest.raises(ValueError, match="empty"):
                strategy.execute_command("display", argv=[])
            mock_run.assert_not_called()

    def test_argv_direct_with_env_file_and_cwd(self):
        """Flag matrix: --env-file/-w still ride BEFORE the sandbox name
        (values never in argv); the direct tokens follow the name."""
        strategy = self._strategy()
        strategy._session_dir = "/tmp/venya-argv-test"
        with patch.object(SbxStrategy, "_write_env_file", return_value="/tmp/venya-argv-test/venya-env"):
            with patch.object(SbxStrategy, "_destroy_env_file"):
                argv = self._run(strategy, env_override={"A": "1"}, cwd="/work", argv=["ls", "-l"])
        assert argv == [
            "sbx",
            "exec",
            "--env-file",
            "/tmp/venya-argv-test/venya-env",
            "-w",
            "/work",
            "venya-test123",
            "ls",
            "-l",
        ]


class TestSbxStrategyRemoveSandbox:
    def test_remove_sandbox_calls_sbx_rm(self):
        strategy = SbxStrategy()
        strategy._sandbox_name = "venya-test123"
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=0, stderr="")
            strategy.remove_sandbox()
            mock_run.assert_called_once()
            call_args = mock_run.call_args[0][0]
            assert call_args[0] == "sbx"
            assert "rm" in call_args
            assert "--force" in call_args
            assert "venya-test123" in call_args

    def test_remove_sandbox_noop_without_name(self):
        strategy = SbxStrategy()
        strategy._sandbox_name = None
        with patch("subprocess.run") as mock_run:
            strategy.remove_sandbox()
            mock_run.assert_not_called()


class TestSbxStrategyStoreHttpSecret:
    def test_store_http_secret_calls_sbx_secret_set(self):
        strategy = SbxStrategy()
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=0, stderr="")
            strategy.store_http_secret("openai", "sk-test123")
            mock_run.assert_called_once()
            call_args = mock_run.call_args[0][0]
            assert call_args[0] == "sbx"
            assert "secret" in call_args
            assert "set" in call_args
            assert "openai" in call_args

    def test_store_http_secret_raises_on_failure(self):
        strategy = SbxStrategy()
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=1, stderr="auth failed")
            with pytest.raises(RuntimeError, match="Failed to store HTTP secret"):
                strategy.store_http_secret("openai", "sk-test123")


class TestSbxStrategyExecuteEnvCwd:
    """env/cwd thread-through (ticket executor-env-override-cwd-sbx-noop;
    transport REPLACED per secret-shape-env-injection option (ii), spike-ruled
    2026-09-21: `sbx exec --env-file` (native flag) fed from a 0600 host-tmpfs
    file. The former `-e K=V` argv transport exposed values in host
    /proc/<pid>/cmdline for the command's duration — the old argv-pinning
    cells were REWRITTEN by that ruling (institutionalization rule: the
    rewrite is recorded here + on the ticket). The 2026-09-18 physical-probe
    fact (env values stay DATA, never shell-parsed) holds a fortiori: values
    now never appear in argv at all.
    """

    def _strategy(self, tmp_path):
        strategy = SbxStrategy()
        strategy._sandbox_name = "venya-test123"
        strategy._session_dir = str(tmp_path)
        return strategy

    def _run(self, strategy, **kwargs):
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=0, stdout=b"", stderr=b"")
            strategy.execute_command("cmd", **kwargs)
            return mock_run.call_args[0][0]

    def test_env_only_uses_env_file_never_argv(self, tmp_path):
        strategy = self._strategy(tmp_path)
        with patch.object(SbxStrategy, "_destroy_env_file") as destroy:
            argv = self._run(strategy, env_override={"A": "1"})
        assert "-e" not in argv
        assert not any("A=1" in tok for tok in argv)  # value NEVER rides argv
        env_file = argv[argv.index("--env-file") + 1]
        assert env_file == str(tmp_path / "venya-env")
        assert argv[-4:] == ["venya-test123", "sh", "-c", "cmd"]
        f = tmp_path / "venya-env"
        assert f.read_text() == "A=1\n"
        assert oct(f.stat().st_mode & 0o777) == "0o600"
        destroy.assert_called_once_with(env_file)

    def test_env_file_destroyed_after_exec(self, tmp_path):
        self._run(self._strategy(tmp_path), env_override={"A": "1"})
        assert not (tmp_path / "venya-env").exists()  # zeroed+unlinked in finally

    def test_env_file_destroyed_even_on_exec_failure(self, tmp_path):
        strategy = self._strategy(tmp_path)
        with patch("subprocess.run") as mock_run:
            mock_run.side_effect = OSError("boom")
            with pytest.raises(OSError):
                strategy.execute_command("cmd", env_override={"A": "1"})
        assert not (tmp_path / "venya-env").exists()

    def test_cwd_only_argv(self, tmp_path):
        argv = self._run(self._strategy(tmp_path), cwd="/work")
        assert argv == ["sbx", "exec", "-w", "/work", "venya-test123", "sh", "-c", "cmd"]

    def test_env_and_cwd_combined_argv(self, tmp_path):
        strategy = self._strategy(tmp_path)
        with patch.object(SbxStrategy, "_destroy_env_file"):
            argv = self._run(strategy, env_override={"A": "1", "B": "2"}, cwd="/work")
        assert argv[:2] == ["sbx", "exec"]
        assert argv[2] == "--env-file"
        assert argv[4:] == ["-w", "/work", "venya-test123", "sh", "-c", "cmd"]
        assert (tmp_path / "venya-env").read_text() == "A=1\nB=2\n"

    def test_neither_backward_compatible_argv(self, tmp_path):
        """Legacy contract unchanged when neither parameter is supplied — no
        --env-file, no file written."""
        argv = self._run(self._strategy(tmp_path))
        assert argv == ["sbx", "exec", "venya-test123", "sh", "-c", "cmd"]
        argv2 = self._run(self._strategy(tmp_path), env_override={}, cwd=None)
        assert argv2 == argv
        assert not (tmp_path / "venya-env").exists()

    def test_metachar_env_value_stays_data_in_file(self, tmp_path):
        """Injection safety (the 2026-09-18 probe cell, file transport): the
        metachar-laden value is ONE line of DATA in the env file and appears
        nowhere in argv."""
        strategy = self._strategy(tmp_path)
        with patch.object(SbxStrategy, "_destroy_env_file"):
            argv = self._run(strategy, env_override={"TRICKY": "v; touch /tmp/pwned"})
        assert (tmp_path / "venya-env").read_text() == "TRICKY=v; touch /tmp/pwned\n"
        assert not any("TRICKY" in tok or "pwned" in tok for tok in argv)

    def test_invalid_env_name_rejected(self, tmp_path):
        """A crafted name can never forge an env-file line."""
        strategy = self._strategy(tmp_path)
        with pytest.raises(ValueError, match="invalid env var name"):
            strategy.execute_command("cmd", env_override={"BAD NAME": "1"})
        with pytest.raises(ValueError, match="invalid env var name"):
            strategy.execute_command("cmd", env_override={"A\nFORGED=1": "x"})
        assert not (tmp_path / "venya-env").exists()

    def test_multiline_env_value_rejected(self, tmp_path):
        strategy = self._strategy(tmp_path)
        with pytest.raises(ValueError, match="multi-line"):
            strategy.execute_command("cmd", env_override={"A": "x\nFORGED=1"})
        assert not (tmp_path / "venya-env").exists()

    def test_nul_env_value_rejected(self, tmp_path):
        """relay-env-value-nul-ungated: write side rejects NUL before the
        env file exists (byte-consistent with the resolver's guard)."""
        strategy = self._strategy(tmp_path)
        with pytest.raises(ValueError, match="NUL"):
            strategy.execute_command("cmd", env_override={"A": "x\x00y"})
        assert not (tmp_path / "venya-env").exists()

    def test_cr_env_value_rejection_unchanged(self, tmp_path):
        """Paired negative: the pre-existing CR half still rejects after the
        NUL extension."""
        strategy = self._strategy(tmp_path)
        with pytest.raises(ValueError, match="multi-line or NUL"):
            strategy.execute_command("cmd", env_override={"A": "x\ry"})
        assert not (tmp_path / "venya-env").exists()


class TestAskpassHelper:
    """write_askpass_helper (ticket secret-shape-askpass-helpers): static 0555
    script at the contract path; fail-closed on any failed step."""

    def _strategy(self):
        s = SbxStrategy()
        s._sandbox_name = "venya-test123"
        return s

    def test_helper_copied_555_to_exec_capable_path(self):
        """RED1 (ticket askpass-helper-noexec-mount-conflict): the static helper
        is staged 0555 on the host and `sbx cp`-copied to the contract path,
        which is now the exec-capable /usr/local/bin — NOT the noexec
        /run/secrets mount that made git/ssh exec die rc=128."""
        s = self._strategy()
        captured: dict = {}

        def fake_run(cmd, *a, **k):
            if cmd[:2] == ["sbx", "cp"]:
                host_temp = cmd[2]
                captured["dest"] = cmd[3]
                captured["mode"] = os.stat(host_temp).st_mode & 0o777
                with open(host_temp, "rb") as fh:
                    captured["content"] = fh.read()
            return MagicMock(returncode=0, stdout="", stderr="")

        with patch("subprocess.run", side_effect=fake_run):
            s.write_askpass_helper()

        assert captured["dest"] == f"venya-test123:{ASKPASS_HELPER_PATH}"
        assert not ASKPASS_HELPER_PATH.startswith("/run/secrets")
        assert ASKPASS_HELPER_PATH == "/usr/local/bin/venya-askpass"
        assert captured["mode"] == 0o555
        assert captured["content"] == ASKPASS_HELPER_CONTENT.encode("utf-8")

    def test_guest_secrets_dir_mkdir_runs_before_cp(self):
        """§12.2 ordering: the guest secrets-dir mkdir (for the
        VENYA_ASKPASS_SECRET file) still runs before the helper copy."""
        s = self._strategy()
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=0, stdout="", stderr="")
            s.write_askpass_helper()
        calls = [c[0][0] for c in mock_run.call_args_list]
        assert calls[0][:4] == ["sbx", "exec", "venya-test123", "mkdir"]
        assert calls[1][:2] == ["sbx", "cp"]

    def test_helper_cp_failure_raises_fail_closed_no_guest_rm(self):
        """Fail-closed on cp failure, and NO in-guest rollback rm: a uid-1000
        `sbx exec rm` cannot unlink from the root-owned dir (§12.3) — the static
        helper is cleaned up by per-run sandbox destruction instead."""
        s = self._strategy()
        with patch("subprocess.run") as mock_run:
            ok = MagicMock(returncode=0, stdout="", stderr="")
            fail = MagicMock(returncode=1, stdout="", stderr="cp: error")
            mock_run.side_effect = [ok, fail]  # mkdir OK, cp FAIL
            with pytest.raises(RuntimeError, match="askpass helper"):
                s.write_askpass_helper()
        calls = [c[0][0] for c in mock_run.call_args_list]
        assert len(calls) == 2
        assert not any("rm" in c for c in calls)

    def test_helper_content_is_static_and_secret_free(self):
        """Truth-table negative (§7): the static helper carries NO secret value
        and no secrets-dir path — the credential arrives only at run time via
        the VENYA_ASKPASS_SECRET file."""
        assert ASKPASS_HELPER_CONTENT.startswith("#!/bin/sh")
        assert 'cat "$VENYA_ASKPASS_SECRET"' in ASKPASS_HELPER_CONTENT
        assert "/run/secrets" not in ASKPASS_HELPER_CONTENT
        for token in ("hunter2", "s3cr3t", "tok-value"):
            assert token not in ASKPASS_HELPER_CONTENT

    def test_no_sandbox_raises(self):
        with pytest.raises(RuntimeError, match="Sandbox not created yet"):
            SbxStrategy().write_askpass_helper()

    def test_helper_guard_unset_secret_exits_nonzero(self, tmp_path):
        """The guard is load-bearing: without it, `cat "$UNSET"` reads stdin
        and hangs until SBX_TIMEOUT instead of failing loudly (defect found
        by the ticket acceptance review — never empty-string success, never
        a silent hang)."""
        import subprocess

        script = tmp_path / "helper.sh"
        script.write_text(ASKPASS_HELPER_CONTENT)
        r = subprocess.run(
            ["sh", str(script), "Password for x"],
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
            env={"PATH": "/usr/bin:/bin"},
        )
        assert r.returncode == 1
        assert "VENYA_ASKPASS_SECRET" in r.stderr

    def test_helper_live_behavior_password_and_username_branches(self, tmp_path):
        """Real sh execution of the helper content: password prompt -> the
        credential file content; username prompt -> VENYA_ASKPASS_USER."""
        import subprocess

        cred = tmp_path / "cred"
        cred.write_text("tok-value\n")
        script = tmp_path / "helper.sh"
        script.write_text(ASKPASS_HELPER_CONTENT)
        base_env = {"PATH": "/usr/bin:/bin", "VENYA_ASKPASS_SECRET": str(cred)}
        r = subprocess.run(
            ["sh", str(script), "Password for 'https://git.example'"],
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
            env=base_env,
        )
        assert r.returncode == 0
        assert r.stdout == "tok-value\n"
        r2 = subprocess.run(
            ["sh", str(script), "Username for 'https://git.example'"],
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
            env={**base_env, "VENYA_ASKPASS_USER": "gituser"},
        )
        assert r2.returncode == 0
        assert r2.stdout == "gituser\n"


class TestCopySshpass:
    """Truth table for _copy_sshpass (ticket executor-installer-missing-sshpass).

    The host-missing case was DEBUG-only — silent on any host installed
    out-of-band — while ssh-password command shapes die 127 in-sandbox.
    The installer apt list now carries sshpass; this warning is the tripwire
    for hosts that lack it anyway.
    """

    def test_missing_host_sshpass_warns_actionably(self, caplog):
        """THE FIX: host without sshpass -> loud WARNING naming the 127 failure
        mode, no copy attempted."""
        strategy = SbxStrategy()
        with (
            patch("shutil.which", return_value=None),
            patch("subprocess.run") as mock_run,
            caplog.at_level(logging.DEBUG, logger="executor.strategies.sbx_strategy"),
        ):
            strategy._copy_sshpass("venya-test123")
        mock_run.assert_not_called()
        warns = [r for r in caplog.records if r.levelno == logging.WARNING and "sshpass" in r.getMessage()]
        assert warns, "host-missing sshpass must log at WARNING, not DEBUG"
        assert "ssh-password command shapes will fail 127" in warns[0].getMessage()

    def test_present_host_sshpass_copies_into_sandbox(self):
        """Positive half: host binary found -> sbx cp into the sandbox /usr/bin."""
        strategy = SbxStrategy()
        with patch("shutil.which", return_value="/usr/bin/sshpass"), patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=0, stderr="")
            strategy._copy_sshpass("venya-test123")
        call_args = mock_run.call_args[0][0]
        assert call_args == ["sbx", "cp", "/usr/bin/sshpass", "venya-test123:/usr/bin/sshpass"]
