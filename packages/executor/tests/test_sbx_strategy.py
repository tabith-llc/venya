"""Tests for Docker Sandboxes (sbx) injection strategy."""

import os
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from executor.bundles import SecretBundle
from executor.strategies.sbx_strategy import SBX_CREATE_TIMEOUT, SbxStrategy, sweep_workspace_base


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
        strategy.prepare(secrets)
        assert strategy._session_dir is not None
        assert os.path.isdir(strategy._session_dir)
        assert str(tmpfs_dir) in strategy._session_dir

    def test_prepare_creates_missing_base(self, strategy, secrets, monkeypatch, tmp_path):
        """Fresh installs have no /dev/shm/venya-secrets — prepare() must
        self-provision it instead of raising FileNotFoundError."""
        base = tmp_path / "not-yet-created"
        monkeypatch.setattr("executor.strategies.sbx_strategy.SECRET_TMPFS_BASE", str(base))
        strategy.prepare(secrets)
        assert base.is_dir()
        assert os.path.isdir(strategy._session_dir)

    def test_prepare_writes_secret_files(self, strategy, secrets, tmpfs_dir):
        result = strategy.prepare(secrets)
        for mount in result.secret_mounts:
            assert os.path.isfile(mount.path)

    def test_prepare_sets_secret_permissions(self, strategy, secrets, tmpfs_dir):
        result = strategy.prepare(secrets)
        for mount in result.secret_mounts:
            mode = os.stat(mount.path).st_mode & 0o777
            assert mode == 0o400

    def test_prepare_returns_correct_mounts(self, strategy, secrets, tmpfs_dir):
        result = strategy.prepare(secrets)
        assert len(result.secret_mounts) == 2
        for mount in result.secret_mounts:
            assert mount.container_path.startswith("/run/venya/secrets/")
            assert mount.secret_id in mount.path

    def test_prepare_empty_secrets(self, strategy, tmpfs_dir):
        result = strategy.prepare([])
        assert len(result.secret_mounts) == 0
        assert result.extra_fds == []

    def test_prepare_no_extra_fds(self, strategy, secrets, tmpfs_dir):
        result = strategy.prepare(secrets)
        assert result.extra_fds == []

    def test_prepare_cleanup_removes_dir(self, strategy, secrets, tmpfs_dir):
        result = strategy.prepare(secrets)
        session_dir = strategy._session_dir
        assert os.path.isdir(session_dir)
        result.cleanup()
        assert not os.path.exists(session_dir)

    def test_prepare_cleanup_is_idempotent(self, strategy, secrets, tmpfs_dir):
        result = strategy.prepare(secrets)
        result.cleanup()
        result.cleanup()  # Should not raise


class TestSbxStrategyCreateSandbox:
    @pytest.fixture
    def ws_base(self, monkeypatch, tmp_path):
        """Point WORKSPACE_TMPFS_BASE at tmp_path (hermetic; not real /dev/shm)."""
        base = tmp_path / "wsbase"
        monkeypatch.setattr("executor.strategies.sbx_strategy.WORKSPACE_TMPFS_BASE", str(base))
        return base

    def test_create_sandbox_calls_sbx_create(self):
        strategy = SbxStrategy()
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=0, stderr="")
            strategy.create_sandbox("venya-test123", "/workspace")
            mock_run.assert_called_once()
            call_args = mock_run.call_args[0][0]
            assert call_args == ["sbx", "create", "--name", "venya-test123", "shell", "/workspace"]
            assert strategy._sandbox_name == "venya-test123"

    def test_create_sandbox_raises_on_failure(self, ws_base):
        strategy = SbxStrategy()
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=1, stderr="image not found")
            with pytest.raises(RuntimeError, match="Failed to create sandbox"):
                strategy.create_sandbox("venya-test123")

    def test_create_sandbox_without_workspace_creates_existing_tmpfs_dir(self, ws_base):
        """No workspace -> strategy creates a per-run dir and always passes it
        as the last argv element (omission was the bug: sbx create prompts on a
        missing path and fails with "user cancelled operation" under non-TTY)."""
        strategy = SbxStrategy()
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=0, stderr="")
            strategy.create_sandbox("venya-test123")
            call_args = mock_run.call_args[0][0]
            assert call_args[:5] == ["sbx", "create", "--name", "venya-test123", "shell"]
            workspace = call_args[len(call_args) - 1]
            assert os.path.isdir(workspace)
            assert workspace.startswith(str(ws_base) + os.sep)
            assert os.path.basename(workspace).startswith("ws_")
            assert strategy._workspace_dir == workspace

    def test_create_sandbox_failure_cleans_created_workspace(self, ws_base):
        strategy = SbxStrategy()
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=1, stderr="boom")
            with pytest.raises(RuntimeError, match="Failed to create sandbox"):
                strategy.create_sandbox("venya-test123")
        assert strategy._workspace_dir is None
        remaining = [p.name for p in ws_base.iterdir()] if ws_base.exists() else []
        assert not any(name.startswith("ws_") for name in remaining)

    def test_create_sandbox_uses_configured_timeout(self):
        strategy = SbxStrategy()
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=0, stderr="")
            strategy.create_sandbox("venya-test123", "/workspace")
            used = mock_run.call_args.kwargs["timeout"]
            expected = int(os.environ.get("VENYA_SBX_CREATE_TIMEOUT", SBX_CREATE_TIMEOUT))
            assert used == expected

    def test_create_sandbox_timeout_env_override(self, monkeypatch):
        strategy = SbxStrategy()
        monkeypatch.setenv("VENYA_SBX_CREATE_TIMEOUT", "777")
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=0, stderr="")
            strategy.create_sandbox("venya-test123", "/workspace")
            assert mock_run.call_args.kwargs["timeout"] == 777


class TestSbxStrategyRemoveSandboxWorkspace:
    @pytest.fixture
    def ws_base(self, monkeypatch, tmp_path):
        base = tmp_path / "wsbase"
        monkeypatch.setattr("executor.strategies.sbx_strategy.WORKSPACE_TMPFS_BASE", str(base))
        return base

    def test_remove_sandbox_deletes_created_workspace_and_keeps_base(self, ws_base):
        strategy = SbxStrategy()
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
        strategy = SbxStrategy()
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
    def test_copy_secrets_creates_dir_and_copies(self):
        strategy = SbxStrategy()
        strategy._sandbox_name = "venya-test123"
        mounts = [
            MagicMock(secret_id="pass", path="/tmp/secret", container_path="/run/venya/secrets/pass"),
        ]
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=0, stderr="")
            strategy.copy_secrets_into_sandbox(mounts)
            assert mock_run.call_count == 3  # mkdir + cp + chmod

    def test_copy_secrets_raises_on_failure(self):
        strategy = SbxStrategy()
        strategy._sandbox_name = "venya-test123"
        mounts = [
            MagicMock(secret_id="pass", path="/tmp/secret", container_path="/run/venya/secrets/pass"),
        ]
        with patch("subprocess.run") as mock_run:
            mock_run.side_effect = [
                MagicMock(returncode=0, stderr=""),  # mkdir
                MagicMock(returncode=1, stderr="copy failed"),  # cp
            ]
            with pytest.raises(RuntimeError, match="Failed to copy secret"):
                strategy.copy_secrets_into_sandbox(mounts)

    def test_copy_secrets_raises_on_chmod_failure(self):
        """L-65: a failed chmod 400 must fail closed, not leave the secret at
        default perms. mkdir + cp succeed, chmod fails -> raise + rollback."""
        strategy = SbxStrategy()
        strategy._sandbox_name = "venya-test123"
        mounts = [
            MagicMock(secret_id="pass", path="/tmp/secret", container_path="/run/venya/secrets/pass"),
        ]
        with patch("subprocess.run") as mock_run:
            mock_run.side_effect = [
                MagicMock(returncode=0, stderr=""),  # mkdir
                MagicMock(returncode=0, stderr=""),  # cp
                MagicMock(returncode=1, stderr="chmod failed"),  # chmod
                MagicMock(returncode=0, stderr=""),  # rollback rm -f
            ]
            with pytest.raises(RuntimeError, match="Failed to set read-only permissions"):
                strategy.copy_secrets_into_sandbox(mounts)

            # rollback rm -f ran for the already-copied path
            rollback_calls = [c for c in mock_run.call_args_list if "rm" in c.args[0]]
            assert rollback_calls, "expected a rollback rm -f after chmod failure"

    def test_copy_secrets_raises_without_sandbox(self):
        strategy = SbxStrategy()
        strategy._sandbox_name = None
        with pytest.raises(RuntimeError, match="Sandbox not created yet"):
            strategy.copy_secrets_into_sandbox([])


class TestSbxStrategyNetworkPolicy:
    def test_apply_network_policy_adds_allow_rules(self, tmp_path: Path):
        strategy = SbxStrategy()
        strategy._sandbox_name = "venya-test123"
        allowlist = tmp_path / "egress-allowlist.txt"
        allowlist.write_text("10.10.10.50\n10.10.10.100\n")

        mock_egress = MagicMock()
        mock_egress.get_allowed_hosts.return_value = ["10.10.10.50", "10.10.10.100", "10.27.28.1"]

        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=0, stderr="", stdout="")
            with patch("executor.egress_filter.EgressFilter", return_value=mock_egress):
                strategy.apply_network_policy("venya-test123")
            # 2 allowlist entries + 1 DNS resolver
            assert mock_run.call_count == 3
            # Check that policy allow commands were called
            calls = [c[0][0] for c in mock_run.call_args_list]
            for call in calls:
                assert "policy" in call
                assert "allow" in call
                assert "network" in call

    def test_apply_network_policy_dns_always_allowed(self, tmp_path: Path):
        strategy = SbxStrategy()
        strategy._sandbox_name = "venya-test123"

        mock_egress = MagicMock()
        mock_egress.get_allowed_hosts.return_value = ["10.27.28.1"]

        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=0, stderr="", stdout="")
            with patch("executor.egress_filter.EgressFilter", return_value=mock_egress):
                strategy.apply_network_policy("venya-test123")
            # Only DNS resolver should be allowed
            assert mock_run.call_count == 1
            call_args = mock_run.call_args[0][0]
            assert "10.27.28.1" in call_args

    def test_apply_network_policy_missing_allowlist(self):
        strategy = SbxStrategy()
        strategy._sandbox_name = "venya-test123"

        mock_egress = MagicMock()
        mock_egress.get_allowed_hosts.return_value = ["10.27.28.1"]

        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=0, stderr="", stdout="")
            with patch("executor.egress_filter.EgressFilter", return_value=mock_egress):
                strategy.apply_network_policy("venya-test123")
            # Only DNS resolver should be allowed
            assert mock_run.call_count == 1


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
