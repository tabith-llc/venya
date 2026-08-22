"""Tests for Docker Sandboxes (sbx) injection strategy."""

import os
from unittest.mock import MagicMock, patch

import pytest

from executor.bundles import SecretBundle
from executor.strategies.sbx_strategy import SbxStrategy


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
    def test_create_sandbox_calls_sbx_create(self):
        strategy = SbxStrategy()
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=0, stderr="")
            strategy.create_sandbox("venya-test123", "/workspace")
            mock_run.assert_called_once()
            call_args = mock_run.call_args[0][0]
            assert call_args == ["sbx", "create", "--name", "venya-test123", "/workspace"]
            assert strategy._sandbox_name == "venya-test123"

    def test_create_sandbox_raises_on_failure(self):
        strategy = SbxStrategy()
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=1, stderr="image not found")
            with pytest.raises(RuntimeError, match="Failed to create sandbox"):
                strategy.create_sandbox("venya-test123")

    def test_create_sandbox_without_workspace(self):
        strategy = SbxStrategy()
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=0, stderr="")
            strategy.create_sandbox("venya-test123")
            call_args = mock_run.call_args[0][0]
            assert call_args == ["sbx", "create", "--name", "venya-test123"]


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
    def test_apply_network_policy_adds_allow_rules(self):
        strategy = SbxStrategy()
        strategy._sandbox_name = "venya-test123"
        allowed_hosts = [
            {"host": "10.10.10.50", "port": 22},
            {"host": "10.10.10.100", "port": 5432},
        ]
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=0, stderr="")
            strategy.apply_network_policy(allowed_hosts)
            assert mock_run.call_count == 2
            # Check that policy allow commands were called
            calls = [c[0][0] for c in mock_run.call_args_list]
            for call in calls:
                assert "policy" in call
                assert "allow" in call
                assert "network" in call

    def test_apply_network_policy_raises_without_sandbox(self):
        strategy = SbxStrategy()
        strategy._sandbox_name = None
        with pytest.raises(RuntimeError, match="Sandbox not created yet"):
            strategy.apply_network_policy([{"host": "example.com", "port": 443}])


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
