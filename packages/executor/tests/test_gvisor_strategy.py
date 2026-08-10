"""Tests for GvisorStrategy."""

import subprocess
from executor.strategies.gvisor_strategy import GvisorStrategy, CONTAINER_SECRET_DIR
from executor.strategies.base import SecretMount
from unittest.mock import patch, MagicMock


class TestGvisorStrategyName:
    """Tests for GvisorStrategy.name()."""

    def test_returns_gvisor(self):
        """name() returns 'gvisor'."""
        strategy = GvisorStrategy()
        assert strategy.name() == "gvisor"


class TestGvisorStrategyInit:
    """Tests for GvisorStrategy initialization."""

    def test_default_secret_base_fd(self):
        """secret_base_fd defaults to 100."""
        strategy = GvisorStrategy()
        assert strategy.secret_base_fd == 100

    def test_session_dir_is_none_initially(self):
        """_session_dir is None before prepare() is called."""
        strategy = GvisorStrategy()
        assert strategy._session_dir is None

    def test_custom_secret_base_fd(self):
        """secret_base_fd can be set to a custom value."""
        strategy = GvisorStrategy(secret_base_fd=200)
        assert strategy.secret_base_fd == 200


class TestGvisorStrategyValidate:
    """Tests for GvisorStrategy.validate()."""

    def test_raises_when_dev_shm_missing(self):
        """validate() raises RuntimeError when /dev/shm does not exist."""
        with patch("executor.strategies.gvisor_strategy.os.path.isdir", return_value=False):
            strategy = GvisorStrategy()
            try:
                strategy.validate()
            except RuntimeError as e:
                assert "/dev/shm not available" in str(e)
            else:
                assert False, "Expected RuntimeError"

    def test_raises_when_docker_missing(self, tmp_path):
        """validate() raises RuntimeError when docker is not installed."""
        with patch("executor.strategies.gvisor_strategy.os.path.isdir", return_value=True):
            with patch("executor.strategies.gvisor_strategy.shutil.which", return_value=None):
                strategy = GvisorStrategy()
                try:
                    strategy.validate()
                except RuntimeError as e:
                    assert "Docker not found" in str(e)
                else:
                    assert False, "Expected RuntimeError"


class TestGvisorStrategyPrepare:
    """Tests for GvisorStrategy.prepare()."""

    def _make_bundle(self, secret_id: str, value: bytes) -> MagicMock:
        bundle = MagicMock()
        bundle.secret_id = secret_id
        bundle.value = value
        return bundle

    def test_prepare_creates_tmpfs_files(self, tmp_path):
        """prepare() writes secrets to tmpfs session directory."""
        strategy = GvisorStrategy()
        bundles = [self._make_bundle("api-key", b"secret-value")]

        with patch("executor.strategies.gvisor_strategy.tempfile.mkdtemp", return_value=str(tmp_path / "session")):
            tmp_path.joinpath("session").mkdir()
            result = strategy.prepare(bundles)

        session_dir = tmp_path / "session"
        assert session_dir.joinpath("api-key").exists()
        assert session_dir.joinpath("api-key").read_bytes() == b"secret-value"

    def test_prepare_returns_secret_mounts(self, tmp_path):
        """prepare() returns InjectionResult with correct SecretMount objects."""
        strategy = GvisorStrategy()
        bundles = [self._make_bundle("db-pass", b"password123")]

        with patch("executor.strategies.gvisor_strategy.tempfile.mkdtemp", return_value=str(tmp_path / "session")):
            tmp_path.joinpath("session").mkdir()
            result = strategy.prepare(bundles)

        assert len(result.secret_mounts) == 1
        mount = result.secret_mounts[0]
        assert isinstance(mount, SecretMount)
        assert mount.secret_id == "db-pass"
        assert mount.path == str(tmp_path / "session" / "db-pass")
        assert mount.container_path == f"{CONTAINER_SECRET_DIR}/db-pass"

    def test_prepare_returns_empty_extra_fds(self, tmp_path):
        """prepare() returns empty extra_fds (uses mounts, not FDs)."""
        strategy = GvisorStrategy()
        bundles = [self._make_bundle("key", b"value")]

        with patch("executor.strategies.gvisor_strategy.tempfile.mkdtemp", return_value=str(tmp_path / "session")):
            tmp_path.joinpath("session").mkdir()
            result = strategy.prepare(bundles)

        assert result.extra_fds == []

    def test_prepare_sets_restricted_permissions(self, tmp_path):
        """prepare() sets 0o400 (read-only) permissions on secret files."""
        strategy = GvisorStrategy()
        bundles = [self._make_bundle("token", b"tok123")]

        with patch("executor.strategies.gvisor_strategy.tempfile.mkdtemp", return_value=str(tmp_path / "session")):
            tmp_path.joinpath("session").mkdir()
            strategy.prepare(bundles)

        file_perms = oct((tmp_path / "session" / "token").stat().st_mode & 0o777)
        assert file_perms == "0o400"

    def test_prepare_multiple_secrets(self, tmp_path):
        """prepare() handles multiple secrets correctly."""
        strategy = GvisorStrategy()
        bundles = [
            self._make_bundle("key1", b"value1"),
            self._make_bundle("key2", b"value2"),
        ]

        with patch("executor.strategies.gvisor_strategy.tempfile.mkdtemp", return_value=str(tmp_path / "session")):
            tmp_path.joinpath("session").mkdir()
            result = strategy.prepare(bundles)

        assert len(result.secret_mounts) == 2
        assert (tmp_path / "session" / "key1").exists()
        assert (tmp_path / "session" / "key2").exists()
        assert (tmp_path / "session" / "key1").read_bytes() == b"value1"
        assert (tmp_path / "session" / "key2").read_bytes() == b"value2"

    def test_prepare_empty_secrets(self, tmp_path):
        """prepare() with empty secrets returns empty mounts."""
        strategy = GvisorStrategy()

        with patch("executor.strategies.gvisor_strategy.tempfile.mkdtemp", return_value=str(tmp_path / "session")):
            tmp_path.joinpath("session").mkdir()
            result = strategy.prepare([])

        assert len(result.secret_mounts) == 0
        assert result.extra_fds == []

    def test_prepare_cleanup_removes_session_dir(self, tmp_path):
        """cleanup() removes the tmpfs session directory."""
        strategy = GvisorStrategy()
        bundles = [self._make_bundle("key", b"value")]

        with patch("executor.strategies.gvisor_strategy.tempfile.mkdtemp", return_value=str(tmp_path / "session")):
            session_dir = tmp_path / "session"
            session_dir.mkdir()
            result = strategy.prepare(bundles)

        assert session_dir.exists()
        result.cleanup()
        assert not session_dir.exists()

    def test_prepare_cleanup_is_idempotent(self, tmp_path):
        """cleanup() is safe to call multiple times."""
        strategy = GvisorStrategy()
        bundles = [self._make_bundle("key", b"value")]

        with patch("executor.strategies.gvisor_strategy.tempfile.mkdtemp", return_value=str(tmp_path / "session")):
            session_dir = tmp_path / "session"
            session_dir.mkdir()
            result = strategy.prepare(bundles)

        result.cleanup()
        result.cleanup()  # Should not raise


class TestFactoryCreateGvisor:
    """Tests for factory.create_strategy with 'gvisor'."""

    def test_create_strategy_returns_gvisor(self):
        """create_strategy('gvisor') returns a GvisorStrategy instance."""
        from executor.strategies.factory import create_strategy

        strategy = create_strategy("gvisor")
        assert isinstance(strategy, GvisorStrategy)

    def test_create_strategy_gvisor_has_correct_name(self):
        """create_strategy('gvisor') returns strategy with name 'gvisor'."""
        from executor.strategies.factory import create_strategy

        strategy = create_strategy("gvisor")
        assert strategy.name() == "gvisor"

    def test_create_strategy_unknown_raises(self):
        """create_strategy('unknown') raises ValueError."""
        from executor.strategies.factory import create_strategy

        try:
            create_strategy("unknown")
        except ValueError as e:
            assert "Unknown injection strategy" in str(e)
            assert "gvisor" in str(e)
            assert "memfd" in str(e)
        else:
            assert False, "Expected ValueError"


class TestCommandPolicyAllowedHosts:
    """Tests for CommandPolicy with allowed_hosts field."""

    def test_policy_has_allowed_hosts_field(self):
        """CommandPolicy has allowed_hosts field."""
        from executor.command_validator import CommandPolicy

        policy = CommandPolicy(
            preset="balanced",
            allowed_commands=frozenset(),
            trusted_paths=frozenset(),
            dangerous_patterns=frozenset(),
            allowed_hosts=[{"host": "10.0.0.1", "port": 22}],
        )
        assert hasattr(policy, "allowed_hosts")
        assert policy.allowed_hosts == [{"host": "10.0.0.1", "port": 22}]

    def test_policy_allowed_hosts_defaults_to_empty_list(self):
        """CommandPolicy allowed_hosts defaults to empty list."""
        from executor.command_validator import CommandPolicy

        policy = CommandPolicy(
            preset="balanced",
            allowed_commands=frozenset(),
            trusted_paths=frozenset(),
            dangerous_patterns=frozenset(),
        )
        assert policy.allowed_hosts == []

    def test_make_balanced_policy_has_empty_allowed_hosts(self):
        """make_balanced_policy() returns policy with empty allowed_hosts."""
        from executor.command_validator import make_balanced_policy

        policy = make_balanced_policy()
        assert policy.allowed_hosts == []

    def test_make_strict_policy_has_empty_allowed_hosts(self):
        """make_strict_policy() returns policy with empty allowed_hosts."""
        from executor.command_validator import make_strict_policy

        policy = make_strict_policy()
        assert policy.allowed_hosts == []


class TestRunCommandGvisor:
    """Tests for Executor._run_command_gvisor()."""

    def _make_mock_docker(self):
        mock_container = MagicMock()
        mock_container.wait.return_value = {"StatusCode": 0}
        mock_container.logs.return_value = [b"\x01hello world"]
        mock_client = MagicMock()
        mock_client.containers.run.return_value = mock_container
        mock_docker = MagicMock()
        mock_docker.from_env.return_value = mock_client
        mock_docker.errors.ContainerError = Exception
        mock_docker.errors.ImageNotFound = Exception
        return mock_docker, mock_client, mock_container

    def test_gvisor_launches_container_with_network_none(self):
        """_run_command_gvisor launches container with network_mode='none'."""
        import sys
        from executor.executor import Executor
        from executor.command_validator import CommandValidator
        from executor.strategies.gvisor_strategy import GvisorStrategy
        from executor.strategies.base import InjectionResult

        mock_docker, mock_client, mock_container = self._make_mock_docker()

        original = sys.modules.get("docker")
        sys.modules["docker"] = mock_docker

        try:
            validator = CommandValidator()
            strategy = GvisorStrategy()

            executor = Executor(
                command_validator=validator,
                session_id="test-session",
                injection_strategy=strategy,
            )
            executor._injection_result = InjectionResult()
            executor._bundles = []

            result = executor._run_command_gvisor("echo hello", [], None, None)

            # Verify container was launched with correct params
            call_kwargs = mock_client.containers.run.call_args[1]
            assert call_kwargs["network_mode"] == "none"
            assert call_kwargs["runtime"] == "runsc"
        finally:
            if original is None:
                sys.modules.pop("docker", None)
            else:
                sys.modules["docker"] = original

    def test_gvisor_container_removed_after_execution(self):
        """_run_command_gvisor always removes the container after execution."""
        import sys
        from executor.executor import Executor
        from executor.command_validator import CommandValidator
        from executor.strategies.gvisor_strategy import GvisorStrategy
        from executor.strategies.base import InjectionResult

        mock_docker, mock_client, mock_container = self._make_mock_docker()

        original = sys.modules.get("docker")
        sys.modules["docker"] = mock_docker

        try:
            validator = CommandValidator()
            strategy = GvisorStrategy()

            executor = Executor(
                command_validator=validator,
                session_id="test-session",
                injection_strategy=strategy,
            )
            executor._injection_result = InjectionResult()
            executor._bundles = []

            executor._run_command_gvisor("echo test", [], None, None)

            assert mock_container.remove.called
        finally:
            if original is None:
                sys.modules.pop("docker", None)
            else:
                sys.modules["docker"] = original

    def test_gvisor_returns_command_result(self):
        """_run_command_gvisor returns a CommandResult with exit code and output."""
        import sys
        from executor.executor import Executor
        from executor.command_validator import CommandValidator
        from executor.strategies.gvisor_strategy import GvisorStrategy
        from executor.strategies.base import InjectionResult

        mock_container = MagicMock()
        mock_container.wait.return_value = {"StatusCode": 42}
        # Docker log format: 1-byte stream indicator + 7 padding bytes + payload
        stdout_chunk = b"\x01" + b"\x00" * 7 + b"stdout data"
        stderr_chunk = b"\x02" + b"\x00" * 7 + b"stderr data"
        mock_container.logs.return_value = [stdout_chunk, stderr_chunk]
        mock_client = MagicMock()
        mock_client.containers.run.return_value = mock_container
        mock_docker = MagicMock()
        mock_docker.from_env.return_value = mock_client
        mock_docker.errors.ContainerError = Exception
        mock_docker.errors.ImageNotFound = Exception

        original = sys.modules.get("docker")
        sys.modules["docker"] = mock_docker

        try:
            validator = CommandValidator()
            strategy = GvisorStrategy()

            executor = Executor(
                command_validator=validator,
                session_id="test-session",
                injection_strategy=strategy,
            )
            executor._injection_result = InjectionResult()
            executor._bundles = []

            result = executor._run_command_gvisor("exit 42", [], None, None)

            assert result.exit_code == 42
            assert b"stdout data" in result.stdout
            assert b"stderr data" in result.stderr
        finally:
            if original is None:
                sys.modules.pop("docker", None)
            else:
                sys.modules["docker"] = original

    def test_gvisor_with_allowed_hosts_creates_network(self, monkeypatch):
        """_run_command_gvisor creates a Docker network when allowed_hosts is provided."""
        import sys
        from executor.executor import Executor
        from executor.command_validator import CommandValidator
        from executor.strategies.gvisor_strategy import GvisorStrategy
        from executor.strategies.base import InjectionResult

        mock_container = MagicMock()
        mock_container.wait.return_value = {"StatusCode": 0}
        mock_container.logs.return_value = [b"\x01hello"]
        mock_network = MagicMock()
        mock_network.name = "venya-net-test123"
        mock_network.id = "net-abc123"
        mock_client = MagicMock()
        mock_client.containers.run.return_value = mock_container
        mock_client.networks.create.return_value = mock_network
        mock_docker = MagicMock()
        mock_docker.from_env.return_value = mock_client
        mock_docker.errors.ContainerError = Exception
        mock_docker.errors.ImageNotFound = Exception

        original = sys.modules.get("docker")
        sys.modules["docker"] = mock_docker

        try:
            validator = CommandValidator()
            strategy = GvisorStrategy()
            executor = Executor(
                command_validator=validator,
                session_id="test-session",
                injection_strategy=strategy,
            )
            executor._injection_result = InjectionResult()
            executor._bundles = []

            allowed_hosts = [{"host": "10.10.10.50", "port": 22}]

            def mock_apply_egress(*args, **kwargs):
                executor._egress_chain_name = "VENYA_EGRESS_test"

            monkeypatch.setattr(executor, "_apply_egress_rules", mock_apply_egress)

            def mock_subprocess_run(cmd, **kwargs):
                mock_result = MagicMock()
                mock_result.stdout = b""
                mock_result.stderr = b""
                mock_result.returncode = 0
                return mock_result

            monkeypatch.setattr("executor.executor.subprocess.run", mock_subprocess_run)

            result = executor._run_command_gvisor("echo hello", [], None, None, allowed_hosts=allowed_hosts)

            # Verify network was created
            call_args = mock_client.networks.create.call_args
            assert call_args is not None
            assert "venya-net" in call_args[0][0]
        finally:
            if original is None:
                sys.modules.pop("docker", None)
            else:
                sys.modules["docker"] = original

    def test_gvisor_with_allowed_hosts_uses_network_mode(self, monkeypatch):
        """_run_command_gvisor uses network=network_name when allowed_hosts is provided."""
        import sys
        from executor.executor import Executor
        from executor.command_validator import CommandValidator
        from executor.strategies.gvisor_strategy import GvisorStrategy
        from executor.strategies.base import InjectionResult

        mock_container = MagicMock()
        mock_container.wait.return_value = {"StatusCode": 0}
        mock_container.logs.return_value = [b"\x01hello"]
        mock_network = MagicMock()
        mock_network.name = "venya-net-test456"
        mock_network.id = "net-abc123"
        mock_client = MagicMock()
        mock_client.containers.run.return_value = mock_container
        mock_client.networks.create.return_value = mock_network
        mock_docker = MagicMock()
        mock_docker.from_env.return_value = mock_client
        mock_docker.errors.ContainerError = Exception
        mock_docker.errors.ImageNotFound = Exception

        original = sys.modules.get("docker")
        sys.modules["docker"] = mock_docker

        try:
            validator = CommandValidator()
            strategy = GvisorStrategy()
            executor = Executor(
                command_validator=validator,
                session_id="test-session",
                injection_strategy=strategy,
            )
            executor._injection_result = InjectionResult()
            executor._bundles = []

            allowed_hosts = [{"host": "10.10.10.50", "port": 22}]

            def mock_apply_egress(*args, **kwargs):
                executor._egress_chain_name = "VENYA_EGRESS_test"

            monkeypatch.setattr(executor, "_apply_egress_rules", mock_apply_egress)

            def mock_subprocess_run(cmd, **kwargs):
                mock_result = MagicMock()
                mock_result.stdout = b""
                mock_result.stderr = b""
                mock_result.returncode = 0
                return mock_result

            monkeypatch.setattr("executor.executor.subprocess.run", mock_subprocess_run)

            executor._run_command_gvisor("echo hello", [], None, None, allowed_hosts=allowed_hosts)

            # Verify container was launched with network name string, not "none"
            call_kwargs = mock_client.containers.run.call_args[1]
            assert isinstance(call_kwargs["network_mode"], str)
            assert call_kwargs["network_mode"] != "none"
            assert "venya-net" in call_kwargs["network_mode"]
        finally:
            if original is None:
                sys.modules.pop("docker", None)
            else:
                sys.modules["docker"] = original

    def test_gvisor_without_allowed_hosts_uses_network_none(self):
        """_run_command_gvisor uses network_mode='none' when allowed_hosts is empty."""
        import sys
        from executor.executor import Executor
        from executor.command_validator import CommandValidator
        from executor.strategies.gvisor_strategy import GvisorStrategy
        from executor.strategies.base import InjectionResult

        mock_docker, mock_client, mock_container = self._make_mock_docker()

        original = sys.modules.get("docker")
        sys.modules["docker"] = mock_docker

        try:
            validator = CommandValidator()
            strategy = GvisorStrategy()

            executor = Executor(
                command_validator=validator,
                session_id="test-session",
                injection_strategy=strategy,
            )
            executor._injection_result = InjectionResult()
            executor._bundles = []

            result = executor._run_command_gvisor("echo hello", [], None, None, allowed_hosts=[])

            call_kwargs = mock_client.containers.run.call_args[1]
            assert call_kwargs["network_mode"] == "none"
            # No network should be created
            mock_client.networks.create.assert_not_called()
        finally:
            if original is None:
                sys.modules.pop("docker", None)
            else:
                sys.modules["docker"] = original

    def test_gvisor_with_allowed_hosts_calls_egress_rules(self, monkeypatch):
        """_run_command_gvisor calls _apply_egress_rules when allowed_hosts is provided."""
        import sys
        from executor.executor import Executor
        from executor.command_validator import CommandValidator
        from executor.strategies.gvisor_strategy import GvisorStrategy
        from executor.strategies.base import InjectionResult

        mock_container = MagicMock()
        mock_container.wait.return_value = {"StatusCode": 0}
        mock_container.logs.return_value = [b"\x01hello"]
        mock_network = MagicMock()
        mock_network.name = "venya-net-test789"
        mock_network.id = "net-abc123"
        mock_client = MagicMock()
        mock_client.containers.run.return_value = mock_container
        mock_client.networks.create.return_value = mock_network
        mock_docker = MagicMock()
        mock_docker.from_env.return_value = mock_client
        mock_docker.errors.ContainerError = Exception
        mock_docker.errors.ImageNotFound = Exception

        original = sys.modules.get("docker")
        sys.modules["docker"] = mock_docker

        try:
            validator = CommandValidator()
            strategy = GvisorStrategy()
            executor = Executor(
                command_validator=validator,
                session_id="test-session",
                injection_strategy=strategy,
            )
            executor._injection_result = InjectionResult()
            executor._bundles = []

            egress_called = []

            def mock_apply_egress(allowed_hosts, network_name, session_uuid):
                egress_called.append((allowed_hosts, network_name, session_uuid))
                executor._egress_chain_name = f"VENYA_EGRESS_{session_uuid}"

            monkeypatch.setattr(executor, "_apply_egress_rules", mock_apply_egress)

            def mock_subprocess_run(cmd, **kwargs):
                mock_result = MagicMock()
                mock_result.stdout = b""
                mock_result.stderr = b""
                mock_result.returncode = 0
                return mock_result

            monkeypatch.setattr("executor.executor.subprocess.run", mock_subprocess_run)

            allowed_hosts = [{"host": "10.10.10.50", "port": 22}]
            executor._run_command_gvisor("echo hello", [], None, None, allowed_hosts=allowed_hosts)

            assert len(egress_called) == 1
            assert egress_called[0][0] == allowed_hosts
            assert "venya-net" in egress_called[0][1]
        finally:
            if original is None:
                sys.modules.pop("docker", None)
            else:
                sys.modules["docker"] = original

    def test_gvisor_with_allowed_hosts_cleans_up_network(self, monkeypatch):
        """_run_command_gvisor removes the Docker network in finally block."""
        import sys
        from executor.executor import Executor
        from executor.command_validator import CommandValidator
        from executor.strategies.gvisor_strategy import GvisorStrategy
        from executor.strategies.base import InjectionResult

        mock_container = MagicMock()
        mock_container.wait.return_value = {"StatusCode": 0}
        mock_container.logs.return_value = [b"\x01hello"]
        mock_network = MagicMock()
        mock_network.name = "venya-net-cleanup"
        mock_network.id = "net-abc123"
        mock_client = MagicMock()
        mock_client.containers.run.return_value = mock_container
        mock_client.networks.create.return_value = mock_network
        mock_docker = MagicMock()
        mock_docker.from_env.return_value = mock_client
        mock_docker.errors.ContainerError = Exception
        mock_docker.errors.ImageNotFound = Exception

        original = sys.modules.get("docker")
        sys.modules["docker"] = mock_docker

        try:
            validator = CommandValidator()
            strategy = GvisorStrategy()
            executor = Executor(
                command_validator=validator,
                session_id="test-session",
                injection_strategy=strategy,
            )
            executor._injection_result = InjectionResult()
            executor._bundles = []

            def mock_apply_egress(*args, **kwargs):
                executor._egress_chain_name = "VENYA_EGRESS_test"

            monkeypatch.setattr(executor, "_apply_egress_rules", mock_apply_egress)

            def mock_subprocess_run(cmd, **kwargs):
                mock_result = MagicMock()
                mock_result.stdout = b""
                mock_result.stderr = b""
                mock_result.returncode = 0
                return mock_result

            monkeypatch.setattr("executor.executor.subprocess.run", mock_subprocess_run)

            executor._run_command_gvisor("echo hello", [], None, None, allowed_hosts=[{"host": "10.10.10.50", "port": 22}])

            # Network should be removed in finally
            assert mock_network.remove.called
        finally:
            if original is None:
                sys.modules.pop("docker", None)
            else:
                sys.modules["docker"] = original

    def test_gvisor_with_allowed_hosts_cleans_up_egress_rules(self, monkeypatch):
        """_run_command_gvisor calls _cleanup_egress_rules in finally block."""
        import sys
        from executor.executor import Executor
        from executor.command_validator import CommandValidator
        from executor.strategies.gvisor_strategy import GvisorStrategy
        from executor.strategies.base import InjectionResult

        mock_container = MagicMock()
        mock_container.wait.return_value = {"StatusCode": 0}
        mock_container.logs.return_value = [b"\x01hello"]
        mock_network = MagicMock()
        mock_network.name = "venya-net-egress"
        mock_network.id = "net-abc123"
        mock_client = MagicMock()
        mock_client.containers.run.return_value = mock_container
        mock_client.networks.create.return_value = mock_network
        mock_docker = MagicMock()
        mock_docker.from_env.return_value = mock_client
        mock_docker.errors.ContainerError = Exception
        mock_docker.errors.ImageNotFound = Exception

        original = sys.modules.get("docker")
        sys.modules["docker"] = mock_docker

        try:
            validator = CommandValidator()
            strategy = GvisorStrategy()
            executor = Executor(
                command_validator=validator,
                session_id="test-session",
                injection_strategy=strategy,
            )
            executor._injection_result = InjectionResult()
            executor._bundles = []

            cleanup_called = []

            original_cleanup = executor._cleanup_egress_rules

            def mock_cleanup():
                cleanup_called.append(True)
                return original_cleanup()

            monkeypatch.setattr(executor, "_cleanup_egress_rules", mock_cleanup)

            def mock_apply_egress(*args, **kwargs):
                executor._egress_chain_name = "VENYA_EGRESS_test"

            monkeypatch.setattr(executor, "_apply_egress_rules", mock_apply_egress)

            def mock_subprocess_run(cmd, **kwargs):
                mock_result = MagicMock()
                mock_result.stdout = b""
                mock_result.stderr = b""
                mock_result.returncode = 0
                return mock_result

            monkeypatch.setattr("executor.executor.subprocess.run", mock_subprocess_run)

            executor._run_command_gvisor("echo hello", [], None, None, allowed_hosts=[{"host": "10.10.10.50", "port": 22}])

            assert len(cleanup_called) == 1
        finally:
            if original is None:
                sys.modules.pop("docker", None)
            else:
                sys.modules["docker"] = original


class TestCaptureContainerOutput:
    """Tests for Executor._capture_container_output()."""

    def _make_executor(self):
        from executor.executor import Executor
        from executor.command_validator import CommandValidator

        validator = CommandValidator()
        return Executor(
            command_validator=validator,
            session_id="test-session",
        )

    def test_separates_stdout_and_stderr(self):
        """_capture_container_output separates stdout and stderr by stream byte."""
        executor = self._make_executor()

        mock_container = MagicMock()
        # 8-byte Docker headers: \x01=stdout, \x02=stderr
        mock_container.logs.return_value = [
            b"\x01" + b"\x00" * 7 + b"hello",
            b"\x02" + b"\x00" * 7 + b"world",
            b"\x01" + b"\x00" * 7 + b" foo",
        ]

        stdout, stderr = executor._capture_container_output(mock_container)

        assert stdout == b"hello foo"
        assert stderr == b"world"

    def test_no_header_treated_as_stdout(self):
        """_capture_container_output treats chunks without headers as stdout."""
        executor = self._make_executor()

        mock_container = MagicMock()
        mock_container.logs.return_value = [
            b"no header line",
            b"\x02" + b"\x00" * 7 + b"stderr only",
        ]

        stdout, stderr = executor._capture_container_output(mock_container)

        assert stdout == b"no header line"
        assert stderr == b"stderr only"

    def test_short_chunk_without_header(self):
        """_capture_container_output handles short chunks (< 9 bytes) as stdout."""
        executor = self._make_executor()

        mock_container = MagicMock()
        mock_container.logs.return_value = [
            b"short",  # less than 9 bytes, no header
        ]

        stdout, stderr = executor._capture_container_output(mock_container)

        assert stdout == b"short"
        assert stderr == b""

    def test_empty_logs(self):
        """_capture_container_output handles empty logs."""
        executor = self._make_executor()

        mock_container = MagicMock()
        mock_container.logs.return_value = []

        stdout, stderr = executor._capture_container_output(mock_container)

        assert stdout == b""
        assert stderr == b""

    def test_logs_exception_returns_empty(self):
        """_capture_container_output returns empty on logs exception."""
        executor = self._make_executor()

        mock_container = MagicMock()
        mock_container.logs.side_effect = RuntimeError("connection lost")

        stdout, stderr = executor._capture_container_output(mock_container)

        assert stdout == b""
        assert stderr == b""


class TestExecuteWithAllowedHosts:
    """Tests for Executor.execute() with allowed_hosts parameter."""

    def _make_mock_docker(self):
        mock_container = MagicMock()
        mock_container.wait.return_value = {"StatusCode": 0}
        mock_container.logs.return_value = [b"\x01hello world"]
        mock_network = MagicMock()
        mock_network.name = "venya-net-test123"
        mock_network.id = "net-abc123"
        mock_client = MagicMock()
        mock_client.containers.run.return_value = mock_container
        mock_client.networks.create.return_value = mock_network
        mock_docker = MagicMock()
        mock_docker.from_env.return_value = mock_client
        mock_docker.errors.ContainerError = Exception
        mock_docker.errors.ImageNotFound = Exception
        return mock_docker, mock_client, mock_container

    def test_execute_with_allowed_hosts_passes_to_gvisor(self, monkeypatch):
        """execute() passes allowed_hosts to _run_command_gvisor."""
        import sys
        from executor.executor import Executor
        from executor.command_validator import CommandValidator
        from executor.strategies.gvisor_strategy import GvisorStrategy
        from executor.strategies.base import InjectionResult

        mock_docker, mock_client, mock_container = self._make_mock_docker()

        original = sys.modules.get("docker")
        sys.modules["docker"] = mock_docker

        try:
            validator = CommandValidator()
            strategy = GvisorStrategy()

            executor = Executor(
                command_validator=validator,
                session_id="test-session",
                injection_strategy=strategy,
            )

            # Mock strategy prepare to avoid /dev/shm dependency
            executor._injection_result = InjectionResult()
            executor._bundles = []

            # Mock _prepare_injections to return empty list
            monkeypatch.setattr(executor, "_prepare_injections", lambda secrets: [])

            gvisor_called_with = []

            original_gvisor = executor._run_command_gvisor

            def mock_gvisor(command, injections, env_override, cwd, allowed_hosts=None):
                gvisor_called_with.append(allowed_hosts)
                return original_gvisor(command, injections, env_override, cwd, allowed_hosts)

            monkeypatch.setattr(executor, "_run_command_gvisor", mock_gvisor)

            def mock_subprocess_run(cmd, **kwargs):
                mock_result = MagicMock()
                mock_result.stdout = b""
                mock_result.stderr = b""
                mock_result.returncode = 0
                return mock_result

            monkeypatch.setattr("executor.executor.subprocess.run", mock_subprocess_run)

            allowed_hosts = [{"host": "10.10.10.50", "port": 22}]
            executor.execute("/bin/echo hello", [], allowed_hosts=allowed_hosts)

            assert len(gvisor_called_with) == 1
            assert gvisor_called_with[0] == allowed_hosts
        finally:
            if original is None:
                sys.modules.pop("docker", None)
            else:
                sys.modules["docker"] = original

    def test_execute_without_allowed_hosts_passes_none(self, monkeypatch):
        """execute() passes None to _run_command_gvisor when no allowed_hosts."""
        import sys
        from executor.executor import Executor
        from executor.command_validator import CommandValidator
        from executor.strategies.gvisor_strategy import GvisorStrategy
        from executor.strategies.base import InjectionResult

        mock_docker, mock_client, mock_container = self._make_mock_docker()

        original = sys.modules.get("docker")
        sys.modules["docker"] = mock_docker

        try:
            validator = CommandValidator()
            strategy = GvisorStrategy()

            executor = Executor(
                command_validator=validator,
                session_id="test-session",
                injection_strategy=strategy,
            )

            # Mock strategy prepare to avoid /dev/shm dependency
            executor._injection_result = InjectionResult()
            executor._bundles = []

            # Mock _prepare_injections to return empty list
            monkeypatch.setattr(executor, "_prepare_injections", lambda secrets: [])

            gvisor_called_with = []

            original_gvisor = executor._run_command_gvisor

            def mock_gvisor(command, injections, env_override, cwd, allowed_hosts=None):
                gvisor_called_with.append(allowed_hosts)
                return original_gvisor(command, injections, env_override, cwd, allowed_hosts)

            monkeypatch.setattr(executor, "_run_command_gvisor", mock_gvisor)

            def mock_subprocess_run(cmd, **kwargs):
                mock_result = MagicMock()
                mock_result.stdout = b""
                mock_result.stderr = b""
                mock_result.returncode = 0
                return mock_result

            monkeypatch.setattr("executor.executor.subprocess.run", mock_subprocess_run)

            executor.execute("/bin/echo hello", [])

            assert len(gvisor_called_with) == 1
            assert gvisor_called_with[0] is None
        finally:
            if original is None:
                sys.modules.pop("docker", None)
            else:
                sys.modules["docker"] = original


class TestApplyEgressRules:
    """Tests for Executor._apply_egress_rules()."""

    def _make_executor(self):
        from executor.executor import Executor
        from executor.command_validator import CommandValidator

        validator = CommandValidator()
        return Executor(
            command_validator=validator,
            session_id="test-session",
        )

    def test_apply_egress_rules_creates_chain(self, monkeypatch):
        """_apply_egress_rules creates an iptables chain for the session."""
        executor = self._make_executor()
        allowed_hosts = [{"host": "10.10.10.50", "port": 22}]
        network_name = "venya-net-abc123"
        session_uuid = "test-uuid-1"

        called_commands = []

        def mock_run(cmd, **kwargs):
            called_commands.append(cmd)
            mock_result = MagicMock()
            mock_result.stdout = b""
            mock_result.stderr = b""
            mock_result.returncode = 0
            return mock_result

        monkeypatch.setattr("executor.executor.subprocess.run", mock_run)

        executor._apply_egress_rules(allowed_hosts, network_name, session_uuid)

        chain_name = f"VENYA_EGRESS_{session_uuid}"
        assert any(chain_name in cmd for cmd in called_commands)

    def test_apply_egress_rules_adds_dns_rules(self, monkeypatch):
        """_apply_egress_rules adds UDP and TCP port 53 DNS rules."""
        executor = self._make_executor()
        allowed_hosts = []
        network_name = "venya-net-abc123"
        session_uuid = "test-uuid-1"

        called_commands = []

        def mock_run(cmd, **kwargs):
            called_commands.append(cmd)
            mock_result = MagicMock()
            mock_result.stdout = b""
            mock_result.stderr = b""
            mock_result.returncode = 0
            return mock_result

        monkeypatch.setattr("executor.executor.subprocess.run", mock_run)

        executor._apply_egress_rules(allowed_hosts, network_name, session_uuid)

        dns_udp_cmds = [cmd for cmd in called_commands if "udp" in cmd]
        dns_tcp_cmds = [cmd for cmd in called_commands if "tcp" in cmd and "--dport" in cmd and "53" in cmd]
        assert any(any("dport" in item for item in cmd) and any("53" in item for item in cmd) for cmd in dns_udp_cmds)
        assert any(any("dport" in item for item in cmd) and any("53" in item for item in cmd) for cmd in dns_tcp_cmds)

    def test_apply_egress_rules_adds_host_rules(self, monkeypatch):
        """_apply_egress_rules adds ACCEPT rules for each allowed host:port."""
        executor = self._make_executor()
        allowed_hosts = [
            {"host": "10.10.10.50", "port": 22},
            {"host": "10.10.10.60", "port": 443},
        ]
        network_name = "venya-net-abc123"
        session_uuid = "test-uuid-1"

        called_commands = []

        def mock_run(cmd, **kwargs):
            called_commands.append(cmd)
            mock_result = MagicMock()
            mock_result.stdout = b""
            mock_result.stderr = b""
            mock_result.returncode = 0
            return mock_result

        monkeypatch.setattr("executor.executor.subprocess.run", mock_run)

        executor._apply_egress_rules(allowed_hosts, network_name, session_uuid)

        host22_cmds = [cmd for cmd in called_commands if "10.10.10.50" in cmd]
        host443_cmds = [cmd for cmd in called_commands if "10.10.10.60" in cmd]
        assert any(any("22" in item for item in cmd) for cmd in host22_cmds)
        assert any(any("443" in item for item in cmd) for cmd in host443_cmds)

    def test_apply_egress_rules_adds_drop_rule(self, monkeypatch):
        """_apply_egress_rules adds a final DROP ALL rule."""
        executor = self._make_executor()
        allowed_hosts = [{"host": "10.10.10.50", "port": 22}]
        network_name = "venya-net-abc123"
        session_uuid = "test-uuid-1"

        called_commands = []

        def mock_run(cmd, **kwargs):
            called_commands.append(cmd)
            mock_result = MagicMock()
            mock_result.stdout = b""
            mock_result.stderr = b""
            mock_result.returncode = 0
            return mock_result

        monkeypatch.setattr("executor.executor.subprocess.run", mock_run)

        executor._apply_egress_rules(allowed_hosts, network_name, session_uuid)

        assert any("DROP" in item for cmd in called_commands for item in cmd)

    def test_apply_egress_rules_attaches_to_forward_chain(self, monkeypatch):
        """_apply_egress_rules attaches the chain to the FORWARD chain."""
        executor = self._make_executor()
        allowed_hosts = []
        network_name = "venya-net-abc123"
        session_uuid = "test-uuid-1"

        called_commands = []

        def mock_run(cmd, **kwargs):
            called_commands.append(cmd)
            mock_result = MagicMock()
            mock_result.stdout = b""
            mock_result.stderr = b""
            mock_result.returncode = 0
            return mock_result

        monkeypatch.setattr("executor.executor.subprocess.run", mock_run)

        executor._apply_egress_rules(allowed_hosts, network_name, session_uuid)

        chain_short = network_name[:12]
        chain_name = f"VENYA_EGRESS_{session_uuid}"
        assert any(f"br-{chain_short}" in cmd and chain_name in cmd for cmd in called_commands)

    def test_apply_egress_rules_stores_chain_name(self, monkeypatch):
        """_apply_egress_rules stores the chain name for cleanup."""
        executor = self._make_executor()
        allowed_hosts = []
        network_name = "venya-net-abc123"
        session_uuid = "test-uuid-1"

        called_commands = []

        def mock_run(cmd, **kwargs):
            called_commands.append(cmd)
            mock_result = MagicMock()
            mock_result.stdout = b""
            mock_result.stderr = b""
            mock_result.returncode = 0
            return mock_result

        monkeypatch.setattr("executor.executor.subprocess.run", mock_run)

        executor._apply_egress_rules(allowed_hosts, network_name, session_uuid)

        assert executor._egress_chain_name == f"VENYA_EGRESS_{session_uuid}"

    def test_apply_egress_rules_fails_on_iptables_error(self, monkeypatch):
        """_apply_egress_rules raises RuntimeError when iptables fails."""
        executor = self._make_executor()
        allowed_hosts = []
        network_name = "venya-net-abc123"
        session_uuid = "test-uuid-1"

        def mock_run(cmd, **kwargs):
            error = subprocess.CalledProcessError(1, cmd)
            error.stderr = b"iptables error"
            raise error

        monkeypatch.setattr("executor.executor.subprocess.run", mock_run)

        try:
            executor._apply_egress_rules(allowed_hosts, network_name, session_uuid)
            assert False, "Expected RuntimeError"
        except RuntimeError as e:
            assert "iptables" in str(e).lower() or "egress" in str(e).lower()


class TestCleanupEgressRules:
    """Tests for Executor._cleanup_egress_rules()."""

    def _make_executor(self):
        from executor.executor import Executor
        from executor.command_validator import CommandValidator

        validator = CommandValidator()
        return Executor(
            command_validator=validator,
            session_id="test-session",
        )

    def test_cleanup_flushes_chain(self, monkeypatch):
        """_cleanup_egress_rules flushes the iptables chain."""
        executor = self._make_executor()
        executor._egress_chain_name = "VENYA_EGRESS_test-uuid"

        called_commands = []

        def mock_run(cmd, **kwargs):
            called_commands.append(cmd)
            mock_result = MagicMock()
            mock_result.stdout = b""
            mock_result.stderr = b""
            mock_result.returncode = 0
            return mock_result

        monkeypatch.setattr("executor.executor.subprocess.run", mock_run)

        executor._cleanup_egress_rules()

        assert any("VENYA_EGRESS_test-uuid" in cmd and ("-F" in cmd or "--flush" in cmd) for cmd in called_commands)

    def test_cleanup_deletes_chain(self, monkeypatch):
        """_cleanup_egress_rules deletes the iptables chain."""
        executor = self._make_executor()
        executor._egress_chain_name = "VENYA_EGRESS_test-uuid"

        called_commands = []

        def mock_run(cmd, **kwargs):
            called_commands.append(cmd)
            mock_result = MagicMock()
            mock_result.stdout = b""
            mock_result.stderr = b""
            mock_result.returncode = 0
            return mock_result

        monkeypatch.setattr("executor.executor.subprocess.run", mock_run)

        executor._cleanup_egress_rules()

        assert any("VENYA_EGRESS_test-uuid" in cmd and "-X" in cmd for cmd in called_commands)

    def test_cleanup_is_noop_when_no_chain(self, monkeypatch):
        """_cleanup_egress_rules is a no-op when no chain was set."""
        executor = self._make_executor()
        executor._egress_chain_name = None

        called_commands = []

        def mock_run(cmd, **kwargs):
            called_commands.append(cmd)
            mock_result = MagicMock()
            mock_result.stdout = b""
            mock_result.stderr = b""
            mock_result.returncode = 0
            return mock_result

        monkeypatch.setattr("executor.executor.subprocess.run", mock_run)

        executor._cleanup_egress_rules()

        assert called_commands == []


class TestFilterAndBuildResult:
    """Tests for Executor._filter_and_build_result()."""

    def _make_executor(self):
        from executor.executor import Executor
        from executor.command_validator import CommandValidator

        validator = CommandValidator()
        return Executor(
            command_validator=validator,
            session_id="test-session",
        )

    def test_uses_stage1_results_without_http_client(self):
        """_filter_and_build_result uses Stage 1 results when no HTTP client."""
        from unittest.mock import patch

        executor = self._make_executor()
        executor.http_client = None

        stage1_stdout = b"hello [REDACTED:z1z1z1z1] world"

        with patch("executor.executor.filter_and_redact", return_value=(stage1_stdout, b"", ["z1z1z1z1"], [])):
            result = executor._filter_and_build_result(
                "echo test", 0, b"hello secret world", b"", []
            )

        assert result.stdout == stage1_stdout
        assert result.masked_secret_ids == ["z1z1z1z1"]

    def test_uses_stage2_results_when_http_client_available(self):
        """_filter_and_build_result uses Stage 2 results when HTTP client is available."""
        from unittest.mock import patch
        import base64

        executor = self._make_executor()

        stage2_stdout = b"server filtered [REDACTED:y2y2y2y2]"
        mock_response = MagicMock()
        mock_response.json.return_value = {
            "stdout": base64.b64encode(stage2_stdout).decode(),
            "stderr": base64.b64encode(b"").decode(),
            "masked_hashes": ["y2y2y2y2"],
        }
        executor.http_client = MagicMock()
        executor.http_client.post.return_value = mock_response

        with patch("executor.executor.filter_and_redact", return_value=(b"local", b"", ["x1x1x1x1"], [])):
            result = executor._filter_and_build_result(
                "echo test", 0, b"raw output", b"", []
            )

        assert result.stdout == stage2_stdout
        assert result.masked_secret_ids == ["y2y2y2y2"]

    def test_falls_back_to_stage1_on_stage2_failure(self):
        """_filter_and_build_result falls back to Stage 1 when Stage 2 fails."""
        from unittest.mock import patch
        import httpx

        executor = self._make_executor()
        stage1_stdout = b"local [REDACTED:z1z1z1z1]"

        executor.http_client = MagicMock()
        executor.http_client.post.side_effect = httpx.RequestError(
            "Connection refused", request=MagicMock()
        )

        with patch("executor.executor.filter_and_redact", return_value=(stage1_stdout, b"", ["z1z1z1z1"], [])):
            result = executor._filter_and_build_result(
                "echo test", 0, b"raw", b"", []
            )

        assert result.stdout == stage1_stdout
        assert result.masked_secret_ids == ["z1z1z1z1"]

    def test_truncation_flag_set_on_large_output(self):
        """_filter_and_build_result sets output_truncated when output exceeds limit."""
        from unittest.mock import patch

        executor = self._make_executor()
        executor.http_client = None

        large_output = b"x" * 300000  # exceeds MAX_OUTPUT_BYTES (262144)

        with patch("executor.executor.filter_and_redact", return_value=(large_output, b"", [], [])):
            result = executor._filter_and_build_result(
                "echo test", 0, large_output, b"", []
            )

        assert result.output_truncated is True
        assert result.original_stdout_size == 300000

    def test_truncation_flag_not_set_on_small_output(self):
        """_filter_and_build_result does not set output_truncated for small output."""
        from unittest.mock import patch

        executor = self._make_executor()
        executor.http_client = None

        small_output = b"small"

        with patch("executor.executor.filter_and_redact", return_value=(small_output, b"", [], [])):
            result = executor._filter_and_build_result(
                "echo test", 0, small_output, b"", []
            )

        assert result.output_truncated is False
        assert result.original_stdout_size == 5
