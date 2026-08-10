"""Tests for GvisorStrategy."""

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
