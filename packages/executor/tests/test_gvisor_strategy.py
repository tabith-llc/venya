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
