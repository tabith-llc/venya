"""Tests for GvisorStrategy."""

from executor.strategies.gvisor_strategy import GvisorStrategy
from unittest.mock import patch


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
