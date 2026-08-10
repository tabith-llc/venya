"""Tests for GvisorStrategy."""

from executor.strategies.gvisor_strategy import GvisorStrategy


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
