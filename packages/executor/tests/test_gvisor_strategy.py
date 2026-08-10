"""Tests for GvisorStrategy."""

from executor.strategies.gvisor_strategy import GvisorStrategy


class TestGvisorStrategyName:
    """Tests for GvisorStrategy.name()."""

    def test_returns_gvisor(self):
        """name() returns 'gvisor'."""
        strategy = GvisorStrategy()
        assert strategy.name() == "gvisor"
