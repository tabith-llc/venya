"""Factory for creating injection strategies.

Registry-based strategy selection driven by configuration.
"""

from __future__ import annotations

from .base import InjectionStrategy
from .gvisor_strategy import GvisorStrategy
from .memfd_strategy import MemfdStrategy

STRATEGY_REGISTRY: dict[str, type[InjectionStrategy]] = {
    "memfd": MemfdStrategy,
    "gvisor": GvisorStrategy,
}


def create_strategy(method: str, secret_base_fd: int = 100) -> InjectionStrategy:
    """Create an injection strategy by name.

    Args:
        method: Strategy name ("memfd" or "gvisor").
        secret_base_fd: Base FD number for injected secrets (memfd only).

    Returns:
        An initialized InjectionStrategy instance.

    Raises:
        ValueError: If the strategy name is unknown.
    """
    cls = STRATEGY_REGISTRY.get(method)
    if cls is None:
        raise ValueError(
            f"Unknown injection strategy: {method!r}. "
            f"Available: {list(STRATEGY_REGISTRY.keys())}"
        )
    return cls(secret_base_fd=secret_base_fd)
