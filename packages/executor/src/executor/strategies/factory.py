"""Factory for creating injection strategies.

Registry-based strategy selection driven by configuration.
"""


from .base import InjectionStrategy
from .memfd_strategy import MemfdStrategy
from .sbx_strategy import SbxStrategy

STRATEGY_REGISTRY: dict[str, type[InjectionStrategy]] = {
    "memfd": MemfdStrategy,
    "sbx": SbxStrategy,
}


def create_strategy(method: str, secret_base_fd: int = 100) -> InjectionStrategy:
    """Create an injection strategy by name.

    Args:
        method: Strategy name ("memfd" or "sbx").
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
