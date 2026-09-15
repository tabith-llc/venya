# Copyright (c) 2026 Tabith LLC.
# Use of this source code is governed by the Business Source License 1.1
# included in the LICENSE file at the root of this repository. As of the
# Change Date listed there, the work is available under MPL 2.0.
# SPDX-License-Identifier: BUSL-1.1

"""Factory for creating injection strategies.

SbxStrategy is the sole execution strategy.
"""

from .base import InjectionStrategy
from .sbx_strategy import SbxStrategy


def create_strategy(method: str, secret_base_fd: int = 100) -> InjectionStrategy:
    """Create an injection strategy.

    Only sbx is supported. The method parameter is ignored.

    Args:
        method: Strategy name (ignored — sbx is the only strategy).
        secret_base_fd: Base FD number for injected secrets (unused for sbx).

    Returns:
        An initialized SbxStrategy instance.
    """
    return SbxStrategy(secret_base_fd=secret_base_fd)
