# Copyright (c) 2026 Tabith LLC.
# Use of this source code is governed by the Business Source License 1.1
# included in the LICENSE file at the root of this repository. As of the
# Change Date listed there, the work is available under MPL 2.0.
# SPDX-License-Identifier: BUSL-1.1

"""Executor ID validation utility for CLI.

Provides strict pattern-based validation for executor identifiers.
Executor IDs are used in certificate CN/SAN fields, TOML config sections,
and shell scripts — so they must follow a tight allowlist.

Pattern: ^[a-z0-9][a-z0-9-]{0,62}[a-z0-9]$
- Lowercase alphanumeric + hyphens only (no underscores)
- 2–64 characters
- Starts and ends with alphanumeric
- DNS-label compatible (RFC 1035)
"""

import re

EXECUTOR_ID_PATTERN = r"^[a-z0-9][a-z0-9-]{0,62}[a-z0-9]$"
EXECUTOR_ID_MAX_LENGTH = 64
EXECUTOR_ID_MIN_LENGTH = 2

_EXECUTOR_ID_RE = re.compile(EXECUTOR_ID_PATTERN)


def validate_executor_id(executor_id: str) -> str:
    """Validate an executor_id against the strict allowlist pattern.

    Args:
        executor_id: The executor ID to validate.

    Returns:
        The validated executor_id (unchanged if valid).

    Raises:
        ValueError: If the executor_id does not match the pattern.
    """
    if not executor_id or not isinstance(executor_id, str):
        raise ValueError("Invalid executor_id: must be a non-empty string")
    if len(executor_id) < EXECUTOR_ID_MIN_LENGTH or len(executor_id) > EXECUTOR_ID_MAX_LENGTH:
        raise ValueError(
            f"Invalid executor_id: must be {EXECUTOR_ID_MIN_LENGTH}-{EXECUTOR_ID_MAX_LENGTH} characters, "
            f"got {len(executor_id)}"
        )
    if not _EXECUTOR_ID_RE.match(executor_id):
        raise ValueError(
            "Invalid executor_id: must be lowercase alphanumeric with "
            "optional hyphens, starting and ending with alphanumeric"
        )
    return executor_id
