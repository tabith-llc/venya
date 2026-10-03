# Copyright (c) 2026 Tabith LLC.
# Use of this source code is governed by the Business Source License 1.1
# included in the LICENSE file at the root of this repository. As of the
# Change Date listed there, the work is available under MPL 2.0.
# SPDX-License-Identifier: BUSL-1.1

"""Stage 1 output filtering wrapper.

Wraps the Rust extension (venya_filter) for content hash matching.
The Rust extension implements a 3-stage cascade:
  1. First-byte pre-filter (first_byte_filter_idx[256])
  2. FNV-1a pre-filter (FnvTable)
  3. SHA-256 verification

This module provides the Python API that the executor uses.
"""

import logging
from typing import Any

from venya_filter import filter_output as _filter_output  # type: ignore[attr-defined]
from venya_filter import filter_outputs as _filter_outputs  # type: ignore[attr-defined]

logger = logging.getLogger("venya.executor.filter")

# Hard-fail: executor must have the Rust filter module available

__all__ = [
    "build_filter_entries",
    "filter_and_redact",
    "filter_output",
]

# The Rust extension stores secret ids in a fixed 64-byte slot.
_MAX_SECRET_ID_BYTES = 64


def build_filter_entries(
    secrets: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    """Build filter entries from secret data.

    Each entry carries the secret_id and the raw secret value. The Rust
    extension reconstructs every detection variant (raw, base64, hex,
    trimmed) from the value, so no precomputed hashes are sent.

    Args:
        secrets: List of secret dicts with 'secret_id' (str) and
            'value' (bytes). Extra keys (e.g. a legacy 'hashes' key)
            are ignored.

    Returns:
        List of filter entries compatible with the Rust extension.

    Raises:
        TypeError: If secret_id is not str or value is not bytes.
        ValueError: If secret_id exceeds the 64-byte FFI slot.
    """
    entries = []
    for i, secret in enumerate(secrets):
        secret_id = secret["secret_id"]
        value = secret["value"]

        if not isinstance(secret_id, str):
            raise TypeError(
                f"secret entry {i}: secret_id must be str, got {type(secret_id).__name__}"
            )
        if not isinstance(value, bytes):
            raise TypeError(
                f"secret entry {i} (secret_id={secret_id!r}): "
                f"value must be bytes, got {type(value).__name__}"
            )
        id_bytes = len(secret_id.encode("utf-8"))
        if id_bytes > _MAX_SECRET_ID_BYTES:
            raise ValueError(
                f"secret entry {i} (secret_id={secret_id!r}): "
                f"secret_id must be at most {_MAX_SECRET_ID_BYTES} bytes, got {id_bytes}"
            )

        entries.append(
            {
                "secret_id": secret_id,
                "secret_value": value,
            }
        )

    return entries


def filter_output(
    data: bytes,
    entries: list[dict[str, Any]],
    _window_size: int = 20,
    _min_match_length: int = 8,
) -> tuple[bytes, list[str]]:
    """Filter output data, masking detected secret leaks.

    Uses the Rust extension to detect and redact secrets in process output.

    Args:
        data: The output bytes to filter (stdout or stderr).
        entries: Filter entries from build_filter_entries().
        _window_size: Unused (retained for API compatibility).
        _min_match_length: Unused (retained for API compatibility).

    Returns:
        Tuple of (masked_data, list_of_masked_secret_ids).
    """
    if not entries:
        return data, []

    masked, masked_ids = _filter_output(data, entries)

    if masked_ids:
        logger.debug(
            "Stage 1 filter: %d secrets masked in %d bytes",
            len(masked_ids),
            len(data),
        )

    return masked, masked_ids


def filter_and_redact(
    stdout: bytes,
    stderr: bytes,
    secrets: list[dict[str, Any]],
    _window_size: int = 20,
    _min_match_length: int = 8,
) -> tuple[bytes, bytes, list[str], list[str]]:
    """Filter both stdout and stderr, returning masked results.

    Args:
        stdout: Raw stdout bytes.
        stderr: Raw stderr bytes.
        secrets: List of secret dicts for detection.
        _window_size: Unused (retained for API compatibility).
        _min_match_length: Unused (retained for API compatibility).

    Returns:
        Tuple of (masked_stdout, masked_stderr, stdout_masked_ids, stderr_masked_ids).
    """
    entries = build_filter_entries(secrets)

    if not entries:
        return stdout, stderr, [], []

    masked_stdout, masked_stderr, stdout_ids, stderr_ids = _filter_outputs(stdout, stderr, entries)

    if stdout_ids or stderr_ids:
        logger.debug(
            "Stage 1 filter: %d stdout / %d stderr secrets masked in %d/%d bytes",
            len(stdout_ids),
            len(stderr_ids),
            len(stdout),
            len(stderr),
        )

    return masked_stdout, masked_stderr, stdout_ids, stderr_ids
