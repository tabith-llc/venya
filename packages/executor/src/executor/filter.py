"""Stage 1 output filtering wrapper.

Wraps the Rust extension (venya_filter) for content hash matching.
The Rust extension implements a 3-stage cascade:
  1. First-byte pre-filter (first_byte_filter_idx[256])
  2. FNV-1a pre-filter (FnvTable)
  3. SHA-256 verification

This module provides the Python API that the executor uses.
"""

from __future__ import annotations

import logging
from typing import Any

from venya_filter import compute_detection_hashes  # type: ignore[attr-defined]
from venya_filter import filter_output as _filter_output  # type: ignore[attr-defined]

logger = logging.getLogger("venya.executor.filter")

# Hard-fail: executor must have the Rust filter module available

__all__ = [
    "compute_detection_hashes",
    "build_filter_entries",
    "filter_output",
    "filter_and_redact",
]


def build_filter_entries(
    secrets: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    """Build filter entries from secret data.

    Each entry contains the secret_id, its detection hashes,
    and the raw secret value for matching.

    Args:
        secrets: List of secret dicts with 'secret_id', 'value', and optionally 'hashes'.

    Returns:
        List of filter entries compatible with the Rust extension.
    """
    entries = []
    for secret in secrets:
        secret_id = secret["secret_id"]
        value = secret["value"]

        if "hashes" in secret:
            hashes = secret["hashes"]
        else:
            hashes = compute_detection_hashes(value)

        entries.append({
            "secret_id": secret_id,
            "hashes": hashes,
            "secret_value": value,
        })

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

    masked_stdout, stdout_ids = filter_output(
        stdout, entries, _window_size, _min_match_length,
    )
    masked_stderr, stderr_ids = filter_output(
        stderr, entries, _window_size, _min_match_length,
    )

    return masked_stdout, masked_stderr, stdout_ids, stderr_ids
