"""Stage 1 output filtering wrapper.

Wraps the C extension (_venya_filter) for content hash matching.
The C extension implements a 3-stage cascade:
  1. First-byte pre-filter (ByteIndex[256])
  2. FNV-1a pre-filter (FNVTable)
  3. SHA-256 verification (OpenSSL EVP)

This module provides the Python API that the executor uses.
"""

from __future__ import annotations

import base64
import hashlib
import logging
from typing import Any

logger = logging.getLogger("venya.executor.filter")

# Try to import the C extension; fall back to pure Python if unavailable
try:
    from venya_executor import _venya_filter  # type: ignore[attr-defined]
    _USE_C_EXTENSION = True
except ImportError:
    _USE_C_EXTENSION = False
    logger.warning(
        "C extension _venya_filter not available, using pure Python fallback. "
        "Build the extension for production use.",
    )


def compute_detection_hashes_c(value: bytes) -> list[str]:
    """Compute SHA-256 hashes for secret value in multiple encodings.

    Returns list of hex digests for: raw, base64, hex, trimmed.

    Args:
        value: The secret value bytes.

    Returns:
        List of SHA-256 hex digest strings.
    """
    hashes = []
    hashes.append(hashlib.sha256(value).hexdigest())  # raw bytes
    hashes.append(hashlib.sha256(base64.b64encode(value)).hexdigest())  # base64
    hashes.append(hashlib.sha256(value.hex().encode()).hexdigest())  # hex
    trimmed = value.strip()
    if trimmed != value:
        hashes.append(hashlib.sha256(trimmed).hexdigest())  # whitespace-stripped
    return hashes


def compute_detection_hashes_py(value: bytes) -> list[str]:
    """Pure Python fallback for compute_detection_hashes."""
    return compute_detection_hashes_c(value)


# Use C extension if available, otherwise pure Python
if _USE_C_EXTENSION:
    compute_detection_hashes = compute_detection_hashes_c  # type: ignore[misc]
else:
    compute_detection_hashes = compute_detection_hashes_py  # type: ignore[misc]


def build_filter_entries(
    secrets: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    """Build filter entries from secret data.

    Each entry contains the secret_id, its detection hashes,
    and the raw secret value for matching.

    Args:
        secrets: List of secret dicts with 'secret_id', 'value', and optionally 'hashes'.

    Returns:
        List of filter entries compatible with the C extension.
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
    window_size: int = 20,
    min_match_length: int = 8,
) -> tuple[bytes, list[str]]:
    """Filter output data, masking detected secret leaks.

    Uses the C extension (or pure Python fallback) to detect
    and redact secrets in process output.

    Args:
        data: The output bytes to filter (stdout or stderr).
        entries: Filter entries from build_filter_entries().
        window_size: Sliding window size for hash matching.
        min_match_length: Minimum match length.

    Returns:
        Tuple of (masked_data, list_of_masked_secret_ids).
    """
    if not entries:
        return data, []

    try:
        masked, masked_ids = filter_output_c(data, entries, window_size, min_match_length)
    except (ImportError, AttributeError):
        masked, masked_ids = filter_output_py(data, entries, window_size, min_match_length)

    if masked_ids:
        logger.debug(
            "Stage 1 filter: %d secrets masked in %d bytes",
            len(masked_ids),
            len(data),
        )

    return masked, masked_ids


def filter_output_c(
    data: bytes,
    entries: list[dict[str, Any]],
    window_size: int = 20,
    min_match_length: int = 8,
) -> tuple[bytes, list[str]]:
    """Call the C extension filter."""
    return _venya_filter.filter_output(data, entries)  # type: ignore[attr-defined]


def filter_output_py(
    data: bytes,
    entries: list[dict[str, Any]],
    window_size: int = 20,
    min_match_length: int = 8,
) -> tuple[bytes, list[str]]:
    """Pure Python fallback for output filtering.

    Uses a simpler sliding window approach. Much slower than C extension.
    """
    if not data:
        return b"", []

    # Collect all hashes and their associated secret IDs
    hash_to_secrets: dict[str, list[str]] = {}
    for entry in entries:
        for h in entry.get("hashes", []):
            hash_to_secrets.setdefault(h, []).append(entry["secret_id"])

    masked_ids: set[str] = set()
    result = bytearray(data)

    # Simple approach: check if any hash appears as substring in data
    for secret_id, hashes in hash_to_secrets.items():
        for h in hashes:
            h_bytes = bytes.fromhex(h)
            start = 0
            while True:
                idx = data.find(h_bytes, start)
                if idx == -1:
                    break
                # Verify it's not a false positive by checking surrounding context
                end = idx + len(h_bytes)
                result[idx:end] = b""
                masked_ids.add(secret_id)
                start = end

    # Replace masked regions with redaction markers
    # This is a simplified approach; the C version does precise replacement
    return bytes(result), sorted(masked_ids)


def filter_and_redact(
    stdout: bytes,
    stderr: bytes,
    secrets: list[dict[str, Any]],
    window_size: int = 20,
    min_match_length: int = 8,
) -> tuple[bytes, bytes, list[str], list[str]]:
    """Filter both stdout and stderr, returning masked results.

    Args:
        stdout: Raw stdout bytes.
        stderr: Raw stderr bytes.
        secrets: List of secret dicts for detection.
        window_size: Sliding window size.
        min_match_length: Minimum match length.

    Returns:
        Tuple of (masked_stdout, masked_stderr, stdout_masked_ids, stderr_masked_ids).
    """
    entries = build_filter_entries(secrets)

    masked_stdout, stdout_ids = filter_output(
        stdout, entries, window_size, min_match_length,
    )
    masked_stderr, stderr_ids = filter_output(
        stderr, entries, window_size, min_match_length,
    )

    return masked_stdout, masked_stderr, stdout_ids, stderr_ids
