# Copyright (c) 2026 Tabith LLC.
# Use of this source code is governed by the Business Source License 1.1
# included in the LICENSE file at the root of this repository. As of the
# Change Date listed there, the work is available under MPL 2.0.
# SPDX-License-Identifier: BUSL-1.1

"""Credential injection helpers: sentinel wrap/strip, registry, FD hygiene.

What actually runs here: the sentinel envelope (``wrap_with_sentinel`` /
``strip_sentinel``) that the relay hands to the engine, the per-session
``SentinelRegistry`` the executor audits with, and the descriptor-hygiene helpers
(``verify_fd_whitelist``, ``scan_open_fds``, ``set_cloexec``).

The FD-injection trio (``inject_via_file`` / ``inject_via_memfd`` /
``inject_via_fifo``) and ``parse_sentinels`` shipped here until #471 deleted them
with no product caller left; secret staging is ``SbxStrategy``'s job (host tmpfs,
copied into the sandbox), so no descriptor-injection path and no ``memfd`` call is
left in this module.
"""

import base64
import hashlib
import logging
import os
import re
from dataclasses import dataclass, field
from typing import NamedTuple

logger = logging.getLogger("venya.executor.injector")


class SecretInjection(NamedTuple):
    """Represents a secret injected into a target process."""

    secret_id: str
    injection_path: str  # staging path the caller hands to the child (tmpfs today)
    sentinel_hash: str  # 8-char hex hash for audit trail


@dataclass
class SentinelRegistry:
    """In-memory sentinel registry per session.

    Maps hash prefixes to secret IDs for audit trail.
    Cleared when session ends.
    """

    session_id: str
    _sentinels: dict[str, str] = field(default_factory=dict)

    def register(self, secret_id: str, sentinel_hash: str) -> None:
        """Register a sentinel mapping.

        Args:
            secret_id: The secret identifier.
            sentinel_hash: 8-char hex hash prefix from the sentinel.
        """
        self._sentinels[sentinel_hash] = secret_id
        logger.debug("Registered sentinel %s -> %s", sentinel_hash, secret_id)

    def get_secret_id(self, sentinel_hash: str) -> str | None:
        """Look up secret ID by sentinel hash.

        Args:
            sentinel_hash: 8-char hex hash prefix.

        Returns:
            Secret ID or None if not found.
        """
        return self._sentinels.get(sentinel_hash)

    def get_session_hashes(self) -> set[str]:
        """Get all registered sentinel hashes.

        Returns:
            Set of 8-char hex hash strings.
        """
        return set(self._sentinels.keys())

    def clear(self) -> None:
        """Clear all registered sentinels."""
        self._sentinels.clear()

    def validate_hash(self, sentinel_hash: str) -> bool:
        """Validate that a sentinel hash is registered for this session.

        Args:
            sentinel_hash: 8-char hex hash prefix to validate.

        Returns:
            True if the hash is registered, False otherwise.
        """
        found = sentinel_hash in self._sentinels
        if not found:
            logger.warning(
                "Unrecognized sentinel hash %s in session %s",
                sentinel_hash,
                self.session_id,
            )
        return found


SENTINEL_PATTERN = re.compile(
    rb"\[VENYA:([a-f0-9]{8})\]"  # [VENYA:{8-hex-char-hash}]
    rb"([A-Za-z0-9+/]*)"  # base64 data (safe: [ cannot appear in base64)
    rb"(=*)"  # optional padding
    rb"\[/VENYA\]"  # closing tag
)
SENTINEL_PREFIX_PATTERN = re.compile(rb"\[VENYA:([a-f0-9]{8})\]")


def wrap_with_sentinel(secret_id: str, secret_value: bytes) -> bytes:
    """Wrap a secret value with a sentinel.

    Format: [VENYA:{8-char-hex-hash}]base64_data[/VENYA]

    Args:
        secret_id: The secret identifier.
        secret_value: The raw secret bytes.

    Returns:
        Sentinel-wrapped bytes.
    """
    hash_prefix = hashlib.sha256(secret_id.encode()).hexdigest()[:8]
    encoded = base64.b64encode(secret_value).decode()
    wrapped = f"[VENYA:{hash_prefix}]{encoded}[/VENYA]"
    return wrapped.encode()


def strip_sentinel(wrapped: bytes) -> bytes:
    """Strip sentinels from wrapped data.

    Removes [VENYA:{hash}] prefix and [/VENYA] suffix.
    Target process sees plaintext only.

    The regex uses an explicit base64 character class [A-Za-z0-9+/=]
    for the data portion. This guarantees the sentinel delimiters
    [VENYA: and [/VENYA] can never appear inside the encoded data,
    making the pattern safe against greedy/non-greedy matching issues
    even with multiple sentinels in a single buffer.

    Args:
        wrapped: Sentinel-wrapped bytes.

    Returns:
        Unwrapped secret bytes, or original if no sentinel found.
    """
    match = SENTINEL_PATTERN.search(wrapped)
    if match:
        hash_prefix = match.group(1).decode()
        encoded_data = match.group(2) + match.group(3)
        logger.debug("Stripped sentinel %s", hash_prefix)
        return base64.b64decode(encoded_data)
    return wrapped


def verify_fd_whitelist(open_fds: set[int], allowed_fds: set[int] | None = None) -> list[int]:
    """Verify that only allowed FDs are open.

    Default-deny model: only FDs 0, 1, 2 are allowed unless
    explicitly annotated.

    Args:
        open_fds: Set of currently open FD numbers.
        allowed_fds: Explicitly allowed additional FDs (beyond 0,1,2).

    Returns:
        List of unexpected FDs found.
    """
    if allowed_fds is None:
        allowed_fds = set()

    expected = {0, 1, 2} | allowed_fds
    unexpected = open_fds - expected
    return sorted(unexpected)


def scan_open_fds(pid: int | None = None) -> set[int] | None:
    """Scan open file descriptors for a process.

    Args:
        pid: Process ID to scan. Defaults to current process.

    Returns:
        Set of open FD numbers, or None when /proc/<pid>/fd could not be read.
        Returning None (rather than an empty set) keeps "could not look"
        distinguishable from "looked and found nothing" (#453).
    """
    if pid is None:
        pid = os.getpid()

    fd_dir = f"/proc/{pid}/fd"
    try:
        return {int(fd) for fd in os.listdir(fd_dir)}
    except (FileNotFoundError, PermissionError):
        return None


def set_cloexec(fd: int) -> None:
    """Set FD_CLOEXEC on a file descriptor.

    Args:
        fd: File descriptor number.
    """
    import fcntl

    flags = fcntl.fcntl(fd, fcntl.F_GETFD)
    fcntl.fcntl(fd, fcntl.F_SETFD, flags | fcntl.FD_CLOEXEC)
