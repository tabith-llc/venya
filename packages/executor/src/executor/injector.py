"""Credential injection via file descriptors.

Handles sentinel stripping, FD injection (memfd/shm/fifo),
and sentinel registry management.
"""

from __future__ import annotations

import base64
import hashlib
import logging
import os
import re
import tempfile
from dataclasses import dataclass, field
from typing import NamedTuple

logger = logging.getLogger("venya.executor.injector")


class SecretInjection(NamedTuple):
    """Represents a secret injected into a target process."""

    secret_id: str
    injection_path: str  # path to tmpfs file or memfd name
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
    rb"([A-Za-z0-9+/]*)"          # base64 data (safe: [ cannot appear in base64)
    rb"(=*)"                        # optional padding
    rb"\[/VENYA\]"                  # closing tag
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


def parse_sentinels(data: bytes) -> list[tuple[str, bytes]]:
    """Parse all sentinels from data.

    Args:
        data: Potentially sentinel-wrapped bytes.

    Returns:
        List of (sentinel_hash, decoded_secret_value) tuples.
    """
    results = []
    for match in SENTINEL_PATTERN.finditer(data):
        hash_prefix = match.group(1).decode()
        encoded_data = match.group(2) + match.group(3)
        secret_value = base64.b64decode(encoded_data)
        results.append((hash_prefix, secret_value))
    return results


def inject_via_file(
    secret_value: bytes,
    tmpfs_dir: str = "/tmp/venya-secrets",  # nosec B108 — tmpfs, not persistent disk
) -> SecretInjection:
    """Inject a secret via a tmpfs file.

    Creates a file on tmpfs with restrictive permissions (0400).
    The file is owned by the current user.

    Args:
        secret_value: The raw secret bytes.
        tmpfs_dir: Directory for secret files (must be on tmpfs).

    Returns:
        SecretInjection with the file path.
    """
    os.makedirs(tmpfs_dir, exist_ok=True)

    fd, path = tempfile.mkstemp(
        prefix="venya_",
        suffix=".secret",
        dir=tmpfs_dir,
    )
    try:
        os.write(fd, secret_value)
        os.fsync(fd)
    finally:
        os.close(fd)

    os.chmod(path, 0o400)
    logger.info("Injected secret via file: %s (mode 0400)", path)

    return SecretInjection(
        secret_id="",  # nosec B106 — placeholder set by caller
        injection_path=path,
        sentinel_hash="",  # nosec B106 — placeholder set by caller
    )


def inject_via_memfd(secret_value: bytes) -> tuple[int, SecretInjection]:
    """Inject a secret via memfd_create.

    Creates an anonymous file descriptor backed by memory.
    No disk residency. Returns the FD number.

    Args:
        secret_value: The raw secret bytes.

    Returns:
        Tuple of (fd, SecretInjection). FD must be closed by caller.
    """
    try:
        import ctypes
        import ctypes.util

        libc = ctypes.CDLL(ctypes.util.find_library("c"), use_errno=True)

        # MFD_CLOEXEC (defined in linux/memfd.h)
        MFD_CLOEXEC = 0x0001
        MFD_ALLOW_SEALING = 0x0002

        fd = libc.memfd_create(b"venya_secret\x00", MFD_CLOEXEC | MFD_ALLOW_SEALING)
        if fd < 0:
            errno = ctypes.get_errno()
            raise OSError(errno, f"memfd_create failed: {os.strerror(errno)}")

        os.write(fd, secret_value)

        logger.info("Injected secret via memfd: fd=%d", fd)

        injection = SecretInjection(
            secret_id="",  # nosec B106 — placeholder set by caller
            injection_path=f"memfd:{fd}",
            sentinel_hash="",  # nosec B106 — placeholder set by caller
        )
        return fd, injection

    except ImportError:
        raise NotImplementedError("memfd_create not available on this platform")


def inject_via_fifo(path: str, secret_value: bytes) -> SecretInjection:
    """Inject a secret via a named pipe (FIFO).

    Args:
        path: Path for the FIFO (must be on tmpfs).
        secret_value: The raw secret bytes.

    Returns:
        SecretInjection with the FIFO path.
    """
    if os.path.exists(path):
        os.unlink(path)

    os.mkfifo(path, 0o600)

    # Write secret to FIFO in a background thread to avoid blocking
    import threading

    def write_secret():
        try:
            with open(path, "wb") as f:
                f.write(secret_value)
        except Exception:
            logger.exception("Failed to write secret to FIFO")

    t = threading.Thread(target=write_secret, daemon=True)
    t.start()

    logger.info("Injected secret via FIFO: %s", path)

    return SecretInjection(
        secret_id="",  # nosec B106 — placeholder set by caller
        injection_path=path,
        sentinel_hash="",  # nosec B106 — placeholder set by caller
    )


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


def scan_open_fds(pid: int | None = None) -> set[int]:
    """Scan open file descriptors for a process.

    Args:
        pid: Process ID to scan. Defaults to current process.

    Returns:
        Set of open FD numbers.
    """
    if pid is None:
        pid = os.getpid()

    fd_dir = f"/proc/{pid}/fd"
    try:
        return {int(fd) for fd in os.listdir(fd_dir)}
    except (FileNotFoundError, PermissionError):
        return set()


def set_cloexec(fd: int) -> None:
    """Set FD_CLOEXEC on a file descriptor.

    Args:
        fd: File descriptor number.
    """
    import fcntl

    flags = fcntl.fcntl(fd, fcntl.F_GETFD)
    fcntl.fcntl(fd, fcntl.F_SETFD, flags | fcntl.FD_CLOEXEC)
