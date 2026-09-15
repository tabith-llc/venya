# Copyright (c) 2026 Tabith LLC.
# Use of this source code is governed by the Business Source License 1.1
# included in the LICENSE file at the root of this repository. As of the
# Change Date listed there, the work is available under MPL 2.0.
# SPDX-License-Identifier: BUSL-1.1

"""Best-effort check if PostgreSQL data directory is on encrypted storage."""

import logging
import os
import subprocess  # nosec B404 — disk encryption check requires subprocess for system commands
from pathlib import Path

logger = logging.getLogger("venya.server")


def check_disk_encryption(db_url: str | None = None) -> None:
    """Best-effort check if PostgreSQL data directory is on encrypted storage.

    Logs INFO if encryption detected, WARNING if unable to verify.
    Never reports "encrypted" with weak evidence — always err toward warning.

    Detection order:
    1. Parse PG data directory from db_url or use default
    2. Find the block device hosting that directory's mount point
    3. Check for crypto_LUKS via lsblk
    4. Check for crypt targets via dmsetup

    Args:
        db_url: PostgreSQL database URL (e.g. postgresql://user@host/db).
    """
    data_dir = _get_pg_data_directory(db_url)
    if data_dir is None:
        _log_warning("Could not determine PostgreSQL data directory path.")
        return

    if not data_dir.exists():
        # Data directory may not exist yet on fresh installs — still check
        # the mount point of the parent directory
        mount_point = _find_mount_point(str(data_dir.parent))
    else:
        mount_point = _find_mount_point(str(data_dir))

    if mount_point is None:
        _log_warning(
            "Could not find mount point for PostgreSQL data directory. "
            "Ensure the data volume uses LUKS or cloud-native encryption."
        )
        return

    # Check for LUKS via lsblk
    fstype = _get_fstype_via_lsblk(mount_point)
    if fstype == "crypto_LUKS":
        logger.info("Disk encryption verified for PostgreSQL data directory (%s)", data_dir)
        return

    # Check for crypt targets via dmsetup
    if _has_crypt_target(mount_point):
        logger.info("Disk encryption verified for PostgreSQL data directory (%s)", data_dir)
        return

    _log_warning(
        "No disk encryption detected for PostgreSQL data directory (%s). "
        "Ensure the data volume uses LUKS or cloud-native encryption.",
        data_dir,
    )


def _log_warning(msg: str, *args) -> None:
    """Log a warning about inability to verify disk encryption."""
    logger.warning(msg, *args)


def _get_pg_data_directory(db_url: str | None) -> Path | None:
    """Infer the PostgreSQL data directory from the database URL.

    Uses common defaults since we can't query the running server.
    """
    if db_url is None:
        return None

    # Extract host from URL: postgresql://[user[:pass]@]host[:port]/db
    # Remove postgresql:// prefix
    url_part = db_url.split("://", 1)[-1] if "://" in db_url else db_url
    # Remove user:pass@ if present
    if "@" in url_part:
        url_part = url_part.split("@", 1)[1]
    # Remove port and db
    host = url_part.split("/", 1)[0].split(":")[0]

    if host in ("localhost", "127.0.0.1", "unix_socket"):
        # Common Ubuntu PostgreSQL data directories
        for candidate in [
            Path("/var/lib/postgresql/16/main"),
            Path("/var/lib/postgresql/main"),
            Path("/var/lib/postgresql"),
        ]:
            if candidate.exists():
                return candidate
        return Path("/var/lib/postgresql")

    # Remote host — can't determine local data directory
    return None


def _find_mount_point(path: str) -> str | None:
    """Find the mount point for a given path.

    Walks up the directory tree from the given path to find the nearest
    mount point.
    """
    current = os.path.realpath(path)
    while current != "/":
        try:
            result = subprocess.run(  # nosec
                ["findmnt", "-n", "-o", "TARGET", current],
                capture_output=True,
                text=True,
                timeout=5,
                check=False,
            )
            if result.returncode == 0 and result.stdout.strip():
                return result.stdout.strip()
        except (FileNotFoundError, subprocess.TimeoutExpired):
            # findmnt not available — fall through to lsblk
            pass
        current = str(Path(current).parent)
    return "/"


def _get_fstype_via_lsblk(mount_point: str) -> str | None:
    """Get the filesystem type for a mount point via lsblk.

    Returns the FSTYPE if found, None otherwise.
    """
    try:
        result = subprocess.run(  # nosec
            ["lsblk", "-d", "-b", "-o", "NAME,FSTYPE,MOUNTPOINT"],
            capture_output=True,
            text=True,
            timeout=5,
            check=False,
        )
        if result.returncode != 0:
            return None

        for line in result.stdout.strip().split("\n"):
            parts = line.split()
            if len(parts) >= 3 and mount_point in parts[-1]:
                # FSTYPE is typically the second column
                return parts[1] if len(parts) >= 2 else None
    except (FileNotFoundError, subprocess.TimeoutExpired):
        pass
    return None


def _has_crypt_target(mount_point: str) -> bool:
    """Check if a mount point's device has a crypt target via dmsetup.

    Returns True if a crypt target is found, False otherwise.
    """
    try:
        result = subprocess.run(  # nosec
            ["dmsetup", "table"],
            capture_output=True,
            text=True,
            timeout=5,
            check=False,
        )
        if result.returncode != 0:
            return False

        for line in result.stdout.strip().split("\n"):
            if "crypt" in line:
                return True
    except (FileNotFoundError, subprocess.TimeoutExpired):
        pass
    return False
