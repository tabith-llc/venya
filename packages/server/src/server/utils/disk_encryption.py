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
    4. Resolve the mount point's backing device (from /proc/self/mountinfo)
       and check THAT device's device-mapper lineage for a crypt target

    Scope law (ticket disk-encryption-mount-check-ignores-argument #444):
    every encryption claim is tied to the device that actually backs the
    PostgreSQL data directory — a crypt target on an unrelated volume can
    never make this check pass.

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
        # Name the device this claim rests on so a reader of the log can
        # falsify it (same law as the dmsetup branch below, #444 fix leg).
        device = _get_lsblk_device_for_mount(mount_point)
        logger.info(
            "Disk encryption verified for PostgreSQL data directory (%s): "
            "lsblk reports crypto_LUKS on device '%s' mounted at %s",
            data_dir,
            device if device is not None else "unknown",
            mount_point,
        )
        return

    # Check the mount's own device lineage for a crypt target via dmsetup
    crypt_device = _find_crypt_backing_device(mount_point)
    if crypt_device is not None:
        logger.info(
            "Disk encryption verified for PostgreSQL data directory (%s): "
            "device-mapper crypt target '%s' backs the mounted device (mount %s)",
            data_dir,
            crypt_device,
            mount_point,
        )
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


def _normalize_mount_point(mount_point: str) -> str:
    """Canonical form for mount-point comparison: no trailing slash, root kept
    as "/" (so "/var/lib/postgresql/" and "/var/lib/postgresql" are one path).
    """
    if mount_point == "/":
        return "/"
    return mount_point.rstrip("/") or "/"


def _lsblk_mount_rows() -> list[tuple[str, str, str]]:
    """Run lsblk and return (NAME, FSTYPE, MOUNTPOINT) rows for devices that
    report all three columns.  Empty list on any failure (fail-closed).
    """
    try:
        result = subprocess.run(  # nosec
            ["lsblk", "-d", "-b", "-n", "-o", "NAME,FSTYPE,MOUNTPOINT"],
            capture_output=True,
            text=True,
            timeout=5,
            check=False,
        )
        if result.returncode != 0:
            return []
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return []

    rows: list[tuple[str, str, str]] = []
    for line in result.stdout.strip().splitlines():
        parts = line.split()
        # Three columns required: a row without a FSTYPE or without a
        # MOUNTPOINT cannot answer a mount-point question.
        if len(parts) >= 3:
            rows.append((parts[0], parts[1], parts[-1]))
    return rows


def _matching_row(mount_point: str) -> tuple[str, str, str] | None:
    """The lsblk row whose MOUNTPOINT column EQUALS ``mount_point`` — or None.

    Exact equality is the whole fix (ticket lsblk-mountcheck-matches-any-mount
    #488): the previous ``mount_point in parts[-1]`` containment test made
    "/" match every mounted row (/boot, /boot/efi, a backup volume), so an
    unrelated crypto_LUKS volume could certify a plain data directory.  This
    mirrors the exact comparisons the sibling helpers already use
    (``_resolve_backing_device`` mount equality, ``target == "crypt"``).
    """
    wanted = _normalize_mount_point(mount_point)
    for row in _lsblk_mount_rows():
        if _normalize_mount_point(row[2]) == wanted:
            return row
    return None


def _get_fstype_via_lsblk(mount_point: str) -> str | None:
    """Get the filesystem type for a mount point via lsblk.

    Returns the FSTYPE if found, None otherwise.  Only the row mounted
    EXACTLY at ``mount_point`` answers — see ``_matching_row``.
    """
    row = _matching_row(mount_point)
    return row[1] if row is not None else None


def _get_lsblk_device_for_mount(mount_point: str) -> str | None:
    """The NAME column of the lsblk row mounted exactly at ``mount_point``,
    or None when no row matches (used to name the verified device in logs).
    """
    row = _matching_row(mount_point)
    return row[0] if row is not None else None


_MOUNTINFO_PATH = "/proc/self/mountinfo"


def _find_crypt_backing_device(mount_point: str) -> str | None:
    """Return the name of the device-mapper crypt target that actually backs
    the device mounted at ``mount_point`` — or None when encryption is not
    verified.

    The mount's backing device is resolved from /proc/self/mountinfo, then
    ONLY that device's device-mapper lineage (the device itself and its
    parent devices, transitively) is examined for a crypt target.  A crypt
    target on an unrelated device can never satisfy the check.

    Resolution choice: parsing /proc/self/mountinfo instead of shelling out
    to findmnt — a plain local file read the kernel maintains (no network,
    no new binary, no new package; offline-safe).  When findmnt is absent,
    _find_mount_point already falls back to root, so mountinfo stays the
    dependable source for the backing device.

    Fail-closed: unresolvable mount or device, non-zero rc, timeout, or
    missing dmsetup → None ("not verified") — never True, never a silent
    pass.

    Args:
        mount_point: resolved mount point (from _find_mount_point).

    Returns:
        The first crypt-backed device name in the mount's dm lineage, else None.
    """
    source = _resolve_backing_device(mount_point)
    if source is None:
        return None

    queue: list[str] = [source]
    seen: set[str] = set()
    while queue:
        device = queue.pop(0)
        if device in seen:
            continue
        seen.add(device)
        name = _dm_name_for_device(device)
        if name is None:
            # Not a device-mapper device (or dmsetup cannot answer) — this
            # leg is unverified; keep walking the other lineage entries.
            continue
        if _dm_has_crypt_target(name):
            return name
        queue.extend(_dm_parent_devices(name))
    return None


def _has_crypt_target(mount_point: str) -> bool:
    """True only when the device backing ``mount_point`` — or a
    device-mapper ancestor of it — carries a crypt target.  Fail-closed
    (False) on any doubt.  Historically this matched the string "crypt"
    against EVERY ``dmsetup table`` line, ignoring its argument entirely
    (ticket disk-encryption-mount-check-ignores-argument #444).
    """
    return _find_crypt_backing_device(mount_point) is not None


def _resolve_backing_device(mount_point: str) -> str | None:
    """Return the SOURCE device (e.g. /dev/mapper/data_crypt) of the
    /proc/self/mountinfo entry with the longest mount point that contains
    ``mount_point``.  None when the mount cannot be resolved (fail-closed).
    """
    target = os.path.realpath(mount_point)
    try:
        with open(_MOUNTINFO_PATH, "r", encoding="utf-8") as fh:
            lines = fh.readlines()
    except OSError:
        return None

    best_mount = ""
    best_source: str | None = None
    for line in lines:
        fields = line.split()
        if len(fields) < 6:
            continue
        try:
            sep = fields.index("-")
        except ValueError:
            continue
        if sep + 2 >= len(fields):
            continue
        mount = _unescape_mountinfo(fields[4])
        source = _unescape_mountinfo(fields[sep + 2])
        if not source.startswith("/dev/"):
            # Pseudo filesystems (tmpfs, overlay, nfs) are not block-device
            # mounts; nothing in a dm lineage backs them.
            continue
        matched = mount == target or target.startswith(mount if mount.endswith("/") else mount + "/")
        if matched and len(mount) > len(best_mount):
            best_mount = mount
            best_source = source
    return best_source


def _unescape_mountinfo(value: str) -> str:
    r"""Undo the octal escapes mountinfo uses for whitespace and backslash
    inside path fields (space \040, tab \011, newline \012, backslash \134).
    """
    return value.replace("\\040", " ").replace("\\011", "\t").replace("\\012", "\n").replace("\\134", "\\")


def _dm_name_for_device(device: str) -> str | None:
    """Return the device-mapper name for ``device`` (a /dev path or a dm
    name), or None when it is not a device-mapper device or dmsetup cannot
    answer (fail-closed)."""
    try:
        result = subprocess.run(  # nosec
            ["dmsetup", "info", "-c", "--noheadings", "-o", "name", device],
            capture_output=True,
            text=True,
            timeout=5,
            check=False,
        )
        if result.returncode != 0:
            return None
        stripped = result.stdout.strip()
        if not stripped:
            return None
        return stripped.splitlines()[0].strip() or None
    except (FileNotFoundError, subprocess.TimeoutExpired, IndexError):
        return None


def _dm_has_crypt_target(name: str) -> bool:
    """True when dmsetup reports a ``crypt`` TARGET TYPE for device ``name``.

    The target type is read POSITIONALLY from the scoped table line
    (``<name>: <start> <length> <target> ...``) and compared for equality
    against "crypt" — never by matching the substring "crypt" anywhere on
    any line (that was ticket disk-encryption-mount-check-ignores-argument
    #444: it matched unrelated devices and even unrelated words such as
    "encrypted").  Table form is scoped by ``name`` itself, so a crypt
    target on another device cannot appear here.
    """
    try:
        result = subprocess.run(  # nosec
            ["dmsetup", "table", name],
            capture_output=True,
            text=True,
            timeout=5,
            check=False,
        )
        if result.returncode != 0:
            return False
        for line in result.stdout.strip().splitlines():
            parts = line.split()
            if len(parts) < 4:
                continue
            if parts[0] == f"{name}:":
                target = parts[3]
            elif parts[0] == name:
                # some dmsetup builds omit the trailing colon
                target = parts[2]
            else:
                # A line about another device must never answer for ours.
                continue
            if target == "crypt":
                return True
    except (FileNotFoundError, subprocess.TimeoutExpired):
        pass
    return False


def _dm_parent_devices(name: str) -> list[str]:
    """Return the device names that device-mapper device ``name`` directly
    depends on (its parents), from ``dmsetup deps -o dev_name``.  Empty list
    when unresolvable — fail-closed: an unknown parent is never assumed
    encrypted."""
    try:
        result = subprocess.run(  # nosec
            ["dmsetup", "deps", "-o", "dev_name", name],
            capture_output=True,
            text=True,
            timeout=5,
            check=False,
        )
        if result.returncode != 0:
            return []
        parents: list[str] = []
        for line in result.stdout.strip().splitlines():
            start = line.find("[")
            end = line.rfind("]")
            if start != -1 and end > start:
                parents.extend(token for token in line[start + 1 : end].split() if token)
        return parents
    except (FileNotFoundError, subprocess.TimeoutExpired):
        pass
    return []
