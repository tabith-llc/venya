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
from urllib.parse import parse_qs, urlsplit

logger = logging.getLogger("venya.server")

#: Hosts that mean "this machine".  An EMPTY authority and an absolute socket
#: path mean it too — that is the shape ``install-venya-core.sh`` writes for the
#: runtime identity (peer auth over the Unix socket carries no password), and
#: treating it as remote is what stopped this assurance from ever running on a
#: machine the installer built (#740).
_LOCAL_PG_HOSTS: tuple[str, ...] = ("localhost", "127.0.0.1", "::1", "unix_socket")

#: Debian/Ubuntu cluster root.  The cluster *under* it is resolved, never
#: assumed: ``install-venya-core.sh`` installs ``postgresql`` unpinned, so the
#: major version follows the distribution and a literal here goes stale on the
#: next release (#740 measured 26.04 shipping 18/main).
_PG_CLUSTER_ROOT = Path("/var/lib/postgresql")

#: Hosts the cluster manager reports as running, and the tool that answers.
_PG_LSCOLUMNS = ("ver", "cluster", "port", "status", "owner", "data_directory", "log_file")


def check_disk_encryption(db_url: str | None = None) -> None:
    """Best-effort check if PostgreSQL data directory is on encrypted storage.

    Logs INFO if encryption detected, WARNING if unable to verify.
    Never reports "encrypted" with weak evidence — always err toward warning.

    Detection order:
    1. Classify the DSN: local (empty authority, a socket path, or a loopback
       name) or remote.  A remote host has no local data directory to inspect.
    2. Resolve the running cluster's data directory — cluster manager first,
       then the server's own ``SHOW data_directory``, then a derived glob
       (``_get_pg_data_directory``), in the same no-guess order as the
       installer's ``venya_resolve_pg_cluster`` (#496).
    3. Find the block device hosting that directory's mount point
    4. Check for crypto_LUKS via lsblk
    5. Resolve the mount point's backing device (from /proc/self/mountinfo)
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


def _dsn_effective_host(db_url: str) -> str:
    """The host libpq would actually connect to, or ``""`` for a socket DSN.

    The query string's ``host=`` wins over the authority — that is libpq's own
    rule, and it is how the shipped runtime DSN says where its socket lives:
    ``postgresql://venya_audit@/venya?host=/var/run/postgresql`` has an empty
    authority and a socket path in the query.
    """
    parts = urlsplit(db_url)
    query_host = parse_qs(parts.query).get("host", [""])[0].strip()
    if query_host:
        return query_host
    try:
        authority_host = parts.hostname or ""
    except ValueError:
        # An authority urllib cannot parse is not one we can classify as local.
        return parts.netloc.rpartition("@")[2]
    return authority_host


def _is_local_dsn(db_url: str) -> bool:
    """True when the DSN describes a connection to this machine.

    Local means: no host at all, an absolute Unix-socket path, or a loopback
    name.  Anything else is remote and has no data directory to inspect here.
    """
    if "://" not in db_url:
        # Not a URL this function can read (a bare keyword DSN): say nothing
        # rather than guess, which is what this function answered before #740.
        return False
    host = _dsn_effective_host(db_url)
    return host == "" or host.startswith("/") or host in _LOCAL_PG_HOSTS


def _run_quiet(argv: list[str], env: dict[str, str] | None = None) -> str:
    """Run a read-only system probe, return its stdout, '' on any doubt.

    Fail-closed the same way every other probe in this module does: missing
    binary, non-zero rc, or timeout all answer with nothing, and the caller
    falls through to the next source rather than assuming an answer.
    """
    try:
        result = subprocess.run(  # nosec B603 — fixed argv, no shell, constant tool name on PATH
            argv,
            capture_output=True,
            text=True,
            timeout=5,
            check=False,
            env=env if env is not None else os.environ.copy(),
        )
    except (OSError, subprocess.SubprocessError):
        # Missing binary, no permission, a bad interpreter, a timeout: all the
        # same answer — this source cannot tell us anything. Fail-closed, never
        # raised, because the caller is a startup assurance that must not break
        # a boot.
        return ""
    if result.returncode != 0:
        return ""
    return result.stdout


def _from_cluster_manager() -> Path | None:
    """The data directory of the ONE online cluster, or None (#496 R1/R2).

    ``pg_lsclusters --no-header`` columns are ``Ver Cluster Port Status Owner
    Data-directory Log-file``.  More than one online cluster is not a guess:
    the answer is None, and the caller's last resort is the cluster root, which
    is the same answer a host with no resolvable cluster gets today.  An absent
    tool answers nothing, which is how a non-Debian host reaches the server
    probe.
    """
    rows = [line.split() for line in _run_quiet(["pg_lsclusters", "--no-header"]).splitlines() if line.strip()]
    online = [row for row in rows if len(row) >= len(_PG_LSCOLUMNS) and row[3] == "online"]
    if len(online) != 1:
        return None
    answer = online[0][5].strip()
    return Path(answer) if answer.startswith("/") else None


def _psql_env(db_url: str) -> dict[str, str]:
    """Child environment for the ``SHOW`` probe, built from the DSN.

    Connection parameters travel as ``PG*`` variables, never in argv: a DSN that
    carries a password would otherwise appear in any other account's ``ps``
    output.  No password is set when the DSN has none — peer auth over the
    socket is the shipped runtime shape.
    """
    parts = urlsplit(db_url)
    env = os.environ.copy()
    env["PGCONNECT_TIMEOUT"] = "3"
    query = parse_qs(parts.query)
    host = query.get("host", [""])[0] or (parts.hostname or "")
    if host:
        env["PGHOST"] = host
    port = query.get("port", [""])[0] or (str(parts.port) if parts.port else "")
    if port:
        env["PGPORT"] = port
    dbname = query.get("dbname", [""])[0] or parts.path.lstrip("/")
    if dbname:
        env["PGDATABASE"] = dbname
    if parts.username:
        env["PGUSER"] = parts.username
    try:
        password = parts.password
    except ValueError:
        password = None
    if password:
        env["PGPASSWORD"] = password
    return env


def _from_running_server(db_url: str) -> Path | None:
    """Ask the running server where its data lives (#496 R1's fallback shape).

    Covers packaging without ``pg_lsclusters``.  Whether a non-superuser may see
    this GUC is the server's answer, not ours: an empty or non-path reply is
    simply no answer, and the caller falls through.  ``-w`` so a DSN the server
    will not take without a password fails here instead of waiting on a prompt.
    """
    answer = _run_quiet(["psql", "-X", "-w", "-q", "-t", "-A", "-c", "SHOW data_directory"], env=_psql_env(db_url))
    stripped = answer.strip().splitlines()[0].strip() if answer.strip() else ""
    return Path(stripped) if stripped.startswith("/") else None


def _from_derived_glob() -> Path | None:
    """A cluster directory under the root, when there is exactly one (#740).

    Derived from the layout, never from a hardcoded major: ``postgresql`` is
    installed unpinned, so ``16/main`` was a promise about the distribution.
    Two clusters installed is ambiguity, and ambiguity resolves to the root
    rather than to the lowest version by sort order — the failure #496 ruled out
    for the installer applies to a read too, because the wrong cluster here
    means an encryption claim about the wrong volume.
    """
    try:
        found = sorted(path for path in _PG_CLUSTER_ROOT.glob("*/main") if path.is_dir())
    except OSError:
        return None
    return found[0] if len(found) == 1 else None


def _get_pg_data_directory(db_url: str | None) -> Path | None:
    """Resolve the local PostgreSQL data directory from the database URL.

    Returns None for a remote host and for a DSN that cannot be read.  A local
    DSN always answers a path: an unresolved cluster falls back to the Debian
    cluster root, which is what this function returned before #740 too, so the
    mount question is still answerable on a fresh install.
    """
    if db_url is None:
        return None
    if not _is_local_dsn(db_url):
        # Remote host — can't determine local data directory
        return None

    answer = _from_cluster_manager()
    if answer is None:
        answer = _from_running_server(db_url)
    if answer is None:
        answer = _from_derived_glob()
    if answer is not None:
        return answer

    # Nothing resolved a cluster: the root still names the volume the data
    # directory lives on (and, on a fresh install, the one it will be created
    # on).  Same last resort this function had before #740.
    return _PG_CLUSTER_ROOT


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
