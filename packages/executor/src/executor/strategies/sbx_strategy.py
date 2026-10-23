# Copyright (c) 2026 Tabith LLC.
# Use of this source code is governed by the Business Source License 1.1
# included in the LICENSE file at the root of this repository. As of the
# Change Date listed there, the work is available under MPL 2.0.
# SPDX-License-Identifier: BUSL-1.1

"""Docker Sandboxes (sbx) injection strategy.

Uses Docker's sbx CLI to create microVM sandboxes with
hypervisor-level isolation and built-in network policies.

Secrets are written to host tmpfs (/dev/shm) and injected into
the sandbox over stdin (`sbx exec -i ... tee`) so the in-sandbox
file is owned by the secret-reading user. Network access is
restricted via `sbx policy allow/deny` rules.
"""

import logging
import os
import re
import shutil
import subprocess  # nosec B404 — sandbox strategy requires subprocess for sbx commands
import tempfile
import threading
from collections.abc import Callable
from pathlib import Path

from venya_contract import ASKPASS_HELPER_PATH

from ..egress_filter import DEFAULT_ALLOWLIST_PATH
from .base import InjectionResult, InjectionStrategy, SecretMount

logger = logging.getLogger("venya.executor.strategies.sbx")

# tmpfs base on host — secrets never touch disk
SECRET_TMPFS_BASE = "/dev/shm/venya-secrets"  # nosec

# Directory prefixes created under SECRET_TMPFS_BASE. Single source of truth: the
# writer here and the daemon's orphan reaper (``daemon.ReaperLoop._check_orphaned``,
# which imports both names) must agree, or a created directory is reaped by nobody
# (ticket #469: ``env_*`` was created here and matched no sweep).
#   SESSION_DIR_PREFIX — prepare()'s per-run secrets dir; the name embeds the
#     execution-session id, so the reaper can attribute a revoke to it.
#   ENV_DIR_PREFIX — the env-file fallback dir; it carries NO session id, so the
#     reaper deletes it and never attributes anything.
SESSION_DIR_PREFIX = "session_"
ENV_DIR_PREFIX = "env_"

# Disk-backed base for per-run sandboxes' host workspace. Must NOT be tmpfs
# (/dev/shm): sbx bind-mounts the workspace into the microVM via virtio-fs,
# which cannot share a tmpfs path ("workspace ... was not mounted into the
# sandbox"). Ephemeral, non-secret, deleted per-run and swept on daemon start.
WORKSPACE_BASE = str(Path.home() / ".venya-workspaces")  # nosec

# Where secrets appear inside the sandbox. The shell agent runs as non-root
# (uid 1000) and /run is root-owned, so the dir must live under the image's
# 1777 /run/secrets. NOTE: the sbx runtime mounts /run/secrets rw,noexec,nosuid
# (its own injected-mount default — we pass no mount flag), so only the
# NON-EXECUTED secret files live here; the exec'd askpass helper is placed at
# ASKPASS_HELPER_PATH under /usr/local/bin instead (ticket
# askpass-helper-noexec-mount-conflict).
CONTAINER_SECRET_DIR = "/run/secrets/venya"  # nosec

# How long to wait for sandbox commands
SBX_TIMEOUT = 3600  # 1 hour

# How long to wait for the agent-template pull + microVM create (`sbx create`).
# Measured (2026-09-02, fast uplink): cold *first-ever* pull of the multi-GB
# `shell-docker` template = 65s; warm (cached) create = ~5.5s. Held **inside** the
# core's relay read budget (executors.py `httpx2.AsyncClient(timeout=300)`) so a slow
# pull times out on the executor with a precise local error before the core's connection
# timeout fires and leaves a doomed create running orphaned in the executor daemon.
# Override per-network: `VENYA_SBX_CREATE_TIMEOUT` (seconds). Durable fix (pre-pull the
# template at enrollment) is tracked in `venya-dev/tickets/sbx-cold-start-prepull.md`.
SBX_CREATE_TIMEOUT = 240

SBX_MIN_VERSION = (0, 39, 0)  # refs ticket sbx-exec-env-file-noop


class SbxVersionError(RuntimeError):
    pass


class SbxCreateTimeoutError(subprocess.TimeoutExpired):
    """`sbx create` exceeded its own budget (#639).

    Before this row the create site caught NOTHING, so a hung create propagated as the
    bare `subprocess.TimeoutExpired` the caller's COMMAND-timeout lane already handles,
    and the operator was told "Command timed out after 3600 seconds" — the wrong stage
    and the wrong number for a create bounded by ``SBX_CREATE_TIMEOUT`` (240 s) or
    ``VENYA_SBX_CREATE_TIMEOUT``. Naming the class keeps the caller's existing lane
    (this IS a `TimeoutExpired`, so the relay outcome is unchanged — #639 AC4) while
    making the create stage and its real bound sayable.
    """


class SbxMemoryRefusalError(RuntimeError):
    """The vendor refused `sbx create` on a memory-shaped line (#639).

    Subclasses `RuntimeError` on purpose: this is the strategy-level refusal channel the
    create path already uses (see `validate()` and the #578 no-cap refusal), so the relay
    status for a refused create is EXACTLY what it was before this row. The name and the
    log line are what change — the vendor's own stderr deliberately does NOT cross the
    relay boundary, because the listener's reason-bearing lane belongs to
    `CommandRejected` alone (#410: it describes the caller's own command, never foreign
    material). A refused create stays a flat 503 on the wire; the distinction this row
    buys is the named line in the executor's own journal.
    """


# #639: the shapes we call a memory refusal, and nothing else. Every entry names memory
# or OOM as the resource; none of them can fire on a bare path, a name collision, or a
# disk-space error. The list may be NARROWED; it may never be widened without a guest
# that has the vendor binary, because a classifier that fires on everything converts an
# unhelpful 503 into a wrong 4xx (that is the load-bearing rule in this row's AC3, and
# the paired-negative cells in tests/test_sbx_create_outcome_639.py are the proof).
_SBX_MEMORY_REFUSAL_SHAPES: tuple[str, ...] = (
    "out of memory",
    "out-of-memory",
    "cannot allocate memory",
    "could not allocate memory",
    "insufficient memory",
    "not enough memory",
    "memory allocation failed",
    "oomkilled",
    "oom killer",
)


def sbx_memory_refusal_shape(stderr: str | None) -> str | None:
    """Return the matched memory shape from vendor stderr, or None.

    Matching is substring against the lower-cased text and ONLY against the list above,
    so "cannot allocate '/workspace/my_memory_dir': no such file" (a path) and "sandbox
    name memory-test already exists" (a name collision) both return None.
    """
    if not stderr:
        return None
    lowered = stderr.lower()
    for shape in _SBX_MEMORY_REFUSAL_SHAPES:
        if shape in lowered:
            return shape
    return None


def _parse_sbx_version(raw: str) -> tuple[int, int, int]:
    m = re.search(r"v?(\d+)\.(\d+)\.(\d+)", raw)
    if not m:
        raise SbxVersionError(f"cannot read sbx version from output: {raw.strip()!r}")
    return (int(m[1]), int(m[2]), int(m[3]))


def require_supported_sbx(timeout: float = 10.0) -> str:
    """Refuse boot on sbx < SBX_MIN_VERSION (silent env-file no-op class)."""
    try:
        # check=False: nonzero exit is still parsed below — unparseable output is a refusal.
        result = subprocess.run(  # nosec
            ["sbx", "version"],
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise SbxVersionError(
            "sbx CLI not runnable — install/upgrade the vendor package docker-sbx; "
            "the executor starts once sbx version >= 0.39.0 is available."
        ) from exc
    version = _parse_sbx_version(result.stdout + result.stderr)
    if version < SBX_MIN_VERSION:
        too_old = "v" + ".".join(map(str, version))
        raise SbxVersionError(
            f"sbx CLI {too_old} is below the required 0.39.0 — secret injection would be "
            "silently ignored. The site administrator should upgrade the vendor package "
            "docker-sbx (Venya does not manage vendor packages); the executor starts "
            "once the CLI is >= 0.39.0. (refs ticket sbx-exec-env-file-noop)"
        )
    return (result.stdout + result.stderr).strip()


# Server-issued secret ids land in path joins (host tmpfs file name and the
# sandbox container_path), so each id must be ONE safe path segment. Server
# truth: core Secret.id / SessionSecret.secret_id are Integer PKs and the
# daemon str()-casts them (executor.py), so at runtime ids are decimal;
# the bundle field is a free str, so the boundary enforces the segment
# charset instead of trusting the int shape.
_SECRET_ID_PATTERN = re.compile(r"[A-Za-z0-9._-]{1,64}")


def _validated_secret_id(secret_id: object) -> str:
    """Validate a server-issued secret_id for path use; return canonical text.

    Raises ValueError (no partial writes — callers validate before the first
    os.open) for ids with path separators, leading '/', over-length ids, or
    dot-only names ("." / "..") that the charset alone would allow.
    """
    text = str(secret_id)
    if not _SECRET_ID_PATTERN.fullmatch(text) or set(text) == {"."}:
        raise ValueError(f"unsafe secret_id for path use: {text!r}")
    return text


def sweep_workspace_base(base: str = WORKSPACE_BASE) -> int:
    """Delete orphaned ws_* workspace directories from dead daemon runs.

    The host workspace base survives daemon kills and reboots but sandboxes
    never do, so at daemon start every ws_* directory in the base is by
    definition an orphan.
    Unconditional sweep is safe: nothing but this package creates ws_* dirs
    there (alpha deployment: one executor daemon per host). Best-effort —
    failures are logged, not raised.
    """
    swept = 0
    try:
        os.makedirs(base, mode=0o700, exist_ok=True)
        for entry in os.listdir(base):
            path = os.path.join(base, entry)
            if entry.startswith("ws_") and os.path.isdir(path):
                shutil.rmtree(path, ignore_errors=True)
                swept += 1
    except OSError:
        logger.exception("Failed to sweep workspace base: %s", base)
    return swept


# ---------------------------------------------------------------------------
# Sandbox reaper (ticket sandbox-residue-unreaped-after-teardown-failure #474)
# ---------------------------------------------------------------------------

# Venya-created sandboxes are named `venya-<execution-session-id>-<run-id>`
# (executor.py _run_command_sbx). The prefix is the reaper's scope: anything
# else on the host belongs to someone else and is never touched.
SBX_NAME_PREFIX = "venya-"

# `sbx ls` (enumerate) and `sbx rm --force` (remove) are bounded CLI calls.
# A reap pass must never outlive the boot/teardown path that invoked it.
SBX_REAP_COMMAND_TIMEOUT = 30.0

# OWNERSHIP KEY: the set below maps sandbox NAME -> owning execution-session
# id for every sandbox THIS daemon process created and still holds live. A
# name present here has a live owning session; a `venya-*` name absent from it
# has none (a failed teardown that already gave the sandbox up, or a residue
# from a previous, dead daemon at boot). Guarded by a lock because the reaper
# thread/relay thread/boot path all read it while a command thread writes it.
_LIVE_SANDBOX_SESSIONS: dict[str, str] = {}
_LIVE_SANDBOX_LOCK = threading.Lock()


def register_live_sandbox(sandbox_name: str, session_id: str) -> None:
    """Record that a live session owns ``sandbox_name`` (ticket #474).

    Called by ``create_sandbox`` on success, so a sandbox is claimed BEFORE
    any later setup step can raise and hand it to the reaper.
    """
    with _LIVE_SANDBOX_LOCK:
        _LIVE_SANDBOX_SESSIONS[sandbox_name] = session_id


def release_live_sandbox(sandbox_name: str) -> None:
    """Drop the ownership claim once the sandbox is really gone (#474).

    Only a SUCCESSFUL ``sbx rm`` calls this: a failed removal leaves the
    claim in place for the live session, and the teardown path hands the
    residue to the reaper, which skips it while it is still claimed and
    collects it on the next pass (a later boot, when the owner is gone).
    """
    with _LIVE_SANDBOX_LOCK:
        _LIVE_SANDBOX_SESSIONS.pop(sandbox_name, None)


def live_sandbox_names() -> set[str]:
    """Snapshot of sandbox names with a live owning session (#474 AC3)."""
    with _LIVE_SANDBOX_LOCK:
        return set(_LIVE_SANDBOX_SESSIONS)


def clear_live_sandboxes() -> None:
    """Drop every ownership claim — test-harness helper (ticket #474).

    The registry is process-global by design (one daemon per host); a unit
    that registers a sandbox must not leak the claim into the next one.
    Never called by production code: boot starts with an empty registry and
    registration happens in create_sandbox.
    """
    with _LIVE_SANDBOX_LOCK:
        _LIVE_SANDBOX_SESSIONS.clear()


def list_sandbox_names(timeout: float = SBX_REAP_COMMAND_TIMEOUT) -> list[str]:
    """Sandbox names reported by the sbx CLI; empty on any failure.

    Best-effort by design — a boot must not die over debris it came to
    clean, and the reaper is debris management, not a security gate. The
    CLI output is parsed for whitespace-delimited tokens carrying the
    ``venya-`` prefix instead of relying on a column layout, so a vendor
    table-format change cannot make the pass silently over- or
    under-collect (names never contain spaces: they are
    ``venya-<uuid>-<hex>``).
    """
    try:
        result = subprocess.run(  # nosec
            ["sbx", "ls"],
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
    except FileNotFoundError:
        logger.warning("sbx CLI unavailable — sandbox reap pass skipped")
        return []
    except subprocess.TimeoutExpired:
        logger.warning("sbx ls timed out after %s s — sandbox reap pass skipped", timeout)
        return []
    except Exception:
        logger.exception("sbx ls failed — sandbox reap pass skipped")
        return []

    if result.returncode != 0:
        logger.warning(
            "sbx ls exited %d — sandbox reap pass skipped: %s",
            result.returncode,
            (result.stderr or "").strip()[:200],
        )
        return []

    names: list[str] = []
    for token in (result.stdout or "").split():
        if token.startswith(SBX_NAME_PREFIX) and token not in names:
            names.append(token)
    return names


def reap_orphan_sandboxes(names: list[str] | None = None) -> int:
    """Remove ``venya-*`` sandboxes that have NO live owning session.

    Runs at daemon boot (before the relay listener can accept a command,
    so the ownership set is empty and every residue is collectible) and
    from the failed-teardown path. A name claimed by a live session is
    skipped — the ownership check is enforced here, not assumed.

    Args:
        names: Sandbox names to consider. None enumerates them via the CLI.

    Returns:
        Number of residue sandboxes collected.
    """
    if names is None:
        names = list_sandbox_names()

    owned = live_sandbox_names()
    reaped = 0
    for name in names:
        if not name.startswith(SBX_NAME_PREFIX):
            continue
        if name in owned:
            logger.info("Sandbox reap: %s has a live owning session — skipped", name)
            continue
        try:
            result = subprocess.run(  # nosec
                ["sbx", "rm", "--force", name],
                capture_output=True,
                text=True,
                timeout=SBX_REAP_COMMAND_TIMEOUT,
                check=False,
            )
        except Exception:
            logger.exception("Sandbox reap: failed to remove %s", name)
            continue
        if result.returncode == 0:
            reaped += 1
            logger.info("Sandbox reap: collected residue %s", name)
        else:
            logger.warning(
                "Sandbox reap: sbx rm %s exited %d: %s",
                name,
                result.returncode,
                (result.stderr or "").strip()[:200],
            )
    return reaped


# Askpass helper script (ticket secret-shape-askpass-helpers): git/ssh invoke
# the file named by GIT_ASKPASS/SSH_ASKPASS with a prompt argument. It prints
# the credential file named by VENYA_ASKPASS_SECRET; username prompts are
# answered from VENYA_ASKPASS_USER when set. The guard is load-bearing: an
# unguarded `cat "$VAR"` with VAR unset becomes `cat` on stdin, which would
# HANG until SBX_TIMEOUT (1h) instead of failing loudly (ticket acceptance:
# "never empty-string success" — and never a silent hang either).
# STATIC content — carries no secret. Staged 0555 on the host and copied to
# ASKPASS_HELPER_PATH (/usr/local/bin — an exec-capable, root-owned dir the
# uid-1000 sandbox user cannot write) via `sbx cp`. NOT tee'd into /run/secrets,
# which the sbx runtime mounts noexec and where git/ssh could not exec it (ticket
# askpass-helper-noexec-mount-conflict).
ASKPASS_HELPER_CONTENT = """#!/bin/sh
if [ -z "${VENYA_ASKPASS_SECRET:-}" ] || [ ! -r "${VENYA_ASKPASS_SECRET:-}" ]; then
    echo "venya-askpass: VENYA_ASKPASS_SECRET is unset or unreadable" >&2
    exit 1
fi
case "${1:-}" in
    *sername*)
        if [ -n "${VENYA_ASKPASS_USER:-}" ]; then
            printf '%s\\n' "$VENYA_ASKPASS_USER"
            exit 0
        fi
        ;;
esac
cat "$VENYA_ASKPASS_SECRET"
"""


class SbxStrategy(InjectionStrategy):
    """Docker Sandboxes strategy using microVM isolation.

    Creates a Docker Sandbox (microVM with separate kernel) for
    each command execution. Secrets are written to host tmpfs and
    injected into the sandbox over stdin (`sbx exec -i ... tee`).
    Network access is controlled via `sbx policy` rules
    (deny-by-default).

    Key properties:
    - Hypervisor isolation (separate kernel per sandbox)
    - Network: SOCKS5 proxy with policy-based allow/deny
    - Secrets: tmpfs on host -> stdin-tee into sandbox (RAM-backed)
    - Cleanup: sandbox destroyed, tmpfs deleted, secrets zeroed
    """

    def __init__(
        self,
        secret_base_fd: int = 100,
        dns_resolver: str | None = None,
        egress_allowlist_path: str | Path = DEFAULT_ALLOWLIST_PATH,
        sandbox_memory_mb: int | None = None,
    ) -> None:
        self.secret_base_fd = secret_base_fd
        self.dns_resolver = dns_resolver
        self.egress_allowlist_path = egress_allowlist_path
        # #578: the explicit --memory cap for every sandbox this strategy
        # creates. None is not "unbounded" — it is "refuse at create", so an
        # unset knob never silently inherits the vendor default (50% of the
        # guest, which on the shipped 5 GB executor shape is ~2.4 GiB each).
        self.sandbox_memory_mb = sandbox_memory_mb
        self._session_dir: str | None = None
        # #469: the env-file fallback dir, when THIS instance created it. Owns
        # the removal in _release_fallback_dir() — never a prepare() session dir.
        self._fallback_env_dir: str | None = None
        self._sandbox_name: str | None = None
        self._workspace_dir: str | None = None

    def name(self) -> str:
        return "sbx"

    def validate(self) -> None:
        """Check that sbx CLI is installed."""
        if shutil.which("sbx") is None:
            raise RuntimeError(
                "sbx CLI not found. Install with: "
                "curl -fsSL https://get.docker.com | sudo REPO_ONLY=1 sh && "
                "sudo apt-get install docker-sbx && "
                "sudo usermod -aG kvm $USER && newgrp kvm"
            )

    def prepare(self, secrets: list, session_id: str) -> InjectionResult:
        """Write secrets to host tmpfs.

        Each secret is written to:
            /dev/shm/venya-secrets/session_{session_id}_{rand}/{secret_id}

        And will be copied into the sandbox at:
            /run/secrets/venya/{secret_id}

        The dir name embeds the server execution-session id — the daemon
        reaper parses it back to attribute orphan revocation to the real
        session (ticket daemon-reaper-phantom-session).

        The sandbox is NOT created here — that happens in the executor.

        Args:
            secrets: List of SecretBundle objects.
            session_id: Server execution-session id for this run.

        Returns:
            InjectionResult with secret mounts and cleanup functions.
        """
        # Boundary check BEFORE any filesystem write: a malformed id aborts
        # with nothing created on tmpfs (no session dir, no partial mounts).
        secret_ids = [_validated_secret_id(bundle.secret_id) for bundle in secrets]

        # Create unique session directory on tmpfs (base is self-provisioned —
        # a fresh install has no /dev/shm/venya-secrets)
        os.makedirs(SECRET_TMPFS_BASE, mode=0o700, exist_ok=True)
        self._session_dir = tempfile.mkdtemp(prefix=f"{SESSION_DIR_PREFIX}{session_id}_", dir=SECRET_TMPFS_BASE)

        # From the moment the directory exists, it is owned (refs #446).
        # Register the cleanup callable IMMEDIATELY — before any secret is
        # written — and wrap the whole window up to "callable registered"
        # in a rollback that removes the directory (with its contents) on
        # ANY error and re-raises. A failure here never returns an
        # InjectionResult, so the caller cannot run cleanup_funcs itself
        # (executor.py only holds _injection_result after prepare() returns):
        # the try/except rollback is the load-bearing guarantee on the raise
        # path; the early registration is double-safety and keeps ownership
        # starting at creation. Same fail-closed style as the in-guest
        # secret-copy chmod-400 rollback in this file.
        session_dir = self._session_dir
        mounts: list[SecretMount] = []
        cleanup_funcs: list[Callable[[], None]] = []

        def _cleanup():
            if session_dir and os.path.exists(session_dir):
                shutil.rmtree(session_dir, ignore_errors=True)
                logger.debug("Cleaned up tmpfs session dir: %s", session_dir)

        cleanup_funcs.append(_cleanup)

        try:
            os.chmod(self._session_dir, 0o700)

            for bundle, secret_id in zip(secrets, secret_ids):
                secret_path = os.path.join(self._session_dir, secret_id)

                # Write secret to tmpfs file
                fd = os.open(secret_path, os.O_WRONLY | os.O_CREAT, 0o400)
                try:
                    os.write(fd, bundle.value)
                finally:
                    os.close(fd)

                # Lock down permissions
                os.chmod(secret_path, 0o400)

                mount = SecretMount(
                    secret_id=secret_id,
                    path=secret_path,
                    container_path=f"{CONTAINER_SECRET_DIR}/{secret_id}",
                )
                mounts.append(mount)

                logger.debug(
                    "Wrote secret %s to tmpfs: %s -> %s",
                    secret_id,
                    secret_path,
                    mount.container_path,
                )
        except BaseException:
            # Ownership closes the write window: an interrupted prepare()
            # must not leave a session_* dir (possibly holding staged
            # secret material) unreferenced on tmpfs. ignore_errors=True
            # because a tmpfs broken enough to fail a write can fail a
            # delete too — but the attempt is made in EVERY failure path.
            shutil.rmtree(session_dir, ignore_errors=True)
            self._session_dir = None
            raise

        return InjectionResult(
            extra_fds=[],  # No FDs — using file copies instead
            secret_mounts=mounts,
            cleanup_funcs=cleanup_funcs,
        )

    def create_sandbox(self, sandbox_name: str, workspace: str | None = None, session_id: str | None = None) -> None:
        """Create a Docker Sandbox (microVM).

        Args:
            sandbox_name: Unique name for the sandbox.
            workspace: Host directory to mount as the sandbox workspace.
                When None, a per-run directory is created under
                WORKSPACE_BASE and tracked in self._workspace_dir so
                remove_sandbox deletes it. Ownership rule: the strategy
                deletes only what it created — a caller-supplied workspace
                is always passed through untouched and never deleted.
            session_id: Executing session claiming ownership (#474). The
                reaper's ownership key: a created sandbox is registered here
                so a reap pass can never collect a VM a live session holds.
        """
        # #578: refuse before anything is created — no workspace directory, no
        # sandbox, no vendor-default claim. RuntimeError is the existing channel
        # for strategy-level refusals (see validate()).
        if self.sandbox_memory_mb is None:
            raise RuntimeError(
                "sandbox_memory_mb is not configured — sbx create refuses without an explicit cap. "
                "Set VENYA_EXECUTOR_SANDBOX_MEMORY_MB to a value between 512 and "
                "75 percent of the executor guest memory. "
                "See docs/deployment-sizing.md for sizing guidance."
            )

        created_workspace = False
        if workspace is None:
            # Existing path is mandatory: sbx create prompts interactively
            # ("create it? (y/N)") for a missing workspace, which reads EOF
            # in a non-TTY subprocess and fails with "user cancelled operation".
            os.makedirs(WORKSPACE_BASE, mode=0o700, exist_ok=True)
            workspace = tempfile.mkdtemp(prefix="ws_", dir=WORKSPACE_BASE)
            self._workspace_dir = workspace
            created_workspace = True

        cmd = [
            "sbx",
            "create",
            "--name",
            sandbox_name,
            "--memory",
            f"{self.sandbox_memory_mb}m",
            "shell",
            workspace,
        ]
        create_timeout = int(os.environ.get("VENYA_SBX_CREATE_TIMEOUT", SBX_CREATE_TIMEOUT))
        try:
            result = subprocess.run(  # nosec
                cmd,
                capture_output=True,
                text=True,
                timeout=create_timeout,
                check=False,
            )
        except subprocess.TimeoutExpired as exc:
            # #639 AC2 — the THIRD catch of this exception in this file (the version probe
            # at require_supported_sbx and the reap pass in reap_orphan_sandboxes already
            # caught it; only create did not). Name the create stage and the number that
            # actually bounded it: VENYA_SBX_CREATE_TIMEOUT, resolved here, defaulting to
            # SBX_CREATE_TIMEOUT — NOT SBX_TIMEOUT, the command budget, which is what the
            # caller's shared TimeoutExpired lane used to print for a hung create.
            if created_workspace:
                shutil.rmtree(workspace, ignore_errors=True)
                self._workspace_dir = None
            logger.error(
                "sbx create timed out after %s seconds (VENYA_SBX_CREATE_TIMEOUT, "
                "SBX_CREATE_TIMEOUT default %s) for sandbox %s — no sandbox was created",
                create_timeout,
                SBX_CREATE_TIMEOUT,
                sandbox_name,
            )
            raise SbxCreateTimeoutError(cmd, create_timeout) from exc
        if result.returncode != 0:
            memory_shape = sbx_memory_refusal_shape(result.stderr)
            if created_workspace:
                shutil.rmtree(workspace, ignore_errors=True)
                self._workspace_dir = None
            if memory_shape:
                # #639 AC1 — a named, operator-actionable outcome, in the executor's own
                # journal, beside the sizing knob and the page that explains them. The
                # vendor's stderr is logged (it is the evidence) but it does NOT cross the
                # relay boundary: the create stays a RuntimeError refusal on the existing
                # channel, so the relay status for it is unchanged (#639 AC4).
                logger.error(
                    "sbx create refused for memory (matched %r) — sandbox %s needs %s MiB "
                    "(VENYA_EXECUTOR_SANDBOX_MEMORY_MB); the guest cannot fit it. Lower the "
                    "cap or size the executor up: see docs/deployment-sizing.md. "
                    "vendor stderr: %s",
                    memory_shape,
                    sandbox_name,
                    self.sandbox_memory_mb,
                    result.stderr,
                )
                raise SbxMemoryRefusalError(
                    f"Failed to create sandbox: the vendor refused the memory request "
                    f"(matched {memory_shape!r}); cap={self.sandbox_memory_mb} MiB, "
                    f"see docs/deployment-sizing.md"
                )
            logger.error("sbx create failed: %s", result.stderr)
            raise RuntimeError(f"Failed to create sandbox: {result.stderr}")

        self._sandbox_name = sandbox_name
        register_live_sandbox(sandbox_name, session_id or sandbox_name)
        logger.info("Created Docker Sandbox: %s", sandbox_name)
        self._copy_sshpass(sandbox_name)

    def _copy_sshpass(self, sandbox_name: str) -> None:
        """Copy sshpass binary into the sandbox (warns if not on host)."""
        host_sshpass = shutil.which("sshpass")
        if not host_sshpass:
            # WARNING, not debug (ticket executor-installer-missing-sshpass):
            # the installer apt list carries sshpass, so this only fires on
            # out-of-band hosts — where it used to be invisible until the
            # ssh-password shape died 127 in-sandbox.
            logger.warning(
                "sshpass not found on host; skipping sandbox copy — ssh-password "
                "command shapes will fail 127 in-sandbox. Install sshpass on the "
                "executor host (apt install sshpass)."
            )
            return
        result = subprocess.run(  # nosec
            ["sbx", "cp", host_sshpass, f"{sandbox_name}:/usr/bin/sshpass"],
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
        )
        if result.returncode != 0:
            logger.warning("sbx cp sshpass failed: %s; falling back to /tmp", result.stderr)
            with open(host_sshpass, "rb") as fh:
                binary = fh.read()
            subprocess.run(  # nosec
                # nosec B108: /tmp here is inside the sandbox's own
                # isolated microVM filesystem, not a shared host tmp.
                ["sbx", "exec", "-i", sandbox_name, "tee", "/tmp/sshpass"],  # nosec B108
                input=binary,
                capture_output=True,
                timeout=10,
                check=False,
            )
            subprocess.run(  # nosec
                ["sbx", "exec", sandbox_name, "chmod", "+x", "/tmp/sshpass"],  # nosec B108
                capture_output=True,
                timeout=5,
                check=False,
            )

    def copy_secrets_into_sandbox(self, mounts: list[SecretMount]) -> None:
        """Copy secrets from host tmpfs into the sandbox.

        Args:
            mounts: List of SecretMount objects with host and container paths.
        """
        if not self._sandbox_name:
            raise RuntimeError("Sandbox not created yet")

        # Create secrets directory inside sandbox. Fail-closed: a swallowed
        # mkdir failure surfaces later as an opaque tee execution error.
        mkdir_result = subprocess.run(  # nosec
            ["sbx", "exec", self._sandbox_name, "mkdir", "-p", CONTAINER_SECRET_DIR],
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
        )
        if mkdir_result.returncode != 0:
            logger.error(
                "mkdir %s in sandbox %s failed: %s",
                CONTAINER_SECRET_DIR,
                self._sandbox_name,
                mkdir_result.stderr,
            )
            raise RuntimeError(f"Failed to create secrets directory {CONTAINER_SECRET_DIR} in sandbox")

        copied_paths: list[str] = []
        for mount in mounts:
            container_path = mount.container_path

            # Pipe the secret over stdin to `tee`: the file is created as the
            # sandbox exec user (uid 1000) and so stays readable by the command
            # that runs as uid 1000. `sbx cp` would tar-preserve the host uid
            # (the daemon user), leaving a 0400 file the uid-1000 runner cannot
            # open. stdin (not argv) keeps the secret out of process listings.
            with open(mount.path, "rb") as fh:
                secret_bytes = fh.read()
            result = subprocess.run(  # nosec
                ["sbx", "exec", "-i", self._sandbox_name, "tee", container_path],
                input=secret_bytes,
                capture_output=True,
                timeout=10,
                check=False,
            )
            if result.returncode != 0:
                logger.error(
                    "inject secret %s into sandbox failed: %s",
                    mount.secret_id,
                    (result.stderr or b"").decode(errors="replace"),
                )
                for copied in copied_paths + [container_path]:
                    subprocess.run(  # nosec
                        ["sbx", "exec", self._sandbox_name, "rm", "-f", copied],
                        capture_output=True,
                        text=True,
                        timeout=10,
                        check=False,
                    )
                raise RuntimeError(f"Failed to copy secret {mount.secret_id} into sandbox")

            copied_paths.append(container_path)

            # Set read-only permissions inside sandbox. Fail-closed (L-65): if
            # chmod fails, roll back everything copied and abort — a secret left
            # at default perms (potentially world-readable) must not be injected.
            chmod_result = subprocess.run(  # nosec
                ["sbx", "exec", self._sandbox_name, "chmod", "400", container_path],
                capture_output=True,
                text=True,
                timeout=10,
                check=False,
            )
            if chmod_result.returncode != 0:
                logger.error("sbx chmod failed for %s: %s", mount.secret_id, chmod_result.stderr)
                for copied in copied_paths:
                    subprocess.run(  # nosec
                        ["sbx", "exec", self._sandbox_name, "rm", "-f", copied],
                        capture_output=True,
                        text=True,
                        timeout=10,
                        check=False,
                    )
                raise RuntimeError(f"Failed to set read-only permissions on secret {mount.secret_id} in sandbox")

            logger.debug("Copied secret %s into sandbox: %s", mount.secret_id, container_path)

    def write_askpass_helper(self) -> None:
        """Stage the static askpass helper on the host and copy it to an
        exec-capable path in the sandbox (0555).

        The sbx runtime mounts /run/secrets rw,noexec,nosuid, so a helper
        tee'd into the secrets dir could be read but not exec'd and the
        git/ssh clone shape died at rc=128 (ticket
        askpass-helper-noexec-mount-conflict). The static script is therefore
        staged on the host (mkstemp -> write -> fchmod 0555) and copied to
        ASKPASS_HELPER_PATH (a root-owned, exec-capable system dir the
        sandbox uid-1000 user cannot write or replace) with `sbx cp` — the
        same mechanism _copy_sshpass uses for a system path. There is NO
        tee-to-/tmp fallback: /tmp is agent-writable and would silently drop
        the unwritable property. cp failure is fail-closed (no in-guest
        rollback rm is attempted — a uid-1000 `sbx exec rm` cannot unlink
        from the root-owned dir, and the static, secret-free helper is
        cleaned up when the per-run sandbox is destroyed).

        The guest secrets dir is still created: the helper references the
        credential file at VENYA_ASKPASS_SECRET inside it regardless of where
        the helper itself lives. The script carries NO secret; at invocation
        it prints that file and answers username prompts from
        VENYA_ASKPASS_USER (ticket secret-shape-askpass-helpers).
        """
        if not self._sandbox_name:
            raise RuntimeError("Sandbox not created yet")

        # Ordering verified in executor.py: copy_secrets_into_sandbox runs
        # BEFORE write_askpass_helper and creates this dir; the mkdir -p here
        # is the idempotent guard for the askpass-only path (an askpass secret
        # always rides a copied secret file, but keep it so the helper never
        # points at a missing dir).
        mkdir_result = subprocess.run(  # nosec
            ["sbx", "exec", self._sandbox_name, "mkdir", "-p", CONTAINER_SECRET_DIR],
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
        )
        if mkdir_result.returncode != 0:
            logger.error("mkdir %s for askpass helper failed: %s", CONTAINER_SECRET_DIR, mkdir_result.stderr)
            raise RuntimeError(f"Failed to create secrets directory {CONTAINER_SECRET_DIR} for askpass helper")

        fd, host_temp = tempfile.mkstemp(prefix="venya-askpass-")
        try:
            with os.fdopen(fd, "wb") as fh:
                fh.write(ASKPASS_HELPER_CONTENT.encode("utf-8"))
                fh.flush()
                os.fchmod(fh.fileno(), 0o555)  # nosec B103 — read+exec for the
                # git/ssh-invoking agent, NO write bit: this is the tamper
                # property. The staged file is the static, secret-free helper.
            cp_result = subprocess.run(  # nosec
                ["sbx", "cp", host_temp, f"{self._sandbox_name}:{ASKPASS_HELPER_PATH}"],
                capture_output=True,
                text=True,
                timeout=10,
                check=False,
            )
            if cp_result.returncode != 0:
                logger.error("askpass helper sbx cp failed: %s", cp_result.stderr)
                raise RuntimeError("Failed to copy askpass helper into sandbox")
        finally:
            # Best-effort host cleanup: the helper is static and secret-free,
            # so a failed unlink is logged, not raised.
            try:
                os.unlink(host_temp)
            except OSError:
                logger.warning("Failed to unlink host askpass helper temp: %s", host_temp)

        logger.debug("Askpass helper copied to %s (mode 555)", ASKPASS_HELPER_PATH)

    # --- env-file injection (ticket secret-shape-env-injection, option ii) ---

    _ENV_NAME_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")

    def _write_env_file(self, env: dict[str, str]) -> str:
        """Write KEY=VALUE lines to a 0600 file in the session tmpfs dir.

        Consumed via `sbx exec --env-file` — native flag on sbx >= 0.39.0.
        The 2026-09-21 exec-1 spike predated the correction: on the 0.38.0
        build of that day the flag is accepted and ignored (silent no-op,
        refs ticket sbx-exec-env-file-noop), which is why the boot floor in
        require_supported_sbx now refuses sbx < 0.39.0. Values never ride
        host argv, unlike the former
        `-e K=V` form which exposed them in `/proc/<pid>/cmdline` for the
        command's duration. The format is line-based: CR/LF/NUL in a value is
        rejected here as the last line of defense against forging extra
        env-file lines (callers validate too).

        #469 — the fallback branch (no ``prepare()`` ran, so no session dir).
        The dir it creates is named ``env_<rand>``, carries NO execution-session
        id, and used to be reaped by nothing: the daemon sweep matched only
        ``session_*`` and the boot sweep walks a different base and matches
        ``ws_*``. Two owners now cover it — this class removes the dir it made
        (``_release_fallback_dir``, AC4) and the daemon reaper collects what an
        abort leaves behind (``daemon.ReaperLoop._check_orphaned``, AC1).
        """
        if self._session_dir is None:
            os.makedirs(SECRET_TMPFS_BASE, mode=0o700, exist_ok=True)
            self._session_dir = tempfile.mkdtemp(prefix=ENV_DIR_PREFIX, dir=SECRET_TMPFS_BASE)
            # #469: this directory is ours — record it so the exec's finally can
            # remove it once the env file is destroyed. Without that bookkeeping
            # the dir survived for the host's uptime, and no reaper matched it.
            self._fallback_env_dir = self._session_dir

        session_dir = self._session_dir
        try:
            lines: list[str] = []
            for name, value in env.items():
                if not self._ENV_NAME_RE.match(name):
                    raise ValueError(f"invalid env var name: {name!r}")
                if "\n" in value or "\r" in value or "\x00" in value:
                    raise ValueError(f"env var {name}: multi-line or NUL values cannot ride the env-file format")
                lines.append(f"{name}={value}\n")
            path = os.path.join(session_dir, "venya-env")
            fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
            with os.fdopen(fd, "w", encoding="utf-8") as fh:
                fh.write("".join(lines))
        except BaseException:
            # A name/value rejection fires before any file exists, so the dir
            # this branch just made is empty — take it back now rather than
            # park it on tmpfs for the reaper to find later. A write failure
            # leaves the file behind; rmdir refuses the non-empty dir and the
            # reaper stays the backstop. Either way the raise is re-raised
            # unchanged: this cleanup cannot turn a rejection into a success.
            self._release_fallback_dir()
            raise
        return path

    @staticmethod
    def _destroy_env_file(path: str) -> None:
        """Zero + delete the env file immediately after the exec — values are needed only during it."""
        try:
            size = os.path.getsize(path)
            with open(path, "r+b") as fh:
                fh.write(b"\x00" * size)
                fh.flush()
                os.fsync(fh.fileno())
            os.unlink(path)
        except OSError:
            logger.warning("Failed to destroy env file %s", path)

    def _release_fallback_dir(self) -> None:
        """Remove the env-file fallback dir this strategy created (#469 AC4).

        Scoped three ways on purpose:

        * only the directory THIS instance created in the fallback branch is
          ever touched — a ``prepare()`` session dir belongs to the cleanup
          callable that ``prepare()`` registered, and is never removed here;
        * ``os.rmdir`` refuses a non-empty directory, so this can never delete
          collateral (a file the destroy failed to unlink stays, with its dir,
          for the reaper);
        * the reaper's ``env_*`` pass is the backstop for an abort between
          ``os.open`` and this call (a kill mid-execution), which is exactly
          the window the ticket filed.

        Clearing ``_session_dir`` on success is what makes the NEXT command in
        the same run build a fresh dir instead of opening a file inside a
        directory that no longer exists.
        """
        path = self._fallback_env_dir
        if path is None:
            return
        try:
            os.rmdir(path)
            removed = True
        except FileNotFoundError:
            removed = True  # already gone — same end state, ownership is released
        except OSError:
            logger.warning("Env fallback dir %s still holds a file; leaving it to the reaper", path)
            removed = False
        if removed:
            self._fallback_env_dir = None
            if self._session_dir == path:
                self._session_dir = None

    def apply_network_policy(self, sandbox_name: str) -> None:
        """Apply egress allowlist to sandbox.

        Reads the configured allowlist file (default /etc/venya/egress-allowlist.txt) and
        allows each entry via sbx policy allow network <host>. DNS resolver is always
        allowed.

        Missing/empty allowlist -> only DNS resolver allowed (fail-closed).

        Args:
            sandbox_name: Name of the sandbox to apply policies to.
        """
        from ..egress_filter import EgressFilter

        if self.dns_resolver is None:
            raise RuntimeError(
                "dns_resolver is not configured — set `dns_resolver` in "
                "/etc/venya/executor.toml (that file's value wins whenever the file "
                "carries the key, including as an empty value; "
                "VENYA_EXECUTOR_DNS_RESOLVER in the daemon environment is read only "
                "when the file does not carry `dns_resolver` at all — precedence is "
                "file > env > default, #598) "
                "(find it: resolvectl status or /etc/resolv.conf)"
            )

        # Config values arrive via the constructor (daemon.create_executor wires
        # them from ExecutorConfig: toml `dns_resolver`/`egress_allowlist_path`
        # or VENYA_EXECUTOR_* env). Ticket executor-dns-resolver-config-inert.
        egress = EgressFilter(
            allowlist_path=Path(self.egress_allowlist_path),
            dns_resolver=self.dns_resolver,
        )

        # Run as the daemon user, never via sudo: the sbx daemon and
        # `sbx login` credentials live under the daemon user, and the
        # root context is unauthenticated — the vendor's own wording is
        # "You are not authenticated to Docker"
        # (docs.docker.com/ai/sandboxes/troubleshooting/, accessed 2026-10-09).
        # --sandbox (not --name) scopes the rule to this sandbox.
        # shortcut: one scoped rule per run is never explicitly removed;
        # if the daemon does not GC rules for dead sandboxes, sweep with
        # `sbx policy rm` when `sbx policy ls` grows unbounded.
        for host in egress.get_allowed_hosts():
            if not host:
                raise RuntimeError(
                    f"Egress allowlist contains an empty entry; " f"refusing to apply policy for sandbox {sandbox_name}"
                )
            cmd = [
                "sbx",
                "policy",
                "allow",
                "network",
                host,
                "--sandbox",
                sandbox_name,
            ]
            result = subprocess.run(  # nosec B603 B607
                cmd,
                capture_output=True,
                text=True,
                check=False,
            )
            if result.returncode != 0:
                logger.error(
                    "Failed to allow network %s for sandbox %s: %s",
                    host,
                    sandbox_name,
                    result.stderr,
                )
                # Fail loud: a swallowed registration failure leaves the
                # sandbox under deny-all and the command dies later with an
                # opaque network error (e.g. SSH kex closed by remote).
                raise RuntimeError(
                    f"Failed to register egress allow {host} for sandbox "
                    f"{sandbox_name} (cmd: {' '.join(cmd)}): {result.stderr.strip()}"
                )
            logger.debug("Allowed network %s for sandbox %s", host, sandbox_name)

    def execute_command(
        self,
        command: str,
        env_override: dict[str, str] | None = None,
        cwd: str | None = None,
        argv: list[str] | None = None,
    ) -> subprocess.CompletedProcess:
        """Execute a command inside the sandbox.

        Execution posture (ticket execution-command-wire-unstructured-string
        #322, ruling Q3=C3): with ``argv`` the guest runs those tokens DIRECT
        — ``sbx exec <sandbox> <argv...>``, no shell, boundaries preserved
        element-for-element (fleet C5 probe: boundaries survive render->sh,
        bare names PATH-resolve execvp-style). Without it the rendered string
        rides ``sh -c`` — retained ONLY for the ruled session-bound ``<``
        sudo-redirect case, where the guest shell must perform the redirect.

        env_override rides as a 0600 `--env-file` on the host session tmpfs
        (NEVER `-e K=V` argv — that exposed values in host /proc for the
        command's duration; ticket secret-shape-env-injection option (ii),
        spike-ruled: `--env-file` is native to `sbx exec` >= 0.39.0). The file
        is zeroed and deleted in a `finally` the moment the exec returns.
        cwd still rides as `-w DIR` (docker-exec semantics; non-secret).
        The 2026-09-18 exec-1 probe ("values stay DATA — never shell-parsed")
        ran on sbx
        0.38.0, where the flag injects nothing — a silent-no-op misread, since
        corrected (refs ticket sbx-exec-env-file-noop; functional proof of
        injection on 0.46.0 in the ticket's note 3951754721).
        `-w` overrides the workspace-mount default pwd
        per command without conflicting with the mount.

        Args:
            command: The command string for the `sh -c` posture (argv=None).
            env_override: Environment variables to set (0600 env-file).
            cwd: Per-command working directory inside the sandbox (-w).
            argv: Direct token list for the no-shell posture (ticket #322
                C3); takes precedence over `command` when given.

        Returns:
            CompletedProcess with stdout, stderr, and returncode.
        """
        if not self._sandbox_name:
            raise RuntimeError("Sandbox not created yet")
        if argv is not None and not argv:
            raise ValueError("argv must not be empty — nothing to exec in the sandbox")

        cmd = ["sbx", "exec"]
        env_file = self._write_env_file(env_override) if env_override else None
        if env_file:
            cmd += ["--env-file", env_file]
        if cwd:
            cmd += ["-w", cwd]
        if argv is not None:
            cmd += [self._sandbox_name, *argv]
        else:
            cmd += [self._sandbox_name, "sh", "-c", command]

        try:
            # stdin=DEVNULL: without it the sbx client inherits the DAEMON's stdin, so a
            # guest command that waits on stdin (ssh at a prompt, `read`, a pager) holds the
            # single admission permit for the full SBX_TIMEOUT while every client fuse blows
            # far earlier. EOF now, fail fast instead. (#695 AC1; the ceiling itself is #696.)
            result = subprocess.run(  # nosec
                cmd,
                capture_output=True,
                timeout=SBX_TIMEOUT,
                check=False,
                stdin=subprocess.DEVNULL,
            )
        finally:
            if env_file:
                self._destroy_env_file(env_file)
                self._release_fallback_dir()
        return result

    def remove_sandbox(self) -> int:
        """Remove the sandbox and all its contents.

        Also deletes the per-run workspace this strategy created (ownership
        rule: only what it created). A caller-supplied workspace is left
        in place — the base directory itself always survives.

        #474: the live-ownership claim drops ONLY when ``sbx rm`` really
        succeeded. A failed removal leaves the sandbox claimed (its session is
        still live) and returns rc != 0 so the caller can hand the residue to
        the reaper instead of losing track of a secrets-bearing VM.

        Returns:
            ``sbx rm`` exit code, or 0 when there was no sandbox to remove.
        """
        rc = 0
        if self._sandbox_name:
            result = subprocess.run(  # nosec
                ["sbx", "rm", "--force", self._sandbox_name],
                capture_output=True,
                text=True,
                timeout=30,
                check=False,
            )
            rc = result.returncode
            if rc == 0:
                logger.debug("Removed sandbox: %s", self._sandbox_name)
                release_live_sandbox(self._sandbox_name)
            else:
                logger.warning("Failed to remove sandbox %s: %s", self._sandbox_name, result.stderr)

        if self._workspace_dir:
            shutil.rmtree(self._workspace_dir, ignore_errors=True)
            logger.debug("Removed per-run workspace: %s", self._workspace_dir)
            self._workspace_dir = None

        return rc
