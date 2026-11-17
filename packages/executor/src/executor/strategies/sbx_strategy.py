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
import pwd
import re
import shutil
import subprocess  # nosec B404 — sandbox strategy requires subprocess for sbx commands
import tempfile
import threading
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path
from typing import NamedTuple

# `CONTAINER_SECRET_DIR` (where an injected secret appears inside the sandbox) is
# defined ONCE in the frozen wire contract and imported here — the server wires the
# same path text for the askpass secret, and the gate's accept set is built from it,
# so a second literal could drift into a target the gate accepts and the audit
# display contradicts (#733). Its full rationale, including the noexec-mount note that
# puts the EXEC'D helper under /usr/local/bin instead, lives beside the constant.
from venya_contract import ASKPASS_HELPER_PATH, CONTAINER_SECRET_DIR

from ..egress_filter import (
    DEFAULT_ALLOWLIST_PATH,
    EgressFilter,
    ProxyEgressDenial,
    ProxyEgressLogOutcome,
    egress_deny_notice,
    proxy_egress_denial_notice,
    proxy_egress_log_outcome,
    proxy_egress_unrecognised_notice,
    sbx_policy_log_argv,
)
from .base import InjectionResult, InjectionStrategy, SecretMount

logger = logging.getLogger("venya.executor.strategies.sbx")


def daemon_account() -> str:
    """The account THIS process runs as, which is the one the sandbox daemon's `sbx login`
    credentials belong to. An operator reading a denial line needs this name: the runtime's
    policy log answers for this account and answers nothing for any other (measured both
    directions on an executor test guest: as the daemon account it lists the refusals, as a login
    account it refuses with an authentication error)."""
    name = os.environ.get("USER")
    if name:
        return name
    try:
        return pwd.getpwuid(os.getuid()).pw_name
    except KeyError:
        # No login name and no passwd row: the numeric uid is still an identity an
        # operator can act on, and a repair line that names nothing is not a repair.
        return str(os.getuid())


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

# How long to wait for sandbox commands.
# Override per-deployment: `VENYA_SBX_TIMEOUT` (seconds), read AT CALL TIME by
# `sbx_command_timeout()` below — ticket no-per-command-ceiling #696 AC1. The
# constant was a bare literal with no door: one command could hold the single
# admission permit for the full hour (#695's durability half). The default is
# unchanged; the knob is what lets a deployment (and a unit cell) bind the hold
# shorter than every client fuse upstream (relay read 300 s, nginx 330 s, CLI/MCP
# 340 s) and shorter than the operator's own budget.
SBX_TIMEOUT = 3600  # 1 hour
SBX_TIMEOUT_ENV = "VENYA_SBX_TIMEOUT"


def sbx_command_timeout() -> float:
    """Sandbox command-execution bound (#696 AC1).

    Same env-override idiom as ``VENYA_DIRECT_PATH_TIMEOUT`` (``_direct_path_timeout``
    in executor.py) and ``VENYA_SBX_CREATE_TIMEOUT``: read at call time so a unit
    cell can inject a short bound instead of waiting out an hour. Empty-or-absent
    keeps the shipped default; a non-numeric value warns with both the value and
    the default and falls back; the floor is 0.0.
    """
    raw = os.environ.get(SBX_TIMEOUT_ENV)
    if raw is None or raw == "":
        return float(SBX_TIMEOUT)
    try:
        return max(float(raw), 0.0)
    except ValueError:
        logger.warning(
            "%s=%r is not a number — using the %d s default for the sbx command path",
            SBX_TIMEOUT_ENV,
            raw,
            SBX_TIMEOUT,
        )
        return float(SBX_TIMEOUT)


# How long to wait for the agent-template pull + microVM create (`sbx create`).
# Measured (2026-09-02, fast uplink): cold *first-ever* pull of the multi-GB
# `shell-docker` template = 65s; warm (cached) create = ~5.5s. Held **inside** the
# core's relay read budget (executors.py `httpx2.AsyncClient(timeout=300)`) so a slow
# pull times out on the executor with a precise local error before the core's connection
# timeout fires and leaves a doomed create running orphaned in the executor daemon.
# Override per-network: `VENYA_SBX_CREATE_TIMEOUT` (seconds). Durable fix (pre-pull the
# template at enrollment) is tracked in `venya-dev/tickets/sbx-cold-start-prepull.md`.
SBX_CREATE_TIMEOUT = 240

# How long to wait for ONE `sbx policy allow network` child (the egress rule
# registration in `apply_network_policy`). Until this row that call carried NO
# `timeout=` at all — the only untimed subprocess child in `packages/*/src` — so a
# wedged sandboxd daemon held the executor's single admission permit indefinitely
# instead of failing the command: an unbounded wait there is an outage, not a slow
# run, because every other client queues behind it.
#
# The bound is per RULE, and the loop applies one rule per allowlist entry plus the
# DNS resolver, so a deployment's worst case is this number times its entry count.
#
# Default 30 s, chosen from a physical capture rather than a guess. Measured on
# `venya-exec-3` as `bot` against the live `venya-sandboxd` unit, with each predicate
# named because the two shapes below are not one number:
#   * 19 SUCCESSFUL registrations (`sbx policy allow network <host>`, global scope):
#     406-1059 ms, median 446 ms.
#   * 19 calls in the SHIPPED argv shape (`... --sandbox <name>`), which this guest
#     answered `sandbox "…" not found` (rc=1) because no sandbox could be created here
#     — the same sbx-absent class the executor suite carries: 293-1465 ms, median 347 ms.
#     This is the round trip the product makes, refused at the daemon.
#   * 20 successful registrations applied back to back as one loop (the shape of one
#     `apply_network_policy` call): 9387 ms total, ~469 ms per rule.
# 30 s is ~28x the slowest SUCCESSFUL registration and ~20x the slowest single call of
# any kind observed on that guest, so a healthy registration cannot trip it; a 20-entry
# allowlist finishes in ~9 s, inside the core's 300 s relay read budget. No cold-daemon
# figure is claimed: `pgrep`/`pkill` for the daemon read 0 as `bot` while
# `systemctl is-active venya-sandboxd` said active (the permission wall fleet-vm-ops
# names), so a "restart" driven that way restarts nothing — the unit reports
# `NRestarts=0` with a start timestamp predating the whole capture.
# NOT MEASURED, and stated so it is not mistaken for measured: the latency of a rule
# registration against a LIVE sandbox. This guest cannot create one — `sbx create` fails
# at "failed to run sandbox container", and the daemon's own journal shows Docker Hub
# token refresh timing out on DNS — so the shipped argv was exercised only in its refused
# face. The two figures above bracket it: a registration against a live sandbox is the
# same RPC with one more lookup, not a different order of work.
# Override per-deployment: `VENYA_SBX_POLICY_TIMEOUT` (seconds), read AT CALL TIME by
# `sbx_policy_timeout()` below, so a unit cell can inject a short bound instead of
# waiting the default out.
SBX_POLICY_TIMEOUT = 30
SBX_POLICY_TIMEOUT_ENV = "VENYA_SBX_POLICY_TIMEOUT"


def sbx_policy_timeout() -> float:
    """Egress-rule registration bound.

    Same env-override idiom as ``VENYA_DIRECT_PATH_TIMEOUT``
    (``_direct_path_timeout`` in executor.py) and ``VENYA_SBX_CREATE_TIMEOUT``:
    read at call time so a unit cell injects a short bound instead of waiting out
    the default. Absent or empty keeps the shipped default; a non-numeric value
    warns with both the value and the default and falls back; the floor is 0.0.
    """
    raw = os.environ.get(SBX_POLICY_TIMEOUT_ENV)
    if raw is None or raw == "":
        return float(SBX_POLICY_TIMEOUT)
    try:
        return max(float(raw), 0.0)
    except ValueError:
        logger.warning(
            "%s=%r is not a number — using the %d s default for the egress policy path",
            SBX_POLICY_TIMEOUT_ENV,
            raw,
            SBX_POLICY_TIMEOUT,
        )
        return float(SBX_POLICY_TIMEOUT)


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


class SbxPolicyTimeoutError(subprocess.TimeoutExpired):
    """One `sbx policy allow network` child exceeded its own budget.

    Named for the same reason `SbxCreateTimeoutError` is (#639): this propagates
    through the caller's existing COMMAND-timeout lane — it IS a `TimeoutExpired`,
    so the relay outcome is unchanged — but without a class of its own the operator
    reads "Sandbox command timed out", the wrong stage, for a failure that happened
    before the command ever ran. The stage and the bound that fired are sayable here.
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


# ---------------------------------------------------------------------------
# iid 795: which install route is TRUE on this host.
#
# The refusal below used to print one sentence for every platform. Leg 1373 measured that
# `docker-sbx` has ZERO stanzas on every Debian publication face (and on jammy, focal,
# oracular, plucky and stonking), while `noble` and `resolute` publish it — so the same
# string was simultaneously correct on the Ubuntu server/executor target and a dead end on a
# Debian host, which `README.md` names as a Workstation CLI platform only.
#
# The table is a MEASUREMENT, not a guess about the vendor's roadmap, so it is deliberately
# narrow: a release is claimed to publish only when the face was read. Everything else —
# including a Debian or Ubuntu release nobody has checked, and any other distribution — falls
# to the asset route, which is the one face proved to work anywhere (leg 1371 installed the
# vendor's linux-amd64 asset with no apt package and no sudo). An unidentified host is never
# assumed to be Ubuntu: that assumption is what this fix removes.
# ---------------------------------------------------------------------------

ROUTE_APT = "apt"
ROUTE_ASSET = "asset"
ROUTE_UNIDENTIFIED = "unidentified"

#: Releases read on download.docker.com with a non-zero `docker-sbx` stanza count.
APT_PUBLISHING_RELEASES: frozenset[str] = frozenset({"noble", "resolute"})

#: Ubuntu releases read on the same host with a ZERO count. Named separately from "anything
#: else", because a measured absence is a different claim from an unmeasured one.
APT_ABSENT_UBUNTU_RELEASES: frozenset[str] = frozenset({"jammy", "focal", "oracular", "plucky", "stonking"})

#: Debian is a supported family in `README.md` (Workstation CLI) whose whole publication was read
#: with zero `docker-sbx` stanzas, so it is recognised — not "unidentified".
APT_ABSENT_FAMILIES: frozenset[str] = frozenset({"debian"})

#: Handed to the reader so they can falsify this sentence at their own face instead of trusting
#: a measurement baked into a release.
APT_CHECK = "apt-cache policy docker-sbx"

#: `download.docker.com` distribution directory whose asset route leg 1371 actually executed.
SBX_VENDOR_ASSET = "https://github.com/docker/sbx-releases"

#: The generic asset's archive, named so an operator can find it without a search engine.
SBX_VENDOR_ASSET_FILE = "DockerSandboxes-linux-amd64.tar.gz"

#: The grant `validate()` used to order inline. It is a host-privilege requirement owned by
#: the installer (iid 384/383), not a line to type at a refusal, and it is stated, not run.
_KVM_NOTE = (
    "KVM access is a host-privilege requirement, not part of this install: the executor "
    "installer grants it to the `venya` service account, so check it with `getent group kvm` "
    "rather than editing your own membership from this message."
)


def read_os_release(path: str | Path = "/etc/os-release") -> dict[str, str]:
    """Parse the KEY=VALUE pairs of an os-release file.

    Absent or unreadable returns ``{}`` — a refusal must not be replaced by a second failure
    while it is being built. Values are unquoted the way the shell would unquote them, because
    a classifier that only recognised the exact lowercase token would silently fall to the safe
    route on a host that legitimately publishes the package.
    """
    fields: dict[str, str] = {}
    try:
        with open(path, encoding="utf-8") as handle:
            for line in handle:
                key, sep, value = line.strip().partition("=")
                if sep and key:
                    fields[key] = value.strip().strip('"').strip("'")
    except OSError:
        return {}
    return fields


def _os_release_token(value: str) -> str:
    """Normalise one os-release token the way the shell would read it.

    The classifier owns this, rather than trusting the caller: an unquoted-vs-quoted or
    capitalised spelling that fell through to the safe route would quietly deny a publishing
    host its apt package.
    """
    return value.strip().strip('"').strip("'").casefold()


def sbx_install_route(os_release: dict[str, str] | None = None) -> str:
    """Return which install route the operator of THIS host can actually follow.

    Pure over the mapping it is given (it reads os-release only when handed nothing), so a test
    can assert a face without owning a box that is that face.
    """
    fields = read_os_release() if os_release is None else os_release
    family = _os_release_token(fields.get("ID", ""))
    release = _os_release_token(fields.get("VERSION_CODENAME", ""))
    if family in APT_ABSENT_FAMILIES:
        # Whole publication read, zero stanzas — a known family with no apt route.
        return ROUTE_ASSET
    if family != "ubuntu":
        return ROUTE_UNIDENTIFIED
    if release in APT_PUBLISHING_RELEASES:
        return ROUTE_APT
    if release in APT_ABSENT_UBUNTU_RELEASES:
        return ROUTE_ASSET
    # A release nobody read gets no claim at all — not the apt route, and not an assertion that
    # the package is absent. Guessing either way is the defect this ticket files.
    return ROUTE_UNIDENTIFIED


def sbx_install_refusal(os_release: dict[str, str] | None = None) -> str:
    """The `sbx CLI not found` sentence, classified for the host raising it.

    Every branch names something the reader can act on at their own face — a package route that
    exists, or the vendor asset with its file name — and none of them says "see the docs".
    """
    route = sbx_install_route(os_release)
    fields = read_os_release() if os_release is None else os_release
    family = _os_release_token(fields.get("ID", ""))
    release = _os_release_token(fields.get("VERSION_CODENAME", "")) or "this release"
    floor = ".".join(map(str, SBX_MIN_VERSION))

    if route == ROUTE_APT:
        head = (
            "sbx CLI not found. This host runs Ubuntu "
            f"{release}, which publishes the vendor package: install it with "
            "curl -fsSL https://get.docker.com | sudo REPO_ONLY=1 sh && "
            "sudo apt-get install docker-sbx. "
        )
    elif route == ROUTE_ASSET and family in APT_ABSENT_FAMILIES:
        head = (
            f"sbx CLI not found. Docker's {family} publication carries no `docker-sbx` package, "
            "so apt would find nothing here; install the vendor's generic asset instead — "
            f"{SBX_VENDOR_ASSET} ({SBX_VENDOR_ASSET_FILE}), whose install.sh honours a PREFIX "
            "you own — and put that bin directory on the executor's PATH. "
            f"Check your own face with `{APT_CHECK}`. "
        )
    elif route == ROUTE_ASSET:
        head = (
            f"sbx CLI not found. No `docker-sbx` package was found for Ubuntu {release} in "
            "Docker's publication, so apt may fail here; install the vendor's generic asset "
            f"instead — {SBX_VENDOR_ASSET} ({SBX_VENDOR_ASSET_FILE}), whose install.sh honours a "
            f"PREFIX you own — and put that bin directory on the executor's PATH. Check your own "
            f"face with `{APT_CHECK}`. "
        )
    else:
        # The lie this leg removes: this arm used to end `Check what your own repository offers
        # with `apt-cache policy docker-sbx`.` on a sentence whose own words are "no package
        # manager is named" — an odd box was handed the same apt instruction #795 was filed for.
        # The falsifiable hand-over survives where an apt route is genuinely plausible (the two
        # asset arms above); it cannot live here without making the first sentence false.
        head = (
            "sbx CLI not found, and no install route was verified for this host, so no package "
            f"manager is named. The vendor's generic asset is the route proved to work on an "
            f"unfamiliar host: {SBX_VENDOR_ASSET} ({SBX_VENDOR_ASSET_FILE}), install.sh with a "
            "PREFIX you own, then put that bin directory on the executor's PATH. "
        )
    return f"{head}{_KVM_NOTE} The executor starts once `sbx version` reports >= {floor}."


# ---------------------------------------------------------------------------
# refs #312 item 3a (beta3 gate): refuse to boot an executor whose sandbox can
# reach a container runtime.
#
# Measured on a live estate executor 2026-11-12 (`reports/312`, fleet face): the
# sandbox's OWN filesystem view carried `/var/run/docker.sock` mode
# `srw-rw---- root docker`, and `id -Gn` inside that sandbox answered
# `agent sudo docker`. `create_sandbox` below passes only
# `--name --memory shell <workspace>` — zero hits in this file for a group, user,
# socket or capability flag — so whether a sandbox can reach a runtime is decided
# entirely by the vendor build (`docker-sbx`), never by venya.
#
# Why a socket is a different class from a bad mount: the command inside the
# sandbox can ask that runtime to create a SECOND container with the host bind
# mounted, and the isolation the sandbox exists to provide ends at that socket.
# venya cannot drop what it never added, so the half it CAN do is refuse to
# pretend: ask one throwaway sandbox what it can write, and refuse to boot on an
# affirmative answer.
# ---------------------------------------------------------------------------

#: Socket paths whose presence means "whoever is inside this sandbox can talk to
#: a container runtime". Both spellings of the docker socket because images
#: mount one or the other; containerd because a containerd socket grants the
#: same power with a different name.
RUNTIME_SOCKET_PATHS: tuple[str, ...] = (
    "/var/run/docker.sock",
    "/run/docker.sock",
    "/run/containerd/containerd.sock",
    "/var/run/containerd/containerd.sock",
)

#: Supplementary groups that are the usual owners of one of those sockets. Used
#: for the WORDING of the refusal, never as the criterion: GIDs are site-specific
#: (this estate's docker group is 1001, most images carry 999) and a group with no
#: socket behind it grants nothing. The criterion is `-w` inside the sandbox.
RUNTIME_EXPOSED_GROUPS: frozenset[str] = frozenset({"docker", "sudo", "wheel", "root"})

#: The probe creates, execs in, and removes ONE throwaway sandbox at boot. Bound
#: far below SBX_CREATE_TIMEOUT (240 s) — a boot must not sit on a doomed create
#: for four minutes — and far above a warm container start. Override per host
#: with VENYA_SBX_RT_PROBE_TIMEOUT, the same env-at-call-time idiom as
#: sbx_command_timeout(), so a unit cell can inject a short bound.
SBX_RT_PROBE_TIMEOUT = 60.0

#: The sandbox template both create sites name, by image NAME at both sites.
#: Passing the bare agent name lets the vendor choose the flavour, and the flavour it
#: chooses for `shell` mounts a container-runtime socket the probe then correctly
#: refuses. Naming the plain `shell` template takes that choice back: the sandbox the
#: boot probe measures becomes the sandbox a workload gets, because both sites read
#: this one value. What it gives up is stated once, here: the plain flavour carries no
#: nested engine, so a container engine inside the sandbox is gone on this template —
#: nothing in venya asks for one today. Revisit if a feature needs an in-sandbox
#: engine, or if the vendor ships a flavour that mounts no runtime socket and still
#: carries one; either is a change to this line and to nothing in the guard.
#: By name, never by digest: `R-2927` cl.1's conditional trust is in the runtime probe's
#: answer about the shape, not in a tag this code cannot check.
SANDBOX_TEMPLATE = "docker.io/docker/sandbox-templates:shell"

#: Marker prefix so probe output can never be confused with sandbox chatter.
_RT_TAG = "VENYA_RT"


class SbxRuntimeExposureError(RuntimeError):
    """The sandbox can write a container-runtime socket, or venya cannot prove
    that it cannot. Both are refusals: the claim this guard makes is about
    reachability, and an unreadable answer is not evidence of isolation."""


class RuntimeProbe(NamedTuple):
    """What one throwaway sandbox reported about itself.

    groups:   the names `id -Gn` printed inside the sandbox (`[]` if it printed
              only numbers, which is why groups are wording and not the test).
    writable: runtime sockets the sandbox user could OPEN FOR WRITING.
    present:  runtime sockets that exist but are NOT writable from inside.
    """

    groups: list[str]
    writable: list[str]
    present: list[str]

    @property
    def exposed(self) -> bool:
        return bool(self.writable)


def rt_probe_timeout() -> float:
    """Probe bound, read at call time (VENYA_SBX_RT_PROBE_TIMEOUT, else 60 s).

    An unusable value falls back to the default rather than disabling the guard:
    a typo in a timeout must never read as "skip the check".
    """
    raw = os.environ.get("VENYA_SBX_RT_PROBE_TIMEOUT", "")
    try:
        value = float(raw)
    except (TypeError, ValueError):
        return SBX_RT_PROBE_TIMEOUT
    return value if value > 0 else SBX_RT_PROBE_TIMEOUT


def rt_probe_argv() -> list[str]:
    """The one shell command the probe execs inside the throwaway sandbox.

    Read-only by construction: `id`, and four `[ -e ]` / `[ -w ]` tests. No
    write, no network, no state, nothing that could consume or alter anything.
    """
    tests = "; ".join(
        f'if [ -e "{p}" ]; then if [ -w "{p}" ]; then echo "{_RT_TAG} W {p}"; ' f'else echo "{_RT_TAG} P {p}"; fi; fi'
        for p in RUNTIME_SOCKET_PATHS
    )
    return ["sh", "-c", f"id -Gn; {tests}"]


def parse_runtime_probe(stdout: str) -> RuntimeProbe:
    """Parse probe stdout; raise SbxRuntimeExposureError when it is unreadable.

    "Unreadable is a refusal" is the rule the sbx version floor already uses
    (require_supported_sbx treats output it cannot parse as a boot refusal), for
    the same reason: a guard that passes on noise is not armed.
    """
    groups: list[str] = []
    writable: list[str] = []
    present: list[str] = []
    saw_marker = False
    for raw_line in (stdout or "").splitlines():
        line = raw_line.strip()
        if not line:
            continue
        if line.startswith(_RT_TAG + " W "):
            saw_marker = True
            writable.append(line[len(_RT_TAG) + 3 :].strip())
        elif line.startswith(_RT_TAG + " P "):
            saw_marker = True
            present.append(line[len(_RT_TAG) + 3 :].strip())
        elif not groups and not saw_marker and all(re.fullmatch(r"[A-Za-z0-9._-]+", t) for t in line.split()):
            groups = line.split()  # the `id -Gn` line, first line of output
        else:
            raise SbxRuntimeExposureError(
                f"cannot read the sandbox runtime probe output (unexpected line {line!r}) — "
                "refusing to boot rather than call unreadable output proof of isolation"
            )
    if not groups and not saw_marker:
        raise SbxRuntimeExposureError(
            "the sandbox runtime probe produced no parsable output — refusing to boot "
            "rather than treat silence as proof of isolation"
        )
    return RuntimeProbe(groups=groups, writable=writable, present=present)


def _report_shape(parsed: RuntimeProbe) -> None:
    """Hand this boot's probe answer to the recorded-shape comparison. Never raises.

    Why it sits BEFORE the exposure branch rather than after it: measured physically on the
    test bed at v0.46.0 (leg 1328), two runtime sockets are writable inside the sandbox
    there, so the guard refuses on every boot. A report mounted only on the pass path would
    therefore print nothing on exactly the face `R-2928` cl.4 was written about, and the
    refusal would remain the only signal there ever was — the failure mode the recorded face
    exists to end. Placed here, an operator reads the refusal AND which field moved.

    It cannot cost the refusal either way: the raise that follows tests the same `parsed`
    unconditionally, every path out of this function is swallowed, and the import is inside
    the call so this module does not depend on the reporting one at load time.
    """
    try:
        from ..sandbox_shape import check_at_boot

        check_at_boot(parsed)
    except Exception as exc:  # a report cannot reopen a decision, in either direction
        logger.warning(
            "the sandbox shape comparison did not run (%s: %s) — the isolation decision is unaffected",
            type(exc).__name__,
            exc,
        )


def require_runtime_isolated_sandbox(memory_mb: int | None, timeout: float | None = None) -> str:
    """Create one throwaway sandbox, ask it what it can reach, refuse on a yes.

    Returns a short human-readable face for the INFO log when the sandbox can
    reach no runtime socket. Raises SbxRuntimeExposureError when it can, when the
    probe cannot be run or completed, when its answer cannot be read, or when
    there is no configured cap to probe with.

    This guard's own signature, predicate, socket paths, raise and shipped default are
    UNCHANGED by the recorded-shape work; the only thing added is the `_report_shape` call
    below, which hands the probe answer to `R-2928` cl.4's comparison and cannot widen or
    narrow the refusal (`R-2923` cl.1, `R-2928` cl.2).

    `memory_mb` is `int | None` because `ExecutorConfig.sandbox_memory_mb` is
    deliberately nullable (#578 — an explicit null stays representable so the
    create-time refusal stays reachable, `config.py`). The probe must describe the
    sandbox venya would actually build, so a null is not a default to invent here:
    it is the same refusal, named, and it comes BEFORE the sandbox exists rather
    than as a `TypeError` out of `int(None)` inside the argv (refs #312 item 3a).

    Named `venya-rt-probe-<pid>` on purpose: the boot reap in daemon.start()
    collects every `venya-*` sandbox as residue, so a probe leaked by a kill
    mid-flight is collected by the next boot rather than orphaned forever.
    """
    if memory_mb is None:
        raise SbxRuntimeExposureError(
            "cannot verify sandbox runtime isolation — sandbox_memory_mb is not configured, so there "
            "is no cap to probe with. Set VENYA_EXECUTOR_SANDBOX_MEMORY_MB to a value between 512 and "
            "75 percent of the executor guest memory. See docs/deployment-sizing.md for sizing guidance "
            "(refs #312 item 3a, #578)."
        )
    bound = float(timeout) if timeout else rt_probe_timeout()
    name = f"venya-rt-probe-{os.getpid()}"
    workspace: str | None = None
    created = False
    try:
        os.makedirs(WORKSPACE_BASE, mode=0o700, exist_ok=True)
        workspace = tempfile.mkdtemp(prefix="rtprobe_", dir=WORKSPACE_BASE)
        create = [
            "sbx",
            "create",
            "--name",
            name,
            "--memory",
            f"{int(memory_mb)}m",
            "-t",
            SANDBOX_TEMPLATE,
            "shell",
            workspace,
        ]
        result = subprocess.run(  # nosec
            create,
            capture_output=True,
            text=True,
            timeout=bound,
            check=False,
            stdin=subprocess.DEVNULL,
        )
        if result.returncode != 0:
            raise SbxRuntimeExposureError(
                "cannot verify sandbox runtime isolation — the throwaway probe sandbox "
                f"could not be created (sbx create rc={result.returncode}: "
                f"{(result.stderr or '').strip()[:300]!r}). The executor starts once the "
                "vendor sandbox can be created; refusing to boot is deliberate, because "
                "an unanswerable question is not an answer (refs #312 item 3a)."
            )
        created = True
        probe = subprocess.run(  # nosec
            ["sbx", "exec", name, *rt_probe_argv()],
            capture_output=True,
            text=True,
            timeout=bound,
            check=False,
            stdin=subprocess.DEVNULL,
        )
        parsed = parse_runtime_probe(probe.stdout)
        _report_shape(parsed)
        if parsed.exposed:
            groups = " ".join(parsed.groups) or "numeric gids only, no names"
            risky = sorted({g.lower() for g in parsed.groups} & set(RUNTIME_EXPOSED_GROUPS))
            # shortcut: INTERIM message shape — no drift-aware wording ("the face changed
            # from X") in THIS message. R-2928 cl.4's recorded face now exists (sandbox_shape,
            # leg 1328) and the drift sentence is logged beside this refusal rather than
            # folded into it, because rewriting the shipped refusal wording is not that leg's
            # scope and its paired-negative cells pin this text. Upgrade trigger: the
            # operator-facing-text item queued second in R-2938 cl.2.
            raise SbxRuntimeExposureError(
                "the sandbox can reach a container runtime — refusing to start. Inside the "
                f"sandbox this executor created, {[p for p in parsed.writable]} is writable "
                f"by the sandbox user (groups: {groups}"
                + (f", including {', '.join(risky)}" if risky else "")
                + "). That writability is the finding: the group list is wording, not the "
                "test, because a group grants nothing unless a socket behind it is writable. "
                "Whoever runs a command here can ask that runtime to create another container "
                "with the host mounted, which ends the isolation the sandbox exists to "
                "provide. `sbx create` is called with no group, user or socket flag, so this "
                "answer is not something a venya setting produced or a venya setting can "
                "undo — venya does not name the cause here. Read the executor log before "
                "changing anything: this line and the `sbx CLI supported` line above it are "
                "both in it (`journalctl -u venya-executor`). The executor starts once the "
                "sandbox reports no writable runtime socket (refs #312 item 3a)."
            )
        if parsed.present:
            logger.warning(
                "runtime socket(s) %s exist in the sandbox view but are NOT writable by "
                "the sandbox user (groups: %s) — starting.",
                ", ".join(parsed.present),
                " ".join(parsed.groups) or "numeric gids only",
            )
        return (
            f"no writable runtime socket in the sandbox view "
            f"(groups: {' '.join(parsed.groups) or 'numeric gids only'}"
            + (f"; present but not writable: {', '.join(parsed.present)}" if parsed.present else "")
            + ")"
        )
    except SbxRuntimeExposureError:
        raise
    except subprocess.TimeoutExpired as exc:
        raise SbxRuntimeExposureError(
            f"cannot verify sandbox runtime isolation — the probe did not finish within "
            f"{bound:g} s (VENYA_SBX_RT_PROBE_TIMEOUT, default {SBX_RT_PROBE_TIMEOUT:g}) "
            f"during {exc.cmd if isinstance(exc.cmd, str) else 'the sbx probe'}; refusing to "
            "boot on an unanswered question (refs #312 item 3a)."
        ) from exc
    except OSError as exc:
        raise SbxRuntimeExposureError(
            "cannot verify sandbox runtime isolation — the sbx probe could not be run "
            f"({exc}); install/upgrade the vendor package docker-sbx and the executor "
            "starts once the question can be answered (refs #312 item 3a)."
        ) from exc
    finally:
        if created:
            try:
                subprocess.run(  # nosec
                    ["sbx", "rm", "--force", name],
                    capture_output=True,
                    text=True,
                    timeout=SBX_REAP_COMMAND_TIMEOUT,
                    check=False,
                    stdin=subprocess.DEVNULL,
                )
            except (OSError, subprocess.TimeoutExpired) as exc:
                logger.warning(
                    "probe sandbox %s was not removed (%s) — the boot reap collects every "
                    "venya-* sandbox as residue, so the next boot takes it (#474)",
                    name,
                    exc,
                )
        if workspace:
            shutil.rmtree(workspace, ignore_errors=True)


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
        # The refusal the runtime recorded for the LAST command this instance ran, or None.
        # `execute_command` writes it on every run, including a clean one, so a value read
        # after the call always describes that call and never an earlier one.
        self.egress_denial: ProxyEgressDenial | None = None
        # #805: the third thing the same read can say — an answer came back and this build could
        # not parse it. It is kept beside the refusal and never inside it, because it is a claim
        # about the instrument and not about the traffic. Written on every run, like the slot above.
        self.egress_log_unreadable: bool = False
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
        """Check that sbx CLI is installed.

        The refusal classifies the install route for the host raising it (iid 795): a face that
        publishes `docker-sbx` is told to install it, a face that does not is sent to the vendor
        asset instead of to an apt package its family never publishes, and a face the product
        cannot identify is never assumed to be Ubuntu.
        """
        if shutil.which("sbx") is None:
            raise RuntimeError(sbx_install_refusal())

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
            "-t",
            SANDBOX_TEMPLATE,
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
        # The arm that warned nothing before (report 311): the file exists and
        # carries entries, and the host the command wanted is not one of them. The
        # journal gets the count at the moment the rule set is built; the caller gets
        # the same case named by `egress_deny_notice`. Names and counts only, never
        # file contents.
        logger.info("Egress inputs for sandbox %s: %s", sandbox_name, egress.describe())

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
            # Bounded per rule — `SBX_POLICY_TIMEOUT` carries the measurement behind the
            # default. What this bound owns and what it does NOT, both measured at this row
            # (tests/test_sbx_policy_timeout_598.py):
            #   * `run(timeout=...)` kills THIS child and re-raises; a grandchild the CLI
            #     forked can outlive it (a stray process was still alive by pid);
            #   * a surviving grandchild does NOT make the return late — `communicate()`
            #     carries its own deadline, so the refusal lands at the bound even when the
            #     orphan still holds the capture pipes. The permit comes back on time.
            # So the residue after this raise is (a) a possible stray helper process and
            # (b) a possible half-registered rule, never a parked executor. (b) is harmless
            # by mechanism: the rule is keyed to THIS sandbox's name, the caller's `finally`
            # removes that sandbox now (its own `sbx rm` is bounded at 30 s), and the name is
            # never reused — `venya-<session>-<uuid12>` — so a stale rule admits no traffic.
            # What remains open is the vendor's own GC of rules for dead sandbox names, which
            # is the `shortcut:` note above this loop and is unchanged by this row.
            try:
                result = subprocess.run(  # nosec B603 B607
                    cmd,
                    capture_output=True,
                    text=True,
                    timeout=sbx_policy_timeout(),
                    check=False,
                )
            except subprocess.TimeoutExpired as exc:
                # Fail closed and say which stage died: the rule for THIS host was
                # never confirmed, so the sandbox must not proceed to exec with
                # partial egress. The named class carries the bound that fired.
                logger.error(
                    "sbx policy allow network timed out after %s seconds "
                    "(VENYA_SBX_POLICY_TIMEOUT, SBX_POLICY_TIMEOUT default %s) for "
                    "sandbox %s host %s — refusing to run the command",
                    exc.timeout,
                    SBX_POLICY_TIMEOUT,
                    sandbox_name,
                    host,
                )
                raise SbxPolicyTimeoutError(cmd, exc.timeout) from exc
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

        started_at = datetime.now(UTC)
        try:
            # stdin=DEVNULL: without it the sbx client inherits the DAEMON's stdin, so a
            # guest command that waits on stdin (ssh at a prompt, `read`, a pager) holds the
            # single admission permit for the full SBX_TIMEOUT while every client fuse blows
            # far earlier. EOF now, fail fast instead. (#695 AC1; the ceiling itself is #696.)
            result = subprocess.run(  # nosec
                cmd,
                capture_output=True,
                timeout=sbx_command_timeout(),
                check=False,
                stdin=subprocess.DEVNULL,
            )
        finally:
            if env_file:
                self._destroy_env_file(env_file)
                self._release_fallback_dir()
        egress = EgressFilter(
            allowlist_path=Path(self.egress_allowlist_path),
            dns_resolver=self.dns_resolver or "",
        )
        # The runtime's own refusal record is the primary face. A denied egress arrives as a
        # COMPLETED response: the proxy answers with its own HTTP 403, so this stream can
        # carry nothing that names the refusal and the exit code is the caller's client
        # judging that answer — measured again at leg 1424 on an executor test
        # guest (sbx v0.46.0): plain `curl` exits 0 and `curl --fail` exits 22 over
        # one and the same denied destination. `sbx policy log` holds the refusal, keyed to
        # this sandbox's name (which carries the session id), and it outlives the sandbox, so
        # it is read after the run and said back in the channel the caller reads.
        outcome = self._proxy_egress_log_outcome(self._sandbox_name, started_at)
        self.egress_denial = outcome.denial if outcome is not None else None
        self.egress_log_unreadable = outcome is not None and outcome.unrecognised
        notice: str | None = None
        if self.egress_denial is not None:
            notice = proxy_egress_denial_notice(
                self.egress_denial,
                sandbox_name=self._sandbox_name,
                daemon_user=daemon_account(),
                egress=egress,
            )
            logger.warning("Sandbox egress denied for %s: %s", self._sandbox_name, notice)
        else:
            # Report 311, R-2909 item 1: a destination the policy never admitted is
            # refused by the sandbox network path, which completes the handshake
            # locally and closes it — so what reached this stream was a PEER's error
            # message about a peer that received no packet
            # (`kex_exchange_identification: Connection closed by remote host`, with
            # the intake file's negative control a probe of a port the operator's own
            # log shows is blocked, failing the same way). This is the FALLBACK face now:
            # it carries the run where the runtime's log did not answer. Name the refusal
            # as venya's own, in the stream the caller reads, and keep the same line in
            # the journal. Nothing about the command's own output is changed: the notice
            # is appended, and it carries a destination, a path, an entry count and a
            # resolver address — never a value, never file contents.
            notice = egress_deny_notice(
                (result.stderr or b"").decode("utf-8", "replace"),
                returncode=result.returncode,
                command=command,
                argv=argv,
                egress=egress,
            )
            if notice:
                logger.warning("Sandbox egress denial shape for %s: %s", self._sandbox_name, notice)
        if outcome is not None and outcome.unrecognised:
            # The runtime answered and venya could not read it. That is reported beside whatever
            # the transport face had to say, because silence here is the exact outcome #798 exists
            # to remove: a refused run must not be handed to the caller as an allowed one.
            unrecognised = proxy_egress_unrecognised_notice(
                outcome,
                sandbox_name=self._sandbox_name,
                daemon_user=daemon_account(),
                tool_version=self._recorded_sbx_version(),
            )
            logger.warning("Sandbox egress record unreadable in shape for %s: %s", self._sandbox_name, outcome.detail)
            notice = f"{notice}\n{unrecognised}" if notice else unrecognised
        if notice:
            result.stderr = (result.stderr or b"") + f"\n{notice}".encode()
        return result

    def _proxy_egress_log_outcome(self, sandbox_name: str, started_at: datetime) -> ProxyEgressLogOutcome | None:
        """Ask the runtime what it recorded for THIS run, and say which of three things came back.

        One bounded read of `sbx policy log` for this sandbox, issued after the exec returns.
        `None` means the instrument did not answer at all — a timeout or a non-zero status — and
        the call site then keeps today's shape fallback and claims nothing in either direction.
        An answer is read by `proxy_egress_log_outcome`, which separates a refused run, a run with
        nothing refused, and a run whose record this build cannot read; only the last of those adds
        the "could not be confirmed" sentence, and none of them is ever inferred from silence.
        """
        log_cmd = sbx_policy_log_argv(sandbox_name)
        try:
            logged = subprocess.run(  # nosec B603 B607
                log_cmd,
                capture_output=True,
                text=True,
                timeout=sbx_policy_timeout(),
                check=False,
                stdin=subprocess.DEVNULL,
            )
        except subprocess.TimeoutExpired:
            logger.warning(
                "sbx policy log timed out after %s seconds (VENYA_SBX_POLICY_TIMEOUT) for "
                "sandbox %s — no egress denial is claimed for this run",
                sbx_policy_timeout(),
                sandbox_name,
            )
            return None
        if logged.returncode != 0:
            # The account matters here, and the operator cannot see it from this side: the
            # log belongs to whoever the sandbox daemon signs in as, so a read from any
            # other account refuses with an authentication error. Name that, and do not
            # quote the vendor's own text onward (it is this daemon's log, not the
            # caller's, and it can carry paths).
            logger.warning(
                "sbx policy log refused for sandbox %s (rc %d) as account %r — no egress "
                "denial is claimed for this run; the record answers only for the account "
                "the sandbox daemon signs in under (`sudo -n sudo -u <that account> %s`)",
                sandbox_name,
                logged.returncode,
                daemon_account(),
                " ".join(log_cmd),
            )
            return None
        if not logged.stdout.strip():
            # rc 0 with no bytes is the instrument giving nothing to read, not an answer in a form
            # venya cannot parse: it goes the way of a timeout, so a silent reader stays silent and
            # the transport fallback keeps its chance. A NON-blank body this build cannot read is
            # the third outcome, and that one is reported to the caller.
            logger.warning(
                "sbx policy log answered nothing for sandbox %s (rc 0, empty body) as account %r — "
                "no egress outcome is claimed for this run",
                sandbox_name,
                daemon_account(),
            )
            return None
        return proxy_egress_log_outcome(logged.stdout, sandbox_name=sandbox_name, started_at=started_at)

    def _recorded_sbx_version(self) -> str:
        """The vendor face this executor already recorded, read without a new vendor call.

        The unreadable-record sentence names a version, because #798 is a drift story and an
        operator needs to know which face the build believes it is talking to. The recorded face
        file (`sandbox_shape`, written at install and re-read at boot) already holds it, so this is
        a file read, not a third subprocess: two vendor calls per exec — the command, then the
        bounded `sbx policy log` — is a pinned posture
        (`test_sbx_strategy.py::test_execute_command_runs_in_sandbox`), and reporting an anomaly is
        not a licence to widen it. With no recorded face on the host the answer is empty, and the
        sentence says that plainly rather than inventing a number.
        """
        from ..sandbox_shape import read_record

        recorded = read_record()
        if not recorded:
            return ""
        entry = recorded.get("fields", {}).get("sbx.version_line")
        value = entry.get("value") if isinstance(entry, dict) else None
        return value.strip() if isinstance(value, str) else ""

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
