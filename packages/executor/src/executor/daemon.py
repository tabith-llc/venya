# Copyright (c) 2026 Tabith LLC.
# Use of this source code is governed by the Business Source License 1.1
# included in the LICENSE file at the root of this repository. As of the
# Change Date listed there, the work is available under MPL 2.0.
# SPDX-License-Identifier: BUSL-1.1

"""Executor daemon process management.

Manages the persistent executor daemon lifecycle:
  - Registration with server (mTLS certificate)
  - Certificate rotation
  - Heartbeat protocol
  - Revocation polling
  - Reaper loop for orphaned resources
  - Signal handling
"""

import contextlib
import enum
import errno
import hashlib
import json
import logging
import os
import shutil
import signal
import ssl
import stat
import sys
import tempfile
import threading
import time
from collections.abc import Iterable
from concurrent.futures import Future, ThreadPoolExecutor
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import httpx2

# tomli_w is required for clearing enrollment tokens after registration.
# Failing fast at import time is correct — a security-critical dependency
# must not be silently unavailable at runtime.
import tomli_w  # type: ignore[import-not-found]
from core.utils.cert_serial import canonical_serial, serial_match_key
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from .audit import AuditLogger
from .command_validator import (
    DEFAULT_DANGEROUS_PATTERNS,
    DEFAULT_TRUSTED_PATHS,
    CommandPolicy,
    CommandValidator,
)
from .config import ExecutorConfig
from .executor import Executor
from .key_passphrase import (
    load_private_key,
    passphrase_or_refuse,
    read_passphrase_or_none,
    serialize_key_encrypted,
    ssl_password_callback,
)
from .relay_listener import REFUSE_NO_ANSWER, RelayListener
from .strategies.sbx_strategy import (
    ENV_DIR_PREFIX,
    SECRET_TMPFS_BASE,
    SESSION_DIR_PREFIX,
    SbxStrategy,
    SbxVersionError,
    reap_orphan_sandboxes,
    require_supported_sbx,
    sweep_workspace_base,
)

logger = logging.getLogger("venya.executor.daemon")

# Canonical bootstrap enrollment-token storage (ticket
# daemon-bootstrap-token-clear-erofs): /etc/venya is ReadOnlyPaths for the
# daemon, so a token kept in executor.toml could never be cleared after use —
# the cleanup itself crash-looped the daemon. This path sits under the unit's
# ReadWritePaths; the toml [bootstrap] section remains a read-only-to-daemon
# LEGACY location honored until old installs are cut over.
BOOTSTRAP_TOKEN_PATH = Path("/var/lib/venya/executor/bootstrap-token")

# refs ticket audit-spool-forwarder-session-lifetime (#436): tag for the boot-time
# AuditLogger. session_id is read ONLY by the emit() write path (audit.py); this
# instance never emits — the forwarder drains spool lines that already carry their
# real session ids — so a fixed boot tag states what it is, not a fake session.
BOOT_FORWARDER_SESSION_ID = "boot-forwarder"

# The endpoint the cooperative daemon polls for revoked credentials. Named once so
# the request and the UNKNOWN log lines cannot drift apart (#551 named the URL from
# the exception's request; #552 has no exception object to read it from).
REVOCATION_LIST_PATH = "/api/v1/executors/certs/revocation-list"


def _atomic_write(path: str | Path, payload: bytes, mode: int) -> None:
    """Write ``payload`` to ``path`` atomically with the FINAL mode at CREATE.

    House pattern (audit.py #310 spool rewrite): temp file created in the
    target's own directory, then ``os.replace``. The final mode is pinned with
    ``fchmod`` while the file is still invisible under the temp name (umask can
    only REMOVE bits at create; fchmod pins the exact mode), so unlike
    write-then-chmod the target never exists at a mode other than ``mode`` and
    secret material has no umask-born world-writable window (ticket
    executor-daemon-umask0-key-write-window).

    #478: the temp name used to be DETERMINISTIC (``<path>.tmp`` with
    O_CREAT|O_EXCL), so one write killed between create and replace — the
    systemd stop-path SIGKILL, an OOM kill, a Restart=always bounce — left
    ``<target>.tmp`` behind and wedged EVERY later write to that target with
    FileExistsError forever. The temp is now mkstemp-unique, exactly the
    proven audit.py spool shape: a stale file cannot block a new writer, and
    the no-interleave property that O_EXCL was bought for is unchanged — the
    only publish step is still a single ``os.replace`` from an exclusive
    temp. Residue (including legacy deterministic names from older builds)
    is reclaimed at boot by ``sweep_stale_tmp_files`` below.

    #479: the raw descriptor returned by ``mkstemp`` is owned by this frame until
    ``os.fdopen`` takes it, and every path that does not reach that handoff closes
    it before re-raising. Both #478 properties (unique temp, temp-unlink on
    failure) are unchanged by that.
    """
    path = str(path)
    # Refuse BEFORE creating a temp when the target itself is not writable
    # (EROFS / read-only file): keeps the erofs pre-write-refusal contract —
    # an atomic replace would otherwise silently succeed over an RO target.
    if os.path.exists(path) and not os.access(path, os.W_OK):
        raise PermissionError(errno.EACCES, os.strerror(errno.EACCES), path)
    parent = os.path.dirname(path) or "."
    fd, tmp_name = tempfile.mkstemp(
        dir=parent,
        prefix=os.path.basename(path) + ".",
        suffix=".tmp",
    )
    try:
        try:
            os.fchmod(fd, mode)
            # Ownership of ``fd`` moves to ``stream`` on this line and nowhere
            # earlier. #479: anything that fails BEFORE the handoff — ``fchmod``
            # raising (EROFS/EPERM on a hardened unit) or ``fdopen`` itself
            # failing — left the descriptor open, because the unlink below gives
            # a name back, never a descriptor. One leak per failed write, in a
            # process that also holds the relay listener, the reaper, the
            # heartbeat pool and the audit forwarder. AFTER the handoff the file
            # object owns it and closes it, which is why the close sits here and
            # not in the outer handler (an unconditional close there would be a
            # double close over a descriptor somebody else just released).
            stream = os.fdopen(fd, "wb")  # mkstemp creates 0600; fchmod above pins the final mode
        except BaseException:
            with contextlib.suppress(OSError):
                os.close(fd)  # still ours: hand back the descriptor, then let the cause travel
            raise
        with stream:
            stream.write(payload)
        os.replace(tmp_name, path)
    except BaseException:
        with contextlib.suppress(OSError):
            os.unlink(tmp_name)
        raise


# #478 AC2: bound for the stale-*.tmp reclaim. A healthy writer here lives for
# microseconds (create -> write -> replace); anything older than this bound is
# by construction debris of a killed writer. 3600 s is deliberately much larger
# than that window (it matches SBX_TIMEOUT, the longest activity the executor
# runs), so a FRESH temp of a live writer is never reclaimed while anything
# stale cannot survive into the next boot.
_STALE_TMP_MAX_AGE_SECONDS = 3600.0


def sweep_stale_tmp_files(
    directories: Iterable[str | Path],
    max_age_seconds: float = _STALE_TMP_MAX_AGE_SECONDS,
) -> int:
    """Boot-time reclaim of stale ``*.tmp`` files (ticket #478 acceptance 2).

    Scoped strictly to the executor's OWN directories — callers pass them
    explicitly, this never walks a tree. Removes regular files whose name ends
    in ``.tmp`` and whose mtime is older than ``max_age_seconds``; anything
    younger, any directory, symlink, or unreadable entry is left alone (fail
    quietly per entry: a boot must not die over debris it came to clean).
    Returns the number of files removed.
    """
    now = time.time()
    removed = 0
    seen: set[str] = set()
    for directory in directories:
        d = str(directory)
        if d in seen:
            continue
        seen.add(d)
        try:
            entries = os.listdir(d)
        except OSError:
            continue
        for name in entries:
            if not name.endswith(".tmp"):
                continue
            victim = os.path.join(d, name)
            try:
                st = os.lstat(victim)
                if not stat.S_ISREG(st.st_mode):
                    continue
                if now - st.st_mtime <= max_age_seconds:
                    continue
                os.unlink(victim)
            except OSError:
                continue
            removed += 1
            logger.info("Reclaimed stale temp file: %s", victim)
    return removed


def _dist_version() -> str:
    """Single-sourced version (feature/version-surfaces condition 1): dist
    metadata (pyproject) is the only truth — never a string literal. Missing
    metadata yields "" (falsy → heartbeat omits the report; server leaves the
    stored column untouched), never a guessed value."""
    from importlib.metadata import PackageNotFoundError
    from importlib.metadata import version as _pkg_version

    try:
        return _pkg_version("executor")
    except PackageNotFoundError:
        return ""


_EXECUTOR_VERSION = _dist_version()

CLOCK_SKEW_TOLERANCE = timedelta(seconds=300)


class CertificateValidationError(Exception):
    """Raised when an executor certificate fails validation."""


class DaemonState:
    """Tracks daemon runtime state."""

    def __init__(self) -> None:
        self.running = False
        self.executor_id: str = "default"
        self.command_policy: Any = None
        self.revoked = False
        # #586: boot-scope record that the core has ANSWERED the revocation question
        # for this credential at least once since this daemon started. Written at ONE
        # site (the poll dispatch in ``_main_loop``) and read by the relay accept gate.
        # False is "we do not know", never "we know it is live" — the same honesty the
        # tri-state poll was built for (#442 site 4).
        self.revocation_answered = False
        # #603: WHY the fault arm stopped service, carried BESIDE the bool instead
        # of being asserted through it. The consecutive-failure threshold means the
        # core never ANSWERED — it is not a server-side revocation, and saying so at
        # the accept point is the whole of this fix. Set only by the threshold arm in
        # ``_main_loop``; read by ``relay_listener.revocation_accept_reason`` so an
        # executor that once had an answer and then starved still refuses (503 class),
        # never admits.
        self.revocation_fault_reason: str | None = None
        self.cert_serial: str | None = None
        self.cert_not_after: datetime | None = None
        self._consecutive_revocation_failures: int = 0


def _token_required_error(exc: httpx2.HTTPStatusError, *, rotation: bool = False) -> RuntimeError | None:
    """Convert a 400 'Enrollment token required' registration response into an
    actionable RuntimeError; return None for any other error (caller re-raises).

    Ticket executor-rotation-require-token-400 Phase 1: a bare `400 Bad Request`
    in the journal is how the day-30 rotation death spiral gets discovered at
    day 30 instead of day 0. Both the bootstrap register() and the periodic
    rotate() paths carry the SAME actionable identifiers (knob name +
    re-enrollment path); only the rotation variant references the
    incumbent-mTLS exemption (Phase 2, landed). Defensive on non-HTTP responses
    (test doubles): anything but a real 400 with the token-required detail
    falls through unchanged.
    """
    resp = getattr(exc, "response", None)
    if resp is None or getattr(resp, "status_code", None) != 400:
        return None
    try:
        detail = str(resp.json().get("detail", ""))
    except Exception:
        return None
    if "Enrollment token required" not in detail:
        return None
    msg = (
        "Registration rejected: the server requires an enrollment token "
        "(server config executor_enrollment.require_token — enforced by default). "
        "An admin must mint one (`venya admin executor-enroll <executor-id>`) and "
        "registration re-run with VENYA_EXECUTOR_ENROLLMENT_TOKEN set "
        "(re-run the executor installer)."
    )
    if rotation:
        msg += (
            " Certificate rotation IS accepted from the verified incumbent mTLS "
            "serial (ticket executor-rotation-require-token-400 Phase 2): this "
            "error during rotation means the presented cert is NOT the current "
            "record credential (revoked, diverged, or replaced) — mint a fresh "
            "token and re-register before the current cert expires (~30 days)."
        )
    return RuntimeError(msg)


_TLS_ERROR_KEYWORDS = ("ssl", "certificate", "tls", "verif")

# #24 (executor-register-retry-storm-ratelimit-lockout): in-process retry
# budget for TRANSIENT registration failures (429/5xx/network). Permanent
# rejects (401/403/404) never enter this path — they stop loud. The unit
# (RestartSec/StartLimit) paces anything beyond this budget.
# shortcut: fixed constants; promote to config knobs only when an operator needs tuning.
_REGISTER_RETRY_ATTEMPTS = 4
_REGISTER_RETRY_BASE_SECONDS = 5.0
_REGISTER_RETRY_CAP_SECONDS = 60.0
_PERMANENT_REGISTER_STATUSES = (401, 403, 404)


def _register_retry_delay(exc: httpx2.HTTPStatusError, attempt: int) -> float:
    """Backoff for a transient register reject: a server Retry-After (every 429
    this endpoint emits carries one — rate_limit contract, ticket
    delta-b-run-low-bundle O2) wins when parseable, else exponential
    5/10/20s capped. The daemon must never wait LESS than the limiter window."""
    raw: object = None
    try:
        raw = exc.response.headers.get("Retry-After")
    except AttributeError:
        raw = None
    if raw is not None:
        try:
            return max(1.0, min(float(int(str(raw).strip())), 900.0))
        except (TypeError, ValueError):
            pass
    return min(_REGISTER_RETRY_BASE_SECONDS * (2**attempt), _REGISTER_RETRY_CAP_SECONDS)


def _permanent_rejection_error(exc: httpx2.HTTPStatusError) -> RuntimeError:
    """#24: a permanent register rejection retried at systemd's 100 ms default
    burns the register rate limiter within seconds and the resulting 429 masks
    the root cause in the journal. Name the status + the server's reason ONCE,
    loudly; the boot stops — re-enrollment is the operator's decision, same
    posture as the token-required and ghost-identity classes."""
    resp = exc.response
    code = getattr(resp, "status_code", "unknown")
    try:
        detail = str(resp.json().get("detail", "")) or str(getattr(resp, "text", ""))
    except Exception:
        detail = ""
    msg = (
        f"Registration permanently rejected by the core (HTTP {code}): {detail} — "
        "retrying cannot change this outcome (identity revoked, bad or expired "
        "enrollment token, or executor not enrollable). Mint a fresh token "
        "(`venya admin executor-enroll <executor-id>`), fix the cause, then "
        "`systemctl restart venya-executor`. Exiting; no retry storm."
    )
    logger.error("%s", msg)
    return RuntimeError(msg)


def _expiry_clock_with_tz(value: str, *, where: str) -> datetime:
    """Parse the server-issued cert expiry for the executor's expiry clock.

    Guarded form (ticket #465), mirroring the server-side pattern at
    ``packages/server/src/server/routes/executors.py:1247-1248``
    (``if not_after.tzinfo is None: not_after = not_after.replace(tzinfo=UTC)``)
    with one ruled strengthening: a NAIVE value is REJECTED rather than stamped.
    Rotation timing consumes this value, and guessing an offset for a value that
    states none is how a serialization change would silently shift the clock —
    fail-closed outranks tidy.

    - Aware input: PRESERVED exactly as the server sent it. A ``+02:00`` value
      keeps its offset; it is never converted and never relabelled.
    - Naive input: ``RuntimeError`` (the named error path of both ``register()``
      and ``rotate()`), so the boot/rotation path fails loudly.

    Producers today emit ``not_valid_after_utc.isoformat()`` → ``+00:00``, which
    parses aware and yields the same instant as the previous unconditional
    relabel: behavior-preserving for every current server.
    """
    parsed = datetime.fromisoformat(value)
    if parsed.tzinfo is None:
        raise RuntimeError(
            f"Certificate rotation: server sent expiry {value!r} with no timezone "
            f"information (parse site: {where}); cannot build a trustworthy expiry "
            "clock. The server must emit an offset-aware value (e.g. +00:00)."
        )
    return parsed


def _is_tls_handshake_failure(exc: BaseException) -> bool:
    """True when a transport error is a TLS-level rejection, not plain connectivity.

    httpx2 wraps ssl.SSLError as ConnectError — check the exception chain and
    the message for TLS keywords (same classification register() applies).
    """
    node: BaseException | None = exc
    seen: set[int] = set()
    while node is not None and id(node) not in seen:
        seen.add(id(node))
        if isinstance(node, ssl.SSLError):
            return True
        node = node.__cause__ or node.__context__
    return any(t in str(exc).lower() for t in _TLS_ERROR_KEYWORDS)


def _ghost_identity_error(reason: str) -> RuntimeError:
    """Ruled ghost-abort error (#361/#369): log it loud and return it for the
    caller to raise — boot stops before any CSR/token consumption."""
    msg = (
        f"Core refused the existing certificate ({reason}) — this "
        "executor's identity is unknown server-side (a rebuilt core mints a new CA). "
        "Refusing to run as a ghost identity. Re-enroll by re-running the executor "
        "installer with a fresh VENYA_EXECUTOR_ENROLLMENT_TOKEN (mint with: "
        "venya admin executor-enroll <executor-id>)."
    )
    logger.error("%s", msg)
    return RuntimeError(msg)


class RevocationStatus(enum.Enum):
    """The three answers a revocation poll can give (#442 site 4, ruling R3).

    The contract this replaces was a bool, and a bool cannot separate "the server
    answered: this certificate is live" from "I could not reach the server to
    ask". Both answered False, and the caller's reset-on-False then WIPED the
    consecutive-failure count on every outage — so the bounded fail-closed the
    threshold exists to provide never engaged while the core was down. That is
    the fail-open this class closes.

    Values are strings, never 0/1, deliberately: a caller has to name the case it
    means, and no answer can land in a falsy branch by accident any more.
    """

    NOT_REVOKED = "not-revoked"
    REVOKED = "revoked"
    UNREACHABLE = "unreachable"


class RevocationPayloadError(ValueError):
    """The revocation endpoint answered 200 with a body this check cannot read (#552).

    Raised only by :func:`parse_revocation_payload`, and never allowed to leave
    ``CertificateManager.check_revocation``: a body whose shape is wrong says
    nothing about whether this credential is live, so the answer it produces is
    ``RevocationStatus.UNREACHABLE`` — a counted failed check, retried on the next
    tick — exactly what a transport fault produces on this same path.

    The class exists so the guard stays NAMED at both ends. Before it, a
    non-JSON 200 raised ``json.JSONDecodeError`` and a 200 that decoded to a list
    raised ``AttributeError`` out of the ``.get`` calls; neither class is an
    ``httpx2.RequestError``, so both escaped ``check_revocation``, escaped the two
    arms in ``_main_loop`` that name the classes it can handle, and unwound
    ``start()`` into ``self.stop()``. One mis-shaped answer stopped the daemon.
    A blanket ``except Exception`` is NOT used anywhere on this path: transport
    faults (``httpx2.RequestError``) and HTTP error statuses
    (``httpx2.HTTPStatusError``) keep their own arms in ``check_revocation``.
    """


def parse_revocation_payload(response: httpx2.Response) -> dict[str, Any]:
    """Decode a revocation-list response and prove its shape before anything uses it.

    The accepted shape is the endpoint's own contract — ``RevocationListResponse``
    in the server's ``routes/executors.py``: a JSON object, optional
    ``revoked_identities`` and ``revoked_serials`` fields, each a list. Anything
    else is refused here, at the parse site, rather than being read downstream.

    Returns:
        The decoded mapping, ready for the two field lookups.

    Raises:
        RevocationPayloadError: the body did not decode as JSON (the two NAMED
            decode classes are what is caught — ``json.JSONDecodeError`` for a body
            that is not JSON, ``UnicodeDecodeError`` for bytes that are not text at
            all; both measured live at this base against a real ``httpx2.Response``
            200), the decoded value is not a mapping (a JSON list, string, number,
            or ``null``), or a revocation field is present but is not a list.
            Transport faults and HTTP error statuses are deliberately NOT handled
            here — they are not this function's question, and swallowing them
            would turn a real outage into a fake answer.
    """
    try:
        data = response.json()
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise RevocationPayloadError(f"revocation body is not JSON text ({type(exc).__name__}: {exc})") from exc

    if not isinstance(data, dict):
        raise RevocationPayloadError(f"revocation body is a {type(data).__name__}, not a JSON object")

    for field in ("revoked_identities", "revoked_serials"):
        value = data.get(field, [])
        if not isinstance(value, list):
            raise RevocationPayloadError(f"revocation field {field!r} is a {type(value).__name__}, not a list")

    return data


class CertificateManager:
    """Manages executor mTLS certificate lifecycle.

    Handles registration, rotation, revocation checking, and fingerprint
    computation. Uses ECDSA P-256 for all keypairs and certificates.
    """

    def __init__(self, config: ExecutorConfig) -> None:
        self.config = config
        self.client: httpx2.Client | None = None
        self.cert_path = config.mtls.cert
        self.key_path = config.mtls.key
        self.ca_cert_path = config.mtls.ca_cert
        self.serial: str | None = None
        self._not_after: datetime | None = None
        self._last_revocation_etag: str | None = None

    @property
    def not_after(self) -> datetime | None:
        """Certificate expiry time."""
        return self._not_after

    def _server_ssl_context(self) -> ssl.SSLContext:
        """Client TLS context for the core, pinned to the configured Venya anchors (#502).

        One construction shared by register() and the boot identity probe so the
        two paths cannot drift apart again: the system store stays loaded (a core
        whose certificate a host already trusts keeps verifying) and every local
        anchor that exists is added — ``ca_bundle`` from the config and the CA
        file written at registration/rotation (``mtls.ca_cert``). Without the
        local anchors a probe verifies only against the host store, which is the
        defect this closes.

        RULED POSTURE (#531, owner ruling 2026-10-07): keeping the system store
        here is intentional and recorded, not an oversight — see the comment at
        the construction site below. The other two #531 dials (the audit
        forwarder and ``_create_mtls_client``) are tightened; this one stands.
        """
        # RULED POSTURE (owner, 2026-10-07, refs #531): this context keeps the OS trust store loaded on
        # purpose — it serves customer bring-your-own-certificate leaves. Do not "tighten" it without a
        # written revision of that ruling. See features/bring-your-own-certificate.md.
        ssl_ctx = ssl.create_default_context()
        for candidate in (self.config.ca_bundle, self.ca_cert_path):
            if candidate and Path(candidate).exists():
                ssl_ctx.load_verify_locations(candidate)
        return ssl_ctx

    def register(self, executor_id: str, enrollment_token: str | None = None) -> None:
        """Register executor with server, obtain signed certificate.

        Always uses full TLS verification. To disable verification in
        development, set VENYA_TLS_VERIFY=false before running.

        Args:
            executor_id: Unique executor identifier.
            enrollment_token: Optional enrollment token for bootstrap auth.

        Raises:
            RuntimeError: If the server returns an error or the certificate
                fails CA validation.
            httpx2.HTTPError: If the network request fails.
        """
        if os.path.exists(self.cert_path) and os.path.exists(self.key_path):
            if not _cert_key_pair_matches(self.cert_path, self.key_path):
                # #480: presence is not identity. A mismatched or unparseable
                # pair (the usual cause: a kill between the rotate() replaces)
                # used to pass this gate and then crash-loop the unit in
                # _create_mtls_client. Chosen behavior per the ticket's
                # acceptance: RE-ENROLL — fall through to the registration
                # path below (fresh keypair, new CSR, POST). With a bootstrap
                # token this self-heals; without one the server's rejection
                # surfaces through the existing actionable token-required
                # error, the same named path a fresh install takes — never a
                # silent SystemExit with zero recovery attempt.
                logger.error(
                    "On-disk certificate/key pair is unusable (mismatched or unparseable — "
                    "an interrupted rotation is the usual cause) — attempting re-enrollment "
                    "for %s instead of booting a broken pair",
                    executor_id,
                )
            else:
                self._load_metadata()
                # #361 ruled A (executor-stale-cert-ghost-identity): local file
                # presence alone used to gate the skip — after a core rebuild
                # (fresh CA + empty executors table) the daemon booted as a GHOST
                # identity, silently refused by the core forever. Ask the core to
                # recognize this certificate BEFORE skipping; a server-side
                # refusal aborts the boot with the named re-enroll path. The
                # decision to re-register stays with the installer/token ceremony
                # — the daemon never self-mints (no token here, no CSR here).
                self._verify_cert_recognized(executor_id)
                logger.info("Certificate already exists — skipping registration for: %s", executor_id)
                return

        # Fail before the HTTP call if a cert directory is not writable (e.g.
        # ReadOnlyPaths=/etc/venya with install-time registration skipped):
        # registering remotely and then failing the local write burns the
        # enrollment token and crash-loops the daemon on EROFS.
        for cert_dir in {
            Path(self.ca_cert_path).parent,
            Path(self.cert_path).parent,
            Path(self.key_path).parent,
        }:
            if not os.access(cert_dir, os.W_OK):
                msg = (
                    f"Cannot write mTLS certificates: {cert_dir} is not writable "
                    "(read-only mount or permissions). The executor cannot register at "
                    "runtime. Reinstall with a non-empty VENYA_EXECUTOR_ENROLLMENT_TOKEN "
                    "so registration completes at install time, or make the certificate "
                    "directory writable by the daemon user."
                )
                logger.error(msg)
                raise RuntimeError(msg)

        logger.info("Registering executor: %s", executor_id)

        # #565 AC3/AC4 + R7-Q3: the executor key is written encrypted, so the
        # passphrase is resolved HERE — after the two local preflights (pair check,
        # writability) and BEFORE the CSR is generated and the registration POST
        # leaves this host. A refusal that arrives after the POST would burn the
        # enrollment token and replace the server-side record while this host still
        # has no usable key; refusing here costs nothing at all. There is no
        # fallback branch: unset, empty, whitespace-only or under the #573 floor is
        # a refusal, never a plaintext key. This is disk protection under a file
        # passphrase, NOT hardware custody (design note §6, R7-Q3 label discipline).
        key_passphrase = passphrase_or_refuse()

        # Generate ECDSA P-256 keypair
        private_key = _generate_ecdsa_p256_keypair()

        # Create CSR with executor_id as CN
        csr_pem = _create_csr(private_key, executor_id)

        # Build payload
        payload = {
            "csr_pem": csr_pem.decode(),
            "executor_id": executor_id,
        }
        if enrollment_token:
            payload["enrollment_token"] = enrollment_token

        url = f"{self.config.server_url}/api/v1/executors/register"

        tls_verify_env = os.environ.get("VENYA_TLS_VERIFY", "")
        if tls_verify_env == "" or tls_verify_env.lower() == "true":
            tls_verify = True
        elif tls_verify_env.lower() == "false":
            tls_verify = False
            logger.warning("VENYA_TLS_VERIFY=false — TLS verification disabled (dev only)")
        else:
            raise RuntimeError(f"Invalid VENYA_TLS_VERIFY value: '{tls_verify_env}'. " "Must be 'true' or 'false'.")

        # Build SSL context for TLS verification (shared with the identity probe)
        verify_param: object = self._server_ssl_context() if tls_verify else False

        response: httpx2.Response | None = None
        for attempt in range(_REGISTER_RETRY_ATTEMPTS):
            try:
                with httpx2.Client(
                    verify=verify_param, timeout=self.config.network.registration_timeout_seconds
                ) as client:
                    response = client.post(url, json=payload)
                response.raise_for_status()
                break
            except httpx2.HTTPStatusError as e:
                # Token-required 400 becomes an actionable named error; the boot
                # path lets it propagate → exit 1 (ero-fs fail-fast semantics).
                actionable = _token_required_error(e)
                if actionable is not None:
                    raise actionable from e
                code = getattr(e.response, "status_code", None)
                if code in _PERMANENT_REGISTER_STATUSES:
                    # #24: revoked/bad-token/un-enrollable — stop loud, single
                    # log naming the root cause; a systemd-paced restart is the
                    # operator's path, never an in-process or 100 ms loop.
                    raise _permanent_rejection_error(e) from e
                transient = isinstance(code, int) and (code == 429 or code >= 500)
                if not transient or attempt == _REGISTER_RETRY_ATTEMPTS - 1:
                    raise
                delay = _register_retry_delay(e, attempt)
                logger.warning(
                    "Registration transiently rejected (HTTP %s) — retrying in %.0fs (%d/%d attempts)",
                    code,
                    delay,
                    attempt + 2,
                    _REGISTER_RETRY_ATTEMPTS,
                )
                time.sleep(delay)
            except httpx2.ConnectError as e:
                # Log full traceback in debug mode for deep diagnostics
                if os.environ.get("VENYA_DEBUG"):
                    import traceback

                    logger.error("Full exception chain:\n%s", traceback.format_exc())

                # Determine if this is a TLS failure by inspecting the exception chain
                # httpx2 wraps ssl.SSLError as ConnectError — check the message for TLS keywords
                if any(t in str(e).lower() for t in _TLS_ERROR_KEYWORDS):
                    raise RuntimeError(
                        f"Registration failed: TLS verification error — {e}. " "Verify server CA is trusted."
                    ) from e
                # #24: plain reachability blips retry in-process with backoff;
                # TLS/CA faults above stay single-shot (they are configuration
                # problems, and re-POSTing them cannot help).
                if attempt == _REGISTER_RETRY_ATTEMPTS - 1:
                    raise RuntimeError(
                        f"Registration failed: cannot reach server — {e}. "
                        "Check: DNS resolution, network connectivity, and core service status."
                    ) from e
                delay = min(_REGISTER_RETRY_BASE_SECONDS * (2**attempt), _REGISTER_RETRY_CAP_SECONDS)
                logger.warning(
                    "Registration unreachable (%s) — retrying in %.0fs (%d/%d attempts)",
                    e,
                    delay,
                    attempt + 2,
                    _REGISTER_RETRY_ATTEMPTS,
                )
                time.sleep(delay)

        if response is None:  # pragma: no cover — the loop always breaks or raises
            raise RuntimeError("Registration failed: no response from server")

        data = response.json()

        cert_pem = data["cert_pem"].encode()
        ca_cert_pem = data["ca_cert_pem"].encode()
        self.serial = data["serial_number"]
        self._not_after = _expiry_clock_with_tz(data["not_after"], where="register")

        # Validate certificate before saving
        validate_executor_certificate(cert_pem, ca_cert_pem, executor_id)

        # Save CA certificate, signed certificate, and private key
        try:
            _atomic_write(self.ca_cert_path, ca_cert_pem, 0o644)
            logger.info("Saved CA certificate to %s", self.ca_cert_path)

            _atomic_write(self.cert_path, cert_pem, 0o644)

            key_pem = serialize_key_encrypted(private_key, key_passphrase)
            _atomic_write(self.key_path, key_pem, 0o600)
        except OSError as e:
            msg = (
                f"mTLS certificate write failed: {e}. The server accepted the "
                "registration but certificates could not be saved locally. Fix the "
                "read-only mount or permissions on the certificate directory, mint a "
                "fresh enrollment token, and reinstall."
            )
            logger.error(msg)
            raise RuntimeError(msg) from e

        logger.info(
            "Registration complete: serial=%s, expires=%s",
            self.serial,
            self._not_after.isoformat(),
        )
        # Stash the propagated policy payload for the daemon to apply
        # (ticket command-policy-no-server-executor-propagation — the
        # daemon owns the validator; CertificateManager only carries bytes).
        self.last_command_policy = data.get("command_policy")

    def _verify_cert_recognized(self, executor_id: str) -> None:
        """Probe the core's heartbeat with the on-disk mTLS pair (raises RuntimeError on rejection).

        Ghost evidence comes in three shapes, all aborting the boot with the
        same ruled re-enroll message (#361 ruled A, widened by #369):
        1. 401/403 from the app — the core cannot map this certificate to a
           known, active identity (superseded CA after a core rebuild, revoked
           row, ...).
        2. A TLS-terminating 400 whose body is nginx's "The SSL certificate
           error" page — with a certificate from an UNRELATED CA, nginx
           rejects the handshake and answers before the request reaches the
           app, so the app never gets to say 401/403.
        3. A connection-level TLS failure (the terminator aborts the handshake
           over our client certificate) — keywords checked through the
           exception chain, same shape register() classifies.
        Any OTHER transport failure (timeout, refused, DNS) carries no
        certificate verdict: it stays INCONCLUSIVE — warn and proceed (the
        daemon's own heartbeat loop keeps checking, and a core outage must
        not strand a legitimately enrolled executor). Other status classes
        propagate loud via raise_for_status. Full TLS verification per house
        policy against the configured Venya anchors, same context register()
        builds (#502); the dev-fleet ``VENYA_TLS_VERIFY=false`` knob still turns
        it off at this site.
        """
        url = f"{self.config.server_url}/api/v1/heartbeat"
        tls_verify_env = os.environ.get("VENYA_TLS_VERIFY", "")
        verify: bool = tls_verify_env.lower() != "false"
        if not verify:
            logger.warning("VENYA_TLS_VERIFY=false — identity probe skips TLS verification (dev only)")
        # Same anchor-pinned context register() uses; `verify=True` here would mean
        # "host trust store only" and ignore the Venya CA (#502).
        probe_verify: object = self._server_ssl_context() if verify else False
        # #565: this dial presents the executor's own client certificate and the key
        # behind it may now be an encrypted envelope. httpx's `cert=` accepts the
        # 3-tuple (cert, key, password) and hands it to load_cert_chain positionally,
        # so the passphrase rides the SAME tuple this site already used — `verify`
        # keeps its ruled shape on both branches (an anchor context when verifying,
        # the literal False under VENYA_TLS_VERIFY=false), and nothing is downgraded
        # to make a cell pass. When the key needs no password the 2-tuple is passed
        # UNCHANGED, so a legacy plaintext host is byte-identical to today (the
        # #502 pin on this site's cert tuple keeps holding without edits). The
        # helper raises the named refusal for an envelope this host cannot open, so
        # a passphrase problem is not reported as a ghost identity — the bare
        # OpenSSL text would have been classified as a TLS handshake failure.
        probe_pw = read_passphrase_or_none(self.key_path)
        probe_cert: object = (
            (self.cert_path, self.key_path, probe_pw) if probe_pw is not None else (self.cert_path, self.key_path)
        )
        try:
            with httpx2.Client(cert=probe_cert, verify=probe_verify, timeout=10.0) as client:
                response = client.post(url, json={"executor_id": executor_id})
        except httpx2.TransportError as exc:
            if _is_tls_handshake_failure(exc):
                raise _ghost_identity_error(f"TLS handshake rejected the certificate: {exc}") from None
            logger.warning(
                "Identity probe to %s unreachable (%s) — proceeding on the existing certificate; "
                "the heartbeat loop will re-check continuously",
                url,
                exc,
            )
            return
        if response.status_code in (401, 403):
            raise _ghost_identity_error(f"{response.status_code} on {url}") from None
        if response.status_code == 400 and "ssl certificate error" in str(getattr(response, "text", "")).lower():
            raise _ghost_identity_error(f"400 TLS-terminator reject ({url}: The SSL certificate error)") from None
        response.raise_for_status()

    def needs_rotation(self) -> bool:
        """Check if the certificate needs rotation.

        Returns True if:
        - No certificate exists on disk
        - Certificate expires within ``rotate_before_days`` of now

        Returns:
            True if certificate needs renewal.
        """
        if not os.path.exists(self.cert_path):
            return True

        cert = x509.load_pem_x509_certificate(Path(self.cert_path).read_bytes())
        now = datetime.now(UTC)
        expiry = cert.not_valid_after_utc
        threshold = timedelta(days=self.config.cert_rotation.rotate_before_days)

        if expiry < now:
            logger.warning("Certificate expired at %s", expiry.isoformat())
            return True

        return expiry - now <= threshold

    def rotate(self) -> None:
        """Request and install a new certificate.

        Submits a fresh CSR to the server, validates the returned certificate
        against the CA, and replaces the on-disk cert and key.

        Raises:
            RuntimeError: If no certificate exists, CA validation fails, or
                the server returns an error.
            httpx2.HTTPError: If the network request fails.
        """
        logger.info("Rotating executor certificate")

        if not os.path.exists(self.cert_path):
            raise RuntimeError("Cannot rotate: no existing certificate (must register first)")

        # Fail BEFORE any network call if the new cert could not be persisted:
        # the register POST replaces the server-side cert record, so a doomed
        # write (read-only mount, permissions) would burn server state and lose
        # the freshly generated keypair every retry (ticket
        # executor-cert-rotation-erofs — deployed units had
        # ReadOnlyPaths=/etc/venya without the identity dir in ReadWritePaths).
        cert_dir = os.path.dirname(os.path.abspath(self.cert_path))
        if not os.access(cert_dir, os.W_OK):
            raise RuntimeError(
                f"Cannot rotate: certificate directory {cert_dir} is not writable "
                "(read-only mount or permissions). Refusing before contacting the "
                "server — an unpersistable rotation burns the server-side record "
                "and loses the new keypair. Fix the unit's ReadWritePaths "
                "(must include /etc/venya/executor) or the directory permissions."
            )

        # #565: resolve the passphrase for the rotated key BEFORE the POST. The
        # comment below (the #EROFS preflight) already states why the order on this
        # path matters — "a doomed write after the POST still diverges the server
        # record from disk" — and an unconfigured passphrase is exactly such a
        # doomed write, one retry per rotation loop forever. Refusing here leaves
        # the incumbent cert/key untouched and the server record unchanged.
        key_passphrase = passphrase_or_refuse()

        # Generate new keypair and CSR
        private_key = _generate_ecdsa_p256_keypair()
        executor_id = _extract_executor_id_from_cert(self.cert_path)
        csr_pem = _create_csr(private_key, executor_id)

        # Re-register with server (same endpoint, replaces old cert)
        response = self.client.post(  # type: ignore[union-attr]
            "/api/v1/executors/register",
            json={
                "executor_id": executor_id,
                "csr_pem": csr_pem.decode(),
            },
            timeout=self.config.network.registration_timeout_seconds,
        )
        try:
            response.raise_for_status()
        except httpx2.HTTPStatusError as e:
            # Runtime-tolerant: _main_loop's except-Exception logs this and the
            # executor keeps running until the cert actually nears expiry —
            # a transient server error must not kill a mid-loop executor
            # (refactor-1 ruling). The actionable text names the knob, the
            # re-enrollment path, and the Phase-2 incumbent exemption.
            actionable = _token_required_error(e, rotation=True)
            if actionable is not None:
                raise actionable from e
            raise
        data = response.json()

        cert_pem = data["cert_pem"].encode()
        ca_cert_pem = data["ca_cert_pem"].encode()

        # Trust-anchor continuity (#500): the anchor is resolved BEFORE any write
        # and BEFORE the leaf is believed. A rotation response is never allowed
        # to install its own trust root.
        anchor_pem = self._resolve_rotation_anchor(ca_cert_pem)

        # Validate the leaf against the resolved anchor (AC4)
        validate_executor_certificate(cert_pem, anchor_pem, executor_id)

        # Replace on disk — #480 AC1: the trio is STAGED before any write
        # (anchor resolved, leaf validated against it, keypair generated in
        # memory above), and the replaces follow an order the boot-time pair
        # check can validate: KEY first, CERT second, CA last, so the new cert
        # never sits on disk ahead of the key it pairs with — the cert replace
        # is the commit point of the pair. A kill between any two replaces
        # leaves a mismatch the register() presence check detects and
        # re-enrolls (see the #480 branch there) instead of a crash-loop.
        key_pem = serialize_key_encrypted(private_key, key_passphrase)
        _atomic_write(self.key_path, key_pem, 0o600)

        _atomic_write(self.cert_path, cert_pem, 0o644)

        # Update CA cert from server response
        _atomic_write(self.ca_cert_path, ca_cert_pem, 0o644)

        # In-memory identity adopts the new serial ONLY after every disk write
        # succeeded — memory must never claim an identity disk doesn't hold
        # (pre-fix, a failed write left serial=new while disk=old, making
        # revocation matching restart-dependent). NOTE: this narrows but does
        # not close the structural gap — a write failure after the POST still
        # diverges the server record from disk; tracked separately (ticket
        # executor-revocation-by-identity).
        self.serial = data["serial_number"]
        self._not_after = _expiry_clock_with_tz(data["not_after"], where="rotate")

        logger.info(
            "Certificate rotated: serial=%s, expires=%s",
            self.serial,
            self._not_after.isoformat(),
        )

    def _resolve_rotation_anchor(self, ca_cert_pem: bytes) -> bytes:
        """Check a rotation response's CA against the anchor already on disk (#500).

        A rotation response carries both the new leaf and a CA. That CA is
        adopted only when it is the anchor this executor ALREADY trusts, in one
        of two shapes:

        1. The same certificate (DER-equal) as the on-disk anchor — the ordinary
           rotation, where the core hands back its own CA again. The leaf is
           then validated against the bytes already on disk, so a response can
           never validate itself.
        2. A different CA that the on-disk anchor's key actually signed — a
           cross-signed CA rollover, where the incumbent vouches for the new
           root; only then is the arriving material the validation anchor.

        Anything else — most notably a fresh self-signed root arriving in this
        very response — is refused before any file is written. That is the
        continuity gap: pre-fix, the response was its own authority.

        Args:
            ca_cert_pem: PEM-encoded CA presented by the rotation response.

        Returns:
            The PEM bytes the returned leaf must be validated against.

        Raises:
            CertificateValidationError: If the presented CA fails its CA-role
                checks (``validate_ca_certificate``) or fails continuity against
                the on-disk anchor.
            RuntimeError: If no anchor is on disk to check continuity against
                (rotation is not a bootstrap path — the message names the
                re-enroll ceremony).
        """
        new_ca = validate_ca_certificate(ca_cert_pem)

        anchor_path = Path(self.ca_cert_path)
        if not anchor_path.exists():
            raise RuntimeError(
                f"Cannot rotate: no trust anchor on disk at {self.ca_cert_path} to check the "
                "rotation response against. Rotation renews a certificate under an anchor this "
                "executor already trusts; it never establishes one. Re-enroll by re-running the "
                "executor installer with a fresh VENYA_EXECUTOR_ENROLLMENT_TOKEN (mint with: "
                "venya admin executor-enroll <executor-id>)."
            )
        incumbent_pem = anchor_path.read_bytes()
        incumbent = x509.load_pem_x509_certificate(incumbent_pem)

        if incumbent.public_bytes(serialization.Encoding.DER) == new_ca.public_bytes(serialization.Encoding.DER):
            # Same root: hand back what is already on disk — the leaf is
            # validated against the incumbent, never against the response.
            return incumbent_pem

        # A different root is legitimate only if the incumbent signed it.
        _verify_ca_signature(new_ca, incumbent)
        logger.info(
            "Rotation adopts a cross-signed CA (CN=%s) vouched for by the incumbent anchor",
            _extract_common_name(new_ca),
        )
        return ca_cert_pem

    def get_fingerprint(self) -> str:
        """Compute the SHA-256 fingerprint of the current certificate.

        Returns:
            Lowercase hex fingerprint string, or empty string if no cert
            exists.
        """
        if not os.path.exists(self.cert_path):
            return ""

        cert = x509.load_pem_x509_certificate(Path(self.cert_path).read_bytes())
        der = cert.public_bytes(serialization.Encoding.DER)
        return hashlib.sha256(der).hexdigest()

    def check_revocation(self) -> RevocationStatus:
        """Check if this executor's certificate has been revoked.

        Polls the server's revocation list endpoint and checks whether the
        current serial number appears in the list. Supports conditional GET
        via ETag to avoid unnecessary network traffic when the list hasn't
        changed.

        Returns (#442 site 4, ruling R3 — a tri-state, not a bool):
            REVOKED — the server answered, and this credential (by identity or by
            serial) is on the revocation list. Terminal.
            NOT_REVOKED — the server ANSWERED and this credential is live (including
            a 304, which is an answer: the list is unchanged since a check that said
            live, and a revoked credential would already have stopped the loop).
            UNREACHABLE — we could not ask: a transport-level failure, or (since
            #551) an HTTP error status from the endpoint. NOT an assertion of
            liveness. The caller bounds how long that may persist.

        The bool this replaces returned False for the last two cases alike, which
        is what made the daemon's consecutive-failure counter reset during an
        outage; see RevocationStatus.

        Exception boundary (#551, AC3 — which classes are caught where):
            * ``httpx2.RequestError`` (transport: connect/read/write/pool, and
              ``TransportError``, which IS its subclass) — caught below: warning,
              ``UNREACHABLE``.
            * ``httpx2.HTTPStatusError`` (what ``raise_for_status`` raises on a
              4xx/5xx) — caught below TOO: warning with the status code and the
              URL, ``UNREACHABLE``. It needs its own arm because it is a SIBLING
              of ``RequestError`` under ``HTTPError``, not a subclass — measured
              MRO at this base is ``HTTPStatusError -> HTTPError -> Exception``.
              Before that arm existed an HTTP 500 from this endpoint escaped both
              handlers here and both caller arms in ``_main_loop`` (which catch
              ``TimeoutError`` and ``RequestError`` only) and unwound into
              ``start()``'s ``try/finally: self.stop()``, so the daemon stopped
              instead of counting one failed check.
            * ``RevocationPayloadError`` (#552) — what the payload-shape guard
              (:func:`parse_revocation_payload`) raises when the request SUCCEEDED
              with a 200 but the body is not a revocation list: it did not decode
              as JSON text (the two named classes ``json.JSONDecodeError`` and
              ``UnicodeDecodeError`` are what is caught there), or it decoded to a
              non-mapping, or a revocation field is not a list. Same answer as a
              transport fault — ``UNREACHABLE``, counted, retried next tick — and it
              is raised by the guard, not caught from the wire: before it, a
              non-JSON 200 escaped as ``json.JSONDecodeError`` and a 200 that
              decoded to a list escaped as ``AttributeError`` from the ``.get``
              calls. Neither class is a ``RequestError``, so both left this
              function, left both ``_main_loop`` arms, and stopped the daemon.
            * Nothing else is caught here, and no blanket ``except Exception`` is
              used: a body this check cannot read is reported as an UNKNOWN
              answer, never as "not revoked", and never as "could not reach the
              server" — the two launderings this class keeps closed.

        ``UNREACHABLE`` means the revocation state is UNKNOWN, never "confirmed
        live"; ``_main_loop`` counts it toward ``max_revocation_failures`` and asks
        again on the next tick — no retry happens in here, so a persistent status
        error costs one request per tick.
        """
        if self.serial is None:
            # No credential loaded yet — nothing to look up. Kept as an ANSWER
            # (not an uncertainty) so the pre-registration daemon behaves exactly
            # as it did: the verdict is the same, only the name changed.
            return RevocationStatus.NOT_REVOKED

        try:
            headers = {}
            if self._last_revocation_etag:
                headers["If-None-Match"] = self._last_revocation_etag

            response = self.client.get(  # type: ignore[union-attr]
                REVOCATION_LIST_PATH,
                headers=headers,
                timeout=self.config.network.request_timeout_seconds,
            )

            if response.status_code == 304:
                logger.debug("Revocation list unchanged, skipping check")
                return RevocationStatus.NOT_REVOKED

            response.raise_for_status()

            # #552: the body is parsed AND shape-checked before the ETag cache
            # advances. Order matters here: caching the ETag of a payload this
            # check could not read would let the next tick answer 304 (an
            # ANSWER — NOT_REVOKED) about a body that was never read, which
            # launders one failed check into a claim that the credential is
            # live. A malformed 200 keeps the last GOOD etag instead, so the
            # next poll re-asks for the whole list.
            data = parse_revocation_payload(response)
            self._last_revocation_etag = response.headers.get("etag")
            # Identity-level revocation FIRST (ticket executor-revocation-by-identity,
            # ruling 2): the server revoked the whole executor_id — terminal, matches
            # ANY serial. This is what catches a restarted daemon on a diverged
            # (stale) cert that the serial-only list can never match, and it lets the
            # cooperative daemon distinguish "my credential was killed" from "my
            # identity was killed" and fail loudly with the right remedy.
            revoked_identities = set(data.get("revoked_identities", []))
            if self.config.executor_id in revoked_identities:
                logger.warning(
                    "Executor IDENTITY revoked server-side (executor_id=%s) — TERMINAL: "
                    "the whole identity was revoked by an admin, not just a serial. "
                    "This identity cannot be re-registered; re-enroll as a NEW "
                    "executor_id. Shutting down.",
                    self.config.executor_id,
                )
                return RevocationStatus.REVOKED
            revoked_serials = data.get("revoked_serials", [])
            # Case/padding-insensitive membership (ticket
            # cert-serial-canonicalization-mismatch #481): the list carries the
            # STORED spelling, and rows written before the single canonical form
            # exist unpadded/upper as well as padded. Keying the list once keeps
            # this a set lookup instead of a scan per poll. Identity-level
            # revocation (checked above) matches ANY serial regardless.
            revoked_keys = {serial_match_key(s) for s in revoked_serials}
            is_revoked = serial_match_key(self.serial) in revoked_keys

            if is_revoked:
                logger.warning("Executor certificate REVOKED (serial=%s)", self.serial)
            else:
                logger.debug("Certificate not revoked (serial=%s)", self.serial)

            return RevocationStatus.REVOKED if is_revoked else RevocationStatus.NOT_REVOKED
        except httpx2.RequestError as exc:
            # #442 site 4: this used to be `logger.debug(...); return False`, which
            # reported "this certificate is live" at the moment nobody was asked.
            # ABOVE debug per AC3, and the answer is now UNREACHABLE — the caller
            # counts it toward max_revocation_failures instead of resetting on it.
            logger.warning(
                "Revocation status UNKNOWN for executor %s — server unreachable (will retry): %s: %s",
                self.config.executor_id,
                type(exc).__name__,
                exc,
            )
            return RevocationStatus.UNREACHABLE
        except httpx2.HTTPStatusError as exc:
            # #551: an HTTP error status is also an unanswered question, and it
            # used to escape. HTTPStatusError is NOT a RequestError in the
            # installed httpx2 build (measured MRO at this base:
            # HTTPStatusError -> HTTPError -> Exception), so the arm above never
            # saw it; it left check_revocation, left both caller arms in
            # _main_loop, and unwound start() into self.stop(). Same answer as a
            # transport fault — UNREACHABLE, counted, retried on the next tick —
            # but named with the status code and the URL, because a core that
            # answers with an error is a different thing from a core that cannot
            # be reached, and a silent skip here would be the same defect in new
            # clothes. No retry inside this function: _main_loop re-enters on its
            # own ~30 s wait, so a persistent 5xx costs one request per tick.
            logger.warning(
                "Revocation status UNKNOWN for executor %s — server answered HTTP %s from %s (will retry)",
                self.config.executor_id,
                exc.response.status_code,
                exc.request.url,
            )
            return RevocationStatus.UNREACHABLE
        except RevocationPayloadError as exc:
            # #552: a 200 whose body is not a revocation list. The answer is the
            # UNKNOWN one the tri-state already defines — NEVER NOT_REVOKED, which
            # would read "the server told me this certificate is live" out of a
            # body that told us nothing — and it is COUNTED, so a persistent
            # mis-shaped endpoint reaches max_revocation_failures instead of
            # silently resetting the counter every tick.
            logger.warning(
                "Revocation status UNKNOWN for executor %s — server answered 200 from %s with a "
                "payload this check cannot read: %s (will retry)",
                self.config.executor_id,
                REVOCATION_LIST_PATH,
                exc,
            )
            return RevocationStatus.UNREACHABLE

    def _load_metadata(self) -> None:
        """Load serial and expiry from the on-disk certificate."""
        if not os.path.exists(self.cert_path):
            return

        try:
            cert = x509.load_pem_x509_certificate(Path(self.cert_path).read_bytes())
            self._not_after = cert.not_valid_after_utc
            self.serial = canonical_serial(cert.serial_number)
        except Exception:
            # Corrupted or invalid cert — metadata unavailable but cert
            # still exists, so registration is still skipped.
            logger.warning("Could not parse existing certificate for metadata")


# --- Helper functions ---


def _generate_ecdsa_p256_keypair() -> ec.EllipticCurvePrivateKey:
    """Generate an ECDSA P-256 private keypair.

    Returns:
        Private key instance.
    """
    return ec.generate_private_key(ec.SECP256R1())


def _create_csr(private_key: ec.EllipticCurvePrivateKey, executor_id: str) -> bytes:
    """Create a Certificate Signing Request for the given executor.

    Args:
        private_key: The ECDSA P-256 private key.
        executor_id: Unique executor identifier (used as CN).

    Returns:
        PEM-encoded CSR bytes.
    """
    subject = x509.Name(
        [
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Venya"),
            x509.NameAttribute(NameOID.COMMON_NAME, executor_id),
        ]
    )

    csr = x509.CertificateSigningRequestBuilder().subject_name(subject).sign(private_key, hashes.SHA256())
    return csr.public_bytes(serialization.Encoding.PEM)


def _cert_key_pair_matches(cert_path: str | Path, key_path: str | Path) -> bool:
    """True only when the on-disk certificate and private key are the same keypair.

    File PRESENCE alone cannot prove a usable identity (ticket
    interrupted-rotation-leaves-mismatched-cert-key-pair #480): a kill between
    the cert and key replaces in CertificateManager.rotate() leaves a NEW
    certificate beside the OLD key. That pair passed the presence gate, then
    crash-looped the unit on ``ssl.load_cert_chain`` (key values mismatch).
    Unparseable material (a half-written PEM from the same kill window) is the
    same recovery class, so both shapes return False here. The comparison is
    on the public key (DER / SubjectPublicKeyInfo).
    """
    try:
        cert = x509.load_pem_x509_certificate(Path(cert_path).read_bytes())
        # #565: this gate used to read the key with password=None, which is a
        # silent "unparseable" verdict for an encrypted envelope — a valid
        # identity would have looked mismatched and fallen through to
        # re-enrollment. load_private_key tries plaintext first (every legacy
        # host) and then the configured passphrase, so a real mismatch still
        # returns False while "encrypted and no passphrase on this host" raises
        # the named refusal instead of quietly re-minting an identity.
        key = load_private_key(Path(key_path).read_bytes(), key_path=key_path)
    except (OSError, ValueError):
        return False
    der = serialization.Encoding.DER
    fmt = serialization.PublicFormat.SubjectPublicKeyInfo
    return cert.public_key().public_bytes(der, fmt) == key.public_key().public_bytes(der, fmt)


def _extract_common_name(cert: x509.Certificate) -> str | None:
    """Extract the CN from a certificate.

    Args:
        cert: The X.509 certificate.

    Returns:
        The CN value, or None if not found.
    """
    attrs = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
    if not attrs:
        return None
    value = attrs[0].value
    return value.decode() if isinstance(value, bytes) else value


def _verify_ca_signature(cert: x509.Certificate, ca_cert: x509.Certificate) -> None:
    """Verify that cert is signed by ca_cert's ECDSA public key.

    Args:
        cert: The certificate to verify.
        ca_cert: The CA certificate.

    Raises:
        CertificateValidationError: If the signature is invalid or key type unsupported.
    """
    from cryptography.exceptions import InvalidSignature

    ca_public_key = ca_cert.public_key()

    if not isinstance(ca_public_key, ec.EllipticCurvePublicKey):
        raise CertificateValidationError(f"Unsupported CA key type: {type(ca_public_key).__name__}")

    try:
        hash_algo = cert.signature_hash_algorithm
        if hash_algo is None:
            raise CertificateValidationError("Certificate has no signature hash algorithm")
        ca_public_key.verify(
            cert.signature,
            cert.tbs_certificate_bytes,
            ec.ECDSA(hash_algo),
        )
    except InvalidSignature:
        raise CertificateValidationError("Certificate not signed by trusted CA")


def validate_ca_certificate(ca_cert_pem: bytes) -> x509.Certificate:
    """Check that a certificate is fit to be held as a trust anchor (#500).

    The anchor decides which leaves this daemon will believe from now on, so
    arriving material is checked for CA SHAPE, not merely for parseability:
    the validity window (same skew tolerance leaf validation uses),
    ``BasicConstraints CA=TRUE`` and ``KeyUsage key_cert_sign``. Leaf-shaped
    material — including a self-signed leaf carrying an ECDSA key, which
    ``_verify_ca_signature`` alone would accept as an issuer — is refused.

    Args:
        ca_cert_pem: PEM-encoded certificate proposed as a trust anchor.

    Returns:
        The parsed certificate, so a caller does not re-parse it.

    Raises:
        CertificateValidationError: If the material is outside its validity
            window, is not flagged as a CA, or cannot sign certificates.
    """
    ca_cert = x509.load_pem_x509_certificate(ca_cert_pem)
    now = datetime.now(UTC)

    # 1. Validity window
    if now + CLOCK_SKEW_TOLERANCE < ca_cert.not_valid_before_utc:
        raise CertificateValidationError("CA certificate not yet valid")
    if now - CLOCK_SKEW_TOLERANCE > ca_cert.not_valid_after_utc:
        raise CertificateValidationError("CA certificate expired")

    # 2. BasicConstraints CA=TRUE
    try:
        bc = ca_cert.extensions.get_extension_for_class(x509.BasicConstraints)
        if not bc.value.ca:
            raise CertificateValidationError("CA certificate has BasicConstraints CA=False (must be a CA)")
    except x509.ExtensionNotFound:
        raise CertificateValidationError("CA certificate missing BasicConstraints extension")

    # 3. KeyUsage key_cert_sign
    try:
        ku = ca_cert.extensions.get_extension_for_class(x509.KeyUsage)
        if not ku.value.key_cert_sign:
            raise CertificateValidationError("CA certificate KeyUsage missing keyCertSign")
    except x509.ExtensionNotFound:
        raise CertificateValidationError("CA certificate missing KeyUsage extension")

    return ca_cert


def validate_executor_certificate(
    cert_pem: bytes,
    ca_cert_pem: bytes,
    expected_executor_id: str,
) -> None:
    """Validate an executor certificate against all security requirements.

    Checks are ordered by cost — cheapest first so most rejections
    short-circuit before expensive crypto operations.

    Args:
        cert_pem: PEM-encoded executor certificate.
        ca_cert_pem: PEM-encoded CA certificate.
        expected_executor_id: The expected executor ID (matches CN).

    Raises:
        CertificateValidationError: If any check fails.
    """
    cert = x509.load_pem_x509_certificate(cert_pem)
    ca_cert = x509.load_pem_x509_certificate(ca_cert_pem)
    now = datetime.now(UTC)

    # 1. Validity period (cheapest — no extension parsing)
    not_before = cert.not_valid_before_utc
    not_after = cert.not_valid_after_utc
    if now + CLOCK_SKEW_TOLERANCE < not_before:
        raise CertificateValidationError("Certificate not yet valid")
    if now - CLOCK_SKEW_TOLERANCE > not_after:
        raise CertificateValidationError("Certificate expired")

    # 2. CN matches executor_id (string comparison)
    cn = _extract_common_name(cert)
    if cn != expected_executor_id:
        raise CertificateValidationError(f"CN mismatch: expected {expected_executor_id!r}, got {cn!r}")

    # 3. BasicConstraints CA=False
    try:
        bc = cert.extensions.get_extension_for_class(x509.BasicConstraints)
        if bc.value.ca:
            raise CertificateValidationError("Certificate has CA=True (must be leaf cert)")
    except x509.ExtensionNotFound:
        raise CertificateValidationError("Missing BasicConstraints extension")

    # 4. KeyUsage includes digitalSignature
    try:
        ku = cert.extensions.get_extension_for_class(x509.KeyUsage)
        if not ku.value.digital_signature:
            raise CertificateValidationError("KeyUsage missing digitalSignature")
    except x509.ExtensionNotFound:
        raise CertificateValidationError("Missing KeyUsage extension")

    # 5. ExtendedKeyUsage includes clientAuth
    try:
        eku = cert.extensions.get_extension_for_class(x509.ExtendedKeyUsage)
        if x509.ExtendedKeyUsageOID.CLIENT_AUTH not in eku.value:
            raise CertificateValidationError("EKU missing clientAuth")
    except x509.ExtensionNotFound:
        raise CertificateValidationError("Missing ExtendedKeyUsage extension")

    # 6. CA signature verification (most expensive — do last)
    _verify_ca_signature(cert, ca_cert)


def _extract_executor_id_from_cert(cert_path: str) -> str:
    """Extract the executor ID (CN) from an existing certificate.

    Args:
        cert_path: Path to the PEM-encoded certificate file.

    Returns:
        The CN value from the certificate subject.

    Raises:
        ValueError: If the CN is not found in the certificate.
    """
    cert = x509.load_pem_x509_certificate(Path(cert_path).read_bytes())
    try:
        cn_attributes = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
        if not cn_attributes:
            raise ValueError("Certificate has no CN (Common Name)")
        value = cn_attributes[0].value
        return value.decode() if isinstance(value, bytes) else value
    except Exception as e:
        raise ValueError(f"Failed to extract executor ID from certificate: {e}")


class ReaperLoop:
    """Background loop for cleaning up orphaned resources.

    Scans for orphaned secret files and stale tokens.
    """

    def __init__(
        self,
        config: ExecutorConfig,
        state: DaemonState,
        tmpfs_dir: str = SECRET_TMPFS_BASE,
        http_client: Any | None = None,
    ) -> None:
        self.config = config
        self.state = state
        self.tmpfs_dir = tmpfs_dir
        self.http_client = http_client
        self._thread: threading.Thread | None = None
        self._stop_event = threading.Event()

    def start(self) -> None:
        """Start the reaper loop in a background thread."""
        self._stop_event.clear()
        self._thread = threading.Thread(
            target=self._run,
            name="venya-reaper",
            daemon=True,
        )
        self._thread.start()
        logger.info("Reaper loop started (interval=%.1fs)", self.config.reaper.check_interval)

    def stop(self) -> None:
        """Stop the reaper loop."""
        self._stop_event.set()
        if self._thread:
            self._thread.join(timeout=10.0)
            logger.info("Reaper loop stopped")

    def _run(self) -> None:
        """Main reaper loop."""
        while not self._stop_event.is_set():
            try:
                self._check_orphaned()
            except Exception:
                logger.exception("Error in reaper loop")
            self._stop_event.wait(self.config.reaper.check_interval)

    def _check_orphaned(self) -> None:
        """Delete orphaned per-run secret dirs and revoke their session secrets.

        Scans tmpfs_dir (default: the sbx strategy's SECRET_TMPFS_BASE) for
        directories older than secret_ttl_seconds under either of the two
        prefixes the strategy writes there (#469):

        * ``session_<server-session-id>_<rand>`` — prepare()'s per-run secrets
          dir. The name carries the real execution-session id, so an aged dir
          is deleted AND its children attributed to that session's revoke.
        * ``env_<rand>`` — the env-file fallback dir (#469). It carries NO
          session id, so it is deleted WITHOUT any revoke attribution; see the
          prefix gate below for why its name must never reach the parser.

        Live runs clean up their own dir; an aged dir belongs to a dead run
        (daemon killed mid-execution). The old flat ``venya_*.secret`` file
        scan matched nothing under the sbx dir layout, and the phantom
        "default" session id never matched a real session (ticket
        daemon-reaper-phantom-session).
        """
        import time

        ttl_seconds = self.config.reaper.secret_ttl_seconds
        now = time.time()

        try:
            if not os.path.exists(self.tmpfs_dir):
                return
            entries = os.listdir(self.tmpfs_dir)
        except OSError:
            logger.exception("Failed to scan %s for orphaned session dirs", self.tmpfs_dir)
            return

        for dirname in entries:
            # #469: BOTH prefixes the strategy writes are in scope. `env_*`
            # matched nothing before this and so survived the host's uptime
            # with a 0600 plaintext env file inside.
            is_session_dir = dirname.startswith(SESSION_DIR_PREFIX)
            if not (is_session_dir or dirname.startswith(ENV_DIR_PREFIX)):
                continue
            dirpath = os.path.join(self.tmpfs_dir, dirname)
            if not os.path.isdir(dirpath):
                continue
            try:
                age = now - os.stat(dirpath).st_mtime
            except OSError:
                continue
            if age <= ttl_seconds:
                continue

            # session_<session-id>_<mkdtemp-rand>: execution-session ids are
            # UUIDs (no underscores — d4a8d9f contract), while the mkdtemp
            # random suffix CAN contain underscores ([a-z0-9_] charset), so
            # parse from the left and ignore the tail. Unparseable → delete
            # without revoke (never a phantom-session revoke).
            #
            # The PARSE ITSELF is gated on the prefix, not just its outcome
            # (#469 AC, the §3 mis-parse check): an `env_<rand>` name is made
            # of the same underscore-bearing charset, so `env_a1b_2c` would
            # split to ['env','a1b','2c'] — three parts, and the left-pick
            # would hand the revoke path "a1b" as a session id. That is a
            # phantom-session revoke wearing a real call: the server skips
            # non-numeric ids for the DELETE, but still writes a
            # credential_revoked audit row for every child name it is given.
            # So `session_id` is only ever derived from a session_* name.
            session_id: str | None = None
            if is_session_dir:
                parts = dirname.split("_")
                if len(parts) >= 3:
                    session_id = parts[1]
            try:
                secret_ids = sorted(os.listdir(dirpath))
            except OSError:
                secret_ids = []

            try:
                shutil.rmtree(dirpath)
                logger.info(
                    "Deleted orphaned %s dir: %s (%d file(s) inside)",
                    "session secret" if is_session_dir else "env-file",
                    dirname,
                    len(secret_ids),
                )
            except OSError:
                logger.exception("Failed to delete orphaned secret dir: %s", dirpath)
                continue

            if session_id and secret_ids and self.http_client:
                try:
                    self.http_client.post(
                        f"/api/v1/sessions/{session_id}/secrets/revoke",
                        json={"secret_ids": secret_ids},
                        timeout=self.config.network.request_timeout_seconds,
                    )
                    logger.info(
                        "Revoked %d secret(s) for orphaned session %s",
                        len(secret_ids),
                        session_id,
                    )
                except Exception:
                    logger.exception("Failed to revoke secrets for orphaned session %s", session_id)


def build_command_policy(cv: Any) -> CommandPolicy:
    """Build a CommandPolicy from the executor config's command_validator section.

    Presets and their trusted_paths behavior:
      - balanced: DEFAULT_TRUSTED_PATHS (operator cannot override; no config field)
      - strict: empty (uses allowed_commands allowlist instead)
      - permissive: empty (no path check; dangerous patterns still apply)
    """
    trusted = frozenset(DEFAULT_TRUSTED_PATHS) if cv.preset == "balanced" else frozenset()
    return CommandPolicy(
        preset=cv.preset,
        allowed_commands=frozenset(cv.allowed_commands) if cv.allowed_commands else frozenset(),
        trusted_paths=trusted,
        dangerous_patterns=(
            frozenset(cv.dangerous_patterns) if cv.dangerous_patterns else frozenset(DEFAULT_DANGEROUS_PATTERNS)
        ),
        match_word_boundaries=cv.match_word_boundaries,
    )


class ExecutorDaemon:
    """Main executor daemon.

    Manages the full executor lifecycle including:
      - Server connection and authentication
      - Command reception and execution
      - Certificate management
      - Heartbeat and revocation polling
      - Reaper loop
    """

    def __init__(self, config: ExecutorConfig | None = None) -> None:
        if config is None:
            config = ExecutorConfig()

        self.config = config
        self._config_path = self.config.config_path or Path("/etc/venya/executor.toml")
        self._bootstrap_token_path = BOOTSTRAP_TOKEN_PATH
        self.state = DaemonState()
        self.state.executor_id = config.executor_id

        # Command validator
        cv = self.config.command_validator

        self.command_validator = CommandValidator(
            policy=build_command_policy(cv),
        )

        # Server-propagated command policy (ticket
        # command-policy-no-server-executor-propagation): signature of the last
        # payload applied via update_policy(); None = the toml-built policy is
        # still the live one. Fail-closed semantics: absence of the payload
        # NEVER reverts to toml mid-run — the last applied server policy sticks
        # until daemon restart (restart re-bootstraps from toml).
        self._applied_server_policy_sig: tuple | None = None

        # Certificate manager — client created after registration
        self.cert_manager = CertificateManager(config)

        # Reaper loop
        self.reaper = ReaperLoop(
            config,
            self.state,
        )

        # Relay listener (B0) — wired to the existing execution engine. The
        # factory is the bound create_executor; it reads self.client at call
        # time, so it is safe to stash here before the client exists. Same
        # lazy-binding shape for #586: ``state`` is this object's own DaemonState
        # (created above, before the relay), so the accept gate reads the ONE
        # revocation answer this side holds — not a second revocation list.
        self.relay = RelayListener(config, self.create_executor, config.relay_client_ids, state=self.state)

        # Signal handling
        self._shutdown_event = threading.Event()

        # HTTP thread pool — keeps network calls off the main loop
        self._http_executor = ThreadPoolExecutor(max_workers=2, thread_name_prefix="http")

        # Bounded-heartbeat guard: last submitted heartbeat future.
        # _submit_heartbeat skips a tick if this is still in flight, so the
        # pool's unbounded work queue cannot grow when request_timeout_seconds
        # is raised above the ~30s loop cadence.
        self._heartbeat_future: Future[None] | None = None

        # HTTP client — initialized in start() after registration
        self.client: httpx2.Client | None = None

        # Boot-time audit spool forwarder — constructed in start(), drained and
        # joined in stop() (refs ticket audit-spool-forwarder-session-lifetime #436).
        self.audit_boot_forwarder: AuditLogger | None = None

    def _create_mtls_client(self) -> httpx2.Client:
        """Create HTTP client with mTLS after certificate registration.

        Missing/unusable material is a named single-line startup refusal, not
        a raw traceback (ticket refactor-1-config-consolidation residual —
        same fail-loud pattern as the deaf-boot guard).

        Trust set (#531, owner ruling 2026-10-07): the configured Venya CA
        (``mtls.ca_cert``) is the ONLY anchor. This used to start from
        ``ssl.create_default_context()``, which loads the HOST trust store and
        then only ADDS our anchor with ``load_verify_locations()`` — so the
        executor's control-channel dial accepted any publicly-issued
        certificate for the core hostname. A bare ``PROTOCOL_TLS_CLIENT``
        context (already ``CERT_REQUIRED`` + ``check_hostname``) carries the
        verification posture the default helper set, and the two flags
        ``create_default_context()`` applied are set explicitly so the anchor
        set is the only thing that changed (same house shape as #501's
        ``_build_relay_ssl_context`` and #530's ``_build_ssl_context``).
        """
        try:
            ssl_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            ssl_ctx.verify_flags |= ssl.VERIFY_X509_STRICT | ssl.VERIFY_X509_PARTIAL_CHAIN
            # #565: the key may now be an encrypted envelope, so the loader answers
            # OpenSSL with the configured passphrase. The callback is invoked ONLY
            # for an encrypted file, so a legacy plaintext key on an existing host
            # still loads exactly as before with nothing set — the no-regression
            # half, and the reason this is a callback and not a value. When the key
            # IS encrypted and the passphrase is missing, the callback raises the
            # named refusal, which is not an (OSError, ssl.SSLError), so it escapes
            # this arm intact instead of being restated as "material unusable".
            ssl_ctx.load_cert_chain(self.config.mtls.cert, self.config.mtls.key, password=ssl_password_callback())
            ssl_ctx.load_verify_locations(self.config.mtls.ca_cert)
        except (OSError, ssl.SSLError) as exc:
            logger.error(
                "mTLS material unusable (cert=%s key=%s ca=%s): %s — "
                "restore the files or re-run the executor installer",
                self.config.mtls.cert,
                self.config.mtls.key,
                self.config.mtls.ca_cert,
                exc,
            )
            raise RuntimeError(f"mTLS material unusable: {exc}") from exc
        return httpx2.Client(
            base_url=self.config.server_url,
            verify=ssl_ctx,
            timeout=self.config.network.request_timeout_seconds,
        )

    def _resolve_bootstrap_token(self) -> str | None:
        """Resolve the bootstrap enrollment token from both storage locations.

        Canonical file wins over the legacy toml [bootstrap] section (dual-
        location reader until legacy installs are cut over — ticket
        daemon-bootstrap-token-clear-erofs). Called ONCE from start(); the
        resolved value is never re-read per loop iteration.
        """
        token_path = self._bootstrap_token_path
        if token_path.exists():
            try:
                token = token_path.read_text().strip()
            except OSError as e:
                logger.error("Bootstrap token file %s unreadable: %s — ignoring", token_path, e)
                return self.config.bootstrap.enrollment_token
            if token:
                return token
            logger.warning("Bootstrap token file %s is empty — falling back to config", token_path)
        return self.config.bootstrap.enrollment_token

    def _clear_bootstrap_token(self) -> None:
        """Remove the consumed bootstrap token from BOTH storage locations.

        The token is server-side single-use and already consumed by the time
        this runs — what gets deleted is spent residue, not a live credential.
        The canonical file lives under the unit's ReadWritePaths, so its
        removal is clean. The legacy executor.toml section sits under
        ReadOnlyPaths=/etc/venya: the rewrite fails EROFS on hardened units.
        That failure must NOT kill the daemon (the uncaught-OSError crash-loop
        is exactly the ticket harm, and exit-1 would reinstate it for the
        legacy population least able to self-heal) — ruling 2026-09-20:
        loud actionable ERROR + proceed, grace strictly scoped to the legacy
        location.
        """
        import tomllib

        token_path = self._bootstrap_token_path
        if token_path.exists():
            try:
                token_path.unlink()
                logger.info("Cleared bootstrap token file %s", token_path)
            except OSError as e:
                logger.error(
                    "Could not remove bootstrap token file %s: %s — remove it manually "
                    "(token already consumed server-side)",
                    token_path,
                    e,
                )

        config_path = self._config_path
        if not config_path.exists():
            return

        try:
            with open(config_path, "rb") as f:
                data = tomllib.load(f)
        except Exception:
            logger.warning("Could not read config file to clear enrollment token")
            return

        # Remove bootstrap section if it exists and contains enrollment_token
        if "bootstrap" in data and "enrollment_token" in data["bootstrap"]:
            del data["bootstrap"]["enrollment_token"]
            # Remove entire bootstrap section if it's now empty
            if not data["bootstrap"]:
                del data["bootstrap"]

            try:
                # tomli_w.dump requires BINARY bytes — the pre-fix text-mode
                # open was a latent TypeError on every successful clear
                # (masked in production: hardened units hit EROFS first and
                # installer-flow clears the toml as root before daemon boot).
                # #316: land via the atomic 0600 writer — the toml is a
                # credential-bearing file, never a umask-mode
                # truncate-and-rewrite.
                _atomic_write(config_path, tomli_w.dumps(data).encode("utf-8"), 0o600)
                logger.info("Cleared enrollment token from config")
            except OSError as e:
                logger.error(
                    "Config file %s is not writable (%s) — remove the [bootstrap] section "
                    "manually; the enrollment token is already consumed server-side and "
                    "the residue is a spent credential only",
                    config_path,
                    e,
                )

    def _reclaim_stale_tmp(self) -> int:
        """Sweep stale ``*.tmp`` across every directory this daemon writes through.

        Single source of the sweep SCOPE (#478 AC2): the mTLS material dirs,
        the executor config dir, the bootstrap-token dir, and the audit-spool
        dir when configured — the executor's own directories only, never a
        global walk. Delegates the age/identity policy to
        ``sweep_stale_tmp_files``.
        """
        dirs: set[str | Path] = {
            Path(self.config.mtls.cert).parent,
            Path(self.config.mtls.key).parent,
            Path(self.config.mtls.ca_cert).parent,
            self._config_path.parent,
            self._bootstrap_token_path.parent,
        }
        spool = getattr(self.config.audit, "spool_path", None)
        if spool:
            dirs.add(Path(spool).parent)
        return sweep_stale_tmp_files(dirs)

    def create_executor(self, session_id: str) -> Executor:
        """Create an Executor instance with mTLS client.

        Args:
            session_id: The session ID for this executor instance.

        Returns:
            Configured Executor instance with HTTP client for server API calls.
        """
        strategy = SbxStrategy(
            dns_resolver=self.config.dns_resolver,
            egress_allowlist_path=self.config.egress_allowlist_path,
            sandbox_memory_mb=self.config.sandbox_memory_mb,
        )
        # #307 D1: the audit sink is executor-mTLS-gated — forward with the
        # same client cert material the daemon client uses (existence is the
        # installer's job; config values are the gate, no stat checks).
        mtls = self.config.mtls
        audit_client_cert = (mtls.cert, mtls.key) if mtls.cert and mtls.key else None
        audit_logger = AuditLogger(self.config.audit, session_id, client_cert=audit_client_cert)
        return Executor(
            command_validator=self.command_validator,
            session_id=session_id,
            injection_strategy=strategy,
            audit_logger=audit_logger,
            http_client=self.client,
            config=self.config,
        )

    def start(self) -> None:
        """Start the executor daemon."""
        # Refuse to boot "deaf": an empty allowlist means the relay listener
        # would fail closed and never bind, yet the process would look healthy
        # to systemd and every normal ops probe. Checked FIRST — before
        # registration — so the one-shot enrollment token is never consumed on
        # a doomed boot (ticket relay-listener-empty-allowlist-not-observable,
        # option B).
        if not self.config.relay_client_ids:
            logger.error(
                "relay_client_ids is empty — refusing to start: the relay listener "
                "would never bind and this executor could not receive commands. "
                "Set relay_client_ids to the core's relay client certificate CN "
                "in executor.toml."
            )
            raise SystemExit(1)
        # Refuse to boot without a configured DNS resolver (ruling D1 option (a):
        # Venya never guesses your network). Same shape/position as the deaf-relay
        # guard above — checked BEFORE registration so the one-shot enrollment
        # token is never consumed on a doomed boot: the egress policy cannot be
        # built without this required input. The resolver IP is always allowed
        # for sandbox egress; hostname targets resolve only when the hostname
        # itself is in the egress allowlist (the sandbox DNS proxy authorizes
        # per domain).
        if not self.config.dns_resolver:
            logger.error(
                "dns_resolver is not configured — refusing to start: the sandbox "
                "egress policy cannot be built without it. The resolver IP is always "
                "allowed for sandbox egress; hostname targets resolve only when the "
                "hostname itself is in the egress allowlist. Set `dns_resolver` in "
                "/etc/venya/executor.toml — that file's value is the one this daemon "
                "uses whenever the file carries the key, including as an empty value; "
                "VENYA_EXECUTOR_DNS_RESOLVER in the service environment is read only "
                "when the file does not carry `dns_resolver` at all "
                "(precedence: file > env > default, #598; find your resolver: "
                "resolvectl status or grep nameserver /etc/resolv.conf)."
            )
            raise SystemExit(1)
        # refs ticket sbx-exec-env-file-noop: refuse boot on an sbx CLI below
        # the version floor — below 0.39.0 `sbx exec --env-file` is a silent
        # no-op, so secrets would never land. Checked BEFORE registration so
        # the one-shot enrollment token is never consumed on a doomed boot.
        try:
            sbx_ver = require_supported_sbx()
            logger.info("sbx CLI supported: %s", sbx_ver)
        except SbxVersionError as exc:
            logger.error("%s", exc)
            raise
        logger.info("Starting executor daemon: %s", self.config.executor_id)

        # /dev/shm survives daemon kills and reboots but sandboxes never do:
        # any ws_* directory present now is an orphan from a dead run. Sweep
        # once, at process start, before any execution can create new ones.
        swept = sweep_workspace_base()
        logger.info("Swept %d orphaned workspace dir(s) from previous run(s)", swept)

        # Ticket sandbox-residue-unreaped-after-teardown-failure (#474): the
        # workspace sweep above only reclaims DIRECTORIES. A sandbox that
        # outlived its daemon (a failed `sbx rm`, or a kill mid-run) is a live
        # microVM that held injected secret material, and nothing collected it.
        # This pass runs HERE, before the relay listener binds, so the
        # ownership registry is necessarily empty: every `venya-*` sandbox on
        # the host is residue by definition. The pass is best-effort end to
        # end (every CLI call inside it is logged, not raised) — a boot must
        # not die over debris it came to clean.
        reaped = reap_orphan_sandboxes()
        if reaped:
            logger.info("Collected %d orphaned sandbox(es) from previous run(s) (#474)", reaped)

        # #478: reclaim stale *.tmp left behind by a killed writer. The legacy
        # deterministic temp name (<target>.tmp) could wedge every later write
        # to that target forever; sweep it (and any mkstemp-era residue older
        # than the bound) BEFORE the writes that would once have been blocked
        # by it. Scoped to this executor's own directories only.
        reclaimed = self._reclaim_stale_tmp()
        if reclaimed:
            logger.info("Reclaimed %d stale temp file(s) from executor directories (#478)", reclaimed)

        # Register with server (creates cert/key if not present)
        # register() uses throwaway httpx2.Client instances internally —
        # never self.client. After registration, certs are on disk.
        enrollment_token = self._resolve_bootstrap_token()
        self.cert_manager.register(self.state.executor_id, enrollment_token=enrollment_token)
        # Registration carries the same additive policy field as the
        # heartbeat; apply it before the first beat so a fresh install
        # enforces the core's policy from its very first command.
        self._maybe_apply_server_policy(
            {"command_policy": getattr(self.cert_manager, "last_command_policy", None)},
            "registration",
        )

        # Clear the consumed bootstrap token (both locations) after successful
        # registration — once per start(), never per loop iteration.
        if enrollment_token:
            self._clear_bootstrap_token()

        # Create mTLS client — takes over for all subsequent communication.
        # Startup refusal: without a working control channel the daemon is
        # useless (heartbeat/revocation/rotation all dead) — exit 1, systemd
        # shows failed. The RUNTIME rotation path in _main_loop keeps its
        # tolerant except-Exception behavior (RuntimeError is an Exception;
        # SystemExit would bypass it and kill a running daemon on a
        # transient rebuild failure).
        try:
            self.client = self._create_mtls_client()
        except RuntimeError:
            raise SystemExit(1) from None
        self.cert_manager.client = self.client

        # Configure reaper with mTLS client and session info
        self.reaper.http_client = self.client

        # Setup signal handlers
        signal.signal(signal.SIGTERM, self._handle_signal)
        signal.signal(signal.SIGINT, self._handle_signal)

        # Start reaper loop
        self.reaper.start()

        # Start the mTLS relay listener (certs already on disk after registration)
        self.relay.start()
        if not self.relay.active:
            # Bind/SSL-setup failure class (the empty-allowlist cause is
            # refused before registration): same deaf-but-booted outcome,
            # same loud refusal.
            logger.error("Relay listener failed to bind — refusing to run deaf")
            raise SystemExit(1)

        # Boot-time audit spool forwarder (refs ticket
        # audit-spool-forwarder-session-lifetime #436): the forwarder thread is
        # owned by AuditLogger, historically constructed ONLY per command
        # session — an idle executor never drained its backlog. Sibling of the
        # reaper/relay starts above; the per-session logger in create_executor
        # is unchanged. Guarded by the sink being configured: with remote_url
        # unset _forward_once returns True without any POST, so the thread
        # would poll for nothing (and the constructor touches the default
        # spool path). client_cert derived exactly as the session path does
        # (#307 D1 fail-closed mTLS sink).
        if self.config.audit.remote_url:
            mtls = self.config.mtls
            self.audit_boot_forwarder = AuditLogger(
                self.config.audit,
                BOOT_FORWARDER_SESSION_ID,
                client_cert=(mtls.cert, mtls.key) if mtls.cert and mtls.key else None,
            )
            # #586: the accept gate's durable record — refusals land on the same spool
            # this forwarder drains. Wired here (not in __init__) because the sink does
            # not exist until now; the listener reads it per refusal, and with it unset
            # a refusal still journals (see _record_refusal's shortcut note).
            self.relay.refusal_sink = self.audit_boot_forwarder
            logger.info("Audit spool forwarder booted (session-less drain armed)")

        # Mark as running
        self.state.running = True
        self.state.cert_serial = self.cert_manager.serial
        self.state.cert_not_after = self.cert_manager.not_after

        # Write PID file
        self._write_pidfile()

        # Main loop
        try:
            self._main_loop()
        finally:
            self.stop()

    def _main_loop(self) -> None:
        """Main daemon loop.

        Checks certificate rotation, revocation status, and sends heartbeats.
        Network calls run in a background thread pool to keep the main loop
        responsive to shutdown signals.
        """
        logger.info("Daemon main loop started")

        while self.state.running and not self.state.revoked:
            # Check certificate rotation (synchronous — rare operation)
            if self.cert_manager.needs_rotation():
                try:
                    self.cert_manager.rotate()
                    # Recreate client with new cert. Ticket daemon-reaper-cert-orphan
                    # #178 residual (acceptance bullet left unimplemented by 9bc0cd7):
                    # the pre-rotation client used to be dropped on the floor — its
                    # connection pool + TLS session lingered with the REVOKED cert
                    # until daemon stop. Capture the outgoing client BEFORE the
                    # reassignments; close it only AFTER all three references
                    # (daemon/cert_manager/reaper) are on the new client, so the
                    # reaper thread's next request can never see a closed client it
                    # fetched after the swap. A close failure is swallowed with a
                    # warning — rotation already succeeded; the orphan (bounded: one
                    # per failed close) is strictly better than an aborted swap.
                    old_client = self.client
                    self.client = self._create_mtls_client()
                    self.cert_manager.client = self.client
                    self.reaper.http_client = self.client
                    if old_client is not None:
                        try:
                            old_client.close()
                        except Exception:
                            logger.warning(
                                "pre-rotation client close failed — orphaned client " "persists until daemon stop",
                                exc_info=True,
                            )
                    self.state.cert_serial = self.cert_manager.serial
                    self.state.cert_not_after = self.cert_manager.not_after
                    # #579: the OUTBOUND half above is not the whole swap. The relay
                    # listener is the SERVER side of :8443 and holds its own mTLS
                    # context; without this call it keeps presenting the pre-rotation
                    # leaf (a serial the server has already revoked) until a restart.
                    # Publishes a freshly built context — new connections get it, an
                    # in-flight handshake finishes on the old one. Never restarts the
                    # listener (that would trade a stale leaf for a #477 drain window).
                    self.relay.reload_ssl_context()
                    logger.info(
                        "Certificate rotated in main loop, new expiry: %s",
                        self.state.cert_not_after,
                    )
                except Exception:
                    logger.exception("Certificate rotation failed")

            # Check revocation status — run in thread pool
            revocation_future = self._http_executor.submit(self.cert_manager.check_revocation)
            try:
                # #442 site 4: the three answers are named, not truth-tested. The
                # UNREACHABLE case now ADVANCES the consecutive-failure counter; the
                # `else: ... = 0` reset below used to fire on it, which is how an
                # outage erased its own evidence. Threshold and its warning text are
                # unchanged — what feeds them is what got fixed.
                revocation = revocation_future.result(timeout=self.config.network.request_timeout_seconds)
                if revocation is RevocationStatus.REVOKED:
                    logger.warning("Executor certificate revoked — shutting down")
                    self.state.revoked = True
                    break
                elif revocation is RevocationStatus.UNREACHABLE:
                    self.state._consecutive_revocation_failures += 1
                else:
                    self.state._consecutive_revocation_failures = 0
                    # #586: the ONE write site for the gate's bootstrap flag. Sticky by
                    # design: a later UNREACHABLE does not clear it, because the bounded
                    # answer to an outage is already the threshold below (which carries a
                    # #603 fault reason and takes the listener down with the daemon — it
                    # does NOT assert revocation).
                    # Clearing it here would refuse live work on a single dropped poll.
                    self.state.revocation_answered = True
            except TimeoutError:
                logger.debug("Revocation check timed out")
                self.state._consecutive_revocation_failures += 1
            except httpx2.RequestError:
                logger.debug("Revocation check failed (server unreachable)")
                self.state._consecutive_revocation_failures += 1

            # #603: the threshold is a FAULT, never a revocation. It keeps counting
            # (#442's posture — an outage must not erase its own evidence), keeps
            # stopping the daemon (stopping under starvation is fail-safe), and stops
            # claiming a server-side fact the server never asserted. The refusal the
            # accept point serves is the 503 OPERATIONAL FAULT sentence that already
            # ships (#586), so no new operator vocabulary is invented here.
            if self.state._consecutive_revocation_failures >= self.config.cert_rotation.max_revocation_failures:
                logger.warning(
                    "Consecutive revocation check failures (%d) reached the fault threshold (%d) — "
                    "no revocation answer received, stopping service "
                    "(the core has neither confirmed nor revoked this credential; check core reachability)",
                    self.state._consecutive_revocation_failures,
                    self.config.cert_rotation.max_revocation_failures,
                )
                self.state.revocation_fault_reason = REFUSE_NO_ANSWER
                break

            # Heartbeat — fire and forget, but bounded (skip+warn if prior in flight)
            self._submit_heartbeat()

            # Wait before next iteration (interruptible by signals)
            self._shutdown_event.wait(30.0)

    def _submit_heartbeat(self) -> None:
        """Submit a heartbeat unless the previous one is still in flight.

        Fire-and-forget into the 2-worker pool, but bounded: if the prior
        heartbeat hasn't completed (server slow/hung so the request outlives the
        ~30s loop cadence — possible when request_timeout_seconds is raised above
        it), skip this tick and warn. Without the guard the pool's unbounded work
        queue grows silently. Fails loudly on every skip so a backlog can never
        accumulate unnoticed.
        """
        if self._heartbeat_future is not None and not self._heartbeat_future.done():
            logger.warning(
                "Heartbeat skipped — previous still in flight (server slow or hung); "
                "backpressure guard tripped, not a normal state"
            )
            return
        self._heartbeat_future = self._http_executor.submit(self._send_heartbeat)

    def _maybe_apply_server_policy(self, data: Any, source: str) -> None:
        """Apply a core-propagated command policy if present and changed.

        Ticket command-policy-no-server-executor-propagation (owner ruling (a)
        2026-09-26): the server's 'default' policy row rides the registration
        and heartbeat responses; this is the consumer that makes
        `set-command-policy`/`add-allowed-command` actually enforce.

        Advisory-channel discipline (same as the revoked flag): a malformed
        payload never kills registration or the heartbeat — it is logged and
        the current policy stays. Change detection: identical payloads apply
        ONCE; a changed row re-applies on the next beat (~30 s). Absence/null
        means "no server policy" — the toml-built (or last applied) policy is
        kept; it never reverts mid-run (fail-closed).
        """
        if not isinstance(data, dict):
            return
        payload = data.get("command_policy")
        if payload is None:
            return
        if not isinstance(payload, dict):
            logger.error("Server command policy from %s is not an object — keeping current policy", source)
            return
        preset = payload.get("preset")
        if preset not in ("permissive", "balanced", "strict"):
            logger.error(
                "Server command policy from %s has unknown preset %r — keeping current policy",
                source,
                preset,
            )
            return
        allowed_raw = payload.get("allowed_commands")
        patterns_raw = payload.get("dangerous_patterns")
        if allowed_raw is not None and not isinstance(allowed_raw, list):
            logger.error("Server command policy from %s: allowed_commands is not a list — keeping current", source)
            return
        if patterns_raw is not None and not isinstance(patterns_raw, list):
            logger.error("Server command policy from %s: dangerous_patterns is not a list — keeping current", source)
            return
        allowed = frozenset(str(c) for c in (allowed_raw or []))
        patterns = frozenset(str(p) for p in patterns_raw) if patterns_raw is not None else None
        sig = (
            preset,
            tuple(sorted(allowed)),
            tuple(sorted(patterns)) if patterns is not None else None,
            str(payload.get("updated_at", "")),
        )
        if sig == self._applied_server_policy_sig:
            return
        # Preset semantics mirror build_command_policy exactly: balanced gets
        # the trusted-path floor; strict enforces the allowlist; permissive
        # skips path checks. A server pattern list REPLACES the built-in
        # defaults (the same authority the local toml has); null keeps them.
        trusted = frozenset(DEFAULT_TRUSTED_PATHS) if preset == "balanced" else frozenset()
        self.command_validator.update_policy(
            CommandPolicy(
                preset=preset,
                allowed_commands=allowed,
                trusted_paths=trusted,
                dangerous_patterns=patterns if patterns is not None else frozenset(DEFAULT_DANGEROUS_PATTERNS),
            )
        )
        self._applied_server_policy_sig = sig
        logger.info(
            "Applied server command policy from %s: preset=%s allowed=%d dangerous=%s",
            source,
            preset,
            len(allowed),
            "custom" if patterns is not None else "built-in-default",
        )

    def _send_heartbeat(self) -> None:
        """Send heartbeat to server.

        POST /api/v1/heartbeat with current cert fingerprint.
        """
        try:
            fingerprint = self.cert_manager.get_fingerprint()
            resp = self.client.post(  # type: ignore[union-attr]
                "/api/v1/heartbeat",
                json={
                    "executor_id": self.state.executor_id,
                    "cert_fingerprint": fingerprint,
                    # Additive wire field (feature/version-surfaces): the
                    # server stores it only when non-empty — old servers
                    # ignore the unknown key (pydantic default), old daemons
                    # simply omit it.
                    "version": _EXECUTOR_VERSION,
                },
                timeout=self.config.network.request_timeout_seconds,
            )
            # The server's revoked flag rides the heartbeat response (ruling 4
            # F3 ride-along — the daemon previously discarded it): a fast
            # cooperative stop between revocation-list polls. Advisory channel:
            # a malformed body never kills the beat; the poll stays the
            # authoritative stop signal. The command-policy payload rides the
            # same advisory discipline (ticket
            # command-policy-no-server-executor-propagation).
            try:
                data = resp.json()
                if data.get("revoked"):
                    logger.warning(
                        "Heartbeat reports this executor REVOKED — shutting down "
                        "(server-side revocation state; identity or current serial "
                        "was revoked — see the revocation list for detail)."
                    )
                    self.state.revoked = True
                self._maybe_apply_server_policy(data, "heartbeat")
            except ValueError:
                pass
        except httpx2.RequestError:
            logger.debug("Heartbeat failed (server unreachable)")

    def _handle_signal(self, signum: int, frame: Any) -> None:
        """Handle shutdown signals."""
        sig_name = signal.Signals(signum).name
        logger.info("Received signal %s — initiating shutdown", sig_name)
        self.state.running = False
        self._shutdown_event.set()

    def stop(self) -> None:
        """Stop the executor daemon."""
        logger.info("Stopping executor daemon")

        for cleanup in (
            self._stop_http_pool,
            self.reaper.stop,
            self.relay.stop,
            self._stop_audit_forwarder,
            self._remove_pidfile,
            self._close_client,
        ):
            try:
                cleanup()
            except Exception:
                logger.exception("Cleanup step failed: %s", cleanup.__name__)

        logger.info("Executor daemon stopped")

    def _stop_http_pool(self) -> None:
        """Stop the HTTP thread pool."""
        self._http_executor.shutdown(wait=True)

    def _stop_audit_forwarder(self) -> None:
        """Drain and join the boot-time spool forwarder (#436). No-op if skipped."""
        if self.audit_boot_forwarder is not None:
            self.audit_boot_forwarder.shutdown()
            logger.info("Audit spool forwarder stopped")

    def _close_client(self) -> None:
        """Close the HTTP client if it exists."""
        if self.client is not None:
            self.client.close()

    def _write_pidfile(self) -> None:
        """Write PID file."""
        pid_file = self.config.pid_file
        os.makedirs(os.path.dirname(pid_file), exist_ok=True)
        with open(pid_file, "w") as f:
            f.write(str(os.getpid()))

    def _remove_pidfile(self) -> None:
        """Remove PID file."""
        pid_file = self.config.pid_file
        try:
            os.unlink(pid_file)
        except FileNotFoundError:
            pass


def _daemonize_detach() -> None:
    """Double-fork + setsid detach for --daemonize (extracted for testability).

    On return, the caller is the grandchild (daemon) process. Every parent
    leg terminates inside this function (sys.exit / os._exit).
    """
    # First fork — detach from parent
    pid = os.fork()
    if pid > 0:
        # Parent — exit
        print(f"Daemon started with PID {pid}")
        sys.exit(0)
    # Child — create new session
    os.setsid()
    # umask 077, NOT 0: umask(0) left every implicit-mode creation (private
    # keys pre-#316, the pid file, the rewritten config) world-writable until
    # an explicit chmod landed — a race window on every boot (ticket
    # executor-daemon-umask0-key-write-window). 077 is the standard daemon
    # umask: new files start owner-only; sites needing a wider mode (certs
    # at 0644) pass it explicitly at create — umask only removes bits.
    os.umask(0o077)

    # Second fork — prevent reacquiring controlling terminal
    pid = os.fork()
    if pid > 0:
        os._exit(0)

    # Change to root directory
    os.chdir("/")

    # Redirect stdin/stdout/stderr to /dev/null
    devnull_fd = os.open(os.devnull, os.O_RDWR)
    os.dup2(devnull_fd, 0)
    os.dup2(devnull_fd, 1)
    os.dup2(devnull_fd, 2)
    if devnull_fd > 2:
        os.close(devnull_fd)


# #647: the shipped ``--log-level`` surface as ONE constant, so the flag and the carriers
# below it cannot advertise different sets of names. The keys are the exact lowercase
# spellings argparse's ``choices`` has always taken, and ``choices=list(_LOG_LEVELS)`` keeps
# the two from drifting apart.
_LOG_LEVELS: dict[str, int] = {
    "debug": logging.DEBUG,
    "info": logging.INFO,
    "warning": logging.WARNING,
    "error": logging.ERROR,
}

#: The level this daemon runs at when a carrier names one it cannot use. Deliberately the
#: same value ``ExecutorConfig.log_level`` defaults to in ``config.py``, so "the built-in
#: default" means one thing across the planes. A cell pins the two against each other.
LOG_LEVEL_DEFAULT = "info"


def resolve_log_level(name: str) -> int | None:
    """Map a configured ``log_level`` name onto a ``logging`` level; None if unusable (#647).

    This guard exists because #647 makes the config-file and environment spellings REACH the
    logger for the first time. Before it the only value that ever got here was argparse's
    own, already constrained by ``choices``, so an unusable name written into
    ``/etc/venya/executor.toml`` was discarded unread and never had to be checked. Honouring
    the file inherits the duty to say what happens when the file is wrong.

    None, rather than a raise, for the same reason: the caller turns it into a WARNING, and
    ``venya-executor.service`` carries ``Restart=always`` — raising here would park a whole
    executor in failed state over a typo in a verbosity knob. Case is NOT folded, because the
    flag refuses ``DEBUG`` today and a carrier that accepted it would make one plane more
    permissive than another, which is how a written value stops working the moment somebody
    moves it.
    """
    return _LOG_LEVELS.get(name)


def _log_precedence_conflicts(config: ExecutorConfig) -> None:
    """Announce every file-versus-environment conflict once, at start (#598).

    Kept as a named function on purpose: main() loads the config before logging exists, and
    the notes have to be emitted after ``basicConfig`` so they arrive through the journal's
    own formatter. Splitting it out is what makes that ordering testable at all — an inline
    loop in ``main()`` cannot be reached without booting the daemon.

    The notes carry no values; see ``executor.config.precedence_conflicts``.
    """
    for note in config.precedence_conflict_notes():
        logger.warning("Config precedence: %s", note)


def _log_cli_level_override(config: ExecutorConfig) -> None:
    """Name the winner the #598 note cannot see, for the one key that has a flag (#647 AC3).

    ``precedence_conflicts`` reports a file-versus-environment contest and states that the
    file won. It is computed in ``ExecutorConfig.from_file``, where the command line does not
    exist — so when an operator ALSO passed ``--log-level``, that note names a value this
    daemon does not run, which is the same false operator-facing statement #598 was opened
    for, one plane up. Correcting it at its source means editing ``config.py``'s template and
    the cells that pin it, outside this leg's fence, so ``main()`` qualifies the note here,
    after it, where the flag is actually known.

    It fires only when a ``log_level`` note was really emitted above. If nothing claimed a
    winner for this key there is nothing to correct, and announcing a contest nobody entered
    is the noise #598's agreement rule already refuses.
    """
    if not any(note.startswith("log_level:") for note in config.precedence_conflict_notes()):
        return
    logger.warning(
        "Config precedence: log_level: --log-level was also given on the command line, so the flag "
        "value is in use and neither the file value nor the environment spelling named above is — "
        "flag > file > env > default (#647)"
    )


def main() -> None:
    """Entry point for venya-executor CLI."""
    import argparse

    parser = argparse.ArgumentParser(description="Venya Executor Daemon")
    parser.add_argument(
        "--version",
        action="version",
        version=f"{_EXECUTOR_VERSION or 'unknown'}",
    )
    parser.add_argument(
        "--config",
        type=str,
        default="/etc/venya/executor.toml",
        help="Path to config file",
    )
    parser.add_argument(
        "--daemonize",
        action="store_true",
        help="Run as daemon (fork to background)",
    )
    parser.add_argument(
        "--log-level",
        choices=list(_LOG_LEVELS),
        # #647: ``None`` means "the operator did not ask", and only that value does. The old
        # ``default="info"`` left this attribute populated on EVERY start, so the override
        # below overwrote the config file with a built-in default nobody passed — and the
        # default is the LAST plane, not a CLI choice. argparse does not check a default
        # against ``choices``, so a value that IS passed is guarded exactly as strictly as it
        # was; nothing about the flag's own door widened.
        default=None,
        help=f"Logging level (default: the value in the config file, else {LOG_LEVEL_DEFAULT})",
    )
    args = parser.parse_args()

    # Load config
    try:
        config = ExecutorConfig.from_file(args.config)
    except FileNotFoundError:
        print(f"Config file not found: {args.config}", file=sys.stderr)
        print("Using defaults (may not work without server connection)", file=sys.stderr)
        config = ExecutorConfig()

    # Apply CLI overrides — only the layer the operator actually asked for. #647: this
    # assignment used to be unconditional, which is the line that made argparse's default
    # outrank the config file a moment after the file was read. ``--daemonize`` below already
    # had the guarded shape (a store_true is only true when passed), so the guard is the
    # house form on this very block, not a new invention. The name is kept because both the
    # logger and the precedence qualifier below need to know whether the flag was given.
    cli_log_level = args.log_level
    if cli_log_level is not None:
        config.log_level = cli_log_level
    if args.daemonize:
        config.daemonize = True

    # Setup logging
    from core.utils.sensitive_log import RedactingFormatter

    # #647: the level is read from the RESOLVED config, not from the argparse namespace — the
    # value the daemon carries and the value the logger runs must be the same one, and a cell
    # that asserted only on ``config.log_level`` would pass green while the logger still read
    # ``args``. An unusable name falls back to the built-in default, says so below (once
    # ``basicConfig`` exists to carry the line through the journal's real formatter), and the
    # config the daemon is handed is corrected to match, so nothing downstream reads a name
    # that is not what is running.
    level_name = config.log_level
    log_level = resolve_log_level(level_name)
    unusable_level = log_level is None
    if unusable_level:
        log_level = _LOG_LEVELS[LOG_LEVEL_DEFAULT]
        config.log_level = LOG_LEVEL_DEFAULT

    logging.basicConfig(
        level=log_level,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )
    for handler in logging.root.handlers:
        handler.setFormatter(RedactingFormatter("%(asctime)s %(levelname)s %(name)s: %(message)s"))

    if unusable_level:
        logger.warning(
            "log_level: %r is not a level this daemon can use, so it runs at %s instead — accepted "
            "names are %s, lowercase, whether the name came from --log-level, the config file, or "
            "VENYA_EXECUTOR_LOG_LEVEL (#647)",
            level_name,
            LOG_LEVEL_DEFAULT,
            ", ".join(_LOG_LEVELS),
        )

    # #598: say it once, loudly, before any work is done. An operator who set a key in the
    # environment while the installer wrote the same key into the file is not making a
    # mistake — it is the ruled order — but it was invisible, and an operator who believes
    # the env spelling took effect is running a configuration they did not choose.
    _log_precedence_conflicts(config)

    # #647 AC3: only when the flag supplied a value, and only if a note above claimed a
    # winner for this key. This is the plane the note's own source cannot see.
    if cli_log_level is not None:
        _log_cli_level_override(config)

    # Create and start daemon
    daemon = ExecutorDaemon(config)

    if config.daemonize:
        _daemonize_detach()

    daemon.start()
