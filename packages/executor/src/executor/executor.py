# Copyright (c) 2026 Tabith LLC.
# Use of this source code is governed by the Business Source License 1.1
# included in the LICENSE file at the root of this repository. As of the
# Change Date listed there, the work is available under MPL 2.0.
# SPDX-License-Identifier: BUSL-1.1

"""Command execution and pipeline orchestration.

Orchestrates the full execution pipeline:
  1. Validate command against policy
  2. Retrieve secrets from server
  3. Stage credentials (SbxStrategy: host tmpfs, copied into the sandbox)
  4. Execute command (direct subprocess OR sandbox)
  5. Capture and filter output (Stage 1 + Stage 2)
  6. Clean up (delete secrets, revoke tokens)
"""

import base64
import contextlib
import errno
import hashlib
import logging
import os
import re
import select
import shlex
import subprocess  # nosec B404 — executor requires subprocess to run commands
import time
import uuid
from collections.abc import Iterable
from dataclasses import dataclass, field
from typing import Any

from .audit import AuditLogger
from .bundles import SecretBundle
from .command_validator import CommandValidator
from .filter import filter_and_redact
from .injector import (
    SentinelRegistry,
    scan_open_fds,
    set_cloexec,
    strip_sentinel,
    verify_fd_whitelist,
)
from .strategies.base import InjectionResult, InjectionStrategy
from .strategies.sbx_strategy import (
    CONTAINER_SECRET_DIR,
    SbxCreateTimeoutError,
    SbxStrategy,
    reap_orphan_sandboxes,
    sbx_command_timeout,
)

logger = logging.getLogger("venya.executor")


@dataclass
class CommandResult:
    """Result of a command execution."""

    command: str
    exit_code: int
    stdout: bytes
    stderr: bytes
    masked_secret_ids: list[str] = field(default_factory=list)
    output_truncated: bool = False
    original_stdout_size: int = 0
    original_stderr_size: int = 0


MAX_OUTPUT_BYTES = 262144  # 256 KB per stream
TRUNCATION_MARKER = "... [OUTPUT TRUNCATED: {n} bytes discarded]\n"


class CommandRejected(ValueError):
    """Pre-run rejection raised by the two gates in ``execute()`` (structural
    + policy) — ticket policy-reject-flat-503 #410. Subclasses ``ValueError``
    so every pre-#410 catcher keeps working; the relay listener maps ONLY
    this class to a 4xx-with-reason lane. Every other engine exception stays
    the flat transport 503: the reason string describes the caller's own
    command, never secret material (both gates run BEFORE injection)."""


def _cap_with_truncation_marker(data: bytes, total_size: int) -> bytes:
    """Single cap+marker idiom for BOTH execution paths (ticket
    sbx-output-silent-truncation #409). When the true produced size exceeds
    the cap, carve the marker out of MAX_OUTPUT_BYTES so a truncated payload
    lands at exactly the cap (the invariant established by ticket
    executor-sbx-truncation-accounting-wrong). Under-cap data is returned
    unchanged — no marker. The direct path applied this inside _capture_output
    only; the sbx path sliced raw, so its clients saw a silent cut."""
    if not data or total_size <= MAX_OUTPUT_BYTES:
        return data
    discarded = max(0, total_size - MAX_OUTPUT_BYTES)
    marker = TRUNCATION_MARKER.format(n=discarded).encode()
    return data[: MAX_OUTPUT_BYTES - len(marker)] + marker


# How long to wait for sandbox commands. #696 AC1: ONE definition, imported from
# the sbx strategy, where the per-command ceiling now lives and where the
# ``VENYA_SBX_TIMEOUT`` override is resolved. It used to be a second bare 3600 in
# this file, and two constants with the same number is how a deployment sets one
# door and still gets the other. Kept as a module name because the direct-path
# bound, the daemon tmp sweep and the existing tests all cite it.

# Cap for the LEGACY direct (subprocess.Popen) path — output capture AND the wait that
# follows it. Ticket direct-path-capture-timeout-untimed-wait #470: the capture
# loop below bounded itself with SBX_TIMEOUT, logged a timeout, and then called
# ``process.wait()`` with NO bound at all, so a child that stopped writing but
# never exited parked the worker forever — the timeout produced a log line,
# not a stop. One constant now bounds both halves, read once per command so a
# deployment (and a unit cell) can shorten it without touching the sandbox
# budget. Override: ``VENYA_DIRECT_PATH_TIMEOUT`` (seconds).
DIRECT_PATH_TIMEOUT_ENV = "VENYA_DIRECT_PATH_TIMEOUT"

# Extra patience for the reaping of a child we terminated ourselves (#470).
# Generous relative to a kill and small relative to the bound it follows.
DIRECT_CHILD_REAP_SECONDS = 5.0


def _mark_cloexec_or_skip_vanished(fd_num: int) -> bool:
    """Mark FD_CLOEXEC on one FD the scan reported, skipping one already closed.

    ``scan_open_fds`` enumerates ``/proc/<pid>/fd`` and the loop below acts on
    those numbers afterwards. A number can stop being an open descriptor in
    that window: the listing's own directory FD appears in its own result and
    ``os.listdir`` closes it before the loop reaches it, and other threads churn
    numbers in flight. On a closed number ``fcntl(F_GETFD)`` raises EBADF, which
    used to escape the middle of an otherwise-healthy command spawn and abort it
    (ticket open-fd-scan-set-cloexec-toctou-ebadf #535).

    A descriptor that is already closed has nothing left to leak into a child,
    so EBADF is a SKIP, not a failure. Every other error is raised unchanged:
    swallowing a blanket ``OSError`` here would silence a genuinely broken mark
    and let the FD through to the child un-marked — the fail-open shape this
    product forbids. An OSError carrying no ``errno`` is therefore also raised.

    ``set_cloexec`` itself keeps its strict contract: an owner of a descriptor
    it expects to be open still learns when it is not.

    Returns:
        True when the flag was set, False when the descriptor had vanished.
    """
    try:
        set_cloexec(fd_num)
    except OSError as exc:
        if exc.errno != errno.EBADF:
            raise
        logger.debug(
            "FD %d closed between the scan and the close-on-exec mark; skipped",
            fd_num,
        )
        return False
    return True


def _close_child_stdin(process: subprocess.Popen) -> None:
    """Close the child's stdin write end (ticket #470 AC2).

    Best-effort by design: an FD that will not close is not worth replacing a
    command outcome, and the bounded wait below is the backstop either way.
    """
    if process.stdin is None:
        return
    try:
        process.stdin.close()
    except OSError:
        logger.exception("Direct path could not close the child stdin pipe")


def _terminate_child_process(process: subprocess.Popen) -> None:
    """Kill a direct-path child that outlived the bound (ticket #470 AC1).

    The child is its own process group (``start_new_session=True``), so the
    group is signalled first: a shell-out grandchild would otherwise keep the
    pipes open and hold the reaping in ``communicate()`` past its own bound.
    Falls back to the plain child kill when the group is already gone.
    """
    try:
        os.killpg(os.getpgid(process.pid), 9)  # nosec B606 — no shell string; a pid we own
    except (ProcessLookupError, PermissionError, OSError):
        try:
            process.kill()
        except OSError:
            logger.exception("Direct path could not terminate child %d", process.pid)


def _direct_path_timeout() -> float:
    """Direct-path capture/wait bound (ticket #470 AC1).

    Same env-override idiom as ``VENYA_SBX_CREATE_TIMEOUT`` in the sbx
    strategy: read at call time so a unit cell can inject a short bound
    instead of waiting out an hour.

    #696 AC1: the fallback is the sbx command ceiling resolver, not the bare
    constant, so ``VENYA_SBX_TIMEOUT`` sets ONE per-command bound for both
    execution paths and a deployment cannot shorten the sandbox hold while a
    legacy-direct command still runs to the hour. ``VENYA_DIRECT_PATH_TIMEOUT``
    stays the more specific override and wins when both are set. With neither
    set the value is the shipped 3600 s, byte-for-byte unchanged.
    """
    raw = os.environ.get(DIRECT_PATH_TIMEOUT_ENV)
    if raw is None or raw == "":
        return sbx_command_timeout()
    try:
        return max(float(raw), 0.0)
    except ValueError:
        logger.warning(
            "%s=%r is not a number — using the %s s default for the direct path",
            DIRECT_PATH_TIMEOUT_ENV,
            raw,
            sbx_command_timeout(),
        )
        return sbx_command_timeout()


# Shell metacharacters that are not permitted in executor commands.
# Enforced PER ELEMENT by `_validate_command_structure` at the top of
# `execute()` — before policy validation and before any strategy dispatch.
# The command crosses the wire as a structured argv list (ticket
# execution-command-wire-unstructured-string #322, ruling Q1=A1), so the gate
# checks every metacharacter INSIDE every argv element — a `|` packed into one
# element can never be misread as a separator. The production sbx path runs
# the validated argv DIRECT (no shell — ticket #322 ruling Q3=C3); the one
# exception is the ruled session-bound `<` redirect case, where the guest
# shell must perform the redirect so the reconstituted string rides `sh -c`.
# Rejection at the gate means these characters never reach any shell. Users
# needing pipes, redirects, or other shell features should provide a script
# file.
# NUL (\x00) joins the set per ticket argv-nul-gate-reject (#333): it is
# never valid in argv (execve contract) — an element carrying it must take
# this audited rejection path, not ride to execve and surface as an opaque
# transport 500 with no command_rejected event.
SHELL_METACHARS = set("\x00|;&$`(){}<>!*?\n\r")


def _redirect_pair(command: list[str], i: int, allowed_redirect_paths: frozenset[str]) -> bool:
    """The ONE shared condition for the ruled session-bound redirect pair
    (secret-shape-sudo-remote option (a), user ruling 2026-09-21): element i is
    EXACTLY ``<`` and element i+1 is EXACTLY a session-bound secret path.

    SINGLE SOURCE (ticket redirect-allowance-neutralized-by-quoting #332):
    the structural gate calls this to decide acceptance, and
    ``render_command`` calls it to re-emit accepted pairs raw — two copies
    of this condition drifting is the second-order bug class, so there is
    exactly one.
    """
    if command[i] != "<":
        return False
    nxt = command[i + 1] if i + 1 < len(command) else None
    return nxt is not None and nxt in allowed_redirect_paths


def _bound_secret_paths(secret_ids: Iterable[str]) -> frozenset[str]:
    """The session-bound allowed-redirect path set for a command's own secret
    ids (ticket secret-shape-sudo-remote option (a)).

    Single source for the in-sandbox secret PATH TEMPLATE (the
    ``CONTAINER_SECRET_DIR`` constant from the sbx strategy — the same
    directory the secrets are copied into): both structural-gate call sites
    (``execute()`` step 1a and the direct-path inner guard) derive their
    allowed set here, from their own secrets/injections, so the two gates can
    compute no decision but the identical ruled one (ticket
    direct-path-inner-guard-drift-trap #374, ruling ALIGN — the #332
    single-source discipline extended from the pair CONDITION to the path
    TEMPLATE).
    """
    return frozenset(f"{CONTAINER_SECRET_DIR}/{secret_id}" for secret_id in secret_ids)


def render_command(command: list[str], allowed_redirect_paths: frozenset[str] = frozenset()) -> str:
    """Reconstitute a gate-validated argv list into the ``sh -c`` payload.

    Every element is ``shlex.quote``'d EXCEPT a redirect pair accepted by the
    shared ``_redirect_pair`` helper: its ``<`` and bound secret path are
    emitted RAW so the guest shell performs a real redirect
    (hunt-wave2 FIND-1: the plain ``shlex.join`` re-quoted the ruled pair into
    inertness, silently killing sudo-remote option (a)). Inputs that contain
    no accepted pair render byte-identically to ``shlex.join`` — the common
    path has zero drift.

    The renderer mirrors the gate's condition, never a broader one: elements
    reach it only after ``_validate_command_structure`` accepted them.
    """
    tokens: list[str] = []
    i = 0
    n = len(command)
    while i < n:
        if _redirect_pair(command, i, allowed_redirect_paths):
            tokens.append(command[i])
            tokens.append(command[i + 1])
            i += 2
        else:
            tokens.append(shlex.quote(command[i]))
            i += 1
    return " ".join(tokens)


def _validate_command_structure(command: list[str], allowed_redirect_paths: frozenset[str] = frozenset()) -> list[str]:
    """Reject shell metacharacters in any argv element (no join, no shlex).

    PER-ELEMENT GATE (ticket execution-command-wire-unstructured-string #322,
    ruling Q2-B1 — resolved-by-consequence of Q1=A1: the wire carries argv, no
    fallback string path exists, so this is the only validation mode). An
    element containing a shell metacharacter is rejected even though the
    sandbox shell would never word-split the reconstituted list around it —
    the 2026-09-16 unconditional-gate ruling is intact, just re-expressed on
    the element list.

    NARROW REDIRECT ALLOWANCE (ticket secret-shape-sudo-remote, option (a),
    user ruling 2026-09-21 — corporate targets almost never grant NOPASSWD
    sudo, so a password must reach remote `sudo -S` over ssh stdin): `<` is
    permitted ONLY as a standalone element immediately followed by an element
    EXACTLY equal to a session-bound secret path (`/run/secrets/venya/<id>`
    for an id in `allowed_redirect_paths`). Every other `<` form (fused `a<b`,
    trailing, unbound target) and every other metacharacter remains rejected.

    Args:
        command: The argv list to validate.
        allowed_redirect_paths: exact secret-file paths bound to this session.

    Returns:
        The validated argv list (identity — kept for the direct-path caller).

    Raises:
        ValueError: If any element contains shell metacharacters or the
            command is empty.
    """
    if not command:
        raise ValueError("Empty command")

    # '<' handled per-element via the shared _redirect_pair helper (standalone
    # + session-bound target only); every other metacharacter keeps the
    # unconditional per-element rejection.
    metachars = SHELL_METACHARS - {"<"}
    for i, elem in enumerate(command):
        # Strict-UTF-8 gate (#334, posture B): a lone surrogate is unencodable,
        # unexecutable-faithfully and unauditable-losslessly. Shares this loop
        # and the ValueError -> command_rejected path with the #333 NUL entry
        # (NUL rides the SHELL_METACHARS set-join; a surrogate is a character
        # CLASS, not a fixed codepoint, so its predicate is the strict-encode
        # probe — one loop, one rejection mechanism, no parallel block). The
        # element value is never echoed. Byte-faithful handling is ticketed
        # for post-beta (#335).
        try:
            elem.encode("utf-8")
        except UnicodeEncodeError:
            raise ValueError(
                f"Argument {i} is not valid strict UTF-8 (a lone surrogate cannot be "
                "executed faithfully or audited losslessly) — command rejected."
            )
        if "<" in elem:
            if elem != "<":
                raise ValueError(
                    "Shell metacharacters are not permitted. "
                    "Wrap complex commands in a script file and execute that instead."
                )
            if not _redirect_pair(command, i, allowed_redirect_paths):
                raise ValueError(
                    "Redirect '<' is only permitted when immediately followed by a "
                    "SESSION-BOUND secret path (/run/secrets/venya/<id> for a secret "
                    "injected in this session). Any other redirect target is rejected."
                )
        if any(c in elem for c in metachars):
            raise ValueError(
                "Shell metacharacters are not permitted. "
                "Wrap complex commands in a script file and execute that instead."
            )

    return list(command)


def _resolve_env_vars(
    env_vars: list[dict[str, Any]] | None,
    injections: list[SecretBundle],
    env_override: dict[str, str] | None,
) -> dict[str, str]:
    """Resolve relay env specs into the final environment mapping.

    ``secret_id`` specs resolve against the unwrapped bundles (the secret MUST
    also be injected, so its fingerprints are registered — an env var is never
    a masking blind spot); ``literal_value`` specs pass verbatim (paths,
    usernames, helper constants). The line-based env-file format rejects
    CR/LF/NUL in values loudly (forged-line defense; NUL entry per
    relay-env-value-nul-ungated — mirrors the argv gate posture). Legacy ``env_override``
    dicts merge underneath (direct-call callers). Ticket
    secret-shape-env-injection.
    """
    env_final = dict(env_override or {})
    for spec in env_vars or []:
        name = spec.get("var_name")
        if not isinstance(name, str) or not name:
            raise ValueError(f"env spec missing var_name: {spec!r}")
        sid = spec.get("secret_id")
        if sid is not None:
            bundle = next((b for b in injections if str(b.secret_id) == str(sid)), None)
            if bundle is None:
                raise ValueError(f"env var {name}: secret_id {sid} is not among the session's injected secrets")
            try:
                value = bundle.value.decode("utf-8")
            except UnicodeDecodeError as exc:
                raise ValueError(
                    f"env var {name}: secret value is not valid UTF-8 — env shapes require text values"
                ) from exc
        else:
            value = spec.get("literal_value") or ""
        if "\n" in value or "\r" in value or "\x00" in value:
            raise ValueError(
                f"env var {name}: value contains a newline or NUL — the env-file format is line-based; "
                "use a file shape for multi-line credentials"
            )
        env_final[name] = value
    return env_final


@dataclass
class Executor:
    """Main executor — orchestrates command execution pipeline.

    Uses Docker Sandboxes (sbx) microVM with tmpfs-mounted secrets
    and policy-based network access.

    NOTE: Executor processes commands sequentially. The _injection_result
    field is per-execution state that assumes one active command at a time.
    """

    command_validator: CommandValidator
    session_id: str
    injection_strategy: InjectionStrategy = field(default_factory=SbxStrategy)
    allowed_fds: set[int] = field(default_factory=lambda: {0, 1, 2})
    audit_logger: AuditLogger | None = None
    _sentinel_registry: SentinelRegistry | None = None
    http_client: Any = None  # httpx2.Client for server API calls
    config: Any = None  # ExecutorConfig for timeout access
    _injection_result: InjectionResult | None = field(init=False, default=None)
    _bundles: list[SecretBundle] = field(init=False, default_factory=list)
    _closed: bool = field(init=False, default=False)

    def __post_init__(self) -> None:
        """Validate the injection strategy before first use."""
        self.injection_strategy.validate()

    @property
    def sentinel_registry(self) -> SentinelRegistry:
        """Lazy-init sentinel registry for this session."""
        if self._sentinel_registry is None:
            self._sentinel_registry = SentinelRegistry(session_id=self.session_id)
        return self._sentinel_registry

    def close(self) -> None:
        """Tear down everything this session owns (ticket #467).

        ``AuditLogger.__init__`` starts a 1 s-poll forwarder thread, and before
        this hook existed only the BOOT instance was ever shut down — so every
        command session leaked a live thread plus its spool handles for the
        whole life of the daemon. The object that owns the logger is the
        Executor, so the teardown lives here.

        ``AuditLogger.shutdown()`` keeps the ruled per-session drain (ticket
        #436): it performs a bounded final forward before stopping, so durable
        spool contents are not dropped by closing. It is also idempotent, and
        so is this method — a caller that closes twice gets one shutdown and
        no error.
        """
        if self._closed:
            return
        self._closed = True
        if self.audit_logger is not None:
            self.audit_logger.shutdown()

    def __del__(self) -> None:
        """Last-resort guard for a session that was never closed (ticket #467).

        The deterministic path is ``close()`` from the code that ends the
        session; this only exists so a dropped Executor cannot leak the
        forwarder thread as well. It must never raise — interpreter shutdown
        hands us partially torn-down state.
        """
        with contextlib.suppress(Exception):
            self.close()

    def execute(
        self,
        command: list[str],
        secrets: list[dict[str, Any]],
        env_override: dict[str, str] | None = None,
        cwd: str | None = None,
        env_vars: list[dict[str, Any]] | None = None,
        askpass_helper: bool = False,
    ) -> CommandResult:
        """Execute a command with secret injection and output filtering.

        Args:
            command: The command argv list to execute (ticket #322: the wire
                carries structured argv; no string path exists).
            secrets: List of secret dicts with 'secret_id', 'value', 'wrapped_value'.
            env_override: Environment variables to set (not for secrets).
            cwd: Working directory for the command.
            env_vars: Relay env specs (ticket secret-shape-env-injection):
                dicts with 'var_name' plus exactly one of 'secret_id' (resolved
                against the injected bundles) or 'literal_value'.
            askpass_helper: Write the static askpass helper into the sandbox
                (ticket secret-shape-askpass-helpers).

        Returns:
            CommandResult with exit code, filtered output, and audit data.
        """
        # Step 1a: STRUCTURAL gate — unconditional whole-string invariant
        # (ticket executor-sbx-skips-shell-metachar-validation, solution A,
        # ruled 2026-09-16). Runs BEFORE the policy gate because: policy is
        # admin-configurable (`permissive` returns True early) and nothing
        # config-dependent may sit in front of the non-negotiable check;
        # cheapest-first (char scan before shlex/PATH work); and the policy
        # layer's `_split_local_remote` shlex-parses, so structure-first
        # guarantees it receives parseable input.
        # ACCEPTED TRADEOFF (ruled, recorded in the ticket + plan-9 tracker
        # Deviations row 6; re-expressed per-element by ticket #322 Q2-B1):
        # metachars inside a single argument (e.g. `echo` + arg `a; b`) are
        # rejected although the reconstituted shell string would keep them
        # quote-safe — quote-scoped parsing cannot soundly distinguish local
        # vs remote interpretation here; the sandbox shell sees the whole
        # string. Shell features must use the script-file path.
        # Session-bound secret paths are the ONLY legal redirect targets
        # (ticket secret-shape-sudo-remote option (a)); the path template is
        # derived via the shared helper (#374).
        allowed_redirects = _bound_secret_paths(s["secret_id"] for s in secrets if "secret_id" in s)
        try:
            _validate_command_structure(command, allowed_redirects)
        except ValueError as exc:
            if self.audit_logger:
                self.audit_logger.emit("command_rejected", command=shlex.join(command), reason=str(exc))
            raise CommandRejected(f"Command rejected: {exc}") from None

        # EXECUTION POSTURE (ticket #322 ruling Q3=C3, owner 2026-10-02; fleet
        # C5 probe grounded): the common case runs the VALIDATED ARGV LIST
        # DIRECT in the sandbox (no shell — boundaries are the list's, nothing
        # re-parses them, mirroring the direct path's shell=False posture). The
        # ONE exception is a command carrying the ruled session-bound redirect
        # pair: the guest shell must perform the redirect, so that case keeps
        # the rendered string through `sh -c`. render_command quotes every
        # element exactly like shlex.join EXCEPT the accepted pair, which it
        # re-emits RAW (ticket redirect-allowance-neutralized-by-quoting #332:
        # the plain shlex.join quoted the pair into inertness, silently killing
        # sudo-remote option (a) since the #319 quoting fix). The rendered
        # string is also the policy-gate input and the audit/display form in
        # BOTH postures — byte-identical to shlex.join when no pair is present.
        has_redirect_pair = any(_redirect_pair(command, i, allowed_redirects) for i in range(len(command)))
        command_str = render_command(command, allowed_redirects)

        # Step 1b: POLICY gate — dangerous patterns / preset checks (string-
        # typed throughout; sees the rendered form, same bytes as today).
        is_valid, reason = self.command_validator.validate(command_str)
        if not is_valid:
            if self.audit_logger:
                self.audit_logger.emit("command_rejected", command=command_str, reason=reason)
            raise CommandRejected(f"Command rejected: {reason}")

        logger.info("Executing command: %s", command_str)
        start_time = time.time()

        # Step 2: Prepare secret injections
        injections: list[SecretBundle] = []
        try:
            injections = self._prepare_injections(secrets)

            # Resolve env-var specs (ticket secret-shape-env-injection):
            # secret_id -> unwrapped bundle value; literal_value -> verbatim.
            # Resolution happens HERE (not in the relay listener) because
            # plaintext values only exist on the bundles after
            # _prepare_injections.
            env_final = _resolve_env_vars(env_vars, injections, env_override)

            # Audit: credential_injected (env var NAMES only — never values)
            if self.audit_logger:
                audit_data = {
                    "command": command_str,
                    "strategy": self.injection_strategy.name(),
                    "fd_count": len(injections),
                    "secret_ids": [s.secret_id for s in injections],
                    "env_vars": sorted(env_final),
                }
                self.audit_logger.emit("credential_injected", **audit_data)

            # Step 3: Execute with injected secrets (sbx only). argv is handed
            # to the guest DIRECT unless the ruled `<` pair needs the shell.
            result = self._run_command_sbx(
                command_str,
                injections,
                env_final or None,
                cwd,
                askpass_helper=askpass_helper,
                argv=None if has_redirect_pair else command,
            )

            # Audit: command_executed
            if self.audit_logger:
                duration_ms = (time.time() - start_time) * 1000
                self.audit_logger.emit(
                    "command_executed",
                    command=command_str,
                    exit_code=result.exit_code,
                    duration_ms=round(duration_ms, 2),
                )

            return result

        finally:
            # Step 4: Cleanup (always runs)
            secret_ids = [s.secret_id for s in injections]
            self._cleanup_injections()
            self.revoke_tokens(secret_ids)

    def _prepare_injections(self, secrets: list[dict[str, Any]]) -> list[SecretBundle]:
        """Prepare secret injections for all provided secrets.

        Strips sentinels, registers hashes, builds SecretBundles,
        then delegates actual injection to the strategy.

        Args:
            secrets: List of secret dicts.

        Returns:
            List of SecretBundle objects.
        """
        self._bundles = []

        for secret in secrets:
            # DB secret PKs are Integer and arrive via the relay payload as
            # JSON ints; the engine contract is str everywhere downstream
            # (SecretBundle, Stage-1 Rust filter, revoke) — normalize at the
            # API boundary. An int leaking through raised
            # TypeError: 'int' object cannot be converted to 'PyString' in
            # the filter (seen in physical e2e 2026-09-03).
            secret_id = str(secret["secret_id"])
            wrapped_value = secret.get("wrapped_value", b"")

            # Strip sentinel to get plaintext
            plaintext = strip_sentinel(wrapped_value) if wrapped_value else secret.get("value", b"")

            # Parse sentinel hash for registry
            sentinel_hash = ""
            if wrapped_value:
                match = None
                for m in re.finditer(rb"\[VENYA:([a-f0-9]{8})\]", wrapped_value):
                    match = m
                    break
                if match:
                    sentinel_hash = match.group(1).decode()
                    self.sentinel_registry.register(secret_id, sentinel_hash)

            bundle = SecretBundle(
                secret_id=secret_id,
                value=plaintext,
                wrapped_value=wrapped_value,
                hash=hashlib.sha256(plaintext).hexdigest(),
            )
            self._bundles.append(bundle)

        # Delegate actual injection to strategy
        self._injection_result = self.injection_strategy.prepare(self._bundles, self.session_id)
        logger.info(
            "Injected %d secrets via strategy '%s'",
            len(self._bundles),
            self.injection_strategy.name(),
        )

        return self._bundles

    # ================================================================
    # DIRECT EXECUTION (legacy direct path: argv straight to Popen)
    # ================================================================

    def _run_command_direct(
        self,
        command: list[str],
        injections: list[SecretBundle],
        env_override: dict[str, str] | None,
        cwd: str | None,
    ) -> CommandResult:
        """Run command directly via subprocess.Popen — the legacy direct path.

        Reached only by direct calls (tests): the product pipeline goes through
        _run_command_sbx (factory.py ships SbxStrategy as the sole strategy, and
        since #471 nothing here stages a secret through a file descriptor). Kept
        for backwards compat.
        Takes the argv list and runs it shell=False (ticket #322: the engine
        boundary is argv-structured end to end; this path was already
        argv-exact after shlex.split — the split moved to the wire).
        """
        # Build process environment
        env = os.environ.copy()
        if env_override:
            env.update(env_override)

        # Determine FDs to pass to child process
        pass_fds: set[int] = set()
        if self._injection_result:
            pass_fds.update(self._injection_result.extra_fds)

        # Validate command structure (rejects shell metacharacters).
        # REDUNDANT with execute() step 1a's gate — kept deliberately:
        # the refactor-5 guardrail that locked the two paths apart is OVERTURNED
        # (owner ruling 2026-10-10 via dispatch 9-0b3405, #471: the dead
        # inject_via_* set was deleted under that grant), and this path is not
        # the product path — so the guard stays because divergence is still the
        # thing #374 ruled out, not because a lock is left standing. ALIGNED to the
        # ruled posture per ticket direct-path-inner-guard-drift-trap #374
        # (ruling ALIGN): the allowed set comes from this path's own
        # injections through the SAME helper execute() uses, so a bound-pair
        # argv (inert data under shell=False) is accepted here exactly when
        # the ruled gate accepts it — the redundancy stays fail-closed.
        args = _validate_command_structure(command, _bound_secret_paths(b.secret_id for b in injections))

        # Create subprocess — shell=False for security
        process = subprocess.Popen(
            args,
            shell=False,  # nosec B603 — shell explicitly disabled for security
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=env,
            cwd=cwd,
            start_new_session=True,
            pass_fds=pass_fds,
        )

        # Set CLOEXEC on all executor FDs to prevent leakage
        proc_fds: set[int] = {
            process.stdin.fileno() if process.stdin else -1,  # type: ignore[union-attr]
            process.stdout.fileno() if process.stdout else -1,  # type: ignore[union-attr]
            process.stderr.fileno() if process.stderr else -1,  # type: ignore[union-attr]
        }
        proc_fds.discard(-1)
        allowed = {0, 1, 2} | proc_fds
        scanned_fds = scan_open_fds()
        if scanned_fds is None:
            logger.warning(
                "FD scan unavailable (unreadable /proc); set_cloexec pass skipped",
            )
        else:
            for fd_num in scanned_fds:
                if fd_num not in allowed:
                    _mark_cloexec_or_skip_vanished(fd_num)

        # Verify FD whitelist
        open_fds = scan_open_fds()
        if open_fds is None:
            logger.warning(
                "FD whitelist verification SKIPPED (indeterminate: unreadable /proc); " "cannot confirm clean",
            )
        else:
            unexpected = verify_fd_whitelist(open_fds, self.allowed_fds)
            if unexpected:
                logger.warning("Unexpected open FDs before exec: %s", unexpected)

        # stdin is dropped HERE — after the FD bookkeeping above (its number is
        # in the allow-set while it is still ours) and before anything waits on
        # the child (ticket #470 AC2). Nothing on this path ever writes to it,
        # so a parent still holding the write end means a child that reads stdin
        # to EOF before exiting blocks forever on a pipe that will never
        # deliver — the deadlock the row names. Closing it hands the child its
        # EOF. The close is best-effort: an fd that will not close is not worth
        # replacing a command outcome, and the bound below is the backstop.
        _close_child_stdin(process)

        # Capture output with size limit, then wait for the process — BOTH
        # inside ONE bound (ticket #470 AC1). Pre-fix the capture loop bounded
        # itself, logged, broke, and the ``process.wait()`` that followed had no
        # bound at all: the timeout produced a log line, not a stop.
        bound = _direct_path_timeout()
        capture_deadline = time.time() + bound
        stdout, stderr, stdout_total, stderr_total = self._capture_output(process, deadline=capture_deadline)

        try:
            exit_code = process.wait(timeout=max(capture_deadline - time.time(), 0.0))
        except subprocess.TimeoutExpired:
            # The bound expired with the child still alive. Killing it is the
            # whole point of the bound; ``communicate()`` then reaps it and
            # drains the pipes (a bare wait() could sit in a zombie loop).
            logger.error("Direct-path child %d did not exit within %s s — terminating it", process.pid, bound)
            _terminate_child_process(process)
            try:
                process.communicate(timeout=DIRECT_CHILD_REAP_SECONDS)
            except subprocess.TimeoutExpired:
                logger.error(
                    "Direct-path child %d still unaccounted for after terminate — exit code reported as -1",
                    process.pid,
                )
                exit_code = -1
            else:
                # ``poll()`` is non-blocking; the reaped child reports its code.
                exit_code = process.returncode if process.returncode is not None else -1

        return self._filter_and_build_result(
            shlex.join(command),  # response-side display stays a string (#322)
            exit_code,
            stdout,
            stderr,
            injections,
            original_stdout_size=stdout_total,
            original_stderr_size=stderr_total,
        )

    def _capture_output(
        self, process: subprocess.Popen, deadline: float | None = None
    ) -> tuple[bytes, bytes, int, int]:
        """Capture stdout/stderr with batch mode and size limit.

        Args:
            process: The subprocess to capture from.
            deadline: Absolute ``time.time()`` bound for the capture loop
                (ticket #470). None derives it from the module bound, so a
                direct caller keeps today's behavior; the direct path passes
                the SAME deadline its ``wait`` uses, so capture and wait cannot
                each grant a fresh budget.

        Returns:
            Tuple of (stdout, stderr, stdout_total, stderr_total). The
            payloads are truncated if needed; the totals are the true
            observed byte counts BEFORE truncation, so callers can report
            accurate truncation metadata.
        """
        stdout_truncated = False
        stderr_truncated = False
        stdout_total = 0
        stderr_total = 0
        deadline = time.time() + _direct_path_timeout() if deadline is None else deadline

        stdout_fd = process.stdout  # type: ignore[union-attr]
        stderr_fd = process.stderr  # type: ignore[union-attr]

        if stdout_fd is None or stderr_fd is None:
            # Bounded too (#470): an unwaited process here would park the caller
            # exactly like the unbounded wait did. The caller's deadline is the
            # right bound — capture never gets a fresh budget.
            try:
                process.wait(timeout=max(deadline - time.time(), 0.0))
            except subprocess.TimeoutExpired:
                logger.error("Direct-path child %d did not exit — terminating it", process.pid)
                _terminate_child_process(process)
            return b"", b"", 0, 0

        fd_map = {stdout_fd.fileno(): "stdout", stderr_fd.fileno(): "stderr"}
        chunk_buffers: dict[int, bytearray] = {
            stdout_fd.fileno(): bytearray(),
            stderr_fd.fileno(): bytearray(),
        }
        fd_active: dict[int, bool] = {stdout_fd.fileno(): True, stderr_fd.fileno(): True}

        bound = max(deadline - time.time(), 0.0)

        while any(fd_active.values()):
            if time.time() > deadline:
                logger.warning("Output capture reached its %s second bound", bound)
                break

            readable_fds = [fd for fd, active in fd_active.items() if active]
            if not readable_fds:
                break

            try:
                readable, _, _ = select.select(readable_fds, [], [], 1.0)
            except OSError:
                break

            if not readable:
                # Timeout — check if process is still running
                if process.poll() is not None:
                    break
                continue

            for fd in readable:
                try:
                    chunk = os.read(fd, 65536)
                except OSError:
                    fd_active[fd] = False
                    continue

                if not chunk:
                    # EOF
                    fd_active[fd] = False
                    continue

                buf = chunk_buffers[fd]
                stream_name = fd_map[fd]

                if stream_name == "stdout":
                    stdout_total += len(chunk)
                else:
                    stderr_total += len(chunk)

                if len(buf) + len(chunk) > MAX_OUTPUT_BYTES:
                    remaining = MAX_OUTPUT_BYTES - len(buf)
                    if remaining > 0:
                        buf.extend(chunk[:remaining])
                    if stream_name == "stdout":
                        stdout_truncated = True
                    else:
                        stderr_truncated = True
                    fd_active[fd] = False
                else:
                    buf.extend(chunk)

        stdout = bytes(chunk_buffers[stdout_fd.fileno()])
        stderr = bytes(chunk_buffers[stderr_fd.fileno()])

        # Apply truncation markers. The marker's own bytes are carved out of
        # the cap, so a truncated payload is exactly MAX_OUTPUT_BYTES long —
        # the invariant "truncated ⇒ len == cap" is stable for downstream
        # checks (ticket executor-sbx-truncation-accounting-wrong, issue 3).
        # Shared idiom with the sbx path via _cap_with_truncation_marker
        # (ticket sbx-output-silent-truncation #409).
        if stdout_truncated and stdout:
            stdout = _cap_with_truncation_marker(stdout, stdout_total)
        if stderr_truncated and stderr:
            stderr = _cap_with_truncation_marker(stderr, stderr_total)

        return stdout, stderr, stdout_total, stderr_total

    # ================================================================
    # SBX SANDBOX EXECUTION
    # ================================================================

    def _run_command_sbx(
        self,
        command: str,
        injections: list[SecretBundle],
        env_override: dict[str, str] | None,
        cwd: str | None,
        askpass_helper: bool = False,
        argv: list[str] | None = None,
    ) -> CommandResult:
        """Run command inside a Docker Sandbox (microVM).

        ``argv`` (ticket #322 ruling Q3=C3): when not None, the guest runs
        these tokens DIRECT (no shell). ``command`` then stays the display/
        audit string only. None keeps the ``sh -c`` posture — used solely for
        the ruled session-bound ``<`` redirect case, where the guest shell
        must perform the redirect.

        Key security properties:
        - Network egress controlled by allowlist file via sbx policy
        - Secrets are copied into sandbox via sbx cp (tmpfs-backed)
        - Sandbox provides hypervisor isolation (separate kernel)
        - stdout/stderr captured from sbx exec output

        Args:
            command: The command to execute inside the sandbox.
            injections: Secret bundles (for filtering reference).
            env_override: Environment variables to set — injected per command
                via `sbx exec -e K=V` argv tokens (values are data, never
                shell-parsed). Previously dropped on this path (ticket
                executor-env-override-cwd-sbx-noop).
            cwd: Working directory — used twice, coherently: as the sandbox
                workspace mount at create time AND as the per-command
                working directory (`sbx exec -w`). None keeps the strategy's
                per-run workspace default for both.

        Returns:
            CommandResult with filtered output.
        """
        if not isinstance(self.injection_strategy, SbxStrategy):
            raise TypeError(f"SBX strategy required but got: {type(self.injection_strategy).__name__}")

        strategy = self.injection_strategy
        session_uuid = uuid.uuid4().hex[:12]
        sandbox_name = f"venya-{self.session_id}-{session_uuid}"

        # Ticket executor-sandbox-setup-orphans-live-vm (#406): the guarded
        # region starts BEFORE create so any setup raise (create/copy-secrets/
        # askpass/egress-policy) still routes through the remove_sandbox
        # finally — no secrets-bearing orphan VM survives a setup failure.
        try:
            # Create the sandbox. When cwd is None the strategy creates a
            # per-run disk-backed workspace (a missing path makes sbx create
            # prompt and fail with "user cancelled operation" in a non-TTY
            # subprocess).
            logger.info("Creating Docker Sandbox: %s", sandbox_name)
            strategy.create_sandbox(sandbox_name, cwd, session_id=self.session_id)

            # Copy secrets into sandbox
            if self._injection_result:
                strategy.copy_secrets_into_sandbox(self._injection_result.secret_mounts)

            # Askpass helper (ticket secret-shape-askpass-helpers): static 0555
            # script git/ssh invoke; it reads the credential file at run time.
            # Written AFTER the secrets (it references their in-sandbox paths).
            if askpass_helper:
                strategy.write_askpass_helper()

            # Apply network policy from allowlist file
            strategy.apply_network_policy(sandbox_name)

            # Execute command inside sandbox
            logger.info("Executing in sandbox: %s", command)
            result = strategy.execute_command(command, env_override=env_override, cwd=cwd, argv=argv)

            # Record true pre-slice sizes BEFORE capping — truncation
            # metadata must describe the real output, not the sliced copy
            # (ticket executor-sbx-truncation-accounting-wrong). The cap is
            # applied with the same in-band TRUNCATION_MARKER idiom the direct
            # path uses, so a cut is visible to server and client alike
            # (ticket sbx-output-silent-truncation #409).
            original_stdout_size = len(result.stdout)
            original_stderr_size = len(result.stderr)
            stdout = _cap_with_truncation_marker(result.stdout, original_stdout_size)
            stderr = _cap_with_truncation_marker(result.stderr, original_stderr_size)

            logger.info(
                "Sandbox command exited: code=%d, stdout=%d bytes, stderr=%d bytes",
                result.returncode,
                len(stdout),
                len(stderr),
            )

            # Stage 1 + Stage 2 filtering (same as direct path)
            return self._filter_and_build_result(
                command,
                result.returncode,
                stdout,
                stderr,
                injections,
                original_stdout_size=original_stdout_size,
                original_stderr_size=original_stderr_size,
            )

        except subprocess.TimeoutExpired as exc:
            # #639: name the stage that actually timed out, and the bound IT carried. This
            # lane used to print "Command timed out after 3600 seconds" for ANY
            # TimeoutExpired in the guarded region — including a create that hung under
            # SBX_CREATE_TIMEOUT (240 s) or VENYA_SBX_CREATE_TIMEOUT — because the guarded
            # region starts BEFORE create (#406) and the create site raised the bare
            # exception. The strategy now raises the named SbxCreateTimeoutError with the
            # real value on it, so the operator can tell a hung create from a hung command
            # and reads a number that is the bound that fired, not a constant.
            if isinstance(exc, SbxCreateTimeoutError):
                logger.error("Sandbox CREATE timed out after %s seconds", exc.timeout)
                timed_out = f"Sandbox create timed out after {exc.timeout} seconds"
            else:
                logger.error("Sandbox command timed out after %s seconds", exc.timeout)
                timed_out = f"Sandbox command timed out after {exc.timeout} seconds"
            return CommandResult(
                command=command,
                exit_code=-1,
                stdout=b"",
                stderr=timed_out.encode(),
            )
        except Exception:
            logger.exception("Sandbox execution failed")
            raise
        finally:
            # Always remove the sandbox. A teardown raise (subprocess-level:
            # timeout, missing sbx binary) must never REPLACE the in-flight
            # origin exception (ticket sandbox-teardown-finally-raise-masks-
            # origin-error #417): swallow it and log, naming the sandbox.
            #
            # #474 adds the reaper behind the swallow — the row was always
            # about the residue the ruled swallow leaves. A failed ``sbx rm``
            # (raise OR non-zero exit) means a secrets-bearing microVM is
            # still live, so the same except branch runs the bounded reap
            # pass; a clean removal collects nothing. Neither case may mask
            # the origin outcome, and #417's log line is unchanged. The
            # isinstance half keeps a stand-in strategy that hands back a
            # non-integer (a bare mock) from reading as "teardown failed".
            try:
                teardown_rc = strategy.remove_sandbox()
            except Exception:
                logger.warning("Sandbox teardown failed for %s; origin outcome preserved", sandbox_name, exc_info=True)
                reap_orphan_sandboxes()
            else:
                if isinstance(teardown_rc, int) and teardown_rc != 0:
                    logger.warning("Sandbox teardown returned %d for %s; arming the reaper", teardown_rc, sandbox_name)
                    reap_orphan_sandboxes()

    # ================================================================
    # SHARED FILTERING (used by both execution paths)
    # ================================================================

    def _filter_and_build_result(
        self,
        command: str,
        exit_code: int,
        stdout: bytes,
        stderr: bytes,
        injections: list[SecretBundle],
        original_stdout_size: int | None = None,
        original_stderr_size: int | None = None,
    ) -> CommandResult:
        """Run Stage 1 + Stage 2 filtering and build CommandResult.

        This is the shared post-processing path for both direct subprocess
        and sandbox execution. The filtering logic is identical
        regardless of how the process was launched.

        Args:
            command: Original command string.
            exit_code: Process exit code.
            stdout: Raw stdout bytes (already capped by the caller).
            stderr: Raw stderr bytes (already capped by the caller).
            injections: Secret bundles for filtering reference.
            original_stdout_size: True pre-truncation stdout byte count.
                None falls back to len(stdout) (uncapped callers).
            original_stderr_size: True pre-truncation stderr byte count.
                None falls back to len(stderr) (uncapped callers).

        Returns:
            CommandResult with filtered output.
        """
        # Stage 1: Local filtering (Rust extension) — needs raw value for matching
        masked_stdout, masked_stderr, stdout_ids, stderr_ids = filter_and_redact(
            stdout,
            stderr,
            [{"secret_id": s.secret_id, "value": s.value} for s in injections],
        )

        all_masked_ids = sorted(set(stdout_ids + stderr_ids))

        # Stage 2: Server-side definitive filtering
        stage2_stdout = masked_stdout
        stage2_stderr = masked_stderr
        stage2_masked_ids = all_masked_ids

        if self.http_client is not None:
            try:
                stage2_stdout, stage2_stderr, stage2_masked_ids = self._send_to_stage2(
                    stdout,
                    stderr,
                )
            except Exception:
                logger.exception("Stage 2 filter failed — using Stage 1 results")

        # Truncation metadata derives from the TRUE pre-slice sizes, never
        # from the already-capped payload (which would always compare ≤ cap).
        if original_stdout_size is None:
            original_stdout_size = len(stdout)
        if original_stderr_size is None:
            original_stderr_size = len(stderr)
        stdout_truncated = original_stdout_size > MAX_OUTPUT_BYTES
        stderr_truncated = original_stderr_size > MAX_OUTPUT_BYTES

        logger.info(
            "Command exited with code %d, %d secrets masked",
            exit_code,
            len(stage2_masked_ids),
        )

        return CommandResult(
            command=command,
            exit_code=exit_code,
            stdout=stage2_stdout,
            stderr=stage2_stderr,
            masked_secret_ids=stage2_masked_ids,
            output_truncated=stdout_truncated or stderr_truncated,
            original_stdout_size=original_stdout_size,
            original_stderr_size=original_stderr_size,
        )

    # ================================================================
    # CLEANUP (unchanged)
    # ================================================================

    def _cleanup_injections(self) -> None:
        """Clean up all secret injections.

        Runs strategy cleanup functions, zeros secret values, clears registry.
        A failed destroy is reported as a degraded teardown: it never aborts the
        rest of the cleanup, and it never changes how the run ends.

        The completion INFO is emitted only when every destroy step succeeded.
        Printing "Cleanup complete" while secret material is still resident
        would say the opposite of what happened on the one surface an operator
        reads. On the degraded path there is no completion line at all: the
        WARNING above already names the failed steps, their count and the
        resident resources, so no second summary line is invented to replace it
        (lead ruling, #456 follow-up).
        """
        degraded = False
        if self._injection_result:
            failures = self._injection_result.cleanup()
            if failures:
                degraded = True
                logger.warning(
                    "Secret cleanup degraded: %d of %d destroy step(s) failed; secret material may still be resident — held by this result: %s (%s)",
                    len(failures),
                    len(self._injection_result.cleanup_funcs),
                    self._injection_result.resident_resources(),
                    "; ".join(f"{f.label} -> {f.error}" for f in failures),
                )
            self._injection_result = None

        # Zero secret values in all bundles
        for bundle in self._bundles:
            if bundle.value:
                bundle.value = b"\x00" * len(bundle.value)

        # Clear sentinel registry for this session
        if self._sentinel_registry:
            self._sentinel_registry.clear()

        if not degraded:
            logger.info("Cleanup complete")

    def revoke_tokens(self, secret_ids: list[str]) -> None:
        """Revoke tokens for given secrets.

        Called after execution to revoke short-lived scoped credentials.

        Args:
            secret_ids: List of secret IDs to revoke.
        """
        if not secret_ids:
            return

        if self.http_client is None:
            logger.warning(
                "No HTTP client available — skipping server token revocation for %d secrets",
                len(secret_ids),
            )
            return

        try:
            timeout = self.config.network.request_timeout_seconds if self.config else 10
            self.http_client.post(
                f"/api/v1/sessions/{self.session_id}/secrets/revoke",
                json={"secret_ids": secret_ids},
                timeout=timeout,
            )
            logger.info(
                "Revoked tokens for %d secrets in session %s",
                len(secret_ids),
                self.session_id,
            )
        except Exception:
            logger.exception(
                "Failed to revoke tokens for secrets in session %s",
                self.session_id,
            )
            if self.audit_logger:
                self.audit_logger.emit(
                    "token_revocation_failed",
                    session_id=self.session_id,
                    secret_ids=secret_ids,
                )

    def _send_to_stage2(
        self,
        stdout: bytes,
        stderr: bytes,
    ) -> tuple[bytes, bytes, list[str]]:
        """Send captured output to Stage 2 server-side filter.

        SIGN-OFF INVARIANT (ticket executor-stage2-plaintext-signoff, ruling
        2026-09-20): the body carries plaintext-equivalent (base64) UNFILTERED
        command output BY DESIGN — Stage-2 is the definitive filter and must
        see pre-Stage-1 bytes to be authoritative over Stage-1 misses.
        Transport protection is mutual mTLS only; the body must NEVER be
        logged on either side. Any future logger touching request/response
        bodies at this hop is a REGRESSION.

        No secret material is sent: the former `secrets` field (ids + sha256
        hashes) was dead wire — the server's FilterRequest never declared it
        and the handler reconstructs plaintext from its own DB via KEK.

        Args:
            stdout: Raw stdout bytes.
            stderr: Raw stderr bytes.

        Returns:
            Tuple of (filtered_stdout, filtered_stderr, masked_secret_ids).

        Raises:
            Exception: If server communication fails.
        """
        payload = {
            "stdout": base64.b64encode(stdout).decode(),
            "stderr": base64.b64encode(stderr).decode(),
        }

        timeout = self.config.network.request_timeout_seconds if self.config else 30
        response = self.http_client.post(
            f"/api/v1/sessions/{self.session_id}/filter",
            json=payload,
            timeout=timeout,
        )
        if response.status_code != 200:
            # Explicit fail-closed (ticket stage2-filter-unknown-session-
            # unmasked-passthrough): a 404 means the server has NO knowledge of
            # this session (unknown or TTL-reaped mid-run) — the caller keeps
            # the Stage-1 masked results instead of adopting an empty-knowledge
            # passthrough. Named RuntimeError, not an accidental KeyError.
            raise RuntimeError(f"Stage-2 filter returned {response.status_code}")
        data = response.json()

        filtered_stdout = base64.b64decode(data["stdout"])
        filtered_stderr = base64.b64decode(data["stderr"])
        masked_ids = sorted(set(data.get("masked_hashes", [])))

        return filtered_stdout, filtered_stderr, masked_ids
