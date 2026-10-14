# Copyright (c) 2026 Tabith LLC.
# Use of this source code is governed by the Business Source License 1.1
# included in the LICENSE file at the root of this repository. As of the
# Change Date listed there, the work is available under MPL 2.0.
# SPDX-License-Identifier: BUSL-1.1

"""Executor configuration.

Loaded from environment variables and/or config file.
Environment variables are prefixed with VENYA_EXECUTOR_.

Precedence, ruled 2026-10-13 (#598): the config FILE wins, then the ENVIRONMENT spelling,
then the field default — `file > env > default`. ``ExecutorConfig.from_file`` is where that
is decided, because passing the parsed TOML as explicit init arguments is what puts the file
above the environment in pydantic-settings' own order. The direction is not the defect that
was filed; the silence was. A key carried by both spellings is now announced at every start
(``precedence_conflicts``), naming the key, the two sources and which one won.
"""

import os
from collections.abc import Mapping
from pathlib import Path
from typing import Any

from pydantic import AliasChoices, BaseModel, Field, PrivateAttr, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict
from pydantic_settings.sources import EnvSettingsSource

#: The ruled order (#598). One home for the wording the log line, the docs and the tests use.
PRECEDENCE_RULE = "file > env > default"


def _values_agree(file_value: Any, env_value: Any) -> bool:
    """Whether the two spellings ask for the same thing.

    The environment only ever carries a string, while TOML carries a native value, so the
    comparison is deliberately loose and biased toward ANNOUNCING: anything this cannot
    recognise as equal is reported. A redundant warning is noise; a missing one is the very
    silence #598 was filed about.
    """
    if isinstance(file_value, bool):
        return str(env_value).strip().lower() in ({"true", "1"} if file_value else {"false", "0"})
    return str(file_value).strip().lower() == str(env_value).strip().lower()


def _leaves(payload: Mapping[str, Any], prefix: str = "") -> dict[str, Any]:
    """Leaf key paths of a nested mapping, as ``{group.key: value}``.

    A section header by itself is not a setting, so an empty table contributes nothing and a
    file carrying only ``[audit]`` cannot report an ``audit`` conflict.
    """
    leaves: dict[str, Any] = {}
    for name, value in payload.items():
        path = f"{prefix}{name}"
        if isinstance(value, Mapping):
            leaves.update(_leaves(value, f"{path}."))
        else:
            leaves[path] = value
    return leaves


def precedence_conflicts(
    *, file_data: Mapping[str, Any], env_data: Mapping[str, Any], rule: str = PRECEDENCE_RULE
) -> list[str]:
    """Keys carried by BOTH the config file and the environment, asking for different things.

    ``env_data`` is pydantic's own environment source resolved against this model, so a key
    appears here only when the model would genuinely read it from the environment. Naming the
    variables by hand instead would risk announcing a conflict for a spelling that was never
    live, and a log line the operator cannot act on is worse than no log line.

    Agreement is NOT reported: two spellings asking for the same value leave nothing
    defeated, and a warning that fires on every boot teaches the operator to ignore the one
    that does not (AC2's third row is the both-set-and-different case).

    Lines name the key, both sources and the winner. They deliberately do not print values:
    this config's key classes include certificate paths and enrollment material, and a
    precedence line is not where one of those belongs in a journal.
    """
    file_leaves = _leaves(file_data)
    env_leaves = _leaves(env_data)
    return [
        f"{key}: set in the executor config file AND in the environment, to different values — "
        f"{rule}, so the file value is in use and the environment spelling is ignored (#598)"
        for key in sorted(file_leaves.keys() & env_leaves.keys())
        if not _values_agree(file_leaves[key], env_leaves[key])
    ]


# #578: `sbx create` must carry an explicit --memory. The vendor's own default
# is a fraction of the guest (50%, clamped 512 MiB-32 GiB), so an un-pinned
# sandbox scales with the machine instead of with the design. These are the
# vendor's bounds, quoted from https://docs.docker.com/reference/cli/sbx/create/
# (read 2026-10-11): minimum 512 MiB, maximum max(75% of host memory, 512 MiB).
SANDBOX_MEMORY_MIN_MB = 512
SANDBOX_MEMORY_VENDOR_MAX_FRACTION = 3 / 4

# #589: the shipped per-sandbox cap. 1024 MiB, measured on the live 5 GiB
# executor shape (venya-exec-5, 2026-10-13): guest MemTotal 4898 MiB (the base
# host_total_memory_mib() reads — NOT the declared 5120, which sits 222 MiB
# above what the guest reports), so the VENDOR default would claim 2449 MiB each
# and two of them are 100.0% of the machine, three are 2449 MiB OVER — the
# #578/#567 condition in numbers. `sbx` enforces its own per-sandbox band and
# refuses an out-of-band value outright (RF-4 bench: 48g rejected), so the
# vendor is not absent here; what neither the vendor nor the #578 guard can do
# is see the SUM of several in-band sandboxes. At 1024 two concurrent sandboxes
# take 2048 MiB and leave ~2850 MiB for the daemon and the OS, and three still
# fit inside MemTotal, which the vendor default never did. This is a CODE field
# default, not a TOML key: `from_file` ends in `cls(**data)` (#598), so a value
# written into the installer's TOML would silently outrank an operator's
# `VENYA_EXECUTOR_SANDBOX_MEMORY_MB` — a default has nothing above it to invert.
SANDBOX_MEMORY_DEFAULT_MB = 1024


def host_total_memory_mib() -> int:
    """Total memory of this host in MiB, for the #578 config-load cap check.

    No psutil dependency lives in this package, so this uses the page-count
    product the kernel already exposes through sysconf — the same number
    `/proc/meminfo`'s MemTotal reports.
    """
    return os.sysconf("SC_PAGE_SIZE") * os.sysconf("SC_PHYS_PAGES") // (1024 * 1024)


class MtlsConfig(BaseModel):
    """mTLS configuration for executor-to-server communication."""

    ca_cert: str = Field(default="/etc/venya/executor/ca.crt", description="Path to CA certificate")
    cert: str = Field(default="/etc/venya/executor/executor.crt", description="Path to executor certificate")
    key: str = Field(default="/etc/venya/executor/executor.key", description="Path to executor private key")


class CertificateRotationConfig(BaseModel):
    """Certificate rotation configuration.

    Deliberately has NO `rotation_days` / `revocation_poll_seconds` fields
    (ticket executor-dead-rotation-config): cert validity is a SERVER-side
    constant (EXECUTOR_VALIDITY_DAYS, server ca.py) and the revocation cadence
    is the daemon main loop (~30s, daemon.py). Both existed here as dead
    knobs — defined, never read — so tuning them silently did nothing.
    Old executor.toml files carrying the removed keys still load (extra keys
    are ignored); see test_config.py TOML-compat pin.
    """

    rotate_before_days: int = Field(
        default=3,
        description="Request new certificate N days before expiry",
    )
    max_revocation_failures: int = Field(
        default=3,
        description="Consecutive revocation check failures with no answer before the executor stops "
        "service (a fault, not a revocation: the core has neither confirmed nor revoked the credential)",
    )


class SessionConfig(BaseModel):
    """Session configuration for executor sessions."""

    session_timeout: int = Field(
        default=900,
        description="Idle timeout in seconds before session expires (default: 15 min)",
    )
    access_token_ttl: int = Field(
        default=300,
        description="Access token lifetime in seconds (default: 5 min)",
    )
    max_session_duration: int = Field(
        default=14400,
        description="Hard cap on session duration in seconds (default: 4 hours)",
    )


class OutputCaptureConfig(BaseModel):
    """Output capture configuration."""

    max_output_bytes: int = Field(
        default=262144,  # 256 KB
        description="Maximum output bytes per stream (stdout/stderr)",
    )
    hash_window_size: int = Field(
        default=20,
        description="Sliding window size for content hash matching",
    )
    min_match_length: int = Field(
        default=8,
        description="Minimum match length for content hash detection",
    )


class CommandValidatorConfig(BaseModel):
    """Command validator configuration."""

    preset: str = Field(
        default="balanced",
        description="Policy preset: strict, balanced, or permissive",
    )
    allowed_commands: list[str] | None = Field(
        default=None,
        description="Explicit allowlist of commands (strict mode)",
    )
    dangerous_patterns: list[str] | None = Field(
        default=None,
        description="Patterns to block using word-boundary matching (e.g., 'sudo', 'mount'). Matches 'sudo' not 'mysudo'.",
    )
    match_word_boundaries: bool = Field(
        default=True,
        description="Match dangerous patterns using word boundaries (\\b) instead of substring matching.",
    )


# Mirror of the server's ingest line cap — server/routes/audit.py
# symbol INGEST_MAX_LINES (#310). Deliberately NOT imported (no
# server→executor import edge); the interlock test
# tests/test_audit.py::TestForwarderIntegrity::test_TF_server_cap_interlock
# parses the server file and pins the pairing.
SERVER_INGEST_MAX_LINES = 2000


class AuditForwarderConfig(BaseModel):
    """Audit log forwarder configuration."""

    remote_url: str | None = Field(
        default=None,
        description="Remote audit sink URL (https://host:port)",
    )
    ca_cert_path: str | None = Field(
        default=None,
        description="Path to CA certificate for TLS verification (required when remote_url is set)",
    )
    max_buffer_size: int = Field(
        default=10_000,
        description="Local event buffer size",
    )
    alert_threshold: float = Field(
        default=0.8,
        description="Buffer occupancy threshold for backlog alert",
    )
    retry_base_delay: float = Field(
        default=2.0,
        description="Retry base delay in seconds",
    )
    retry_max_delay: float = Field(
        default=300.0,
        description="Retry max delay in seconds",
    )
    max_retries: int = Field(
        default=5,
        description="Maximum retry attempts per flush before re-queuing",
    )
    request_timeout_seconds: int = Field(
        default=10,
        ge=1,
        le=120,
        description="Request timeout for audit forward in seconds (1-120)",
    )
    spool_path: str | None = Field(
        default=None,
        description="Durable audit event spool file (default: ~/.venya/audit-spool.jsonl)",
    )
    local_retention_days: int = Field(
        default=90,
        description="Local audit log retention days",
    )
    max_batch_lines: int = Field(
        default=500,
        description="Max spool lines per forwarded batch (bounded by max_buffer_size)",
    )

    @model_validator(mode="after")
    def _batch_within_buffer(self) -> AuditForwarderConfig:
        """#307 D3 + #310: a forwarded batch must fit the local buffer AND
        the server's ingest line cap (SERVER_INGEST_MAX_LINES, mirroring
        server symbol INGEST_MAX_LINES). This boot clamp is the PRIMARY
        brace — a hand-configured batch above the cap is a config error and
        refuses to load (behavior change: pre-#310 such a config booted and
        stalled, the server 413-ing every batch while drop-oldest evicted
        the backlog). The SECONDARY brace is the forwarder's in-cycle 413
        halve-and-retry (_forward_once), so a lowered server cap degrades to
        split forwards, never to silent loss."""
        limit = min(self.max_buffer_size, SERVER_INGEST_MAX_LINES)
        if not 1 <= self.max_batch_lines <= limit:
            raise ValueError(
                f"audit.max_batch_lines must satisfy 1 <= {self.max_batch_lines} <= "
                f"min(max_buffer_size ({self.max_buffer_size}), "
                f"server ingest cap ({SERVER_INGEST_MAX_LINES}))"
            )
        return self

    @model_validator(mode="after")
    def _require_verified_https_remote(self) -> AuditForwarderConfig:
        """Fail closed at config load (daemon startup): a remote audit sink
        must be https:// with an existing CA cert path. The audit stream must
        never degrade to unverified TLS or plaintext (Production Environment
        Mandate). Same precedent as relay_client_ids and the MCP CA gate."""
        if not self.remote_url:
            return self
        if not self.remote_url.startswith("https://"):
            raise ValueError(
                f"audit.remote_url must use the https:// scheme, got {self.remote_url!r} — "
                "refusing to forward the audit stream unencrypted"
            )
        if not self.ca_cert_path:
            raise ValueError(
                "audit.remote_url requires audit.ca_cert_path — "
                "refusing to forward the audit stream over unverified TLS"
            )
        if not Path(self.ca_cert_path).expanduser().exists():
            raise ValueError(
                f"audit.ca_cert_path does not exist: {self.ca_cert_path} — "
                "refusing to start with a broken audit forwarder configuration"
            )
        return self


class ConcurrencyConfig(BaseModel):
    """Relay-command admission (RF-3).

    One knob, two spellings, as pinned by the owner 2026-10-11: env
    `VENYA_EXECUTOR__MAX_CONCURRENT_COMMANDS` and TOML
    `[executor] max_concurrent_commands`. It lands here through the parent
    alias pair on `ExecutorConfig.executor` — measured on the shipped
    interpreter (3.14.6) against this exact prefix/delimiter configuration.

    The shipped default is 1, which is today's sequential posture. The maximum
    is RAM-derived from the measured per-sandbox footprint (RF-3 bench), never
    a fixed integer, so this class deliberately carries no ceiling.
    """

    max_concurrent_commands: int = Field(
        default=1,
        description=(
            "Relayed commands the executor may run at once. 1 (the default) is "
            "today's behaviour: one command at a time. Any value above 1 requires "
            "the RF-3 acceptance cells (cross-command leak, pool-before-listener) "
            "to have passed on the bench VM"
        ),
    )

    @model_validator(mode="after")
    def _at_least_one_slot(self) -> ConcurrencyConfig:
        """A cap below 1 admits nothing, so it is a config error rather than a
        stopped executor: refuse at load with the knob named. (No upper bound is
        checked here — the ceiling is the RAM-derived RF-3 measurement, not a
        constant this file could know.)"""
        if self.max_concurrent_commands < 1:
            raise ValueError(
                f"executor.max_concurrent_commands must be at least 1, got "
                f"{self.max_concurrent_commands} — a cap of 0 would admit no command at all"
            )
        return self


class NetworkConfig(BaseModel):
    """Network timeout configuration."""

    request_timeout_seconds: int = Field(
        default=10,
        ge=1,
        le=120,
        description="Default timeout for server API calls in seconds (1-120)",
    )
    registration_timeout_seconds: int = Field(
        default=30,
        ge=5,
        le=120,
        description="Timeout for registration/rotation in seconds (5-120)",
    )


class ReaperConfig(BaseModel):
    """Reaper loop configuration for orphaned resources."""

    check_interval: float = Field(
        default=5.0,
        description="Check interval in seconds for orphaned resources",
    )
    secret_ttl_seconds: int = Field(
        default=300,
        description="Secret TTL in seconds (cleanup if not consumed)",
    )


class BootstrapConfig(BaseModel):
    """Bootstrap configuration for initial executor registration.

    These settings are used only during the one-time registration
    with the core server. After registration, the enrollment token
    is cleared from the config.
    """

    enrollment_token: str | None = None
    tls_verify: bool = True


class ExecutorConfig(BaseSettings):
    """Executor configuration.

    Loaded from environment variables and/or config file.
    Environment variables are prefixed with VENYA_EXECUTOR_.
    """

    model_config = SettingsConfigDict(
        env_prefix="VENYA_EXECUTOR_",
        env_nested_delimiter="__",
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    # Server connection
    server_url: str = Field(
        default="https://localhost:8080",
        description="Core server URL",
    )

    # CA bundle for TLS verification of core server
    ca_bundle: str | None = Field(
        default=None,
        description="Path to CA bundle certificate for verifying core server TLS",
    )

    # Bootstrap (registration-only)
    bootstrap: BootstrapConfig = Field(default_factory=BootstrapConfig)

    # Path to this config file (legacy [bootstrap] clear in _clear_bootstrap_token)
    config_path: Path | None = None

    # Executor identity
    executor_id: str = Field(
        default="default",
        description="Unique executor identifier (lowercase alphanumeric + hyphens)",
    )

    # Network timeouts
    network: NetworkConfig = Field(default_factory=NetworkConfig)

    # mTLS
    mtls: MtlsConfig = Field(default_factory=MtlsConfig)

    # Relay (core -> executor mTLS listener on :8443). Fail-closed: an empty
    # list means the listener never binds and /execute is unreachable (the
    # daemon logs the refusal at ERROR on start, so it is loud, not silent).
    # Set to the CN(s) of the core's relay *client* certificate — the peer the
    # listener authenticates. No installer step writes it yet; pairing this
    # allowlist with a core-presented client cert is the C1 trust-chain
    # prerequisite.
    relay_client_ids: list[str] = Field(
        default_factory=list,
        description=(
            "Common Names of core client certificates authorized to call the relay "
            "/execute endpoint. The listener is fail-closed when this is empty."
        ),
    )

    # Certificate rotation
    cert_rotation: CertificateRotationConfig = Field(default_factory=CertificateRotationConfig)

    # Sessions
    session: SessionConfig = Field(default_factory=SessionConfig)

    # Output capture
    output_capture: OutputCaptureConfig = Field(default_factory=OutputCaptureConfig)

    # Command validation
    command_validator: CommandValidatorConfig = Field(default_factory=CommandValidatorConfig)

    # Audit forwarding
    audit: AuditForwarderConfig = Field(default_factory=AuditForwarderConfig)

    # Reaper
    reaper: ReaperConfig = Field(default_factory=ReaperConfig)

    # Secret injection (sbx only)
    secret_base_fd: int = Field(
        default=100,
        description="Base FD number for injected secrets (unused for sbx)",
    )

    # Egress allowlist
    egress_allowlist_path: str = Field(
        default="/etc/venya/egress-allowlist.txt",
        description="Path to egress allowlist file (one CIDR/host per line)",
    )
    dns_resolver: str | None = Field(
        default=None,
        description=(
            "DNS resolver IP always allowed for sandbox egress. REQUIRED — no default: "
            "unset, the executor refuses to start (Venya never guesses your network)"
        ),
    )

    # RF-3 admission knob — see ConcurrencyConfig. Named `executor` because that
    # is the TOML table it round-trips to: save_file dumps the FIELD name, so a
    # differently named field would write a table the loader then ignores
    # (measured: dumping it as `concurrency` and reloading leaves the knob at 1).
    # The alias pair is what makes the owner's two spellings ONE truth: the env
    # source resolves the nested group as VENYA_EXECUTOR + "VENYA_EXECUTOR" +
    # "__" + key, which is exactly VENYA_EXECUTOR__MAX_CONCURRENT_COMMANDS, and
    # the dict source keys off "executor", which is [executor].
    executor: ConcurrencyConfig = Field(
        default_factory=ConcurrencyConfig,
        validation_alias=AliasChoices("executor", "VENYA_EXECUTOR"),
        description="Relay-command admission (RF-3): env VENYA_EXECUTOR__MAX_CONCURRENT_COMMANDS, TOML [executor] max_concurrent_commands",
    )

    # Per-sandbox memory cap, passed to `sbx create --memory` (#578).
    # #589: the shipped default is 1024 MiB (see SANDBOX_MEMORY_DEFAULT_MB for
    # the measurement), so a fresh install runs a command without an
    # operator-supplied value. An operator value in either carrier still wins:
    # the default is the LAST plane, and the #578 floor/ceiling check below is
    # untouched. Deliberately does NOT go in the installer TOML — a key there
    # silently outranks the env spelling (the #598 precedence inversion).
    # Still `int | None`: an explicit null remains representable and keeps the
    # #578 create-time refusal reachable, so shipping a default does not narrow
    # what an operator can ask for.
    sandbox_memory_mb: int | None = Field(
        default=SANDBOX_MEMORY_DEFAULT_MB,
        description=(
            "Per-sandbox memory cap in MiB passed to `sbx create --memory`. "
            f"Defaults to {SANDBOX_MEMORY_DEFAULT_MB} MiB (the shipped measurement, #589); "
            "env VENYA_EXECUTOR_SANDBOX_MEMORY_MB or the `sandbox_memory_mb` toml key "
            "override it, and a value outside the vendor bounds refuses at config load"
        ),
    )

    # Logging
    log_level: str = Field(default="info", description="Logging level")
    # Daemon mode
    daemonize: bool = Field(default=False, description="Run as daemon (fork to background)")
    pid_file: str = Field(default="/var/lib/venya/executor/venya-executor.pid", description="PID file path")

    # #598 — the loud list computed by from_file. A private attribute, deliberately not a
    # setting: it is read from neither the file nor the environment, and save_file must never
    # write it back, or the report of a conflict would itself become a config key.
    _precedence_conflicts: list[str] = PrivateAttr(default_factory=list)

    @model_validator(mode="after")
    def _sandbox_memory_within_vendor_bounds(self) -> ExecutorConfig:
        """#578 fail-closed at config load: an out-of-band cap is a config error,
        not a pass-through. Refuses a value below the vendor minimum (512 MiB) or
        above the vendor maximum (max(75% of this machine's memory, 512 MiB)).

        Corrected at #589: this docstring used to say the vendor would "silently
        clamp behind our back". That was our guess, never a cited vendor
        statement, and the RF-4 bench disproved it — `sbx` REFUSES an out-of-band
        value (a 48 GiB `--memory` was rejected outright). The guard stays for
        what it actually buys: a Venya-named refusal at config load, before any
        sandbox exists, instead of a vendor error at create. It is NOT the only
        protection — but both checks are per-sandbox, so neither sees the SUM of
        several in-band caps; that aggregate is why the shipped default is
        measured rather than max-allowed (see `SANDBOX_MEMORY_DEFAULT_MB`).
        #589 gave the field a shipped default, so an unset knob no longer reaches
        the create-time refusal by accident — an explicit null still does.
        """
        if self.sandbox_memory_mb is None:
            return self
        host_total_mib = host_total_memory_mib()
        vendor_max_mib = max(
            int(host_total_mib * SANDBOX_MEMORY_VENDOR_MAX_FRACTION),
            SANDBOX_MEMORY_MIN_MB,
        )
        if self.sandbox_memory_mb < SANDBOX_MEMORY_MIN_MB:
            raise ValueError(
                f"sandbox_memory_mb must be at least {SANDBOX_MEMORY_MIN_MB} MiB (the sbx vendor "
                f"minimum), got {self.sandbox_memory_mb} MiB"
            )
        if self.sandbox_memory_mb > vendor_max_mib:
            raise ValueError(
                f"sandbox_memory_mb must be at most {vendor_max_mib} MiB — 75% of this machine's "
                f"{host_total_mib} MiB (the sbx vendor maximum), got {self.sandbox_memory_mb} MiB"
            )
        return self

    @classmethod
    def from_file(cls, path: str | Path) -> ExecutorConfig:
        """Load configuration from a TOML file.

        Args:
            path: Path to config file.

        Returns:
            Configured ExecutorConfig.
        """
        path = Path(path)
        if not path.exists():
            raise FileNotFoundError(f"Config file not found: {path}")

        try:
            import tomllib
        except ImportError:
            import tomli as tomllib  # type: ignore[import-not-found,no-redef]

        with open(path, "rb") as f:
            data = tomllib.load(f)

        # #598 — this is the resolution site, so the ruled contract is stated where it is
        # decided rather than in folklore: passing the parsed TOML as explicit init arguments
        # is what puts the FILE above the environment in pydantic-settings' order, making the
        # precedence `file > env > default` (lead ruling, 2026-10-13). The direction was never
        # the defect; the silence was. Every key BOTH spellings carry is recorded here and
        # announced by the daemon at start, once logging exists to carry it.
        config = cls(**data)
        config._precedence_conflicts = precedence_conflicts(
            file_data=data,
            env_data=EnvSettingsSource(cls)(),
        )
        return config

    def precedence_conflict_notes(self) -> list[str]:
        """The #598 loud list: keys this file set that the environment also set.

        Empty when the config was built without a file, or when nothing overlaps. Values are
        never included — see ``precedence_conflicts``.
        """
        return list(self._precedence_conflicts)

    def save_file(self, path: str | Path) -> None:
        """Save current configuration to a TOML file.

        Args:
            path: Path to write config file.
        """
        try:
            import tomli_w  # type: ignore[import-not-found]
        except ImportError:
            raise ImportError("tomli_w is required for config save. Install with: pip install tomli-w")

        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)

        import json

        data = json.loads(self.model_dump_json())

        def filter_none(obj):
            if isinstance(obj, dict):
                return {k: filter_none(v) for k, v in obj.items() if v is not None}
            if isinstance(obj, list):
                return [filter_none(item) for item in obj if item is not None]
            return obj

        data = filter_none(data)
        # The toml can carry the [bootstrap] enrollment token — land it 0600
        # atomically instead of a bare open() under the process umask (ticket
        # executor-daemon-umask0-key-write-window). Local import: daemon
        # imports config at module level, config must not import daemon back.
        from .daemon import _atomic_write

        _atomic_write(path, tomli_w.dumps(data).encode("utf-8"), 0o600)

    def model_post_init(self, _context, /):
        """Validate executor_id on initialization."""
        import re

        pattern = r"^[a-z0-9][a-z0-9-]{0,62}[a-z0-9]$"
        if len(self.executor_id) < 2 or len(self.executor_id) > 64:
            raise ValueError(f"executor_id must be 2-64 characters, got {len(self.executor_id)}")
        if not re.match(pattern, self.executor_id):
            raise ValueError(
                "executor_id must be lowercase alphanumeric with "
                "optional hyphens, starting and ending with alphanumeric"
            )
