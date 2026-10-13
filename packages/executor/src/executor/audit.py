# Copyright (c) 2026 Tabith LLC.
# Use of this source code is governed by the Business Source License 1.1
# included in the LICENSE file at the root of this repository. As of the
# Change Date listed there, the work is available under MPL 2.0.
# SPDX-License-Identifier: BUSL-1.1

"""Audit event logging and forwarding.

Audit events are appended synchronously to a local spool file (durable
queue) and forwarded to the remote URL asynchronously by a background
thread.  emit() touches local disk only — requests are never blocked on
the audit forwarder, and events survive process restarts (the spool file
is the source of truth; there is no in-memory buffer).

Serialization failures are written as error-marker lines, never dropped.
"""

# stdlib zstd compression (Python 3.14+, PEP 784)
import contextlib
import json
import logging
import os
import ssl
import tempfile
import threading
import time
from collections import Counter
from compression import zstd
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import httpx2

from .config import AuditForwarderConfig
from .key_passphrase import ssl_password_callback

logger = logging.getLogger("venya.executor.audit")

EVENT_TYPES = (
    "credential_injected",
    "command_executed",
    "command_rejected",
    "token_revocation_failed",
    # #586: the relay accept gate refused a connection (revoked credential, or no
    # revocation answer this boot). Recorded because a silent refusal is invisible
    # to the customer whose premise is the trail.
    "relay_refused",
)

# Idle poll interval (seconds) for the forwarder between events. Audit
# forwarding is not latency-critical; this bounds worst-case forward lag.
FORWARDER_IDLE_POLL_SECONDS = 1.0

# #468: the spool path is process-scoped — _resolve_spool_path derives it
# from config or a fixed default with NO session identity in the name — but
# the daemon runs TWO AuditLogger instances over that one path in ONE
# process (the per-session logger, daemon.py create_executor, and the
# session-less boot forwarder, audit_boot_forwarder). A per-instance lock
# therefore serialized nothing between them: one instance could compute a
# rewrite from a stale read and os.replace it over lines the other had just
# appended — a lost update that silently deletes durable audit events.
# All spool mutation is now serialized on a process-wide registry of locks
# keyed by the RESOLVED spool path: instances sharing one path share one
# lock; instances on different paths never block each other.
#
# Guarantee this gives: mutual exclusion across EVERY AuditLogger instance
# in this process (any threads) that resolves to the same file. Guarantee
# it does NOT give: cross-PROCESS exclusion — two executor processes
# sharing one spool home remain the documented unsupported shape
# ("one executor per host" in _resolve_spool_path's shortcut note).
# Entries live for the process lifetime; the count is bounded by the number
# of distinct spool paths a deployment resolves (one), so no eviction.
_SPOOL_LOCKS: dict[Path, threading.Lock] = {}
_SPOOL_LOCKS_GUARD = threading.Lock()


def _spool_lock_for(path: Path) -> threading.Lock:
    """Return the one lock shared by all in-process loggers writing ``path``.

    The key is the fully resolved path (symlinks and ``..`` normalized) so
    two spellings of one file cannot land on two locks — that would ship
    the #468 defect right back.
    """
    key = path.resolve()
    with _SPOOL_LOCKS_GUARD:
        lock = _SPOOL_LOCKS.get(key)
        if lock is None:
            lock = threading.Lock()
            _SPOOL_LOCKS[key] = lock
        return lock


@dataclass
class AuditEvent:
    """Single audit event."""

    event_type: str
    session_id: str
    timestamp: str = field(default_factory=lambda: datetime.now(UTC).isoformat())
    extra: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "event_type": self.event_type,
            "session_id": self.session_id,
            "timestamp": self.timestamp,
            **self.extra,
        }

    def to_json(self) -> str:
        return json.dumps(self.to_dict())


class AuditLogger:
    """Durable audit event spool with asynchronous remote forwarding.

    The forwarder presents the executor mTLS client certificate (client_cert,
    wired by the daemon) — the server sink authenticates it and writes the
    events to the core audit ledger.

    Delivery is AT-LEAST-ONCE below capacity and LOSSY above it: a failed
    batch is kept and retried (duplicates possible server-side, tolerated by
    ruling), but a spool that exceeds max_buffer_size drops its OLDEST lines
    (#307 R2 honesty — any no-loss claim must state this ceiling).

    Lifetime of an event:
      1. emit() serializes the event (a failed serialization is written as
         an error line) and appends it to the spool file under the lock —
         synchronous, local disk only, no network.
      2. The background forwarder drains the spool in batches of
         min(max_buffer_size, max_batch_lines) lines (#307 D3),
         zstd-compresses, and POSTs to remote_url with the executor client
         cert. On success the sent lines are removed BY CONTENT — a line
         leaves the spool only if it was sent or explicitly warned-dropped
         (#310); on failure the lines are kept and the backoff doubles
         (capped at retry_max_delay). A 413 halves the batch and retries
         within the drain cycle (#310). A configured remote without
         client_cert is a loud fail-closed refusal, never a silent 401 loop
         (#307 D1).
      3. When the spool exceeds max_buffer_size lines the oldest lines are
         dropped (with a warning) so a long outage cannot grow it without
         bound.

    Lock scope (#468 — read this before constructing another instance):
    ``self._lock`` is NOT per-instance. It is the process-wide lock
    registered for this logger's RESOLVED spool path (``_spool_lock_for``),
    so every spool mutation — append, capacity drop-oldest, drain read,
    content removal and ``_rewrite_spool`` — serializes across ALL
    AuditLogger instances in this process sharing that path (the daemon's
    real shape: per-session logger + boot forwarder). Two loggers on two
    different paths hold two different locks and never block each other.
    OUT OF SCOPE: cross-process writers of one spool path — that remains
    the unsupported multi-executor-per-home shape (``_resolve_spool_path``
    shortcut note), and a new caller must not treat the shared lock as a
    file lock. Duplicated forwards between coexisting drains stay possible
    and are tolerated (at-least-once, above).

    flush() performs one best-effort drain. shutdown() runs a bounded final
    drain and stops the forwarder thread.
    """

    def __init__(
        self,
        config: AuditForwarderConfig,
        session_id: str,
        client_cert: tuple[str, str] | None = None,
    ) -> None:
        self._config = config
        self._client_cert = client_cert
        self._session_id = session_id
        self._wakeup = threading.Event()
        self._forwarding = False
        self._shutdown = False
        self._spool_path = self._resolve_spool_path(config.spool_path)
        # #468: the lock is keyed by the RESOLVED spool path, not by this
        # object — two instances over one file MUST share one lock (see
        # _spool_lock_for and the class docstring's lock-scope note).
        self._lock = _spool_lock_for(self._spool_path)
        self._spool_path.parent.mkdir(parents=True, exist_ok=True)
        # The spool holds FULL command lines (a caller inlining credentials
        # puts plaintext here) — create it 0600 and REPAIR a legacy
        # world-readable spool at startup. Pre-fix, .open("a") inherited the
        # umask (typically 0644) — ticket sec-secret-redaction-log-leaks #19.
        # #310: creation goes through the append helper so the mode lands AT
        # CREATE on every re-create path (drain-to-empty + re-emit), not just
        # at startup; the chmod below stays as the legacy-file repair.
        with self._spool_append_handle():
            pass
        os.chmod(self._spool_path, 0o600)
        self._forwarder = threading.Thread(target=self._forward_loop, daemon=True)
        self._forwarder.start()

    @staticmethod
    def _resolve_spool_path(p: str | None) -> Path:
        # shortcut: spool lives in the executor user's home — the deployment
        # model is one executor per host; two executor instances sharing a
        # home would interleave their spools. Upgrade path: add executor_id
        # to the default filename.
        if p:
            return Path(p).expanduser()
        return Path.home() / ".venya" / "audit-spool.jsonl"

    # -- write path (synchronous, local disk only, never network) ----------

    def _spool_append_handle(self):
        """Open the spool for append, CREATING IT 0600 when absent (#310).

        ``os.open`` applies the mode at CREATE (umask can only remove bits,
        and the usual 022 leaves 0600 intact), so a post-drain re-create is
        never umask-born world-readable — the #19 hardening holds across the
        file's whole lifetime, not just the startup repair window.
        """
        fd = os.open(self._spool_path, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
        return os.fdopen(fd, "a", encoding="utf-8")

    def emit(self, event_type: str, **kwargs: Any) -> None:
        """DURABLY record an audit event.

        Args:
            event_type: One of the allowed event types.
            **kwargs: Additional fields to include in the event.

        The event is serialized (a failed serialization is written as an
        error-marker line) and appended to the spool file. No network I/O
        happens here, ever.
        """
        if event_type not in EVENT_TYPES:
            logger.warning("Unknown audit event type: %s", event_type)
            return

        event = AuditEvent(
            event_type=event_type,
            session_id=self._session_id,
            extra=kwargs,
        )
        try:
            line = event.to_json()
        except (TypeError, ValueError) as e:
            # Unserializable extra kwargs — write a marker line instead of
            # dropping the event entirely.
            line = json.dumps(
                {
                    "event_type": event.event_type,
                    "session_id": event.session_id,
                    "timestamp": event.timestamp,
                    "serialization_error": str(e),
                }
            )

        with self._lock:
            with self._spool_append_handle() as f:
                f.write(line + "\n")
            count = self._count_lines()
            capacity = self._config.max_buffer_size
            if count >= capacity:
                logger.warning(
                    "Audit buffer at %.0f%% capacity (%d/%d)",
                    100.0,
                    count,
                    capacity,
                )
                self._drop_oldest(count - capacity)
            elif count >= capacity * self._config.alert_threshold:
                logger.warning(
                    "Audit buffer at %.0f%% capacity (%d/%d)",
                    (count / capacity) * 100,
                    count,
                    capacity,
                )
        self._wakeup.set()

    def _count_lines(self) -> int:
        """Number of lines in the spool. Caller must hold the lock."""
        if not self._spool_path.exists():
            return 0
        with self._spool_path.open("r", encoding="utf-8") as f:
            return sum(1 for _ in f)

    def _drop_oldest(self, n: int) -> None:
        """Drop the n oldest spool lines. Caller must hold the lock."""
        if n <= 0:
            return
        self._truncate_prefix(n)
        logger.warning("Audit spool full — dropped %d oldest event(s)", n)

    # -- forward path (background thread + on-demand) -----------------------

    def flush(self) -> None:
        """Attempt one best-effort drain of the spool to the remote."""
        self._forward_once()

    def _forward_loop(self) -> None:
        backoff = self._config.retry_base_delay
        while not self._shutdown:
            self._wakeup.wait(timeout=FORWARDER_IDLE_POLL_SECONDS)
            self._wakeup.clear()
            if self._shutdown:
                break
            if self._forward_once():
                backoff = self._config.retry_base_delay
            else:
                time.sleep(backoff)
                backoff = min(backoff * 2, self._config.retry_max_delay)

    def _build_forward_ssl_context(self) -> ssl.SSLContext:
        """One TLS context carrying both directions for the forward client (#432).

        Port of the cli-admin-mtls-verify-cert-conflict precedent
        (venya_cli.api_client._build_ssl_context): httpx2 >= 2.12 rejects a
        string ``verify=`` combined with ``cert=``, so the CA anchors and the
        executor mTLS client cert chain live in a single SSLContext.

        Trust set (#531, owner ruling 2026-10-07): the configured
        ``ca_cert_path`` is the ONLY anchor — this dial never loads the host
        trust store. The retired ``else: ctx.load_default_certs()`` meant an
        audit row could be posted to whatever a publicly-issued certificate
        claimed was the core, so a forwarded line was not provably addressed
        to our core. ``ssl.create_default_context()`` is deliberately NOT used
        here either: it calls ``load_default_certs()`` and
        ``load_verify_locations()`` only ADDS to that set. The repair for a
        missing anchor is the CA the executor installer copies to this host
        (workstations: ``venya setup <core>``) — never an implicit host store
        (same ruling as #530/#501).

        Fail-loud postures: an empty ``ca_cert_path`` and a CA or cert-FILE
        load failure both raise into the per-cycle handler in
        ``_forward_once`` (spool lines kept, loud log, no crash loop — same
        semantics as the old constructor TypeError, now fixed). Nothing here
        ever degrades to ``verify=False``.
        """
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        if not self._config.ca_cert_path:
            # Defense in depth: AuditForwarderConfig._require_verified_https_remote
            # already refuses remote_url-without-CA at config load, so reaching
            # this line means the config was mutated past the validator.
            raise RuntimeError(
                "Audit forwarder has no trust anchor: audit.ca_cert_path is empty and the "
                "host trust store is not consulted (#531) — events stay spooled. Repair: point "
                "audit.ca_cert_path at the Venya CA this installer copies to the executor "
                "(workstations: 'venya setup <core>')"
            )
        ctx.load_verify_locations(cafile=self._config.ca_cert_path)
        if self._client_cert:
            # #565: the forwarder dials with the executor's own client pair, and the
            # key may now be an encrypted envelope. The callback is consulted only
            # for an encrypted file, so a legacy plaintext key forwards exactly as
            # before; an envelope this host cannot open raises the named refusal
            # (a spool-stays-put failure, never a degrade to no-client-cert).
            ctx.load_cert_chain(
                certfile=self._client_cert[0],
                keyfile=self._client_cert[1],
                password=ssl_password_callback(),
            )
        return ctx

    def _forward_once(self) -> bool:
        """Drain up to min(max_buffer_size, max_batch_lines) spool lines to the remote.

        Success removes the batch BY CONTENT (``_remove_sent_lines``, #310) —
        never by count, so an interleaved drop-oldest during the POST cannot
        charge un-forwarded lines for the sent batch. On HTTP 413 the batch
        is halved (floor 1) and re-POSTED within the same drain cycle until
        accepted or a single line fails (#310 survivability brace; the boot
        clamp in ``AuditForwarderConfig`` is the primary brace).

        Returns:
            True if nothing was pending or the batch (or a split remainder
            of it) was accepted.
            False if the remote failed/rejected the batch (lines are kept).
        """
        remote_url = self._config.remote_url
        if not remote_url:
            return True

        # Fail closed (#307 D1): the sink is executor-mTLS-gated — a batch
        # without the client cert is a guaranteed 401 retry loop (loud
        # deaf-boot class). Refuse LOUDLY here instead of hammering the sink.
        if self._client_cert is None:
            logger.error(
                "Audit forwarder configured without client certificate — "
                "target requires executor mTLS; events will be refused (401)"
            )
            return False

        with self._lock:
            if self._forwarding:
                return True
            self._forwarding = True
        try:
            with self._lock:
                cap = min(self._config.max_buffer_size, self._config.max_batch_lines)
                lines = self._read_all_lines()[:cap]
            if not lines:
                return True

            client = httpx2.Client(
                verify=self._build_forward_ssl_context(),
                timeout=self._config.request_timeout_seconds,
            )
            batch = lines
            with client:
                while True:
                    compressed = zstd.compress("".join(batch).encode(), level=3)
                    response = client.post(
                        remote_url,
                        content=compressed,
                        headers={
                            "Content-Type": "application/x-ndjson",
                            "Content-Encoding": "zstd",
                        },
                    )
                    if response.status_code < 400:
                        break
                    if response.status_code == 413 and len(batch) > 1:
                        # #310: a sink line cap below our batch must never
                        # mean silent loss — halve and retry in-cycle.
                        halved = max(1, len(batch) // 2)
                        logger.warning(
                            "Audit sink 413 on %d-line batch — splitting to %d lines and retrying in this drain cycle",
                            len(batch),
                            halved,
                        )
                        batch = batch[:halved]
                        continue
                    logger.error(
                        "Audit forward failed (HTTP %d): %s",
                        response.status_code,
                        response.text[:200],
                    )
                    return False
            with self._lock:
                self._remove_sent_lines(batch)
            logger.debug("Forwarded %d audit events", len(batch))
            return True
        except Exception as e:
            logger.warning("Audit forward error: %s", e)
            return False
        finally:
            with self._lock:
                self._forwarding = False

    def _read_all_lines(self) -> list[str]:
        """Read all spool lines. Caller must hold the lock."""
        if not self._spool_path.exists():
            return []
        with self._spool_path.open("r", encoding="utf-8") as f:
            return f.readlines()

    def _truncate_prefix(self, n: int) -> None:
        """Remove the n oldest spool lines (the warned drop-oldest path —
        count is legitimate there because every removal is logged by
        ``_drop_oldest``). Caller must hold the lock."""
        lines = self._read_all_lines()
        self._rewrite_spool(lines[n:])

    def _remove_sent_lines(self, batch: list[str]) -> None:
        """Content-addressed success truncation (#310): a line leaves the
        spool only if it was SENT or was explicitly warned-dropped by
        ``_drop_oldest``. Count-truncation is retired on the forward path —
        an interleaved capacity drop during the POST moves the file head,
        and ``len(batch)`` blind-removal would charge un-forwarded lines.

        The batch's remaining lines are removed by CONTENT (one occurrence
        per sent line, order preserved). If the head moved (part of the sent
        batch was already warned-dropped in flight), that is logged with
        counts, never guessed at. Caller must hold the lock.
        """
        current = self._read_all_lines()
        if current[: len(batch)] == batch:
            self._rewrite_spool(current[len(batch) :])
            return
        # Head moved: remove exactly the sent content, wherever it remains.
        remaining = Counter(batch)
        kept: list[str] = []
        for line in current:
            if remaining.get(line, 0) > 0:
                remaining[line] -= 1
            else:
                kept.append(line)
        already_gone = sum(remaining.values())
        logger.warning(
            "Audit spool head moved during forward: %d of %d sent lines still present removed by content; "
            "%d already warned-dropped in flight (see spool-full warnings) — never count-deleting",
            len(batch) - already_gone,
            len(batch),
            already_gone,
        )
        self._rewrite_spool(kept)

    def _rewrite_spool(self, lines: list[str]) -> None:
        """Atomically replace the spool contents: temp file created 0600 in
        the spool's own directory, then ``os.replace`` (#310). The file is
        never unlinked-then-recreated, so no window exists for a umask-mode
        spool between a full drain and the next append. Caller must hold
        the lock."""
        fd, tmp_name = tempfile.mkstemp(
            dir=self._spool_path.parent,
            prefix=self._spool_path.name + ".",
            suffix=".tmp",
        )
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as f:  # mkstemp creates 0600
                f.writelines(lines)
            os.replace(tmp_name, self._spool_path)
        except BaseException:
            with contextlib.suppress(OSError):
                os.unlink(tmp_name)
            raise

    def shutdown(self) -> None:
        """Run a bounded final drain and stop the forwarder thread."""
        self._shutdown = True
        self._wakeup.set()
        for _ in range(min(self._config.max_retries, 3)):
            if not self._forward_once():
                break
        self._forwarder.join(timeout=5.0)
