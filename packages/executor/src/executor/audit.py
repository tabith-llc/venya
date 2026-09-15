"""Audit event logging and forwarding.

Audit events are appended synchronously to a local spool file (durable
queue) and forwarded to the remote URL asynchronously by a background
thread.  emit() touches local disk only — requests are never blocked on
the audit forwarder, and events survive process restarts (the spool file
is the source of truth; there is no in-memory buffer).

Serialization failures are written as error-marker lines, never dropped.
"""

# stdlib zstd compression (Python 3.14+, PEP 784)
import json
import logging
import threading
import time
from compression import zstd
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import httpx2

from .config import AuditForwarderConfig

logger = logging.getLogger("venya.executor.audit")

EVENT_TYPES = (
    "credential_injected",
    "command_executed",
    "command_rejected",
    "token_revocation_failed",
)

# Idle poll interval (seconds) for the forwarder between events. Audit
# forwarding is not latency-critical; this bounds worst-case forward lag.
FORWARDER_IDLE_POLL_SECONDS = 1.0


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

    Lifetime of an event:
      1. emit() serializes the event (a failed serialization is written as
         an error line) and appends it to the spool file under the lock —
         synchronous, local disk only, no network.
      2. The background forwarder drains the spool in batches of
         max_buffer_size lines, zstd-compresses, and POSTs to remote_url.
         On success the consumed prefix is truncated; on failure the lines
         are kept and the backoff doubles (capped at retry_max_delay).
      3. When the spool exceeds max_buffer_size lines the oldest lines are
         dropped (with a warning) so a long outage cannot grow it without
         bound.

    flush() performs one best-effort drain. shutdown() runs a bounded final
    drain and stops the forwarder thread.
    """

    def __init__(self, config: AuditForwarderConfig, session_id: str) -> None:
        self._config = config
        self._session_id = session_id
        self._lock = threading.Lock()
        self._wakeup = threading.Event()
        self._forwarding = False
        self._shutdown = False
        self._spool_path = self._resolve_spool_path(config.spool_path)
        self._spool_path.parent.mkdir(parents=True, exist_ok=True)
        self._forwarder = threading.Thread(target=self._forward_loop, daemon=True)
        self._forwarder.start()

    @staticmethod
    def _resolve_spool_path(p: str | None) -> Path:
        # ponytail: spool lives in the executor user's home — the deployment
        # model is one executor per host; two executor instances sharing a
        # home would interleave their spools. Upgrade path: add executor_id
        # to the default filename.
        if p:
            return Path(p).expanduser()
        return Path.home() / ".venya" / "audit-spool.jsonl"

    # -- write path (synchronous, local disk only, never network) ----------

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
            with self._spool_path.open("a", encoding="utf-8") as f:
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

    def _forward_once(self) -> bool:
        """Drain up to max_buffer_size spool lines to the remote.

        Returns:
            True if nothing was pending or the batch was accepted.
            False if the remote failed/rejected the batch (lines are kept).
        """
        remote_url = self._config.remote_url
        if not remote_url:
            return True

        with self._lock:
            if self._forwarding:
                return True
            self._forwarding = True
        try:
            with self._lock:
                lines = self._read_all_lines()[: self._config.max_buffer_size]
            if not lines:
                return True

            payload = "".join(lines)
            compressed = zstd.compress(payload.encode(), level=3)
            client = httpx2.Client(
                # Fail closed: config validation guarantees ca_cert_path when
                # remote_url is set; if validation is bypassed (direct
                # mutation), fall back to the system trust store — never False.
                verify=self._config.ca_cert_path if self._config.ca_cert_path else True,
                timeout=self._config.request_timeout_seconds,
            )
            with client:
                response = client.post(
                    remote_url,
                    content=compressed,
                    headers={
                        "Content-Type": "application/x-ndjson",
                        "Content-Encoding": "zstd",
                    },
                )
        except Exception as e:
            logger.warning("Audit forward error: %s", e)
            return False
        finally:
            with self._lock:
                self._forwarding = False

        if response.status_code < 400:
            with self._lock:
                self._truncate_prefix(len(lines))
            logger.debug("Forwarded %d audit events", len(lines))
            return True

        logger.error(
            "Audit forward failed (HTTP %d): %s",
            response.status_code,
            response.text[:200],
        )
        return False

    def _read_all_lines(self) -> list[str]:
        """Read all spool lines. Caller must hold the lock."""
        if not self._spool_path.exists():
            return []
        with self._spool_path.open("r", encoding="utf-8") as f:
            return f.readlines()

    def _truncate_prefix(self, n: int) -> None:
        """Remove the n oldest spool lines. Caller must hold the lock."""
        lines = self._read_all_lines()
        self._keep_latest(len(lines) - n)

    def _keep_latest(self, keep: int) -> None:
        """Rewrite the spool keeping only its last `keep` lines. Caller must
        hold the lock."""
        lines = self._read_all_lines()
        if keep <= 0:
            if self._spool_path.exists():
                self._spool_path.unlink()
            return
        with self._spool_path.open("w", encoding="utf-8") as f:
            f.writelines(lines[-keep:])

    def shutdown(self) -> None:
        """Run a bounded final drain and stop the forwarder thread."""
        self._shutdown = True
        self._wakeup.set()
        for _ in range(min(self._config.max_retries, 3)):
            if not self._forward_once():
                break
        self._forwarder.join(timeout=5.0)
