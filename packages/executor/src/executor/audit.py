"""Audit event logging and forwarding.

Buffers audit events locally and forwards to remote URL with retry.
Thread-safe for use during command execution.
"""


import json
import logging
import threading
import time
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

import httpx2

from .config import AuditForwarderConfig

# stdlib zstd compression (Python 3.14+, PEP 784)
import compression.zstd

logger = logging.getLogger("venya.executor.audit")

EVENT_TYPES = ("credential_injected", "command_executed", "command_rejected", "token_revocation_failed")


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
    """Buffers and forwards audit events.

    Events are buffered in memory and flushed when the buffer reaches
    max_buffer_size or when flush() is called explicitly.

    If remote_url is configured, events are POSTed as JSON lines.
    Uses exponential backoff on failure.
    """

    def __init__(self, config: AuditForwarderConfig, session_id: str) -> None:
        self._config = config
        self._session_id = session_id
        self._buffer: list[AuditEvent] = []
        self._lock = threading.Lock()
        self._shutdown = False

    def emit(self, event_type: str, **kwargs: Any) -> None:
        """Buffer an audit event.

        Args:
            event_type: One of the allowed event types.
            **kwargs: Additional fields to include in the event.
        """
        if event_type not in EVENT_TYPES:
            logger.warning("Unknown audit event type: %s", event_type)
            return

        event = AuditEvent(
            event_type=event_type,
            session_id=self._session_id,
            extra=kwargs,
        )

        buffer_to_flush: list[AuditEvent] | None = None

        with self._lock:
            self._buffer.append(event)

            threshold = self._config.max_buffer_size * self._config.alert_threshold
            if len(self._buffer) >= threshold:
                logger.warning(
                    "Audit buffer at %.0f%% capacity (%d/%d)",
                    (len(self._buffer) / self._config.max_buffer_size) * 100,
                    len(self._buffer),
                    self._config.max_buffer_size,
                )

            if len(self._buffer) >= self._config.max_buffer_size:
                buffer_to_flush = self._buffer
                self._buffer = []

        # Flush outside the lock — new events arriving during flush
        # go into the fresh empty buffer.
        if buffer_to_flush:
            self._flush_buffer(buffer_to_flush)

    def flush(self) -> None:
        """Flush all buffered events to remote."""
        with self._lock:
            if not self._config.remote_url or not self._buffer:
                return
            buffer_to_flush = self._buffer
            self._buffer = []

        self._flush_buffer(buffer_to_flush)

    def _flush_buffer(self, events: list[AuditEvent]) -> None:
        """Flush a batch of events to remote URL.

        Args:
            events: List of audit events to send.
        """
        payload = "\n".join(e.to_json() for e in events)
        remote_url = self._config.remote_url

        try:
            self._post_with_retry(payload, remote_url)
            logger.debug("Flushed %d audit events", len(events))
        except Exception:
            # Re-queue events that couldn't be sent
            with self._lock:
                self._buffer = events + self._buffer
            logger.warning(
                "Re-queued %d audit events after flush failure",
                len(events),
            )

    def _post_with_retry(self, payload: str, remote_url: str) -> None:
        """POST payload to remote_url with exponential backoff.

        Args:
            payload: JSON lines payload to send.
            remote_url: Target URL.

        Raises:
            RuntimeError: If all retry attempts are exhausted.
        """
        from compression import zstd

        compressed = zstd.compress(payload.encode(), level=3)
        delay = self._config.retry_base_delay
        max_delay = self._config.retry_max_delay
        max_retries = self._config.max_retries
        attempts = 0

        if self._config.ca_cert_path:
            client = httpx2.Client(
                verify=self._config.ca_cert_path,
                timeout=self._config.request_timeout_seconds,
            )
        else:
            client = httpx2.Client(
                verify=False,
                timeout=self._config.request_timeout_seconds,
            )

        with client:
            while not self._shutdown and attempts < max_retries:
                attempts += 1
                try:
                    response = client.post(
                        remote_url,
                        content=compressed,
                        headers={
                            "Content-Type": "application/x-ndjson",
                            "Content-Encoding": "zstd",
                        },
                    )
                    if response.status_code < 400:
                        return
                    if response.status_code == 429:
                        retry_after = response.headers.get("retry-after")
                        if retry_after:
                            delay = float(retry_after)
                        else:
                            delay = min(delay * 2, max_delay)
                    else:
                        logger.error(
                            "Audit forward failed (HTTP %d): %s",
                            response.status_code,
                            response.text[:200],
                        )
                except httpx2.ConnectError as e:
                    logger.warning("Audit forward connection error: %s", e)
                except Exception as e:  # noqa: BLE001
                    logger.error("Audit forward error: %s", e)

                time.sleep(delay)
                delay = min(delay * 2, max_delay)

        raise RuntimeError(
            f"Audit forward failed after {attempts} attempts to {remote_url}"
        )

    def shutdown(self) -> None:
        """Flush remaining events and stop background processing."""
        self.flush()
        self._shutdown = True
