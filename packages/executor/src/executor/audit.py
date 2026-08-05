"""Audit event logging and forwarding.

Buffers audit events locally and forwards to remote URL with retry.
Thread-safe for use during command execution.
"""

from __future__ import annotations

import json
import logging
import threading
import time
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

from .config import AuditForwarderConfig

logger = logging.getLogger("venya.executor.audit")

EVENT_TYPES = ("credential_injected", "command_executed", "command_rejected")


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

        with self._lock:
            self._buffer.append(event)

            # Check buffer threshold for alert
            threshold = self._config.max_buffer_size * self._config.alert_threshold
            if len(self._buffer) >= threshold:
                logger.warning(
                    "Audit buffer at %.0f%% capacity (%d/%d)",
                    (len(self._buffer) / self._config.max_buffer_size) * 100,
                    len(self._buffer),
                    self._config.max_buffer_size,
                )

            # Auto-flush when full
            if len(self._buffer) >= self._config.max_buffer_size:
                self._flush_unlocked()

    def flush(self) -> None:
        """Flush all buffered events to remote."""
        with self._lock:
            if self._config.remote_url and self._buffer:
                self._flush_unlocked()

    def _flush_unlocked(self) -> None:
        """Flush buffer (caller must hold lock)."""
        if not self._buffer or not self._config.remote_url:
            return

        payload = "\n".join(e.to_json() for e in self._buffer)
        events_sent = len(self._buffer)
        self._buffer.clear()
        remote_url = self._config.remote_url

        self._post_with_retry(payload, remote_url)
        logger.debug("Flushed %d audit events", events_sent)

    def _post_with_retry(self, payload: str, remote_url: str) -> None:
        """POST payload to remote_url with exponential backoff."""
        import httpx

        delay = self._config.retry_base_delay
        max_delay = self._config.retry_max_delay

        while not self._shutdown:
            try:
                with httpx.Client(verify=False, timeout=10.0) as client:
                    response = client.post(
                        remote_url,
                        content=payload,
                        headers={"Content-Type": "application/x-ndjson"},
                    )
                    if response.status_code < 400:
                        return
                    if response.status_code == 429:
                        # Rate limiting — use retry-after or default
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
            except httpx.ConnectError as e:
                logger.warning("Audit forward connection error: %s", e)
            except Exception as e:  # noqa: BLE001
                logger.error("Audit forward error: %s", e)

            time.sleep(delay)
            delay = min(delay * 2, max_delay)

    def shutdown(self) -> None:
        """Flush remaining events and stop background processing."""
        self._shutdown = True
        self.flush()
