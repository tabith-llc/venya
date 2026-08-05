"""Shared dataclasses for the executor pipeline."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass
class SecretBundle:
    """Secrets retrieved for a command execution."""

    secret_id: str
    value: bytes
    wrapped_value: bytes  # sentinel-wrapped value
