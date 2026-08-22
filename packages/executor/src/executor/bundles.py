"""Shared dataclasses for the executor pipeline."""

from dataclasses import dataclass


@dataclass
class SecretBundle:
    """Secrets retrieved for a command execution."""

    secret_id: str
    value: bytes
    wrapped_value: bytes  # sentinel-wrapped value
    hash: str | None = None  # SHA-256 hex digest of plaintext value
