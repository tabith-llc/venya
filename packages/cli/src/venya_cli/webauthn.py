# Copyright (c) 2026 Tabith LLC.
# Use of this source code is governed by the Business Source License 1.1
# included in the LICENSE file at the root of this repository. As of the
# Change Date listed there, the work is available under MPL 2.0.
# SPDX-License-Identifier: BUSL-1.1

"""Reusable WebAuthn encoding helpers (base64 / base64url handling).

This module is the single source of truth for how binary fields
(credential IDs, etc.) are encoded in Venya's WebAuthn JSON.

The server currently emits standard base64 for credential IDs
(packages/server/src/server/fido2/manager.py:253). This helper
accepts both standard base64 and base64url for forward compatibility.
"""

import base64


def b64_decode_id(data: str) -> bytes:
    """Decode a WebAuthn binary field (credential ID, challenge, etc.).

    Accepts both standard base64 (current server) and base64url.
    Raises ValueError on invalid input.
    """
    if not isinstance(data, str) or not data:
        raise ValueError("Credential ID must be a non-empty string")

    # Try standard base64 first (exact match to what the server emits today)
    try:
        return base64.b64decode(data, validate=True)
    except Exception:  # nosec B110  # noqa: S110
        pass

    # Fall back to base64url (used by browsers and many WebAuthn libraries)
    try:
        padding = 4 - len(data) % 4
        if padding != 4:
            data += "=" * padding
        return base64.urlsafe_b64decode(data)
    except Exception as e:
        raise ValueError(f"Invalid base64 credential ID: {data!r}") from e


def b64_encode_id(data: bytes) -> str:
    """Encode bytes as standard base64 without padding (server convention)."""
    return base64.b64encode(data).decode("ascii").rstrip("=")
