# Copyright (c) 2026 Tabith LLC.
# Use of this source code is governed by the Business Source License 1.1
# included in the LICENSE file at the root of this repository. As of the
# Change Date listed there, the work is available under MPL 2.0.
# SPDX-License-Identifier: BUSL-1.1

"""Reusable WebAuthn encoding helpers (base64 / base64url handling).

This module is the single source of truth for how the CLI decodes binary
WebAuthn fields (credential IDs, challenges, etc.).

The server emits venya API-response credential_id fields as base64url
(/auth/login/complete), while WebAuthn wire fields (challenge,
allow/excludeCredentials id) remain standard base64. b64_decode_id is a
tolerant reader: it accepts BOTH alphabets, so it stays correct across that
boundary and against any legacy values.
"""

import base64


def b64_decode_id(data: str) -> bytes:
    """Decode a WebAuthn binary field (credential ID, challenge, etc.).

    Accepts both standard base64 (WebAuthn wire fields) and base64url
    (venya response credential_id). Raises ValueError on invalid input.
    """
    if not isinstance(data, str) or not data:
        raise ValueError("Credential ID must be a non-empty string")

    # Try standard base64 first (WebAuthn wire fields: challenge, cred ids)
    try:
        return base64.b64decode(data, validate=True)
    except Exception:  # nosec B110  # noqa: S110
        pass

    # Fall back to base64url (venya response credential_id + browser WebAuthn)
    try:
        padding = 4 - len(data) % 4
        if padding != 4:
            data += "=" * padding
        return base64.urlsafe_b64decode(data)
    except Exception as e:
        raise ValueError(f"Invalid base64 credential ID: {data!r}") from e
