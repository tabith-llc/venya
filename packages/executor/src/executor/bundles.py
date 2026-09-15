# Copyright (c) 2026 Tabith LLC.
# Use of this source code is governed by the Business Source License 1.1
# included in the LICENSE file at the root of this repository. As of the
# Change Date listed there, the work is available under MPL 2.0.
# SPDX-License-Identifier: BUSL-1.1

"""Shared dataclasses for the executor pipeline."""

from dataclasses import dataclass


@dataclass
class SecretBundle:
    """Secrets retrieved for a command execution."""

    secret_id: str
    value: bytes
    wrapped_value: bytes  # sentinel-wrapped value
    hash: str | None = None  # SHA-256 hex digest of plaintext value
