# Copyright (c) 2026 Tabith LLC.
# Use of this source code is governed by the Business Source License 1.1
# included in the LICENSE file at the root of this repository. As of the
# Change Date listed there, the work is available under MPL 2.0.
# SPDX-License-Identifier: BUSL-1.1

"""Break-glass recovery code generation + hashing — single source of truth.

Ticket recovery-code-reissue (#296, Q8 ruling): consolidates three former
copies — init.py's private _generate_recovery_code/_hash_recovery_code and
recovery.py's inline sha256(pepper+code) expression — into this module.
Semantics are VERBATIM from init.py (256-bit, base62, 8 groups of 6;
sha256(pepper + code) hex). The equivalence pins live in
packages/server/tests/test_recovery.py (helper == old-inline expression),
so the refactor is provably behavior-preserving.

The plaintext code exists ONLY transiently: returned once to the operator,
never logged, never stored (only the hash crosses the DB boundary).
"""

import hashlib
import secrets

_BASE62_ALPHABET = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"


def generate_recovery_code() -> str:
    """Generate a break-glass recovery code.

    256 bits of randomness, encoded as base62, split into 8 groups of 6.
    Format: XXXXXX-XXXXXX-XXXXXX-XXXXXX-XXXXXX-XXXXXX-XXXXXX-XXXXXX
    """
    raw_bytes = secrets.token_bytes(256 // 8)
    # Convert to base62
    number = int.from_bytes(raw_bytes, byteorder="big")
    base62 = ""
    while number > 0:
        number, remainder = divmod(number, len(_BASE62_ALPHABET))
        base62 = _BASE62_ALPHABET[remainder] + base62
    # Pad to 48 characters (8 groups of 6)
    base62 = base62.zfill(48)
    # Split into groups of 6
    groups = [base62[i : i + 6] for i in range(0, 48, 6)]
    return "-".join(groups)


def hash_recovery_code(code: str, pepper: str) -> str:
    """Hash a recovery code with a server-side pepper.

    Uses SHA-256 with pepper prepended to the code — byte-for-byte the
    construction recovery.py validated against and init.py issued with.
    """
    return hashlib.sha256((pepper + code).encode()).hexdigest()
