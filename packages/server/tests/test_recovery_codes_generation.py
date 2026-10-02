# Copyright (c) 2026 Tabith LLC.
# Use of this source code is governed by the Business Source License 1.1
# included in the LICENSE file at the root of this repository. As of the
# Change Date listed there, the work is available under MPL 2.0.
# SPDX-License-Identifier: BUSL-1.1

"""#344: recovery codes are drawn as 48 base62 characters directly.

The old path encoded a 256-bit int and zfill(48)-padded, so EVERY code began
with at least four zeros. These cells pin the format, the alphabet, the death
of the fixed prefix, and exact-string compat for previously issued codes
(hash = sha256(pepper + code); no migration — old codes still verify).
"""

import hashlib

from server.recovery_codes import generate_recovery_code, hash_recovery_code

_ALPHABET = set("0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz")


def _bare(code: str) -> str:
    return code.replace("-", "")


def test_format_48_chars_alphabet_only():
    code = generate_recovery_code()
    groups = code.split("-")
    assert len(groups) == 8
    assert all(len(g) == 6 for g in groups)
    bare = _bare(code)
    assert len(bare) == 48
    assert set(bare) <= _ALPHABET


def test_no_fixed_prefix_across_draws():
    draws = [generate_recovery_code() for _ in range(200)]
    # The old defect: 100% of draws began "0000" (int < 44 base62 digits,
    # zfill prepended >=4 zeros). A single shared first character across all
    # draws would already be a fixed-char class; assert the first character
    # is not constant, and specifically that not all codes begin 0000.
    assert len({d[0] for d in draws}) > 1, "first character is constant across 200 draws"
    assert not all(d.startswith("0000") for d in draws), "fixed zero prefix survived"


def test_old_format_code_still_verifies():
    # Compat cell (GREEN at base too): an issued pre-fix code (the "0000..."
    # shape) matches by exact string against its stored hash.
    pepper = "test-pepper"
    legacy = "000000-00abc1-De2f34-567890-AbCdEf-123456-ABCDEF-abcdef"
    stored = hashlib.sha256((pepper + legacy).encode()).hexdigest()
    assert stored == hash_recovery_code(legacy, pepper)
    assert len(legacy.replace("-", "")) == 48
