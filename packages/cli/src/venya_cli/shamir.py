# Copyright (c) 2026 Tabith LLC.
# Use of this source code is governed by the Business Source License 1.1
# included in the LICENSE file at the root of this repository. As of the
# Change Date listed there, the work is available under MPL 2.0.
# SPDX-License-Identifier: BUSL-1.1

"""Shamir's Secret Sharing over GF(256).

Implements Shamir's Secret Sharing (SSS) using GF(256) arithmetic
with the AES irreducible polynomial (x^8 + x^4 + x^3 + x + 1).

This allows splitting a secret (byte string) into N shares where
any K shares can reconstruct it, but fewer than K reveal nothing.

Share format (V2, ticket shamir-combine-no-threshold-verification):
    id | b"V2" | K | shard(checksum + secret)
where checksum = sha256(secret)[:4] is shared along the polynomial, so
combine() can (a) refuse fewer-than-K sets up front and (b) verify the
reconstruction — pre-V2, a K-1 restore SILENTLY yielded a corrupt secret.
Legacy shares (id | shard, no marker) still combine with the old UNVERIFIED
behavior; mixing formats is rejected.

Usage:
    shares = split(b"secret_key_data", threshold=3, shares=5)
    secret = combine(shares[:3])  # any 3 shares work
"""

import hashlib
import os

# AES irreducible polynomial: x^8 + x^4 + x^3 + x + 1
_MODULUS = 0x11B

_V2_MAGIC = b"V2"
_CHECKSUM_LEN = 4


def _checksum(secret: bytes) -> bytes:
    return hashlib.sha256(secret).digest()[:_CHECKSUM_LEN]


def _gf256_add(a: int, b: int) -> int:
    """Addition in GF(256) is XOR."""
    return a ^ b


def _gf256_mul(a: int, b: int) -> int:
    """Multiplication in GF(256) using Russian peasant algorithm."""
    result = 0
    for _ in range(8):
        if b & 1:
            result = _gf256_add(result, a)
        a <<= 1
        if a & 0x100:
            a ^= _MODULUS
        b >>= 1
    return result


def _gf256_inv(a: int) -> int:
    """Multiplicative inverse in GF(256) using exponentiation."""
    if a == 0:
        raise ValueError("Cannot invert zero in GF(256)")
    # a^(-1) = a^(254) in GF(256)
    result = 1
    base = a
    for _ in range(7):  # a^254 = a^(2^8 - 2)
        base = _gf256_mul(base, base)
        result = _gf256_mul(result, base)
    return result


def _lagrange_interpolate(shares: list[tuple[int, int]], x: int) -> int:
    """Lagrange interpolation at point x over GF(256)."""
    result = 0
    for i, (x_i, y_i) in enumerate(shares):
        if x_i == x:
            result = y_i
            break
        numerator = 1
        denominator = 1
        for j, (x_j, _) in enumerate(shares):
            if i != j:
                numerator = _gf256_mul(numerator, _gf256_add(x, x_j))
                denominator = _gf256_mul(denominator, _gf256_add(x_i, x_j))
        lagrange = _gf256_mul(numerator, _gf256_inv(denominator))
        result = _gf256_add(result, _gf256_mul(y_i, lagrange))
    return result


def split(secret: bytes, threshold: int, shares: int) -> list[bytes]:
    """Split a secret into shares using Shamir's Secret Sharing.

    Args:
        secret: The secret bytes to split.
        threshold: Minimum shares needed to reconstruct (K).
        shares: Total number of shares to create (N).

    Returns:
        List of N shares: id byte | b"V2" | K byte | shard bytes, where the
        sharded payload is sha256(secret)[:4] + secret (see module docstring).

    Raises:
        ValueError: If threshold > shares or threshold < 2.
    """
    if threshold < 2:
        raise ValueError("Threshold must be at least 2")
    if threshold > shares:
        raise ValueError("Threshold cannot exceed number of shares")
    if shares > 255:
        raise ValueError("Maximum 255 shares supported")

    payload = _checksum(secret) + secret

    result: list[bytes] = []

    for i in range(len(payload)):
        # Random polynomial of degree (threshold - 1) with payload[i] as constant term
        coeffs = [payload[i]]
        for _ in range(threshold - 1):
            coeffs.append(ord(os.urandom(1)))

        # Evaluate polynomial at points 1, 2, ..., shares
        share_bytes = []
        for x in range(1, shares + 1):
            y = 0
            for coeff in reversed(coeffs):
                y = _gf256_add(_gf256_mul(y, x), coeff)
            share_bytes.append(y)

        result.append(bytes(share_bytes))

    # Transpose: each share gets one byte from each position
    transposed: list[bytearray] = [bytearray() for _ in range(shares)]
    for share in result:
        for i, byte_val in enumerate(share):
            transposed[i].append(byte_val)

    # V2 wire format: id (1-indexed) | magic | K | shard
    return [bytes([i + 1]) + _V2_MAGIC + bytes([threshold]) + share for i, share in enumerate(transposed)]


def combine(shares: list[bytes]) -> bytes:
    """Reconstruct a secret from shares.

    Args:
        shares: List of shares. Each share is one byte ID + body. V2 bodies
                (b"V2" + K + shard) get threshold enforcement + integrity
                verification; legacy bodies (bare shard) reconstruct with the
                old UNVERIFIED behavior — all shares must be the same format.

    Returns:
        The reconstructed secret bytes.

    Raises:
        ValueError: If fewer than 2 shares, duplicate/mismatched IDs or
            lengths, mixed format versions, fewer than K V2 shares, or a
            failed integrity check (corrupt shares / wrong split / < K set).
    """
    if len(shares) < 2:
        raise ValueError("At least 2 shares required")

    # Validate share IDs are unique
    ids = {s[0] for s in shares}
    if len(ids) != len(shares):
        raise ValueError("Duplicate share IDs")

    bodies = [s[1:] for s in shares]
    v2_flags = [b.startswith(_V2_MAGIC) for b in bodies]
    if any(v2_flags) and not all(v2_flags):
        raise ValueError("Mixed share format versions (V2 and legacy) — cannot combine")

    # All shares must have the same body length
    data_len = len(bodies[0])
    for body in bodies:
        if len(body) != data_len:
            raise ValueError("Inconsistent share lengths")

    if all(v2_flags):
        thresholds = {b[2] for b in bodies}
        if len(thresholds) != 1:
            raise ValueError("Inconsistent threshold markers across shares")
        threshold = thresholds.pop()
        if len(shares) < threshold:
            raise ValueError(f"Below threshold: at least {threshold} shares required, got {len(shares)}")
        shard_body = [b[3:] for b in bodies]
    else:
        shard_body = bodies

    # Reconstruct each byte position using Lagrange interpolation at x=0
    result = []
    for pos in range(len(shard_body[0])):
        share_points = [(s[0], shard_body[i][pos]) for i, s in enumerate(shares)]
        result.append(_lagrange_interpolate(share_points, 0))
    reconstructed = bytes(result)

    if all(v2_flags):
        secret = reconstructed[_CHECKSUM_LEN:]
        if reconstructed[:_CHECKSUM_LEN] != _checksum(secret):
            raise ValueError(
                "Integrity check failed — shares are corrupt, truncated, "
                "or from different splits; refusing to return a wrong secret"
            )
        return secret

    return reconstructed
