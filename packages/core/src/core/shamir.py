"""Shamir's Secret Sharing over GF(256).

Implements Shamir's Secret Sharing (SSS) using GF(256) arithmetic
with the AES irreducible polynomial (x^8 + x^4 + x^3 + x + 1).

This allows splitting a secret (byte string) into N shares where
any K shares can reconstruct it, but fewer than K reveal nothing.

Usage:
    shares = split(b"secret_key_data", threshold=3, shares=5)
    secret = combine(shares[:3])  # any 3 shares work
"""


import os
from typing import List, Tuple


# AES irreducible polynomial: x^8 + x^4 + x^3 + x + 1
_MODULUS = 0x11B


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


def _lagrange_interpolate(shares: List[Tuple[int, int]], x: int) -> int:
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


def split(secret: bytes, threshold: int, shares: int) -> List[bytes]:
    """Split a secret into shares using Shamir's Secret Sharing.

    Args:
        secret: The secret bytes to split.
        threshold: Minimum shares needed to reconstruct (K).
        shares: Total number of shares to create (N).

    Returns:
        List of N shares, each being threshold bytes + 1 (the share ID byte).

    Raises:
        ValueError: If threshold > shares or threshold < 2.
    """
    if threshold < 2:
        raise ValueError("Threshold must be at least 2")
    if threshold > shares:
        raise ValueError("Threshold cannot exceed number of shares")
    if shares > 255:
        raise ValueError("Maximum 255 shares supported")

    result: List[bytes] = []

    for i in range(len(secret)):
        # Random polynomial of degree (threshold - 1) with secret[i] as constant term
        coeffs = [secret[i]]
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
    transposed: List[bytearray] = [bytearray() for _ in range(shares)]
    for share in result:
        for i, byte_val in enumerate(share):
            transposed[i].append(byte_val)

    # Prepend share ID (1-indexed) to each share
    return [bytes([i + 1]) + share for i, share in enumerate(transposed)]


def combine(shares: List[bytes]) -> bytes:
    """Reconstruct a secret from shares.

    Args:
        shares: List of at least `threshold` shares. Each share is
                one byte ID + data bytes.

    Returns:
        The reconstructed secret bytes.

    Raises:
        ValueError: If fewer than 2 shares provided.
    """
    if len(shares) < 2:
        raise ValueError("At least 2 shares required")

    # Validate share IDs are unique
    ids = {s[0] for s in shares}
    if len(ids) != len(shares):
        raise ValueError("Duplicate share IDs")

    # All shares must have the same data length
    data_len = len(shares[0]) - 1  # Subtract 1 for ID byte
    for share in shares:
        if len(share) - 1 != data_len:
            raise ValueError("Inconsistent share lengths")

    # Reconstruct each byte position using Lagrange interpolation at x=0
    points = [(share[0], share[j + 1]) for share in shares for j in range(data_len)]
    # Group by position
    result = []
    for pos in range(data_len):
        share_points = [(s[0], s[pos + 1]) for s in shares]
        result.append(_lagrange_interpolate(share_points, 0))

    return bytes(result)
