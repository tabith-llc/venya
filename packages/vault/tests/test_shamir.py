"""Tests for Shamir's Secret Sharing module."""

import os
from pathlib import Path

import pytest

from vault.shamir import combine, split


class TestShamirSplitCombine:
    """Tests for Shamir's Secret Sharing split and combine."""

    def test_basic_split_combine(self):
        """Basic split and combine with threshold=3, shares=5."""
        secret = b"test secret key data here!!!"
        shares = split(secret, threshold=3, shares=5)

        assert len(shares) == 5
        # Each share has 1 ID byte + len(secret) data bytes
        assert len(shares[0]) == len(secret) + 1

        # Any 3 shares should reconstruct
        for i in range(5):
            for j in range(i + 1, 5):
                for k in range(j + 1, 5):
                    reconstructed = combine([shares[i], shares[j], shares[k]])
                    assert reconstructed == secret

    def test_threshold_2(self):
        """Split with threshold=2."""
        secret = b"short"
        shares = split(secret, threshold=2, shares=3)

        assert len(shares) == 3
        # Any 2 shares should work
        assert combine([shares[0], shares[1]]) == secret
        assert combine([shares[0], shares[2]]) == secret
        assert combine([shares[1], shares[2]]) == secret

    def test_threshold_equals_shares(self):
        """All shares required when threshold == shares."""
        secret = b"all required"
        shares = split(secret, threshold=5, shares=5)

        # All 5 shares needed
        reconstructed = combine(shares)
        assert reconstructed == secret

        # Any 4 shares should produce wrong result
        for i in range(5):
            subset = shares[:i] + shares[i + 1:]
            reconstructed = combine(subset)
            assert reconstructed != secret, f"4 shares incorrectly reconstructed for index {i}"

    def test_various_secret_sizes(self):
        """Test with various secret sizes."""
        for size in [1, 8, 16, 32, 64, 128, 255]:
            secret = os.urandom(size)
            shares = split(secret, threshold=2, shares=3)
            assert combine([shares[0], shares[1]]) == secret

    def test_empty_secret(self):
        """Empty secret can be split and combined."""
        secret = b""
        shares = split(secret, threshold=2, shares=3)
        assert len(shares) == 3
        assert len(shares[0]) == 1  # Only ID byte
        assert combine([shares[0], shares[1]]) == secret

    def test_all_zero_bytes(self):
        """Secret of all zero bytes."""
        secret = b"\x00" * 32
        shares = split(secret, threshold=3, shares=5)
        for i in range(5):
            for j in range(i + 1, 5):
                for k in range(j + 1, 5):
                    reconstructed = combine([shares[i], shares[j], shares[k]])
                    assert reconstructed == secret

    def test_all_ff_bytes(self):
        """Secret of all 0xFF bytes."""
        secret = b"\xff" * 32
        shares = split(secret, threshold=3, shares=5)
        for i in range(5):
            for j in range(i + 1, 5):
                for k in range(j + 1, 5):
                    reconstructed = combine([shares[i], shares[j], shares[k]])
                    assert reconstructed == secret

    def test_binary_secret(self):
        """Secret with all possible byte values."""
        secret = bytes(range(256))
        shares = split(secret, threshold=2, shares=4)
        assert combine([shares[0], shares[1]]) == secret

    def test_share_ids_are_unique(self):
        """Share IDs should be unique (1-indexed)."""
        shares = split(b"test", threshold=3, shares=5)
        ids = {s[0] for s in shares}
        assert len(ids) == 5
        assert ids == {1, 2, 3, 4, 5}

    def test_share_ids_are_1_indexed(self):
        """Share IDs start at 1, not 0."""
        shares = split(b"test", threshold=2, shares=3)
        for share in shares:
            assert share[0] >= 1
            assert share[0] <= 3


class TestShamirErrors:
    """Tests for error handling in Shamir's Secret Sharing."""

    def test_threshold_too_low(self):
        """Threshold must be at least 2."""
        with pytest.raises(ValueError, match="Threshold must be at least 2"):
            split(b"secret", threshold=1, shares=3)

    def test_threshold_exceeds_shares(self):
        """Threshold cannot exceed number of shares."""
        with pytest.raises(ValueError, match="Threshold cannot exceed"):
            split(b"secret", threshold=5, shares=3)

    def test_too_many_shares(self):
        """Maximum 255 shares supported."""
        with pytest.raises(ValueError, match="Maximum 255 shares"):
            split(b"secret", threshold=2, shares=256)

    def test_combine_too_few_shares(self):
        """Combine requires at least 2 shares."""
        with pytest.raises(ValueError, match="At least 2 shares"):
            combine([b"\x01\x02"])

    def test_combine_duplicate_ids(self):
        """Duplicate share IDs are rejected."""
        with pytest.raises(ValueError, match="Duplicate share IDs"):
            combine([b"\x01\x02", b"\x01\x03"])

    def test_combine_inconsistent_lengths(self):
        """Inconsistent share lengths are rejected."""
        with pytest.raises(ValueError, match="Inconsistent share lengths"):
            combine([b"\x01\x02\x03", b"\x02\x04"])


class TestShamirGF256:
    """Tests for underlying GF(256) arithmetic."""

    def test_gf256_add_is_xor(self):
        """GF(256) addition is XOR."""
        from vault.shamir import _gf256_add

        assert _gf256_add(0, 0) == 0
        assert _gf256_add(1, 1) == 0
        assert _gf256_add(255, 255) == 0
        assert _gf256_add(0xAB, 0x53) == 0xF8
        assert _gf256_add(100, 200) == 172  # 100 ^ 200 = 172

    def test_gf256_mul_identity(self):
        """Multiplying by 1 returns the same value."""
        from vault.shamir import _gf256_mul

        for i in range(256):
            assert _gf256_mul(i, 1) == i
            assert _gf256_mul(1, i) == i

    def test_gf256_mul_zero(self):
        """Multiplying by 0 returns 0."""
        from vault.shamir import _gf256_mul

        for i in range(256):
            assert _gf256_mul(i, 0) == 0
            assert _gf256_mul(0, i) == 0

    def test_gf256_mul_commutative(self):
        """GF(256) multiplication is commutative."""
        from vault.shamir import _gf256_mul

        for _ in range(100):
            a = os.urandom(1)[0]
            b = os.urandom(1)[0]
            assert _gf256_mul(a, b) == _gf256_mul(b, a)

    def test_gf256_mul_associative(self):
        """GF(256) multiplication is associative."""
        from vault.shamir import _gf256_mul

        for _ in range(100):
            a = os.urandom(1)[0]
            b = os.urandom(1)[0]
            c = os.urandom(1)[0]
            if a != 0 and b != 0 and c != 0:
                assert _gf256_mul(_gf256_mul(a, b), c) == _gf256_mul(a, _gf256_mul(b, c))

    def test_gf256_inv(self):
        """Inverse of a * a^(-1) should be 1."""
        from vault.shamir import _gf256_inv, _gf256_mul

        for i in range(1, 256):
            inv = _gf256_inv(i)
            assert _gf256_mul(i, inv) == 1

    def test_gf256_inv_zero_raises(self):
        """Inverse of zero should raise."""
        from vault.shamir import _gf256_inv

        with pytest.raises(ValueError, match="Cannot invert zero"):
            _gf256_inv(0)
