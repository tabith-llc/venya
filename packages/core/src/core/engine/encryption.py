# Copyright (c) 2026 Tabith LLC.
# Use of this source code is governed by the Business Source License 1.1
# included in the LICENSE file at the root of this repository. As of the
# Change Date listed there, the work is available under MPL 2.0.
# SPDX-License-Identifier: BUSL-1.1

"""ChaCha20-Poly1305 AEAD encryption + Argon2id key derivation.

Per-secret Data Encryption Key (DEK) encrypted by Key Encryption Key (KEK).
KEK (32 bytes) wraps plaintext DEK (32 bytes) via AES-256-KW (RFC 5649)
to produce wrapped DEK (40 bytes: 32-byte DEK + 8-byte AEAD tag).
"""

import os
from typing import Final

from argon2.low_level import Type, hash_secret_raw
from Crypto.Cipher import AES as PyCryptoAES  # nosec B413 — AES-KW per RFC 5649 requires pycryptodome
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

# Argon2id parameters per plan: 3 iterations, 4 lanes, 64MB memory
ARGON2_TIME_COST: Final[int] = 3
ARGON2_MEMORY_COST: Final[int] = 2**16  # 64 MB in KiB
ARGON2_PARALLELISM: Final[int] = 4
ARGON2_HASH_LEN: Final[int] = 32
ARGON2_SALT_LEN: Final[int] = 16

# KEK/DEK sizes
KEK_SIZE: Final[int] = 32
DEK_SIZE: Final[int] = 32

# ChaCha20 nonce size
CHACHA20_NONCE_SIZE: Final[int] = 12  # 12-byte (96-bit) nonce


class EncryptionError(Exception):
    """Base encryption error."""


class DecryptionError(EncryptionError):
    """Decryption failed — possibly corrupted data or wrong key."""


class KeyDerivationError(EncryptionError):
    """Failed to derive keys."""


def derive_kek(passphrase: bytes, salt: bytes | None = None) -> tuple[bytes, bytes]:
    """Derive a 32-byte KEK from a passphrase using Argon2id.

    Args:
        passphrase: The master passphrase.
        salt: Optional salt (16 bytes). If not provided, a random salt is generated.

    Returns:
        Tuple of (KEK, salt): KEK is 32 bytes, salt is 16 bytes.
    """
    if salt is None:
        salt = os.urandom(ARGON2_SALT_LEN)

    kek = hash_secret_raw(
        secret=passphrase,
        salt=salt,
        time_cost=ARGON2_TIME_COST,
        memory_cost=ARGON2_MEMORY_COST,
        parallelism=ARGON2_PARALLELISM,
        hash_len=ARGON2_HASH_LEN,
        type=Type.ID,
    )
    return kek, salt


def wrap_key(kek: bytes, plaintext_key: bytes) -> bytes:
    """Wrap a DEK using AES-256-KW (RFC 5649).

    Args:
        kek: 32-byte Key Encryption Key.
        plaintext_key: 32-byte Data Encryption Key to wrap.

    Returns:
        40-byte wrapped key (32-byte ciphertext + 8-byte ICV tag).

    Raises:
        KeyDerivationError: If key sizes are invalid.
    """
    if len(kek) != KEK_SIZE:
        raise KeyDerivationError(f"KEK must be {KEK_SIZE} bytes, got {len(kek)}")
    if len(plaintext_key) != DEK_SIZE:
        raise KeyDerivationError(f"DEK must be {DEK_SIZE} bytes, got {len(plaintext_key)}")

    return _aes_kw_wrap(kek, plaintext_key)


def unwrap_key(kek: bytes, wrapped_key: bytes) -> bytes:
    """Unwrap a DEK using AES-256-KW (RFC 5649).

    Args:
        kek: 32-byte Key Encryption Key.
        wrapped_key: 40-byte wrapped key.

    Returns:
        32-byte unwrapped Data Encryption Key.

    Raises:
        DecryptionError: If unwrapping fails (wrong key or corrupted data).
    """
    if len(kek) != KEK_SIZE:
        raise KeyDerivationError(f"KEK must be {KEK_SIZE} bytes, got {len(kek)}")
    if len(wrapped_key) != KEK_SIZE + 8:  # DEK + ICV tag
        raise KeyDerivationError(f"Wrapped key must be {KEK_SIZE + 8} bytes, got {len(wrapped_key)}")

    return _aes_kw_unwrap(kek, wrapped_key)


def encrypt_secret(kek: bytes, secret_value: bytes) -> tuple[bytes, bytes, bytes]:
    """Encrypt a secret value using per-secret random DEK and nonce.

    Uses DEK/KEK model:
    1. Generate random 32-byte DEK
    2. Wrap DEK with KEK (AES-256-KW)
    3. Encrypt secret with DEK (ChaCha20-Poly1305)

    Args:
        kek: 32-byte Key Encryption Key.
        secret_value: The plaintext secret to encrypt.

    Returns:
        Tuple of (wrapped_dek, nonce, ciphertext_with_tag).
    """
    # Generate random DEK and nonce
    dek = os.urandom(DEK_SIZE)
    nonce = os.urandom(CHACHA20_NONCE_SIZE)

    # Wrap the DEK
    wrapped_dek = wrap_key(kek, dek)

    # Encrypt the secret with ChaCha20-Poly1305
    chacha = ChaCha20Poly1305(dek)
    ciphertext = chacha.encrypt(nonce, secret_value, None)

    return wrapped_dek, nonce, ciphertext


def decrypt_secret(kek: bytes, wrapped_dek: bytes, nonce: bytes, ciphertext: bytes) -> bytes:
    """Decrypt a secret value.

    Uses DEK/KEK model:
    1. Unwrap DEK with KEK (AES-256-KW)
    2. Decrypt secret with DEK (ChaCha20-Poly1305)

    Args:
        kek: 32-byte Key Encryption Key.
        wrapped_dek: 40-byte wrapped Data Encryption Key.
        nonce: 12-byte ChaCha20 nonce.
        ciphertext: Encrypted data with AEAD tag.

    Returns:
        Decrypted plaintext secret.

    Raises:
        DecryptionError: If decryption fails.
    """
    # Unwrap the DEK
    dek = unwrap_key(kek, wrapped_dek)

    # Decrypt with ChaCha20-Poly1305
    chacha = ChaCha20Poly1305(dek)
    try:
        plaintext = chacha.decrypt(nonce, ciphertext, None)
    except InvalidTag:
        raise DecryptionError("Decryption failed: invalid tag (wrong key or corrupted data)")

    return plaintext


def _aes_kw_wrap(kek: bytes, plaintext: bytes) -> bytes:
    """AES-Key-Wrap per RFC 5649 using pycryptodome.

    Args:
        kek: 32-byte AES-256 key.
        plaintext: Data to wrap (must be 8-{(2**32-2)*8} bytes, multiple of 8).

    Returns:
        Wrapped data (input length + 8 bytes).
    """
    n = len(plaintext) // 8
    if n * 8 != len(plaintext) or n < 1:
        raise KeyDerivationError(f"Plaintext must be 8-{(2**32 - 2) * 8} bytes and a multiple of 8")

    # IV per RFC 5649
    a = b"\xa6\xa6\xa6\xa6\xa6\xa6\xa6\xa6"

    # AES-KW wrap algorithm (RFC 5649 Section 2.2.3)
    for i in range(1, n + 1):
        # Encrypt A || R[i]
        cipher = PyCryptoAES.new(kek, PyCryptoAES.MODE_ECB)  # nosec B305 — AES-KW per RFC 5649 requires ECB
        encrypted = cipher.encrypt(a + plaintext[(i - 1) * 8 : i * 8])

        # Split result
        a = encrypted[:8]
        plaintext = plaintext[: (i - 1) * 8] + encrypted[8:] + plaintext[i * 8 :]

        # XOR A with (t + i) where t = n * 64
        a_int = int.from_bytes(a, "big")
        a_int ^= n * 64 + i
        a = a_int.to_bytes(8, "big")

    # Output: A || R[1] || R[2] || ... || R[n]
    return a + plaintext


def _aes_kw_unwrap(kek: bytes, ciphertext: bytes) -> bytes:
    """AES-Key-Unwrap per RFC 5649 using pycryptodome.

    Args:
        kek: 32-byte AES-256 key.
        ciphertext: Wrapped data (must be 9-{(2**32-1)*8} bytes, multiple of 8).

    Returns:
        Unwrapped plaintext.

    Raises:
        DecryptionError: If unwrap fails (wrong key).
    """
    n = len(ciphertext) // 8 - 1
    if n * 8 + 8 != len(ciphertext) or n < 1:
        raise DecryptionError(f"Ciphertext must be 9-{(2**32 - 1) * 8} bytes and a multiple of 8")

    # Split ciphertext
    a = ciphertext[:8]
    plaintext = ciphertext[8:]

    # AES-KU algorithm (RFC 5649 Section 5)
    for i in range(n, 0, -1):
        # XOR A with (t + i) where t = n * 64
        a_int = int.from_bytes(a, "big")
        a_int ^= n * 64 + i
        a = a_int.to_bytes(8, "big")

        # Decrypt A || R[i]
        cipher = PyCryptoAES.new(kek, PyCryptoAES.MODE_ECB)  # nosec B305 — AES-KW per RFC 5649 requires ECB
        decrypted = cipher.decrypt(a + plaintext[(i - 1) * 8 : i * 8])

        # Split result
        a = decrypted[:8]
        plaintext = plaintext[: (i - 1) * 8] + decrypted[8:] + plaintext[i * 8 :]

    # Verify IV
    if a != b"\xa6\xa6\xa6\xa6\xa6\xa6\xa6\xa6":
        raise DecryptionError("Unwrap failed: integrity check failed (wrong key)")

    return plaintext


def _bytes_to_int(b: bytes) -> int:
    """Convert bytes to big-endian integer."""
    return int.from_bytes(b, byteorder="big")


def _int_to_bytes(i: int, length: int) -> bytes:
    """Convert integer to big-endian bytes of specified length."""
    return i.to_bytes(length, byteorder="big")
