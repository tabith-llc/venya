# Copyright (c) 2026 Tabith LLC.
# Use of this source code is governed by the Business Source License 1.1
# included in the LICENSE file at the root of this repository. As of the
# Change Date listed there, the work is available under MPL 2.0.
# SPDX-License-Identifier: BUSL-1.1

"""CA-key backup envelope contract (ticket fido2-device-layer-sweep-findings
finding 5, canonical-format ruling 2026-09-21).

Canonical envelope (CLI-side single implementation — the server's export/
restore pair was retired by issue 336 ruling A, `b7d814d`, and the CLI custody
path owns this format; both "directions" are re-founded here as frozen-spec
pins, no server import — see TestCrossCompatContract):

    b"VENYACA1" + PBKDF2 salt (16) + GCM nonce (12) + AES-256-GCM ct+tag
    KDF: PBKDF2HMAC(SHA256, 32, salt, 600_000)

Legacy alpha.11 CLI CBC envelope (read-only on restore, never written):

    salt (16) + iv (16) + AES-256-CBC(PKCS7(key_pem))

Real crypto only (house discipline — no mocked crypto); paired negatives;
legacy fixtures are minted inline against the FROZEN pre-fix format so the
pins survive the deletion of the old code path. No exported key material may
be stranded.
"""

import os
from types import SimpleNamespace
from unittest.mock import patch

from venya_cli.commands import cmd_admin_export_ca_key, cmd_admin_restore_ca_key

MAGIC = b"VENYACA1"


def _mint_legacy_cbc(plaintext: bytes, passphrase: str) -> bytes:
    """Mint a byte-exact alpha.11 CLI CBC blob (frozen legacy format)."""
    from cryptography.hazmat.primitives import ciphers, hashes
    from cryptography.hazmat.primitives.ciphers import algorithms, modes
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

    salt = os.urandom(16)
    iv = os.urandom(16)
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=600_000)
    key = kdf.derive(passphrase.encode())
    pad = 16 - (len(plaintext) % 16)
    padded = plaintext + bytes([pad]) * pad
    enc = ciphers.Cipher(algorithms.AES(key), modes.CBC(iv)).encryptor()
    return salt + iv + enc.update(padded) + enc.finalize()


def _mint_legacy_cbc_raw(padded: bytes, passphrase: str) -> bytes:
    """Mint a legacy CBC blob from EXACT decrypted bytes — no PKCS7 applied.

    For the weak-validation pin: the pre-fix reader checked only the LAST
    byte's range, so a blob decrypting to an invalid-PKCS7 tail was accepted
    and silently-corrupted key material was restored. `padded` must be a
    multiple of 16 (raw CBC block constraint).
    """
    from cryptography.hazmat.primitives import ciphers, hashes
    from cryptography.hazmat.primitives.ciphers import algorithms, modes
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

    assert len(padded) % 16 == 0
    salt = os.urandom(16)
    iv = os.urandom(16)
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=600_000)
    key = kdf.derive(passphrase.encode())
    enc = ciphers.Cipher(algorithms.AES(key), modes.CBC(iv)).encryptor()
    return salt + iv + enc.update(padded) + enc.finalize()


def _mint_canonical_gcm(plaintext: bytes, passphrase: str) -> bytes:
    """Mint a canonical VENYACA1 GCM blob (contract reference, mirrors both impls)."""
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

    salt = os.urandom(16)
    nonce = os.urandom(12)
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=600_000)
    key = kdf.derive(passphrase.encode())
    return MAGIC + salt + nonce + AESGCM(key).encrypt(nonce, plaintext, None)


def _real_key_pem() -> bytes:
    """A REAL parseable EC P-256 PKCS#8 PEM. Content validation (the fix)
    rejects PEM-shaped dummies, so restore-success paths need bytes that pass
    the compensating control on their merits. House pattern (test_executor_cert_renew)."""
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import ec

    return ec.generate_private_key(ec.SECP256R1()).private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )


# #297: the module fixture key must be a REAL parseable PEM — custody paths
# now unwrap-and-validate the at-rest file, so the old PEM-shaped dummy
# ("real-ca-key-bytes") fails closed. One generated EC key stands in for the
# old dummy constant everywhere it was used as opaque blob content too.
KEY = _real_key_pem()  # pragma: allowlist secret


# Deterministic valid-PKCS7-tail negative constants. #573 lengthened the passphrase this
# vector is keyed to ("wrong-pw" is under the new 15-code-point floor), so the four blocks
# were RE-DERIVED for the current passphrase — constructively rather than by search: fix
# SALT/IV/C_LAST and a pad-1 tail P_last, then set C_PREV := D_k(C_LAST) XOR P_last, which
# forces the final CBC plaintext block to end in 0x01 for THIS passphrase's derived key.
# Same property as the 2026-09-30 offline find (a wrong-key decrypt with a VALID PKCS7
# tail every run — pre-fix it restored 31 bytes of garbage behind the banner); only the
# bytes moved, the assertion below is untouched.
# These are constructed TEST VECTORS (salt/iv/ciphertext), NOT secrets; the
# Hex High Entropy scanner cannot tell, so each line carries the allowlist pragma.
_DET_SALT = "fc47d85811dd9900a702bfb490f3aa6c"  # pragma: allowlist secret
_DET_IV = "3a6a2b7ee5f16f0bfcd38c5a3b8e4f21"  # pragma: allowlist secret
_DET_CPREV = "7120f0d327a5e26cd71a606c603fb71e"  # pragma: allowlist secret
_DET_CLAST = "1c4e7f93b5a2d8e6f0c3a5b7d9e1f2a4"  # pragma: allowlist secret


def _ca_dir(tmp_path, key: bytes = KEY):
    d = tmp_path / "ca"
    d.mkdir(parents=True, exist_ok=True)
    (d / "ca.key").write_bytes(key)
    return d


def _export(tmp_path, pw="pw1-format-roundtrip", key: bytes = KEY):
    ca = _ca_dir(tmp_path, key)
    out = tmp_path / "b.enc"
    with patch("venya_cli.commands.getpass.getpass", side_effect=[pw, pw]):
        rc = cmd_admin_export_ca_key(SimpleNamespace(output=str(out), ca_dir=str(ca)))
    assert rc == 0
    return ca, out


def _restore(ca, blob_path, pw):
    with patch("venya_cli.commands.getpass.getpass", side_effect=[pw]):
        return cmd_admin_restore_ca_key(
            SimpleNamespace(mode="backup", backup_file=str(blob_path), shares=None, ca_dir=str(ca))
        )


class TestCanonicalEnvelope:
    def test_export_writes_canonical_magic(self, tmp_path):
        """CLI export writes the canonical VENYACA1 GCM envelope (was CBC)."""
        _ca, out = _export(tmp_path)
        data = out.read_bytes()
        assert data.startswith(MAGIC)
        assert KEY not in data

    def test_canonical_roundtrip(self, tmp_path):
        key = _real_key_pem()
        ca, out = _export(tmp_path, key=key)
        (ca / "ca.key").unlink()
        assert _restore(ca, out, "pw1-format-roundtrip") == 0
        assert (ca / "ca.key").read_bytes() == key

    def test_restore_minted_canonical_blob(self, tmp_path):
        """A contract-reference canonical blob (minted independently of the
        CLI code) restores — pins the byte format, not the implementation."""
        key = _real_key_pem()
        ca = _ca_dir(tmp_path)
        (ca / "ca.key").unlink()
        blob = tmp_path / "ref.enc"
        blob.write_bytes(_mint_canonical_gcm(key, "refpw-contract-vector"))
        assert _restore(ca, blob, "refpw-contract-vector") == 0
        assert (ca / "ca.key").read_bytes() == key


class TestLegacyCbcReader:
    def test_legacy_cbc_blob_restores(self, tmp_path):
        """No stranded key material: an alpha.11 CBC export still restores."""
        key = _real_key_pem()
        ca = _ca_dir(tmp_path)
        (ca / "ca.key").unlink()
        blob = tmp_path / "legacy.enc"
        blob.write_bytes(_mint_legacy_cbc(key, "oldpw-legacy-vector"))
        assert _restore(ca, blob, "oldpw-legacy-vector") == 0
        assert (ca / "ca.key").read_bytes() == key

    def test_legacy_cbc_bogus_pkcs7_rejected(self, tmp_path):
        """RED-FIRST pin of the weak-validation defect: pre-fix restore checked
        only the LAST padding byte's RANGE. This blob decrypts to a tail of
        [0x0a, 0x03, 0x03, 0x04] — last byte 4 is in 1..16, so the old code
        stripped 4 bytes and restored SILENTLY CORRUPTED key material (rc 0).
        Full PKCS7 requires the last `pad` bytes to ALL equal `pad` → loud rc 1."""
        ca = _ca_dir(tmp_path)
        (ca / "ca.key").unlink()
        blob = tmp_path / "bogus.enc"
        # Raw 16-byte block ending [0x0a, 0x03, 0x03, 0x04]: last byte 4 is
        # in 1..16 (pre-fix accepted, stripped 4 bytes, restored corrupt
        # material); full PKCS7 demands the last 4 bytes ALL equal 4 → reject.
        blob.write_bytes(_mint_legacy_cbc_raw(b"ORIGINAL-KEY\n" + bytes([3, 3, 4]), "pw-weak-validation-vector"))
        rc = _restore(ca, blob, "pw-weak-validation-vector")
        assert rc == 1
        assert not (ca / "ca.key").exists()

    def test_legacy_cbc_wrong_passphrase_rejected(self, tmp_path):
        ca = _ca_dir(tmp_path)
        (ca / "ca.key").unlink()
        blob = tmp_path / "legacy.enc"
        blob.write_bytes(_mint_legacy_cbc(KEY, "right-pw-legacy-vector"))
        assert _restore(ca, blob, "wrong-pw-legacy-vector") == 1

    def test_legacy_cbc_valid_padding_garbage_rejected_deterministic(self, tmp_path, capsys):
        """FIXED-bytes negative (ticket legacy-ca-restore-padding-only-validation):
        a legacy CBC blob whose WRONG-passphrase decrypt carries a VALID PKCS7 tail
        (found offline for these exact constants — final block D_k(c_last) XOR c_prev
        ends in a strict pad-1 tail 0x01). Pre-fix the reader stripped the padding and
        wrote 31 bytes of garbage as ca.key behind the success banner (rc 0). Post-fix
        the write-site content validator rejects it rc 1 EVERY run — deterministic,
        flake class eliminated. The probabilistic pin above is retained as a broad fuzz."""
        ca = _ca_dir(tmp_path)
        (ca / "ca.key").unlink()
        blob = tmp_path / "det.enc"
        # salt(16) + iv(16) + c_prev(16) + c_last(16); IV only steers block 0, so the
        # baked (salt, c_prev, c_last) makes the wrong-key tail valid-PKCS7 every run.
        blob.write_bytes(bytes.fromhex(_DET_SALT + _DET_IV + _DET_CPREV + _DET_CLAST))
        rc = _restore(ca, blob, "wrong-pw-legacy-vector")
        assert rc == 1
        assert not (ca / "ca.key").exists()
        assert "not a valid PEM private key" in capsys.readouterr().err


class TestCanonicalNegatives:
    def test_tampered_ciphertext_rejected(self, tmp_path):
        """Bit-flip in the GCM body → authentication failure, loud rc 1."""
        ca = _ca_dir(tmp_path)
        (ca / "ca.key").unlink()
        blob = tmp_path / "t.enc"
        data = bytearray(_mint_canonical_gcm(KEY, "pw1-format-roundtrip"))
        data[-1] ^= 0xFF
        blob.write_bytes(bytes(data))
        assert _restore(ca, blob, "pw1-format-roundtrip") == 1

    def test_truncated_blob_rejected(self, tmp_path):
        ca = _ca_dir(tmp_path)
        (ca / "ca.key").unlink()
        blob = tmp_path / "tr.enc"
        blob.write_bytes(_mint_canonical_gcm(KEY, "pw1-format-roundtrip")[:40])  # < magic+salt+nonce+tag
        assert _restore(ca, blob, "pw1-format-roundtrip") == 1

    def test_wrong_passphrase_rejected(self, tmp_path):
        ca = _ca_dir(tmp_path)
        (ca / "ca.key").unlink()
        blob = tmp_path / "wp.enc"
        blob.write_bytes(_mint_canonical_gcm(KEY, "right-pw-canonical-vector"))
        assert _restore(ca, blob, "wrong-pw-legacy-vector") == 1


class TestCrossCompatContract:
    """Byte-level contract on the canonical envelope. #336 ruling A deleted the
    server-side export/restore pair (test-only callers, raw-envelope defect), so
    both directions are re-founded HERE at the CLI layer — no server import:
    (1) an independent decoder built from the frozen format spec decrypts a
    CLI-produced blob to exactly the on-disk PEM — the single-envelope pin (the
    deleted pair's defect was re-wrapping the encrypted at-rest file; an
    aligned sibling implementation must see one envelope of key bytes);
    (2) a reference-minted canonical blob (the exact byte shape any aligned
    implementation produces) restores CLI-side to byte-identical real keys."""

    def test_cli_export_independent_decoder_roundtrip(self, tmp_path):
        """Direction 1, re-founded (refs #336): CLI export -> independent
        canonical decode yields the key PEM itself, not a re-wrapped envelope."""
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

        key = _real_key_pem()
        ca, out = _export(tmp_path, pw="xpw-independent-decoder", key=key)
        blob = out.read_bytes()
        assert blob.startswith(MAGIC)
        body = blob[len(MAGIC) :]
        salt, nonce, ciphertext = body[:16], body[16:28], body[28:]
        kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=600_000)
        inner = AESGCM(kdf.derive(b"xpw-independent-decoder")).decrypt(nonce, ciphertext, None)
        assert inner == key
        assert inner == (ca / "ca.key").read_bytes()

    def test_minted_canonical_blob_cli_restore(self, tmp_path):
        """Direction 2, re-founded (refs #336): the minted canonical form — the
        exact bytes the deleted server export produced when correct — restores
        CLI-side unchanged."""
        key = _real_key_pem()
        cli_dir = _ca_dir(tmp_path / "cli", key=key)
        (cli_dir / "ca.key").unlink()
        blob_path = tmp_path / "srv.enc"
        blob_path.write_bytes(_mint_canonical_gcm(key, "xpw-independent-decoder"))
        assert _restore(cli_dir, blob_path, "xpw-independent-decoder") == 0
        assert (cli_dir / "ca.key").read_bytes() == key


class TestSharesRestoreContentGate:
    """The content validator sits at the single convergence write site, so it
    gates shares-mode restore too (not just backup). T6 proves a legitimate
    reconstruction (a real key) passes; T7 proves shares that recombine to
    non-PEM fail closed — the guard is at the convergence site, both modes."""

    def _restore_shares(self, tmp_path, secret: bytes, threshold: int, n_shares: int):
        from venya_cli.shamir import split

        ca = _ca_dir(tmp_path)
        (ca / "ca.key").unlink()
        shares = split(secret, threshold=threshold, shares=n_shares)
        paths = []
        for share in shares[:threshold]:
            p = tmp_path / f"share-{share[0]:02d}"
            p.write_bytes(share[1:])  # handler contract: file stores data, ID from filename
            paths.append(str(p))
        return ca, cmd_admin_restore_ca_key(
            SimpleNamespace(mode="shares", shares=paths, backup_file=None, ca_dir=str(ca))
        )

    def test_shares_restore_real_key_succeeds(self, tmp_path):
        """T6: a legitimate shares reconstruction of a real key passes the gate."""
        key = _real_key_pem()
        ca, rc = self._restore_shares(tmp_path, key, threshold=2, n_shares=3)
        assert rc == 0
        assert (ca / "ca.key").read_bytes() == key

    def test_shares_restore_non_pem_rejected(self, tmp_path, capsys):
        """T7: shares that recombine to non-PEM are rejected rc 1 at the write site."""
        ca, rc = self._restore_shares(tmp_path, b"NOT-PEM-GARBAGE-SECRET-32B!!", threshold=2, n_shares=3)
        assert rc == 1
        assert not (ca / "ca.key").exists()
        assert "not a valid PEM private key" in capsys.readouterr().err
