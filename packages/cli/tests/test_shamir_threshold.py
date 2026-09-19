# Copyright (c) 2026 Tabith LLC.
# Use of this source code is governed by the Business Source License 1.1
# included in the LICENSE file at the root of this repository. As of the
# Change Date listed there, the work is available under MPL 2.0.
# SPDX-License-Identifier: BUSL-1.1

"""Regression for ticket shamir-combine-no-threshold-verification.

Pre-fix, combine() performed Lagrange interpolation on ANY >=2 shares with no
threshold or integrity knowledge: restoring a CA key with fewer than K shares
SILENTLY produced a corrupt key (deterministic wrong bytes, no error). Same
for corrupt/truncated share files and shares from different splits.

Fix: V2 share format — id | "V2" | K | shard(sha256-prefix-checksum + secret).
combine() enforces len(shares) >= K up front and verifies the embedded
checksum after reconstruction. Legacy (pre-V2) shares still combine with the
old unverified behavior (backward compat, CLI warns); mixed sets are rejected.
"""

import hashlib
from pathlib import Path
from types import SimpleNamespace

import pytest
from venya_cli.commands import cmd_admin_restore_ca_key
from venya_cli.shamir import combine, split


class TestThresholdEnforcement:
    def test_below_threshold_fails_loudly(self):
        """K=3: any 2 shares must raise, never return bytes."""
        secret = b"CA-KEY-MATERIAL-32-BYTES-LONG!!!"
        shares = split(secret, threshold=3, shares=5)
        with pytest.raises(ValueError, match="[Tt]hreshold|at least 3"):
            combine([shares[0], shares[2]])

    def test_at_threshold_succeeds(self):
        secret = b"CA-KEY-MATERIAL-32-BYTES-LONG!!!"
        shares = split(secret, threshold=3, shares=5)
        assert combine([shares[0], shares[2], shares[4]]) == secret

    def test_corrupt_share_detected(self):
        """A flipped bit inside a K-share set must fail the integrity check."""
        secret = b"another-secret-value"
        shares = split(secret, threshold=3, shares=5)
        corrupted = bytearray(shares[1])
        corrupted[-1] ^= 0x01
        with pytest.raises(ValueError, match="[Ii]ntegrity|corrupt"):
            combine([shares[0], bytes(corrupted), shares[2]])

    def test_shares_from_different_splits_detected(self):
        """Same shape, different splits — must not silently reconstruct junk."""
        shares_a = split(b"secret-aaaa", threshold=2, shares=3)
        shares_b = split(b"secret-bbbb", threshold=2, shares=3)
        with pytest.raises(ValueError, match="[Ii]ntegrity|corrupt|mixed"):
            combine([shares_a[0], shares_b[1]])

    def test_mixed_format_versions_rejected(self):
        secret = b"mixed-test"
        shares = split(secret, threshold=2, shares=3)
        legacy = shares[0][:1] + shares[0][4:]  # strip "V2"+K -> legacy shape
        with pytest.raises(ValueError, match="[Mm]ixed"):
            combine([legacy, shares[1]])


class TestLegacyCompat:
    def test_legacy_shares_still_combine(self):
        """Pre-V2 shares (id | shard) keep working — old unverified semantics:
        the reconstruction returns the shared payload as-is."""
        secret = b"legacy-secret"
        shares = split(secret, threshold=2, shares=3)
        legacy = [s[:1] + s[4:] for s in (shares[0], shares[1])]
        payload = combine(legacy)
        # V2 payload = sha256 checksum prefix + secret; legacy path returns it raw
        assert payload[4:] == secret
        assert payload[:4] == hashlib.sha256(secret).digest()[:4]


class TestRestoreHandler:
    def _write_shares(self, tmp_path: Path, shares: list[bytes]) -> list[str]:
        paths = []
        for share in shares:
            p = tmp_path / f"share-{share[0]:02d}"
            p.write_bytes(share[1:])  # handler contract: files store data, ID from filename
            paths.append(str(p))
        return paths

    def test_restore_below_threshold_refuses_and_writes_nothing(self, tmp_path):
        secret = b"THE-CA-KEY"
        shares = split(secret, threshold=3, shares=5)
        ca_dir = tmp_path / "ca"
        ca_dir.mkdir()
        paths = self._write_shares(tmp_path, [shares[0], shares[1]])
        args = SimpleNamespace(mode="shares", shares=paths, backup_file=None, ca_dir=str(ca_dir))
        rc = cmd_admin_restore_ca_key(args)
        assert rc == 1
        assert not (ca_dir / "ca.key").exists()  # never writes a corrupt key

    def test_restore_at_threshold_roundtrips(self, tmp_path):
        secret = b"THE-CA-KEY"
        shares = split(secret, threshold=2, shares=3)
        ca_dir = tmp_path / "ca"
        ca_dir.mkdir()
        paths = self._write_shares(tmp_path, [shares[0], shares[2]])
        args = SimpleNamespace(mode="shares", shares=paths, backup_file=None, ca_dir=str(ca_dir))
        rc = cmd_admin_restore_ca_key(args)
        assert rc == 0
        restored = ca_dir / "ca.key"
        assert restored.read_bytes() == secret
        assert restored.stat().st_mode & 0o777 == 0o600
