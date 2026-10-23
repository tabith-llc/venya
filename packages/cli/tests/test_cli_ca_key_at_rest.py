# Copyright (c) 2026 Tabith LLC.
# Use of this source code is governed by the Business Source License 1.1
# included in the LICENSE file at the root of this repository. As of the
# Change Date listed there, the work is available under MPL 2.0.
# SPDX-License-Identifier: BUSL-1.1

"""#297 — CA-key custody (export/split/restore) against ENCRYPTED-at-rest keys.

Class-shipped defect: the CLI read ca.key as plaintext while the server has
stored it as PKCS#8-encrypted PEM (4218ec1/3667c6e) since the at-rest
envelope landed. These cells are the missing fixture half (F-matrix, A1 brief
#297 §4): an ENCRYPTED at-rest fixture is planted, then every custody path is
exercised with real cryptography (house discipline: no mocked crypto). The
legacy-plaintext pass-through half is pinned alongside (no-regression).

Truth table (paired negatives per A2): round-trip on encrypted-at-rest,
round-trip on legacy plaintext, wrong server passphrase LOUD on all three
sites with zero writes / zero shards, byte-identity on abort, admin-ca key
variant, no plaintext ever on disk, no secret material in logs.
"""

import logging
import os
import stat
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

from venya_cli.at_rest_key import ensure_secret_dir, rewrap_at_rest, unwrap_at_rest
from venya_cli.commands import (
    _decrypt_ca_backup,
    cmd_admin_export_ca_key,
    cmd_admin_restore_ca_key,
    cmd_admin_split_ca_key,
)

SERVER_PW = "srv-pw-297"  # pragma: allowlist secret — TEST passphrase, never real
ADMIN_PW = "adm-pw-297"  # pragma: allowlist secret
OP_PW = "op-pw-297-operator"  # pragma: allowlist secret


def _boom(*_a, **_k):
    raise AssertionError("secret-material prompt regressed to echoed input()")


def _real_key_pem() -> bytes:
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import ec

    return ec.generate_private_key(ec.SECP256R1()).private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )


def _encrypted_ca(tmp_path, passphrase=SERVER_PW, name="ca.key"):
    """Plant an AT-REST-ENCRYPTED fixture (the half no pre-#297 fixture had)."""
    d = tmp_path / "ca"
    d.mkdir(parents=True, exist_ok=True)
    key = _real_key_pem()
    (d / name).write_bytes(rewrap_at_rest(key, passphrase))
    return d, key


def _plaintext_ca(tmp_path, name="ca.key"):
    d = tmp_path / "ca"
    d.mkdir(parents=True, exist_ok=True)
    key = _real_key_pem()
    (d / name).write_bytes(key)
    return d, key


def _export(ca_dir, out, op_pw=OP_PW):
    with patch("venya_cli.commands.getpass.getpass", side_effect=[op_pw, op_pw]):
        return cmd_admin_export_ca_key(SimpleNamespace(output=str(out), ca_dir=str(ca_dir)))


def _restore_backup(ca_dir, blob, op_pw=OP_PW):
    with patch("venya_cli.commands.getpass.getpass", side_effect=[op_pw]):
        return cmd_admin_restore_ca_key(
            SimpleNamespace(mode="backup", backup_file=str(blob), shares=None, ca_dir=str(ca_dir))
        )


def _split(ca_dir, out_dir, threshold=2, shares=3):
    return cmd_admin_split_ca_key(
        SimpleNamespace(ca_dir=str(ca_dir), output_dir=str(out_dir), threshold=threshold, shares=shares)
    )


class TestAtRestCodecUnitPins:
    def test_rewrap_unwrap_roundtrip(self):
        key = _real_key_pem()
        blob = rewrap_at_rest(key, SERVER_PW)
        assert b"ENCRYPTED" in blob
        assert unwrap_at_rest(blob, SERVER_PW) == key

    def test_unwrap_plaintext_passthrough_is_byte_identical(self):
        key = _real_key_pem()
        assert unwrap_at_rest(key) == key


class TestExportUnwrapsAtRest:
    def test_export_encrypted_blob_carries_plaintext(self, tmp_path, monkeypatch):
        """F1: export on an ENCRYPTED-at-rest install must put the UNWRAPPED
        key in the operator envelope — not ciphertext-of-ciphertext."""
        monkeypatch.setenv("VENYA_CA_KEY_PASSPHRASE", SERVER_PW)
        ca, key = _encrypted_ca(tmp_path)
        out = tmp_path / "b.enc"
        assert _export(ca, out) == 0
        payload = _decrypt_ca_backup(out.read_bytes(), OP_PW)
        assert payload == key
        assert b"ENCRYPTED" not in payload

    def test_export_legacy_plaintext_passthrough(self, tmp_path, monkeypatch):
        """No-regression half: pre-at-rest installs export exactly their bytes."""
        monkeypatch.delenv("VENYA_CA_KEY_PASSPHRASE", raising=False)
        ca, key = _plaintext_ca(tmp_path)
        out = tmp_path / "b.enc"
        assert _export(ca, out) == 0
        assert _decrypt_ca_backup(out.read_bytes(), OP_PW) == key

    def test_export_wrong_server_passphrase_loud(self, tmp_path, monkeypatch, capsys):
        monkeypatch.setenv("VENYA_CA_KEY_PASSPHRASE", "totally-wrong")
        ca, _key = _encrypted_ca(tmp_path)
        out = tmp_path / "b.enc"
        assert _export(ca, out) == 1
        err = capsys.readouterr().err
        assert "failed to decrypt" in err
        assert not out.exists()

    def test_export_headless_without_server_passphrase_loud(self, tmp_path, monkeypatch, capsys):
        monkeypatch.delenv("VENYA_CA_KEY_PASSPHRASE", raising=False)
        ca, _key = _encrypted_ca(tmp_path)
        out = tmp_path / "b.enc"
        with patch("venya_cli.at_rest_key.sys.stdin", MagicMock(isatty=MagicMock(return_value=False))):
            rc = _export(ca, out)
        assert rc == 1
        assert "not set" in capsys.readouterr().err
        assert not out.exists()

    def test_export_getpass_is_primary_and_hidden(self, tmp_path, monkeypatch):
        """Q1: interactive getpass is the primary acquisition; env is override.
        builtins.input is booby-trapped: any echoed prompt fails loud.
        NOTE: commands.getpass and at_rest_key.getpass are the SAME module
        object — one patch sees the full prompt sequence: server unwrap
        first, then operator confirm."""
        monkeypatch.delenv("VENYA_CA_KEY_PASSPHRASE", raising=False)
        ca, key = _encrypted_ca(tmp_path)
        out = tmp_path / "b.enc"
        with (
            patch("builtins.input", _boom),
            patch("venya_cli.at_rest_key.sys.stdin", MagicMock()),
            patch("venya_cli.commands.getpass.getpass", side_effect=[SERVER_PW, OP_PW, OP_PW]) as gp,
        ):
            assert cmd_admin_export_ca_key(SimpleNamespace(output=str(out), ca_dir=str(ca))) == 0
        assert gp.call_count == 3
        assert "VENYA_CA_KEY_PASSPHRASE" in gp.call_args_list[0].args[0]  # server var named in prompt
        assert _decrypt_ca_backup(out.read_bytes(), OP_PW) == key

    def test_export_garbage_source_rejected_loud(self, tmp_path, monkeypatch, capsys):
        """Validator site 1 (export read): bytes that are neither parseable
        plaintext nor passphrase-openable PKCS#8 abort with zero output."""
        monkeypatch.setenv("VENYA_CA_KEY_PASSPHRASE", SERVER_PW)
        d = tmp_path / "ca"
        d.mkdir()
        (d / "ca.key").write_bytes(b"K-NOT-A-KEY\n")
        out = tmp_path / "b.enc"
        assert _export(d, out) == 1
        assert "decrypt" in capsys.readouterr().err.lower()
        assert not out.exists()


class TestSplitPreShardValidation:
    def test_split_encrypted_shards_plaintext(self, tmp_path, monkeypatch):
        """Q2: shards encode the UNWRAPPED key; combine yields the original
        plaintext PEM (pre-fix: silent ciphertext-shares-of-ciphertext)."""
        from venya_cli.shamir import combine

        monkeypatch.setenv("VENYA_CA_KEY_PASSPHRASE", SERVER_PW)
        ca, key = _encrypted_ca(tmp_path)
        od = tmp_path / "shards"
        assert _split(ca, od) == 0
        files = sorted(od.glob("share-*"))
        assert len(files) == 3
        chosen = [bytes([int(p.stem.split("-")[-1])]) + p.read_bytes() for p in files[:2]]
        assert combine(chosen) == key

    def test_split_wrong_server_passphrase_zero_shards(self, tmp_path, monkeypatch):
        """Paired negative: a wrong server passphrase dies at SPLIT time —
        before any shard is written (never plausible-looking garbage shares)."""
        monkeypatch.setenv("VENYA_CA_KEY_PASSPHRASE", "totally-wrong")
        ca, _key = _encrypted_ca(tmp_path)
        od = tmp_path / "shards"
        assert _split(ca, od) == 1
        assert not od.exists()

    def test_split_garbage_source_zero_shards(self, tmp_path, monkeypatch):
        """Validator site 2 (split pre-shard)."""
        monkeypatch.setenv("VENYA_CA_KEY_PASSPHRASE", SERVER_PW)
        d = tmp_path / "ca"
        d.mkdir()
        (d / "ca.key").write_bytes(b"K-NOT-A-KEY\n")
        od = tmp_path / "shards"
        assert _split(d, od) == 1
        assert not od.exists()

    def test_split_then_restore_e2e_over_encrypted_target(self, tmp_path, monkeypatch):
        """F5 e2e (first time ANY test invokes cmd_admin_split_ca_key):
        split(encrypted install) -> restore(mode=shares) -> still encrypted at
        rest and decrypts to the original key."""
        monkeypatch.setenv("VENYA_CA_KEY_PASSPHRASE", SERVER_PW)
        ca, key = _encrypted_ca(tmp_path)
        od = tmp_path / "shards"
        assert _split(ca, od) == 0
        paths = [str(p) for p in sorted(od.glob("share-*"))[:2]]
        with patch("venya_cli.commands.getpass.getpass", return_value=OP_PW):
            rc = cmd_admin_restore_ca_key(
                SimpleNamespace(mode="shares", shares=paths, backup_file=None, ca_dir=str(ca))
            )
        assert rc == 0
        final = (ca / "ca.key").read_bytes()
        assert b"ENCRYPTED" in final
        assert unwrap_at_rest(final, SERVER_PW) == key


class TestRestoreReencrypts:
    def _roundtrip(self, tmp_path, ca, key, unlink=False):
        out = tmp_path / "b.enc"
        assert _export(ca, out) == 0
        if unlink:
            (ca / "ca.key").unlink()
        assert _restore_backup(ca, out) == 0
        return (ca / "ca.key").read_bytes()

    def test_restore_over_encrypted_target_stays_encrypted(self, tmp_path, monkeypatch):
        """F2: export->restore on an encrypted install leaves the at-rest
        envelope in place (pre-fix: validator abort made the round-trip
        impossible — the R6-b drill symptom)."""
        monkeypatch.setenv("VENYA_CA_KEY_PASSPHRASE", SERVER_PW)
        ca, key = _encrypted_ca(tmp_path)
        final = self._roundtrip(tmp_path, ca, key)
        assert b"ENCRYPTED" in final
        assert unwrap_at_rest(final, SERVER_PW) == key

    def test_restore_absent_target_with_env_encrypts(self, tmp_path, monkeypatch):
        """Q5: disaster restore with a known server passphrase -> encrypted."""
        monkeypatch.setenv("VENYA_CA_KEY_PASSPHRASE", SERVER_PW)
        ca, key = _encrypted_ca(tmp_path)
        final = self._roundtrip(tmp_path, ca, key, unlink=True)
        assert b"ENCRYPTED" in final
        assert unwrap_at_rest(final, SERVER_PW) == key

    def test_restore_absent_target_no_env_warns_and_stays_plaintext(self, tmp_path, monkeypatch, capsys):
        """Q5 loud-warning half: passphrase unknown (headless) -> legacy
        plaintext with a stderr warning; server keeps its own boot warning."""
        monkeypatch.delenv("VENYA_CA_KEY_PASSPHRASE", raising=False)
        src, key = _plaintext_ca(tmp_path / "src")
        ca = tmp_path / "dst"
        ca.mkdir()
        out = tmp_path / "b.enc"
        assert _export(src, out) == 0
        assert _restore_backup(ca, out) == 0
        assert (ca / "ca.key").read_bytes() == key
        assert "UNENCRYPTED" in capsys.readouterr().err

    def test_restore_legacy_plaintext_target_stays_plaintext(self, tmp_path, monkeypatch):
        """F4 no-regression: restoring on a pre-at-rest install keeps plaintext
        at rest (byte-identical payload, no silent upgrade, no warning spam)."""
        monkeypatch.delenv("VENYA_CA_KEY_PASSPHRASE", raising=False)
        ca, key = _plaintext_ca(tmp_path)
        final = self._roundtrip(tmp_path, ca, key)
        assert final == key
        assert b"ENCRYPTED" not in final

    def test_restore_wrong_server_passphrase_zero_writes_byte_identical(self, tmp_path, monkeypatch, capsys):
        """F3: wrong server passphrase at rewrap/probe time -> LOUD, the
        current at-rest file is byte-identical afterwards (R6-b property)."""
        monkeypatch.setenv("VENYA_CA_KEY_PASSPHRASE", SERVER_PW)
        ca, _key = _encrypted_ca(tmp_path)
        out = tmp_path / "b.enc"
        assert _export(ca, out) == 0
        before = (ca / "ca.key").read_bytes()
        monkeypatch.setenv("VENYA_CA_KEY_PASSPHRASE", "totally-wrong")
        assert _restore_backup(ca, out) == 1
        err = capsys.readouterr().err
        assert "does not decrypt" in err
        assert (ca / "ca.key").read_bytes() == before
        assert not list(ca.glob("ca.key.*.tmp"))

    def test_no_plaintext_on_disk_after_encrypted_roundtrip(self, tmp_path, monkeypatch):
        """Invariant: plaintext key material is never persisted — scan the
        whole fixture tree post-run for the plaintext PEM body."""
        monkeypatch.setenv("VENYA_CA_KEY_PASSPHRASE", SERVER_PW)
        ca, key = _encrypted_ca(tmp_path)
        final = self._roundtrip(tmp_path, ca, key)
        body = key.splitlines()[1]  # PEM payload line — the plaintext fingerprint
        leftovers = []
        for path in Path(tmp_path).rglob("*"):
            if path.is_file():
                data = path.read_bytes()
                if body in data and b"ENCRYPTED" not in data:
                    leftovers.append(str(path))
        assert not leftovers
        assert b"ENCRYPTED" in final


class TestAdminCaKeyVariant:
    """Q4: custody paths are key-agnostic (ca.key OR admin-ca.key) with the
    matching server env var name (ca.py:150 vs ca.py:619)."""

    def test_export_admin_ca_variant_uses_admin_env(self, tmp_path, monkeypatch):
        monkeypatch.delenv("VENYA_CA_KEY_PASSPHRASE", raising=False)
        monkeypatch.setenv("VENYA_ADMIN_CA_KEY_PASSPHRASE", ADMIN_PW)
        ca, key = _encrypted_ca(tmp_path, passphrase=ADMIN_PW, name="admin-ca.key")
        out = tmp_path / "adm.enc"
        assert _export(ca, out) == 0
        assert _decrypt_ca_backup(out.read_bytes(), OP_PW) == key

    def test_restore_admin_ca_variant_stays_encrypted(self, tmp_path, monkeypatch):
        monkeypatch.delenv("VENYA_CA_KEY_PASSPHRASE", raising=False)
        monkeypatch.setenv("VENYA_ADMIN_CA_KEY_PASSPHRASE", ADMIN_PW)
        ca, key = _encrypted_ca(tmp_path, passphrase=ADMIN_PW, name="admin-ca.key")
        out = tmp_path / "adm.enc"
        assert _export(ca, out) == 0
        assert _restore_backup(ca, out) == 0
        final = (ca / "admin-ca.key").read_bytes()
        assert b"ENCRYPTED" in final
        assert unwrap_at_rest(final, ADMIN_PW) == key


class TestLogHygiene:
    def test_no_secret_material_in_logs(self, tmp_path, monkeypatch, caplog):
        """X-cell: no passphrase or key material in ANY log record, DEBUG."""
        caplog.set_level(logging.DEBUG)
        monkeypatch.setenv("VENYA_CA_KEY_PASSPHRASE", SERVER_PW)
        ca, key = _encrypted_ca(tmp_path)
        out = tmp_path / "b.enc"
        _export(ca, out)
        monkeypatch.setenv("VENYA_CA_KEY_PASSPHRASE", "totally-wrong")
        _restore_backup(ca, out)  # the loud-failure path too
        body = key.splitlines()[1]
        for record in caplog.records:
            msg = record.getMessage()
            assert SERVER_PW not in msg
            assert OP_PW not in msg
            assert body not in msg
            assert "totally-wrong" not in msg


def test_environment_variable_names_match_server_spec():
    """ca.py names, not invented ones (Q1b): default ca.key -> VENYA_CA_KEY_
    PASSPHRASE, admin-ca.key -> VENYA_ADMIN_CA_KEY_PASSPHRASE."""
    from venya_cli.at_rest_key import server_passphrase_env_for

    assert server_passphrase_env_for(Path("/var/lib/venya/ca/ca.key")) == "VENYA_CA_KEY_PASSPHRASE"
    assert server_passphrase_env_for(Path("/var/lib/venya/ca/admin-ca/admin-ca.key")) == "VENYA_ADMIN_CA_KEY_PASSPHRASE"


class TestSecretFileCreationModes:
    """#317: export blob, split shares, and atomic_write_key land 0600 /
    fresh parent dirs 0700 AT CREATION (atomic-create house pattern;
    Path.mkdir(mode=0o700) — verified 0700 survives umask 022)."""

    def test_export_blob_0600_parent_dir_0700_at_creation(self, tmp_path, monkeypatch):
        monkeypatch.setenv("VENYA_CA_KEY_PASSPHRASE", SERVER_PW)
        ca, key = _encrypted_ca(tmp_path)
        out = tmp_path / "backups" / "b.enc"
        old = os.umask(0o022)
        try:
            assert _export(ca, out) == 0
        finally:
            os.umask(old)
        assert stat.S_IMODE(out.parent.stat().st_mode) == 0o700
        assert stat.S_IMODE(out.stat().st_mode) == 0o600
        # byte-content identical envelope to the old write path: decrypts
        assert _decrypt_ca_backup(out.read_bytes(), OP_PW) == key
        assert not list(out.parent.glob(".venya-cabackup-*"))

    def test_export_replaces_preexisting_0644_target(self, tmp_path, monkeypatch):
        monkeypatch.setenv("VENYA_CA_KEY_PASSPHRASE", SERVER_PW)
        ca, key = _encrypted_ca(tmp_path)
        out = tmp_path / "b2.enc"
        out.write_bytes(b"OLD-OLD-OLD" * 200)
        out.chmod(0o644)
        assert _export(ca, out) == 0
        assert _decrypt_ca_backup(out.read_bytes(), OP_PW) == key  # replaced whole
        assert stat.S_IMODE(out.stat().st_mode) == 0o600  # temp mode wins over 0644

    def test_split_shares_0600_dir_0700_at_creation(self, tmp_path, monkeypatch):
        monkeypatch.setenv("VENYA_CA_KEY_PASSPHRASE", SERVER_PW)
        ca, _key = _encrypted_ca(tmp_path)
        od = tmp_path / "shards"
        old = os.umask(0o022)
        try:
            assert _split(ca, od) == 0
        finally:
            os.umask(old)
        assert stat.S_IMODE(od.stat().st_mode) == 0o700
        files = sorted(od.glob("share-*"))
        assert len(files) == 3
        for f in files:
            assert stat.S_IMODE(f.stat().st_mode) == 0o600
            assert len(f.read_bytes()) > 0
        assert not list(od.glob(".venya-share-*"))

    def test_split_replaces_preexisting_share_targets(self, tmp_path, monkeypatch):
        monkeypatch.setenv("VENYA_CA_KEY_PASSPHRASE", SERVER_PW)
        ca, key = _encrypted_ca(tmp_path)
        od = tmp_path / "shards"
        od.mkdir()
        for name in ("share-01", "share-02", "share-03"):
            junk = od / name
            junk.write_bytes(b"GARBAGE" * 50)
            junk.chmod(0o644)
        assert _split(ca, od) == 0
        for f in sorted(od.glob("share-*")):
            assert f.read_bytes() != b"GARBAGE" * 50  # replaced whole
            assert stat.S_IMODE(f.stat().st_mode) == 0o600
        from venya_cli.shamir import combine

        chosen = [bytes([int(p.stem.split("-")[-1])]) + p.read_bytes() for p in sorted(od.glob("share-*"))[:2]]
        assert combine(chosen) == key  # shares are real, byte-correct material

    def test_atomic_write_key_parent_dir_0700_at_creation(self, tmp_path):
        from venya_cli.at_rest_key import atomic_write_key

        d = tmp_path / "keys" / "ca"
        old = os.umask(0o022)
        try:
            atomic_write_key(d / "ca.key", _real_key_pem())
        finally:
            os.umask(old)
        assert stat.S_IMODE(d.stat().st_mode) == 0o700
        assert stat.S_IMODE((d / "ca.key").stat().st_mode) == 0o600


class TestEnsureSecretDir:
    """#317 fold-in: a PRE-EXISTING secret dir gets tightened (never
    loosened); non-owner/group-only cases warn loud and touch nothing."""

    def test_preexisting_0755_owned_dir_tightens_to_0700(self, tmp_path, capsys):
        d = tmp_path / "conf"
        d.mkdir()
        d.chmod(0o755)
        f = d / "token"
        f.write_bytes(b"tok")
        f.chmod(0o600)
        ensure_secret_dir(d)
        assert stat.S_IMODE(d.stat().st_mode) == 0o700
        assert f.read_bytes() == b"tok"  # content flow unchanged (paired positive)
        assert capsys.readouterr().err == ""  # silent one-time tightening, no per-run spam

    def test_ensure_secret_dir_posix_ladder_unchanged(self, tmp_path, monkeypatch, capsys):
        """#438 paired positive: with os.name pinned to "posix", the ladder
        behaves exactly as before the Windows guard — a loose owned dir
        tightens to 0700, silently."""
        monkeypatch.setattr("os.name", "posix")
        d = tmp_path / "conf"
        d.mkdir()
        d.chmod(0o755)
        ensure_secret_dir(d)
        assert stat.S_IMODE(d.stat().st_mode) == 0o700
        assert capsys.readouterr().err == ""

    def test_ensure_secret_dir_non_posix_is_noop(self, tmp_path, monkeypatch, capsys):
        """#438 AC2 negative half: a non-POSIX platform (os.name == "nt")
        must not raise — os.geteuid does not exist there — and must not
        chmod. The geteuid stub raises the exact Windows AttributeError, so
        this cell fails at HEAD and passes only with the guard."""
        monkeypatch.setattr("os.name", "nt")
        monkeypatch.setattr(
            "os.geteuid",
            lambda *a: (_ for _ in ()).throw(AttributeError("module 'os' has no attribute 'geteuid'")),
        )
        d = tmp_path / "conf"
        d.mkdir()
        d.chmod(0o755)
        ensure_secret_dir(d)  # returns without raising
        assert stat.S_IMODE(d.stat().st_mode) == 0o755  # mode unchanged: no chmod attempted
        assert capsys.readouterr().err == ""  # silent no-op, no per-command spam

    def test_already_0700_untouched_no_warning(self, tmp_path, capsys):
        d = tmp_path / "ok"
        d.mkdir(mode=0o700)
        ensure_secret_dir(d)
        assert stat.S_IMODE(d.stat().st_mode) == 0o700
        assert capsys.readouterr().err == ""

    def test_owned_group_only_mode_warns_not_overridden(self, tmp_path, capsys):
        d = tmp_path / "shared"
        d.mkdir()
        d.chmod(0o750)
        ensure_secret_dir(d)
        assert stat.S_IMODE(d.stat().st_mode) == 0o750  # deliberate group grant left intact
        err = capsys.readouterr().err
        assert "WARNING" in err and "mode 750" in err

    def test_looser_not_owned_warns_no_chmod_attempt(self, tmp_path, monkeypatch, capsys):
        d = tmp_path / "svc"
        d.mkdir()
        d.chmod(0o755)
        # chown needs privileges the test lacks; the guard branches on
        # st_uid != geteuid(), so patching geteuid exercises it honestly.
        monkeypatch.setattr("venya_cli.at_rest_key.os.geteuid", lambda: d.stat().st_uid + 1)
        ensure_secret_dir(d)
        assert stat.S_IMODE(d.stat().st_mode) == 0o755  # no chmod attempted
        err = capsys.readouterr().err
        assert "WARNING" in err and "not owned" in err

    def test_atomic_write_key_tightens_preexisting_parent(self, tmp_path):
        from venya_cli.at_rest_key import atomic_write_key

        d = tmp_path / "ca"
        d.mkdir()
        d.chmod(0o755)
        atomic_write_key(d / "ca.key", _real_key_pem())
        assert stat.S_IMODE(d.stat().st_mode) == 0o700
        assert stat.S_IMODE((d / "ca.key").stat().st_mode) == 0o600
