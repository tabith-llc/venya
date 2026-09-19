# Copyright (c) 2026 Tabith LLC.
# Use of this source code is governed by the Business Source License 1.1
# included in the LICENSE file at the root of this repository. As of the
# Change Date listed there, the work is available under MPL 2.0.
# SPDX-License-Identifier: BUSL-1.1

"""Regression for ticket export-ca-key-echoed-passphrase.

The CA-key export/restore passphrase prompts used echoed input() — the
passphrase protecting the exported (encrypted) CA private key was typed in
cleartext. Fixed to getpass. These tests booby-trap builtins.input: if any
secret-material prompt regresses to echoed input, the test fails loudly.
"""

from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from venya_cli.commands import cmd_admin_export_ca_key, cmd_admin_restore_ca_key


def _boom(*_a, **_k):
    raise AssertionError("secret-material prompt regressed to echoed input()")


class TestCaKeyPromptsHidden:
    def test_export_uses_getpass_and_encrypts(self, tmp_path):
        ca_dir = tmp_path / "ca"
        ca_dir.mkdir()
        (ca_dir / "ca.key").write_bytes(b"DUMMY-CA-KEY-BYTES\n")
        out = tmp_path / "export" / "ca.key.enc"
        args = SimpleNamespace(output=str(out), ca_dir=str(ca_dir))
        with patch("builtins.input", _boom), patch(
            "venya_cli.commands.getpass.getpass", side_effect=["s3cret-pw", "s3cret-pw"]
        ) as gp:
            rc = cmd_admin_export_ca_key(args)
        assert rc == 0
        assert gp.call_count == 2  # prompt + confirm, both hidden
        data = out.read_bytes()
        assert b"DUMMY-CA-KEY-BYTES" not in data  # actually encrypted
        assert out.stat().st_mode & 0o777 == 0o600

    def test_export_mismatch_reprompts(self, tmp_path):
        ca_dir = tmp_path / "ca"
        ca_dir.mkdir()
        (ca_dir / "ca.key").write_bytes(b"K\n")
        args = SimpleNamespace(output=str(tmp_path / "o.enc"), ca_dir=str(ca_dir))
        with patch("builtins.input", _boom), patch(
            "venya_cli.commands.getpass.getpass", side_effect=["a", "b", "pw", "pw"]
        ) as gp:
            rc = cmd_admin_export_ca_key(args)
        assert rc == 0
        assert gp.call_count == 4

    def test_export_empty_passphrase_rejected(self, tmp_path):
        """Negative half: empty passphrase must fail, not export an empty-key file."""
        ca_dir = tmp_path / "ca"
        ca_dir.mkdir()
        (ca_dir / "ca.key").write_bytes(b"K\n")
        out = tmp_path / "o.enc"
        args = SimpleNamespace(output=str(out), ca_dir=str(ca_dir))
        with patch("builtins.input", _boom), patch("venya_cli.commands.getpass.getpass", side_effect=["", ""]):
            rc = cmd_admin_export_ca_key(args)
        assert rc == 1
        assert not out.exists()

    def test_restore_backup_roundtrip_uses_getpass(self, tmp_path):
        ca_dir = tmp_path / "ca"
        ca_dir.mkdir()
        (ca_dir / "ca.key").write_bytes(b"ORIGINAL-KEY\n")
        backup = tmp_path / "b.enc"
        with patch("builtins.input", _boom), patch("venya_cli.commands.getpass.getpass", side_effect=["pw", "pw"]):
            assert cmd_admin_export_ca_key(SimpleNamespace(output=str(backup), ca_dir=str(ca_dir))) == 0
        (ca_dir / "ca.key").unlink()
        with patch("builtins.input", _boom), patch("venya_cli.commands.getpass.getpass", side_effect=["pw"]):
            rc = cmd_admin_restore_ca_key(
                SimpleNamespace(mode="backup", backup_file=str(backup), shares=None, ca_dir=str(ca_dir))
            )
        assert rc == 0
        assert (ca_dir / "ca.key").read_bytes() == b"ORIGINAL-KEY\n"
        assert Path(ca_dir / "ca.key").stat().st_mode & 0o777 == 0o600
