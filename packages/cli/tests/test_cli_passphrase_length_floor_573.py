# Copyright (c) 2026 Tabith LLC.
# Use of this source code is governed by the Business Source License 1.1
# included in the LICENSE file at the root of this repository. As of the
# Change Date listed there, the work is available under MPL 2.0.
# SPDX-License-Identifier: BUSL-1.1

"""#573 — the CLI CA plane carries a passphrase LENGTH floor (carrier n15).

Owner ruling (s85 batch, verbatim): *"Deny whitespace-only passphrases **and enforce a
proper length passcode.**"* The whitespace half shipped in #554 (`c5712bd`); these cells
are the length half — **15 Unicode code points, INCLUSIVE**, counted on the decoded string
before any encode. The server twin of this file is
`packages/server/tests/test_ca_passphrase_length_floor_573.py`; the two planes are ALIGNED
COPIES (the CLI has no core/server dependency), so each carries its own named constant and
each pins the same blessed sentence.

Doors covered here, with the variant picked by the TRUTH test (a refusal prints
``Nothing was written.`` only where nothing has been written at that point in that door's
flow — proven per door by the filesystem assertion in the same cell):

- WRITE: `admin init-admin-ca`, `admin generate-admin-cert`, `admin cert renew` (all read
  ``VENYA_ADMIN_CA_KEY_PASSPHRASE`` ahead of any write), and the `export-ca-key` passphrase
  prompt (the blob is written below the prompt).
- READ: the `generate-admin-cert` admin-CA key gate, and the `restore-ca-key` backup
  decrypt prompt (its job is to unseal a blob that already exists).

The ceiling (64) is STATED in the text and never enforced — the 65-code-point cell asserts
ACCEPTANCE, and `test_ceiling_flip_changes_no_refusal` proves no door reads that constant.
"""

import inspect
from datetime import UTC
from types import SimpleNamespace

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from venya_cli import commands as commands_mod
from venya_cli.commands import (
    MAX_PASSPHRASE_CODE_POINTS,
    MIN_PASSPHRASE_CODE_POINTS,
    _passphrase_has_material,
    _passphrase_is_below_floor,
    _short_passphrase_refusal,
    cmd_admin_cert_renew,
    cmd_admin_export_ca_key,
    cmd_admin_generate_admin_cert,
    cmd_admin_init_admin_ca,
    cmd_admin_restore_ca_key,
)

ADMIN_ENV = "VENYA_ADMIN_CA_KEY_PASSPHRASE"
_ONE = "a"
_BELOW = _ONE * 14  # 14: refuses — a LITERAL length, so flipping the constant goes red
_AT_FLOOR = _ONE * 15  # 15: passes INCLUSIVE — the boundary is pinned in stone, not derived
_AT_CEILING = _ONE * 64  # 64: passes
_OVER_CEILING = _ONE * 65  # 65: PASSES — the ceiling is stated, not enforced
_SPACED = " sword with spaces in it "  # legal length; the spaces are CONTENT
_ACCENTED_15 = "é" * 15  # 15 code points = 30 UTF-8 bytes
_ACCENTED_14 = "é" * 14  # 14 code points = 28 bytes: over 15 BYTES, under the floor
_LEGAL = [_AT_FLOOR, _AT_CEILING, _OVER_CEILING, _SPACED, _ACCENTED_15]
_LEGAL_IDS = ["at-15", "at-64", "over-65", "meaningful-spaces", "15-accented"]


def _real_key_pem() -> bytes:
    return ec.generate_private_key(ec.SECP256R1()).private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )


def _ca_dir(tmp_path, passphrase=_AT_FLOOR, name="admin-ca.key"):
    """An admin CA directory holding a key sealed with `passphrase` (at-rest encrypted)."""
    from datetime import datetime, timedelta

    from cryptography import x509
    from cryptography.hazmat.primitives import hashes
    from cryptography.x509.oid import NameOID

    d = tmp_path / "ca"
    d.mkdir(parents=True, exist_ok=True)
    key = ec.generate_private_key(ec.SECP256R1())
    (d / name).write_bytes(
        key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.BestAvailableEncryption(passphrase.encode("utf-8")),
        )
    )
    now = datetime.now(UTC)
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Venya Admin CA")])
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + timedelta(days=30))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(key, hashes.SHA256())
    )
    (d / name.replace(".key", ".crt")).write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    return d


class TestFloorUnit:
    """The decision itself, at the one place that makes it."""

    def test_blank_is_still_not_supplied_never_too_short(self, monkeypatch):
        """#554's shipped posture, asserted unchanged: the floor runs AFTER it."""
        for blank in [None, "", " ", "   ", "\t"]:
            if blank is None:
                monkeypatch.delenv(ADMIN_ENV, raising=False)
            else:
                monkeypatch.setenv(ADMIN_ENV, blank)
            supplied = commands_mod._admin_ca_passphrase_or_none()
            assert supplied is None, f"{blank!r} must read as no passphrase"
            assert _passphrase_is_below_floor(supplied) is False

    def test_typed_prompt_ordering_is_material_then_floor(self):
        """The prompt half of the family keeps #554's answer FIRST.

        A blank typed value fails `_passphrase_has_material()` (the shipped "cannot be
        empty" sentence) and the command returns before the floor is asked, so the floor
        never replaces that shape. The floor independently covers the same strings too —
        asserted here so nobody reads the ordering as a hole: a value that reached the
        length check would still be refused, never accepted.
        """
        for blank in ["", "   ", "\t"]:
            assert _passphrase_has_material(blank) is False, "blank is 'no passphrase' first"
            assert _passphrase_is_below_floor(blank) is True, "and the floor would catch it too"

    @pytest.mark.parametrize("value", [_BELOW, _ACCENTED_14], ids=["14-ascii", "14-accented"])
    def test_below_the_floor_is_flagged(self, value):
        assert _passphrase_is_below_floor(value) is True

    @pytest.mark.parametrize("value", _LEGAL, ids=_LEGAL_IDS)
    def test_at_and_above_the_floor_is_not_flagged(self, value):
        assert _passphrase_is_below_floor(value) is False

    def test_code_points_not_bytes(self):
        assert len(_ACCENTED_14) == 14 and len(_ACCENTED_14.encode("utf-8")) == 28
        assert _passphrase_is_below_floor(_ACCENTED_14) is True
        assert _passphrase_is_below_floor(_ACCENTED_15) is False

    def test_the_ruled_numbers_live_in_two_named_constants(self):
        """AC5: one named constant per plane for the floor, one for the stated ceiling."""
        assert MIN_PASSPHRASE_CODE_POINTS == 15
        assert MAX_PASSPHRASE_CODE_POINTS == 64

    def test_the_sentence_carries_the_ruled_digits_as_literals(self):
        """The interpolation proof, pinned with TYPED digits: move MIN and this goes red."""
        assert _passphrase_is_below_floor(_ONE * 14) is True
        assert _passphrase_is_below_floor(_ONE * 15) is False
        assert "at least 15 characters" in _short_passphrase_refusal(ADMIN_ENV)

    def test_value_and_its_length_are_never_echoed(self):
        typed = "sup3rvaluepromptstring"
        message = _short_passphrase_refusal(ADMIN_ENV)
        assert typed not in message
        assert f"{len(typed)} characters" not in message

    def test_read_variant_is_the_blessed_block_minus_one_clause(self):
        write_text = _short_passphrase_refusal(ADMIN_ENV)
        read_text = _short_passphrase_refusal(ADMIN_ENV, read_path=True)
        assert "Nothing was written." in write_text
        assert "Nothing was written." not in read_text
        assert read_text == write_text.replace(
            " Nothing was written.", "", 1
        ), "exactly one clause moves between the doors — no other wording differs"


class TestInitAdminCaWriteDoor:
    def _args(self, tmp_path):
        return SimpleNamespace(output_dir=str(tmp_path / "admin-ca"))

    @pytest.mark.parametrize("phrase", [_BELOW, _ACCENTED_14], ids=["14-ascii", "14-accented"])
    def test_below_floor_refuses_and_creates_nothing(self, tmp_path, monkeypatch, capsys, phrase):
        monkeypatch.setenv(ADMIN_ENV, phrase)
        assert cmd_admin_init_admin_ca(self._args(tmp_path)) == 1
        err = capsys.readouterr().err
        assert err.strip() == _short_passphrase_refusal(ADMIN_ENV), "the blessed write block, word for word"
        assert not (tmp_path / "admin-ca").exists(), "the refusal created the output directory"

    def test_blank_still_answers_with_the_547_refusal_byte_identical(self, tmp_path, monkeypatch, capsys):
        monkeypatch.setenv(ADMIN_ENV, "   ")
        assert cmd_admin_init_admin_ca(self._args(tmp_path)) == 1
        err = capsys.readouterr().err
        assert err.strip() == commands_mod._admin_ca_no_passphrase_refusal()
        assert "shorter than Venya's minimum" not in err

    @pytest.mark.parametrize("phrase", _LEGAL, ids=_LEGAL_IDS)
    def test_legal_length_writes_and_the_key_is_encrypted(self, tmp_path, monkeypatch, phrase):
        monkeypatch.setenv(ADMIN_ENV, phrase)
        assert cmd_admin_init_admin_ca(self._args(tmp_path)) == 0
        key_bytes = (tmp_path / "admin-ca" / "admin-ca.key").read_bytes()
        assert b"ENCRYPTED" in key_bytes
        loaded = serialization.load_pem_private_key(key_bytes, password=phrase.encode("utf-8"))
        assert loaded is not None, "the exact bytes typed are the secret that opened the key"


class TestLeafKeyWriteDoors:
    """Both #547a leaf writers: the floor asks before the ceremony and before any write."""

    def test_generate_admin_cert_below_floor_writes_nothing(self, tmp_path, monkeypatch, capsys):
        ca = _ca_dir(tmp_path)
        out = tmp_path / "leaf"
        monkeypatch.setenv(ADMIN_ENV, _BELOW)
        args = SimpleNamespace(identity="dusty", output_dir=str(out), ca_dir=str(ca))
        assert cmd_admin_generate_admin_cert(args) == 1
        assert not out.exists()
        err = capsys.readouterr().err
        assert "shorter than Venya's minimum" in err and "Nothing was written." in err

    def test_cert_renew_below_floor_skips_the_ceremony_and_writes_nothing(self, tmp_path, monkeypatch, capsys):
        key_path = tmp_path / "admin.key"
        key_path.write_bytes(_real_key_pem())
        client = SimpleNamespace(config=SimpleNamespace(access_token="tok"))
        monkeypatch.setenv(ADMIN_ENV, _ACCENTED_14)
        monkeypatch.setenv("VENYA_ADMIN_CERT", str(tmp_path / "admin.crt"))
        monkeypatch.setenv("VENYA_ADMIN_KEY", str(key_path))
        with monkeypatch.context() as m:
            m.setattr(commands_mod, "_elevate", lambda *a, **k: pytest.fail("ceremony was asked"))
            rc = cmd_admin_cert_renew(client, SimpleNamespace(cert_path=None, key_path=None))
        assert rc == 1
        assert not (tmp_path / "admin.crt").exists(), "the refusal wrote a certificate"
        err = capsys.readouterr().err
        assert "shorter than Venya's minimum" in err

    def test_read_gate_shares_the_predicate_and_the_read_wording(self):
        """Gate-shape cell (the test_n3 pattern from #554): the CA read path may not fork the text."""
        source = inspect.getsource(cmd_admin_generate_admin_cert)
        assert "_admin_ca_passphrase_or_none()" in source
        assert "_passphrase_is_below_floor(passphrase)" in source
        assert "read_path=True" in source, "the CA-key read gate speaks the read variant"


class TestExportPromptWriteDoor:
    def _export(self, tmp_path, typed):
        from unittest.mock import patch

        ca = tmp_path / "ca"
        ca.mkdir(parents=True, exist_ok=True)
        key = _real_key_pem()
        (ca / "ca.key").write_bytes(key)
        out = tmp_path / "o.enc"
        with patch("venya_cli.commands.getpass.getpass", side_effect=[typed, typed]):
            rc = cmd_admin_export_ca_key(SimpleNamespace(output=str(out), ca_dir=str(ca)))
        return rc, out, key

    @pytest.mark.parametrize("phrase", [_BELOW, _ACCENTED_14], ids=["14-ascii", "14-accented"])
    def test_below_floor_refuses_before_any_file_work(self, tmp_path, phrase):
        rc, out, _key = self._export(tmp_path, phrase)
        assert rc == 1
        assert not out.exists(), "the refusal wrote a blob"
        assert not out.parent.joinpath(".venya-cabackup-x").exists()

    def test_refusal_names_the_prompt_not_an_env_var(self, tmp_path, capsys):
        rc, _out, _key = self._export(tmp_path, _BELOW)
        assert rc == 1
        err = capsys.readouterr().err
        assert "the passphrase you enter at this prompt is set to a passphrase" in err
        assert "Nothing was written." in err, "write door: the blob is written below this prompt"
        assert ADMIN_ENV not in err, "this door has no env var to name"

    def test_legal_length_proceeds_and_the_spaces_survive_byte_exact(self, tmp_path):
        rc, out, key = self._export(tmp_path, _SPACED)
        assert rc == 0
        blob = out.read_bytes()
        assert blob[:8] == commands_mod._CA_BLOB_MAGIC
        assert blob != key, "the envelope is not the plaintext key"
        # The envelope opens with the untrimmed bytes and not with the stripped ones.
        from unittest.mock import patch

        ca = out.parent / "ca"
        (ca / "ca.key").unlink()
        with patch("venya_cli.commands.getpass.getpass", side_effect=[_SPACED.strip()]):
            rc2 = cmd_admin_restore_ca_key(
                SimpleNamespace(mode="backup", backup_file=str(out), shares=None, ca_dir=str(ca))
            )
        assert rc2 == 1, "a trimmed passphrase must not open what the untrimmed one sealed"


class TestRestorePromptReadDoor:
    def _blob(self, tmp_path, typed):
        from unittest.mock import patch

        ca = tmp_path / "ca"
        ca.mkdir(parents=True, exist_ok=True)
        key = _real_key_pem()
        (ca / "ca.key").write_bytes(key)
        blob = tmp_path / "b.enc"
        with patch("venya_cli.commands.getpass.getpass", side_effect=[typed, typed]):
            assert cmd_admin_export_ca_key(SimpleNamespace(output=str(blob), ca_dir=str(ca))) == 0
        return ca, blob, key

    def test_below_floor_refuses_with_the_read_wording_and_loads_nothing(self, tmp_path, capsys):
        from unittest.mock import patch

        ca, blob, _key = self._blob(tmp_path, _AT_FLOOR)
        incumbent = (ca / "ca.key").read_bytes()
        (ca / "ca.key").unlink()
        with patch("venya_cli.commands.getpass.getpass", side_effect=[_BELOW]):
            rc = cmd_admin_restore_ca_key(
                SimpleNamespace(mode="backup", backup_file=str(blob), shares=None, ca_dir=str(ca))
            )
        assert rc == 1
        assert not (ca / "ca.key").exists(), "the refused restore wrote a key file"
        err = capsys.readouterr().err
        assert "the passphrase you enter at this prompt is set to a passphrase" in err
        assert "Nothing was written." not in err, "read door: that clause is the one blessed deletion"
        assert "To fix it:" in err and "Reference: docs/" in err
        _ = incumbent

    def test_legal_length_restore_still_proceeds(self, tmp_path):
        from unittest.mock import patch

        ca, blob, key = self._blob(tmp_path, _AT_FLOOR)
        (ca / "ca.key").unlink()
        with patch("venya_cli.commands.getpass.getpass", side_effect=[_AT_FLOOR]):
            rc = cmd_admin_restore_ca_key(
                SimpleNamespace(mode="backup", backup_file=str(blob), shares=None, ca_dir=str(ca))
            )
        assert rc == 0
        assert (ca / "ca.key").read_bytes() == key


class TestCeilingIsStatedOnly:
    def test_text_states_the_supported_maximum(self):
        message = _short_passphrase_refusal(ADMIN_ENV)
        assert "Venya supports passphrases up to 64 characters" in message
        assert "no maximum below" not in message
        assert "always acceptable" not in message

    def test_ceiling_flip_changes_no_refusal(self, tmp_path, monkeypatch):
        """MAX 64→63 moves no door: the constant exists only to interpolate the sentence."""
        monkeypatch.setattr(commands_mod, "MAX_PASSPHRASE_CODE_POINTS", 63)
        for phrase in [_AT_CEILING, _OVER_CEILING]:
            monkeypatch.setenv(ADMIN_ENV, phrase)
            out = tmp_path / f"admin-ca-{len(phrase)}"
            assert cmd_admin_init_admin_ca(SimpleNamespace(output_dir=str(out))) == 0

    def test_floor_flip_moves_the_stated_number(self, monkeypatch):
        monkeypatch.setattr(commands_mod, "MIN_PASSPHRASE_CODE_POINTS", 5)
        message = commands_mod._short_passphrase_refusal(ADMIN_ENV)
        assert "at least 5 characters" in message
        assert "at least 15 characters" not in message
