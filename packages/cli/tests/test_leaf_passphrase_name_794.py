# Copyright (c) 2026 Tabith LLC.
# Use of this source code is governed by the Business Source License 1.1
# included in the LICENSE file at the root of this repository. As of the
# Change Date listed there, the work is available under MPL 2.0.
# SPDX-License-Identifier: BUSL-1.1

"""iid 794 — the admin passphrase NAME must not assert a CA secret at the LEAF doors.

`VENYA_ADMIN_CA_KEY_PASSPHRASE` is read on two planes (#554's one-name-two-planes ruling,
which is shipped law and is NOT moved by this leg): the Admin CA key, and the admin CLIENT
(leaf) key that `admin cert renew` / `admin generate-admin-cert` mint and that an admin mTLS
dial opens. The variable name cannot move — a rename is a config-contract change — so the
SENTENCES are what has to be true: at a leaf door the text an operator acts on names the key
this command writes or opens, and does not send him for a CA secret he neither needs nor has.

**The trap this file is written around.** `git grep` over a source file RETURNS the old
literal from docstrings and from the CA doors, where it is correct — so a file-level check is
red on good text and green on bad text. Every cell here runs the shipped builder (or the
shipped command) and asserts on the string that came back. Two predicates carry it:

* the ACTION text — the headline plus the `To fix it:` block, with the variable name removed
  because the name is fixed by ruling — contains no standalone `ca` token. `init-admin-ca`
  matches that token too (a hyphen is a word boundary), so one predicate covers both "names a
  CA" and "points at the CA mint"; and
* it names the key the command itself touches.

The CA doors are the positive control, pinned against LITERALS typed in this file (never
against the shipped function, which would move both sides at once). And the shared predicate
is asserted NOT split: the leaf reader still delegates, and blank is one answer on both
planes — the #554 law this leg must not disturb.
"""

import os
import re
import stat
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from test_cli_admin_leaf_key_passphrase_547a import _minted_cert_pem, _renew_args, _renew_client, _seed_pair
from venya_cli.api_client import APIClient, APIClientError, _admin_key_no_passphrase_refusal, _build_ssl_context
from venya_cli.commands import (
    ADMIN_CA_SETUP_FRAGMENT,
    _admin_ca_no_passphrase_refusal,
    _admin_ca_passphrase_or_none,
    _admin_leaf_key_no_passphrase_refusal,
    _admin_leaf_key_passphrase_or_none,
    cmd_admin_cert_renew,
    cmd_admin_generate_admin_cert,
    cmd_admin_init_admin_ca,
)

VAR = "VENYA_ADMIN_CA_KEY_PASSPHRASE"
# dev-only test values, 26 and 27 code points: both clear the #573 floor, so no cell here can
# be answering the length door by accident, and neither is ever printed. pragma per conftest.py's
# TEST_EXECUTOR_KEY_PASSPHRASE — a TEST value in a test file, never real, never shipped.
CA_SIDE_PASSPHRASE = "test-ca-side-passphrase-794"  # pragma: allowlist secret — TEST value, never real
LEAF_SIDE_PASSPHRASE = "test-leaf-side-passphrase-794x"  # pragma: allowlist secret — TEST value, never real
SENTINEL = "sentinel-from-the-shared-predicate"

#: A standalone `ca` token, case-insensitive.
_CA_TOKEN = re.compile(r"\bca\b", re.IGNORECASE)

#: The #547 CA-key refusal, first six lines, typed here as an independent face.
CA_WRITE_REFUSAL_HEAD = (
    "REFUSED: the Venya admin CA key must never be stored unencrypted. Nothing was written.\n"
    "Why it matters: anyone who can read an unencrypted admin CA key can mint admin\n"
    "certificates that every Venya deployment trusts.\n"
    "To fix it:\n"
    "  1. Set VENYA_ADMIN_CA_KEY_PASSPHRASE in the environment of this command before you\n"
    "     run it. On an installed core the same value is already stored as\n"
    "     VENYA_ADMIN_CA_KEY_PASSPHRASE=... in /etc/venya/venya-core.env.\n"
)


def _action_text(text: str) -> str:
    """The lines an operator ACTS on: the headline plus the `To fix it:` block.

    Stops at the shipped `Note:` / `Reference:` lines — those say where the docs live, not
    what to set — and removes the variable name, which is allowed to spell CA.
    """
    lines = text.replace(VAR, "").splitlines()
    kept = lines[:1]
    in_fix = False
    for line in lines[1:]:
        if line.startswith("To fix it:"):
            in_fix = True
        elif in_fix and line.startswith(("Note:", "Reference:")):
            break
        if in_fix:
            kept.append(line)
    return "\n".join(kept)


@pytest.fixture(autouse=True)
def _clean_admin_env(monkeypatch):
    for name in (
        "VENYA_ADMIN_CERT",
        "VENYA_ADMIN_KEY",
        "VENYA_CONFIG",
        "SSL_CERT_FILE",
        "VENYA_SERVER_URL",
        "VENYA_ADMIN_CA_DIR",
        VAR,
    ):
        monkeypatch.delenv(name, raising=False)
    yield


def _mint_admin_ca(tmp_path: Path) -> Path:
    """A real Admin CA on disk, sealed with `CA_SIDE_PASSPHRASE`, written by the shipped writer."""
    os.environ[VAR] = CA_SIDE_PASSPHRASE
    ca_dir = tmp_path / "admin-ca"
    assert cmd_admin_init_admin_ca(SimpleNamespace(output_dir=str(ca_dir))) == 0
    return ca_dir


def _generate_args(ca_dir: Path, out: Path, identity: str = "admin@example.com") -> SimpleNamespace:
    return SimpleNamespace(identity=identity, ca_dir=str(ca_dir), output_dir=str(out))


def _renew_with(tmp_path, capsys, passphrase):
    """Drive `admin cert renew`'s leaf door with `passphrase` configured. Returns (rc, stderr)."""
    os.environ[VAR] = passphrase
    cp, kp = _seed_pair(tmp_path)

    def fake_request(self, method, path, json_data=None, params=None, extra_headers=None, timeout=None):
        csr = x509.load_pem_x509_csr(json_data["csr_pem"].encode())
        return {"certificate_pem": _minted_cert_pem(csr.public_key()).decode()}

    with (
        patch("venya_cli.commands._elevate", return_value="t"),
        patch.object(APIClient, "_request", fake_request),
    ):
        rc = cmd_admin_cert_renew(_renew_client(tmp_path, cp, kp), _renew_args(cp, kp))
    return rc, capsys.readouterr().err, kp


# --- §3.1 cell 1: the leaf doors, on the string that comes back ---


class TestLeafDoorsMakeNoCAClaim:
    def test_dial_refusal_action_text_carries_no_ca_token(self):
        """RED at base: the dial refusal interpolated the shipped CA setup fragment, whose
        second half is the CA mint — so the operator's action list ended in a command that
        creates a certificate authority he does not need at a dial."""
        msg = _admin_key_no_passphrase_refusal("/home/op/.config/venya/admin.key")
        action = _action_text(msg)
        assert "REFUSED" in msg and "no passphrase is" in msg, msg
        assert VAR in msg, "the variable name stays — it is the config contract, not this defect"
        assert _CA_TOKEN.search(action) is None, f"the dial action text names a CA: {action!r}"
        assert ADMIN_CA_SETUP_FRAGMENT not in msg, f"the CA setup fragment shipped here: {msg!r}"

    def test_dial_refusal_names_the_key_it_could_not_open(self):
        """RED at base: nothing in the action text said WHICH key the value opens."""
        keyfile = "/home/op/.config/venya/admin.key"
        msg = _admin_key_no_passphrase_refusal(keyfile)
        assert keyfile in msg, "the refusal must still name the file it could not open"
        action = _action_text(msg)
        assert "client key" in action.lower(), f"the dial text does not name the client key: {action!r}"

    def test_renew_leaf_door_action_text_carries_no_ca_token(self, tmp_path, capsys):
        """RED at base — the same fragment at the write door."""
        _rc, err, _kp = _renew_with(tmp_path, capsys, "   ")
        action = _action_text(err)
        assert "REFUSED" in err, err
        assert _CA_TOKEN.search(action) is None, f"the leaf write action text names a CA: {action!r}"
        assert ADMIN_CA_SETUP_FRAGMENT not in err

    def test_renew_leaf_door_names_the_key_this_command_writes(self, tmp_path, capsys):
        """RED at base: the text never said the value is the passphrase of the key the command
        is about to write, which is the only thing asked for at this door."""
        _rc, err, _kp = _renew_with(tmp_path, capsys, "")
        lowered = _action_text(err).lower()
        assert "this command writes" in lowered, f"the leaf write text does not name its own key: {lowered!r}"

    def test_generate_leaf_door_action_text_carries_no_ca_token(self, tmp_path, capsys):
        """The other caller of the same refusal, asserted on its own string: one sentence can
        be true at renew and false at a local-CA mint."""
        _mint_admin_ca(tmp_path)
        os.environ.pop(VAR, None)
        out = tmp_path / "leaf"
        assert cmd_admin_generate_admin_cert(_generate_args(tmp_path / "admin-ca", out)) == 1
        err = capsys.readouterr().err
        assert "REFUSED" in err, err
        assert _admin_leaf_key_no_passphrase_refusal("venya admin generate-admin-cert") in err
        action = _action_text(err)
        assert _CA_TOKEN.search(action) is None, f"the leaf write action text names a CA: {action!r}"

    def test_no_leaf_door_prints_the_ca_setup_fragment(self):
        """The negative half of the control: the fragment belongs to CA-precondition sites only."""
        sites = ("venya admin cert renew", "venya admin generate-admin-cert")
        for site in sites:
            text = _admin_leaf_key_no_passphrase_refusal(site)
            assert ADMIN_CA_SETUP_FRAGMENT not in text, site
            assert _CA_TOKEN.search(_action_text(text)) is None, f"{site}: {_action_text(text)!r}"

    def test_generate_shares_one_value_with_the_stored_signing_key(self, tmp_path, capsys):
        """The paired negative that set this leg's wording, and the reason the leaf sentence is
        conditional rather than cheerful. `admin generate-admin-cert` signs LOCALLY, so the one
        variable must carry the stored key's value too: drive it with a fresh value the
        authority was not sealed with and the mint fails at the signing-key read, in the CA
        door's own words. So 'choose a value here, nothing else to look up' would be TRUE of
        renew and FALSE of generate, and the shipped sentence says neither.

        This cell is green at base and must stay green — it is the mechanism the text now
        matches, not a claim about a string.
        """
        ca_dir = _mint_admin_ca(tmp_path)
        os.environ[VAR] = LEAF_SIDE_PASSPHRASE  # real value, clears the floor, seals nothing here
        out = tmp_path / "leaf"
        assert cmd_admin_generate_admin_cert(_generate_args(ca_dir, out)) == 1
        err = capsys.readouterr().err
        assert not out.exists(), "a mint that cannot open its signing key wrote a leaf anyway"
        assert "failed to decrypt" in err and str(ca_dir / "admin-ca.key") in err, err
        # and with the stored value the same mint succeeds — one variable, both planes (#554)
        os.environ[VAR] = CA_SIDE_PASSPHRASE
        assert cmd_admin_generate_admin_cert(_generate_args(ca_dir, out)) == 0
        assert serialization.load_pem_private_key(
            (out / "admin.key").read_bytes(), password=CA_SIDE_PASSPHRASE.encode()
        )


# --- §3.2 mechanism vs sentence ---


class TestMechanismAndSentenceAgree:
    def test_renew_asks_for_a_value_the_operator_chooses_not_a_stored_ca_secret(self, tmp_path, capsys):
        """The mechanism the leaf text must match. Green at base and must STAY green: an Admin
        CA exists on disk sealed with one value, renew is driven with a DIFFERENT value and
        succeeds, and the key it writes opens only with the new one. So this door cannot be
        asking for the CA's secret — and if a later edit made it demand that, this cell is red."""
        ca_dir = _mint_admin_ca(tmp_path)
        ca_key = ca_dir / "admin-ca.key"
        assert serialization.load_pem_private_key(ca_key.read_bytes(), password=CA_SIDE_PASSPHRASE.encode())
        assert stat.S_IMODE(ca_key.stat().st_mode) == 0o600

        rc, err, kp = _renew_with(tmp_path, capsys, LEAF_SIDE_PASSPHRASE)
        assert rc == 0, err
        written = kp.read_bytes()
        assert written.split(b"\n", 1)[0] == b"-----BEGIN ENCRYPTED PRIVATE KEY-----", written[:64]
        assert serialization.load_pem_private_key(written, password=LEAF_SIDE_PASSPHRASE.encode())
        with pytest.raises(ValueError):
            serialization.load_pem_private_key(written, password=CA_SIDE_PASSPHRASE.encode())
        # and the CA key on disk is untouched by a renewal that never read it
        assert serialization.load_pem_private_key(ca_key.read_bytes(), password=CA_SIDE_PASSPHRASE.encode())

    def test_dial_door_reads_the_value_that_opens_the_stored_client_key(self, tmp_path):
        """The dial half of the same fact, with no mock in the path: the shipped writer makes
        the encrypted pair, and the shipped builder answers from the value that seals the
        CLIENT key on disk — the CA-side value opens it, so it is the client key's own
        passphrase the door reads, and a blank value refuses in our words, not OpenSSL's."""
        ca_dir = _mint_admin_ca(tmp_path)
        out = tmp_path / "leaf"
        assert cmd_admin_generate_admin_cert(_generate_args(ca_dir, out)) == 0

        os.environ[VAR] = "   "
        with pytest.raises(APIClientError) as excinfo:
            _build_ssl_context(
                cafile=str(ca_dir / "admin-ca.crt"), certfile=str(out / "admin.crt"), keyfile=str(out / "admin.key")
            )
        msg = str(excinfo.value)
        assert "REFUSED" in msg and "no passphrase is" in msg, msg
        assert _CA_TOKEN.search(_action_text(msg)) is None, f"the dial action text names a CA: {_action_text(msg)!r}"

    def test_the_stored_client_key_opens_with_the_value_its_writer_was_given(self, tmp_path):
        """Positive half of the pair above: the same three files DO load when the value that
        sealed the leaf key is configured — proof the leaf value is the client key's own, and
        that the leg did not relax the read door to make a sentence true."""
        ca_dir = _mint_admin_ca(tmp_path)
        out = tmp_path / "leaf"
        assert cmd_admin_generate_admin_cert(_generate_args(ca_dir, out)) == 0
        assert _build_ssl_context(
            cafile=str(ca_dir / "admin-ca.crt"), certfile=str(out / "admin.crt"), keyfile=str(out / "admin.key")
        )


# --- §3.2 positive control: the CA doors, byte for byte ---


class TestCaSiteWordingUnchanged:
    def test_ca_write_refusal_is_byte_for_byte_the_shipped_block(self, tmp_path, capsys):
        os.environ.pop(VAR, None)
        ca_dir = tmp_path / "admin-ca"
        assert cmd_admin_init_admin_ca(SimpleNamespace(output_dir=str(ca_dir))) == 1
        err = capsys.readouterr().err
        assert err.startswith(CA_WRITE_REFUSAL_HEAD), err
        assert "Reference: docs/cert-rotation-runbook.md and docs/BACKUPS.md (CA file locations and rotation)." in err
        assert not ca_dir.exists(), "the CA refusal must still create nothing"

    def test_ca_setup_fragment_is_unchanged(self):
        """The constant the CA-precondition sites print, pinned against a literal rather than
        against itself, so this leg cannot have leaned on it."""
        assert ADMIN_CA_SETUP_FRAGMENT == "Set VENYA_ADMIN_CA_KEY_PASSPHRASE, then run: venya admin init-admin-ca"

    def test_the_ca_block_is_still_one_home_for_the_569_picker(self):
        """#569 lifts lines out of this block BY PREFIX. If this leg had re-worded the CA block
        while fixing a leaf door, the picker's contract would quietly move — so it is pinned."""
        text = _admin_ca_no_passphrase_refusal()
        assert text.startswith("REFUSED: the Venya admin CA key must never be stored unencrypted. Nothing was written.")
        assert len([line for line in text.splitlines() if line.startswith("Reference:")]) == 1
        assert "  1. Set VENYA_ADMIN_CA_KEY_PASSPHRASE in the environment of this command" in text

    def test_ca_absent_hint_at_generate_still_names_the_mint(self, tmp_path, capsys):
        """A CA-absent precondition is NOT a leaf door: the mint pointer there is the correct
        answer and must survive this leg untouched."""
        os.environ[VAR] = CA_SIDE_PASSPHRASE
        out = tmp_path / "leaf"
        assert cmd_admin_generate_admin_cert(_generate_args(tmp_path / "absent-ca", out)) == 1
        err = capsys.readouterr().err
        assert "admin CA key not found" in err
        assert ADMIN_CA_SETUP_FRAGMENT in err, "the CA-absent hint stopped naming the mint"


# --- §3.3 paired negative: one predicate, one blank answer, both planes (the #554 law) ---


class TestSharedPredicateNotSplit:
    @pytest.mark.parametrize("value", [None, "", " ", "   ", "\t"], ids=["unset", "empty", "sp1", "sp3", "tab"])
    def test_blank_is_no_passphrase_on_both_planes(self, monkeypatch, value):
        if value is None:
            monkeypatch.delenv(VAR, raising=False)
        else:
            monkeypatch.setenv(VAR, value)
        assert _admin_ca_passphrase_or_none() is None
        assert _admin_leaf_key_passphrase_or_none() is None

    @pytest.mark.parametrize(
        "value", ["a-real-value-here", "  padded  ", "x" * 15], ids=["plain", "padded", "at-floor"]
    )
    def test_a_value_with_material_answers_the_same_on_both_planes(self, monkeypatch, value):
        """DENY, never TRIM — and the two readers cannot disagree about it."""
        monkeypatch.setenv(VAR, value)
        assert _admin_ca_passphrase_or_none() == value
        assert _admin_leaf_key_passphrase_or_none() == value

    def test_the_leaf_reader_still_delegates_to_the_one_predicate(self, monkeypatch):
        """The stronger structural half: patch the shared CA reader and the leaf reader moves
        with it. A forked implementation would read `os.environ` itself and not budge."""
        monkeypatch.setattr("venya_cli.commands._admin_ca_passphrase_or_none", lambda: SENTINEL)
        assert _admin_leaf_key_passphrase_or_none() == SENTINEL

    @pytest.mark.parametrize("blank", ["", "  "], ids=["empty", "spaces"])
    def test_both_doors_answer_a_blank_value_the_same_way(self, tmp_path, capsys, blank):
        """Operator-visible rather than function-level: each door refuses a blank value with
        its OWN per-site sentence, and each creates or writes nothing."""
        os.environ[VAR] = blank
        ca_dir = tmp_path / "admin-ca"
        assert cmd_admin_init_admin_ca(SimpleNamespace(output_dir=str(ca_dir))) == 1
        ca_err = capsys.readouterr().err
        assert not ca_dir.exists(), "the CA door wrote on a blank value"

        cp, kp = _seed_pair(tmp_path)
        before = kp.read_bytes()
        with patch("venya_cli.commands._elevate") as elevate:
            assert cmd_admin_cert_renew(_renew_client(tmp_path, cp, kp), _renew_args(cp, kp)) == 1
        elevate.assert_not_called()
        leaf_err = capsys.readouterr().err
        assert kp.read_bytes() == before, "the leaf door wrote on a blank value"

        assert "REFUSED" in ca_err and "REFUSED" in leaf_err
        assert ca_err != leaf_err, "two doors with one sentence means the leaf text did not become per-site"
        assert "shorter than Venya's minimum" not in ca_err + leaf_err, "blank must not read as too short"
