# Copyright (c) 2026 Tabith LLC.
# Use of this source code is governed by the Business Source License 1.1
# included in the LICENSE file at the root of this repository. As of the
# Change Date listed there, the work is available under MPL 2.0.
# SPDX-License-Identifier: BUSL-1.1

"""#577 server-damaged-ca-key-blamed-on-the-passphrase — the blame half of the CA-key refusal family.

The defect is in a BRANCH, not in a sentence. ``_deserialize_key`` caught ``ValueError`` from the
PEM loader and then asked one question — ``if passphrase:`` — before answering with the
wrong-passphrase refusal. ``ValueError`` covers two different failures: the passphrase did not open
an intact key, AND the bytes are not a parseable key at all. So a truncated CA key, or armor kept
over a body that no longer decodes, was reported to the operator through a sentence whose subject
was their passphrase — the exact outcome #572/#574's own ruling names as the thing this family
exists to prevent, because the operator re-types a correct passphrase forever.

The fix is the #572 mechanism, re-expressed server-side (the lead's AC5 pre-decision: server-local
probe in ``server.utils``, the CLI copy stays put, the two are NOT unified, nothing from the CLI is
imported here): re-read the same bytes with NO password and branch on the exception CLASS.
An intact encrypted key raises ``TypeError`` — the parser got far enough to need a password, so a
password is a meaningful thing to have gotten wrong. A damaged file raises ``ValueError`` first.
No code path here reads, matches or copies a library MESSAGE.

Every gate number in this file's report was measured at the base this branch was cut from; the
library classes cited are the loader's documented API at cryptography 50.0.0.

Truth table, both halves, per the house law:
  * damaged + passphrase set   -> the FILE is named, the passphrase sentence is ABSENT (this row);
  * intact + wrong passphrase  -> the ruled #574 sentence, unchanged (paired negative);
  * intact + correct passphrase -> loads (paired negative);
  * damaged + NO passphrase    -> #541's shipped bytes, byte-for-byte (the AC3(iii) "do not disturb").
"""

import re
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization
from server.ca import (
    AdminCAManager,
    CAManager,
    _ca_key_damaged_refusal,
    _ca_key_decrypt_refusal,
    _deserialize_key,
    _unencrypted_key_refusal,
)
from server.utils.ca_key_probe import encrypted_key_is_parseable

_ROOT_ENV = "VENYA_CA_KEY_PASSPHRASE"
_ADMIN_ENV = "VENYA_ADMIN_CA_KEY_PASSPHRASE"
_RIGHT = "correct-passphrase-577"
_WRONG = "wrong-passphrase-577"

#: The #574 headline. Asserted ABSENT on every damaged-key arm here: this row adds a branch, it does
#: not re-word that one, and the whole point is that a damaged file must not reach that sentence.
_PASSPHRASE_BLAME = "could not be decrypted — the passphrase did not match."

#: The ruled subject of the new sentence — the file, named, with its own repair pointer.
_DAMAGED_HEADLINE = "could not be read — the file is damaged."
_DAMAGED_NO_RETRY_POINTER = "re-typing the passphrase will not help"
_DAMAGED_RESTORE_POINTER = "when either was made for this key"
_DAMAGED_SETUP_ALTERNATIVE = "otherwise re-run the CA setup"

#: The library's own sentences, as pinned by the #574 suite at this base under cryptography 50.0.0.
#: None of these may reach the operator through the new arm either.
_LIBRARY_VOICES = (
    "Incorrect password",
    "could not decrypt key",
    "Unable to load PEM file",
    "MalformedFraming",
    "InvalidData",
    "Password was not given",
    "Password was given but private key is not encrypted",
)


def _intact_encrypted_pem(tmp_path: Path, monkeypatch, passphrase: str = _RIGHT) -> bytes:
    """A REAL encrypted CA key from the shipped generator, as bytes."""
    monkeypatch.setenv(_ROOT_ENV, passphrase)
    manager = CAManager(str(tmp_path / "ca"))
    manager.initialize()
    return manager.ca_key_path.read_bytes()


def _truncated(data: bytes) -> bytes:
    """Armor kept, body cut mid-key — the shape a half-copied or half-written file leaves behind."""
    lines = data.decode("ascii").splitlines()
    body = [line for line in lines[1:-1] if line.strip()]
    kept = lines[0] + "\n" + "\n".join(body[: max(1, len(body) // 2)]) + "\n-----END ENCRYPTED PRIVATE KEY-----\n"
    return kept.encode("ascii")


def _non_base64_body(data: bytes) -> bytes:
    """Armor kept verbatim over a body that is not base64 at all — a corrupted-then-saved file."""
    lines = data.decode("ascii").splitlines()
    return (lines[0] + "\n" + "!!!!not base64!!!!\n" + lines[-1] + "\n").encode("ascii")


def _swapped_body(data: bytes) -> bytes:
    """Armor kept, body replaced with base64-shaped bytes that decode to a non-key structure."""
    lines = data.decode("ascii").splitlines()
    filler = "AAAA" * 24
    return (lines[0] + "\n" + filler + "\n" + lines[-1] + "\n").encode("ascii")


#: The three damaged shapes flash1 measured at s87, all constructible as bytes with no product run.
DAMAGED_SHAPES = {
    "truncated-mid-body": _truncated,
    "armor-over-non-base64": _non_base64_body,
    "armor-over-garbage-body": _swapped_body,
}


def _assert_damaged_voice(message: str, expect_path: str | None) -> None:
    """The ruled invariant for the new arm, as assertions: file blamed, passphrase NOT blamed."""
    assert _DAMAGED_HEADLINE in message, f"the damaged-file headline is missing: {message!r}"
    assert _PASSPHRASE_BLAME not in message, f"a damaged file was still blamed on the passphrase: {message!r}"
    assert _DAMAGED_NO_RETRY_POINTER in message, "the refusal must say retrying the passphrase cannot help"
    assert _DAMAGED_RESTORE_POINTER in message, "the restore pointer is not conditional (Q4-AMENDMENT)"
    assert _DAMAGED_SETUP_ALTERNATIVE in message, "the always-true alternative is missing"
    assert "None" not in message, "the literal word None reached the operator"
    for voice in _LIBRARY_VOICES:
        assert voice not in message, f"the library's own sentence leaked into the refusal: {voice!r}"
    if expect_path is not None:
        assert expect_path in message, f"the refusal must name the key it tried to open: {expect_path!r}"
    else:
        assert "The CA key at " not in message, "a no-path refusal must not claim a path it does not have"


class TestProbeDiscriminates577:
    """The mechanism itself, tested directly — a probe that does not discriminate cannot fix a blame."""

    def test_intact_encrypted_key_is_parseable(self, tmp_path, monkeypatch):
        data = _intact_encrypted_pem(tmp_path, monkeypatch)
        assert b"ENCRYPTED" in data, "fixture precondition: the generated key really is encrypted"
        assert encrypted_key_is_parseable(data) is True

    @pytest.mark.parametrize("shape", sorted(DAMAGED_SHAPES))
    def test_every_damaged_shape_is_not_parseable(self, tmp_path, monkeypatch, shape: str):
        data = DAMAGED_SHAPES[shape](_intact_encrypted_pem(tmp_path, monkeypatch))
        assert encrypted_key_is_parseable(data) is False, f"the {shape} file was vouched for as an encrypted key"

    def test_plaintext_key_is_not_an_encrypted_key(self, tmp_path, monkeypatch):
        """The third outcome: bytes that load with no password at all are not "parseable ENCRYPTED"."""
        data = _intact_encrypted_pem(tmp_path, monkeypatch)
        key = _deserialize_key(data, _RIGHT.encode("utf-8"))
        plaintext = key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
        assert encrypted_key_is_parseable(plaintext) is False

    def test_garbage_bytes_are_not_parseable(self):
        assert encrypted_key_is_parseable(b"this is not a key file at all\n") is False

    def test_probe_reads_no_message(self):
        """AC1's no-message-reading clause, proven on the source rather than asserted in prose.

        A probe that matched the library's sentence would rot the day the dependency reworded it,
        which is the exact coupling #572 removed from the operator's view.
        """
        source = Path(__file__).resolve().parents[1].joinpath("src/server/utils/ca_key_probe.py").read_text()
        assert re.findall(r"str\(\s*e\b|\.args\b|\.msg\b|except\s+\w+\s+as\s+\w+\s*:\s*\n\s*if\s+\"", source) == []
        assert "TypeError" in source and "ValueError" in source, "the branch must be on the exception class"


class TestDamagedKeyBlamesTheFile577:
    """AC1 — damaged bytes plus a supplied passphrase must NOT produce the passphrase sentence."""

    @pytest.mark.parametrize("shape", sorted(DAMAGED_SHAPES))
    def test_deserialize_key_names_the_file_for_every_damaged_shape(self, tmp_path, monkeypatch, shape: str):
        data = DAMAGED_SHAPES[shape](_intact_encrypted_pem(tmp_path, monkeypatch))
        key_path = tmp_path / f"{shape}-ca.key"
        key_path.write_bytes(data)

        with pytest.raises(RuntimeError) as excinfo:
            _deserialize_key(data, _RIGHT.encode("utf-8"), key_path)

        _assert_damaged_voice(str(excinfo.value), expect_path=str(key_path))
        # The mechanism is not lost — it rides the chained cause for support, never the screen.
        assert isinstance(excinfo.value.__cause__, ValueError)

    def test_right_passphrase_on_a_damaged_file_blames_the_file_not_the_passphrase(self, tmp_path, monkeypatch):
        """The row's failure mode stated as a cell: the passphrase was CORRECT, and that is irrelevant.

        This is what makes #577 a behavior row and not a wording row — at base the answer depended
        only on whether a passphrase was supplied at all.
        """
        data = _truncated(_intact_encrypted_pem(tmp_path, monkeypatch))
        with pytest.raises(RuntimeError) as excinfo:
            _deserialize_key(data, _RIGHT.encode("utf-8"))

        message = str(excinfo.value)
        assert _PASSPHRASE_BLAME not in message
        assert _DAMAGED_HEADLINE in message

    def test_wrong_passphrase_on_a_damaged_file_also_blames_the_file(self, tmp_path, monkeypatch):
        """A passphrase can also be wrong while the file is damaged — the file is the actionable blame."""
        data = _non_base64_body(_intact_encrypted_pem(tmp_path, monkeypatch))
        with pytest.raises(RuntimeError) as excinfo:
            _deserialize_key(data, _WRONG.encode("utf-8"))

        _assert_damaged_voice(str(excinfo.value), expect_path=None)

    def test_root_load_ca_blames_the_file_on_a_damaged_key(self, tmp_path, monkeypatch):
        """The real surface: an operator's damaged /etc/venya key read through CAManager.load_ca."""
        monkeypatch.setenv(_ROOT_ENV, _RIGHT)
        manager = CAManager(str(tmp_path / "ca"))
        manager.initialize()
        manager.ca_key_path.write_bytes(_truncated(manager.ca_key_path.read_bytes()))

        with pytest.raises(RuntimeError) as excinfo:
            manager.load_ca()

        _assert_damaged_voice(str(excinfo.value), expect_path=str(manager.ca_key_path))
        assert str(excinfo.value) == _ca_key_damaged_refusal(manager.ca_key_path)

    def test_admin_load_ca_key_blames_the_file_on_a_damaged_key(self, tmp_path, monkeypatch):
        """Admin twin — the same defect lived on both planes, so both get the same cell."""
        monkeypatch.setenv(_ADMIN_ENV, _RIGHT)
        manager = AdminCAManager(tmp_path / "admin-ca")
        manager.initialize()
        manager.ca_key_path.write_bytes(_non_base64_body(manager.ca_key_path.read_bytes()))

        with pytest.raises(RuntimeError) as excinfo:
            manager._load_ca_key()

        _assert_damaged_voice(str(excinfo.value), expect_path=str(manager.ca_key_path))

    def test_both_planes_share_one_damaged_sentence_modulo_the_path(self, tmp_path, monkeypatch):
        """R8-ADDENDUM's class invariant re-used for the new arm: one sentence, path substituted."""
        root = CAManager(str(tmp_path / "ca"))
        admin = AdminCAManager(tmp_path / "admin-ca")
        monkeypatch.setenv(_ROOT_ENV, _RIGHT)
        monkeypatch.setenv(_ADMIN_ENV, _RIGHT)
        root.initialize()
        admin.initialize()
        root.ca_key_path.write_bytes(_truncated(root.ca_key_path.read_bytes()))
        admin.ca_key_path.write_bytes(_truncated(admin.ca_key_path.read_bytes()))

        with pytest.raises(RuntimeError) as root_exc:
            root.load_ca()
        with pytest.raises(RuntimeError) as admin_exc:
            admin._load_ca_key()

        root_text = str(root_exc.value).replace(str(root.ca_key_path), "<PATH>")
        admin_text = str(admin_exc.value).replace(str(admin.ca_key_path), "<PATH>")
        assert root_text == admin_text, "the two planes typed two damaged sentences"
        assert "<PATH>" in root_text

    def test_two_argument_call_blames_the_file_without_a_path(self, tmp_path, monkeypatch):
        """The no-path caller keeps an honest sentence, same as #574's AC2 half."""
        data = _truncated(_intact_encrypted_pem(tmp_path, monkeypatch))
        with pytest.raises(RuntimeError) as excinfo:
            _deserialize_key(data, _RIGHT.encode("utf-8"))

        _assert_damaged_voice(str(excinfo.value), expect_path=None)

    def test_none_and_empty_path_take_the_same_damaged_headline(self):
        assert _ca_key_damaged_refusal(None) == _ca_key_damaged_refusal("")
        assert _ca_key_damaged_refusal(None).startswith("The CA key could not be read ")


class TestPairedNegatives577:
    """AC2 + AC3 — the branch was ADDED; nothing that already answered correctly changed its answer."""

    def test_intact_key_with_wrong_passphrase_keeps_the_ruled_decrypt_sentence(self, tmp_path, monkeypatch):
        """AC2, the half this row could have broken: an intact file must STILL be blamed on the passphrase."""
        data = _intact_encrypted_pem(tmp_path, monkeypatch)
        with pytest.raises(RuntimeError) as excinfo:
            _deserialize_key(data, _WRONG.encode("utf-8"))

        message = str(excinfo.value)
        assert _PASSPHRASE_BLAME in message, "the #574 wrong-passphrase voice moved — this row does not touch it"
        assert _DAMAGED_HEADLINE not in message, "an intact key was called damaged"
        assert message == _ca_key_decrypt_refusal(None)
        # from e is KEPT (AC2): the leak is fixed by what is shown, not by dropping the chain.
        assert isinstance(excinfo.value.__cause__, ValueError)
        assert "Incorrect password" in str(excinfo.value.__cause__)

    def test_intact_key_with_correct_passphrase_still_loads_on_both_planes(self, tmp_path, monkeypatch):
        """AC3(i) — a catch that eats success would be worse than the blame it fixed."""
        monkeypatch.setenv(_ROOT_ENV, _RIGHT)
        monkeypatch.setenv(_ADMIN_ENV, _RIGHT)
        root = CAManager(str(tmp_path / "ca"))
        admin = AdminCAManager(tmp_path / "admin-ca")
        root.initialize()
        admin.initialize()

        cert, key = root.load_ca()
        assert cert is not None and key is not None
        assert admin._load_ca_key() is not None

    def test_damaged_key_without_a_passphrase_keeps_the_541_bytes(self, tmp_path, monkeypatch):
        """AC3(iii), the "do not disturb" cell: the no-passphrase arm is byte-identical to what 541 shipped.

        Reached the documented way — the loader raises ValueError on unparseable bytes before the
        passphrase question is ever asked, so this arm is the one the #574 suite also pins.
        """
        data = _non_base64_body(_intact_encrypted_pem(tmp_path, monkeypatch))
        with pytest.raises(RuntimeError) as excinfo:
            _deserialize_key(data, None)

        assert str(excinfo.value) == (
            "Failed to load CA key (may be encrypted but no passphrase provided). "
            "Set the passphrase environment variable."
        )
        assert _DAMAGED_HEADLINE not in str(excinfo.value), "the 541 arm was replaced, not preserved"
        assert isinstance(excinfo.value.__cause__, ValueError)

    def test_plaintext_key_with_a_passphrase_still_takes_the_541_refusal(self, tmp_path, monkeypatch):
        """The neighbouring arm #541 ruled (REFUSE LOUDLY, NO REWRAP) is unchanged by this row.

        The manager decides that posture from the ENCRYPTED marker BEFORE the loader is reached, so
        the new probe is not on that path at all — this cell says so with an assertion.
        """
        monkeypatch.setenv(_ROOT_ENV, _RIGHT)
        manager = CAManager(str(tmp_path / "ca"))
        manager.initialize()
        key = _deserialize_key(manager.ca_key_path.read_bytes(), _RIGHT.encode("utf-8"))
        manager.ca_key_path.write_bytes(
            key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption(),
            )
        )

        with pytest.raises(RuntimeError) as excinfo:
            manager.load_ca()

        assert str(excinfo.value) == _unencrypted_key_refusal(_ROOT_ENV)
        assert _DAMAGED_HEADLINE not in str(excinfo.value)
        assert _PASSPHRASE_BLAME not in str(excinfo.value)


class TestNoLibraryVoiceOnTheNewArm577:
    """The new sentence carries our words only — the #541 blanket rule applies to this arm too."""

    def test_no_exception_is_interpolated_into_a_raised_string(self):
        source = Path(__file__).resolve().parents[1].joinpath("src/server/ca.py").read_text()
        offenders = re.findall(r'raise \w+\(\s*f"[^"]*\{e\}', source)
        assert offenders == [], f"exception text is interpolated into a raise: {offenders}"

    def test_library_sentences_appear_nowhere_in_the_damaged_refusal(self):
        text = _ca_key_damaged_refusal(Path("/etc/venya/admin/ca.key"))
        for voice in _LIBRARY_VOICES:
            assert voice not in text, f"library voice in the damaged refusal: {voice!r}"

    def test_the_damaged_refusal_has_exactly_one_hand_written_home(self):
        """#568's single-home shape, applied to the new arm."""
        source = Path(__file__).resolve().parents[1].joinpath("src/server/ca.py").read_text()
        typed = [
            line for line in source.splitlines() if _DAMAGED_HEADLINE in line and not line.lstrip().startswith("#")
        ]
        assert len(typed) == 2, f"expected the two headline lines in one builder, found {len(typed)}: {typed}"

    def test_the_probe_is_not_imported_from_the_cli(self):
        """AC5's scope guard, asserted on the import lines rather than trusted in prose."""
        source = Path(__file__).resolve().parents[1].joinpath("src/server/ca.py").read_text()
        assert "venya_cli" not in source, "the server must not import the CLI"
        assert "from .utils.ca_key_probe import encrypted_key_is_parseable" in source


class TestNothingElseChanged577:
    """The narrowness claim, checked: this row adds a branch and a builder, it edits nothing else."""

    def test_the_decrypt_refusal_builder_is_unchanged(self):
        """#574's shipped sentence, byte-for-byte, is still what its own builder returns."""
        text = _ca_key_decrypt_refusal(Path("/etc/venya/ca.key"))
        assert text.startswith("The CA key at /etc/venya/ca.key ")
        assert _PASSPHRASE_BLAME in text
        assert "Retry with the correct passphrase" in text

    def test_the_two_refusals_are_different_sentences(self):
        """Guards against a copy-paste that made both arms say the same thing."""
        assert _ca_key_damaged_refusal(None) != _ca_key_decrypt_refusal(None)
        assert _DAMAGED_HEADLINE not in _ca_key_decrypt_refusal(None)
        assert _PASSPHRASE_BLAME not in _ca_key_damaged_refusal(None)
