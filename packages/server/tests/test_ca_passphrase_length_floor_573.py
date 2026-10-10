# Copyright (c) 2026 Tabith LLC.
# Use of this source code is governed by the Business Source License 1.1
# included in the LICENSE file at the root of this repository. As of the
# Change Date listed there, the work is available under MPL 2.0.
# SPDX-License-Identifier: BUSL-1.1

"""#573 — the server CA plane carries a passphrase LENGTH floor (carrier n15).

Owner ruling (s85 batch, verbatim): *"Deny whitespace-only passphrases **and enforce a
proper length passcode.**"* Clause 1 shipped in #554 (server half `9fb5537`); these cells
are clause 2 — the floor, ruled at **15 Unicode code points, inclusive**, counted on the
decoded string before any encode.

Scope of the floor here is the CA plane, BOTH doors, which is what R5(b) of the s87 owner
ruling set closed: ``CAManager.initialize``/``AdminCAManager.initialize`` (writes) and
``CAManager.load_ca``/``AdminCAManager._load_ca_key`` (reads). The DB-KEK plane
(``core/engine/backend.py`` + the installer) is a sequenced follow-up, not this leg.

**The ceiling is STATED, not enforced.** Research clause C2 (NIST SP 800-63B) requires a
verifier to *permit* at least 64; refusing above it would be a door the owner never ruled.
So `test_64_and_65_code_points_are_both_accepted` asserts ACCEPTANCE at 65, and
`test_ceiling_flip_changes_no_refusal` is its non-vacuity half: moving
``MAX_PASSPHRASE_CODE_POINTS`` changes no door's behavior, only the sentence.

Wording: nothing here invents a sentence. The block is the blessed §6 text with the two
authorized corrections (the supported maximum stated plainly, the floor number
interpolated from the same constant the check uses), and the read door is that block with
exactly one clause deleted — ``Nothing was written.`` The cells pin those bytes, so a
wording fork or a hard-typed number going stale against the constant is RED here.
"""

import pytest
from cryptography.hazmat.primitives import serialization
from server.ca import (
    MAX_PASSPHRASE_CODE_POINTS,
    MIN_PASSPHRASE_CODE_POINTS,
    AdminCAManager,
    CAManager,
    _configured_passphrase,
    _passphrase_is_below_floor,
    _short_passphrase_refusal,
    _unencrypted_key_refusal,
)

_ROOT_ENV = "VENYA_CA_KEY_PASSPHRASE"
_ADMIN_ENV = "VENYA_ADMIN_CA_KEY_PASSPHRASE"

# Synthetic dev-only values (AGENTS.md test-password vocabulary, never real).
_ONE = "a"
_BELOW = _ONE * 14  # 14 code points: refuses — typed as a LITERAL length, not from the constant
_AT_FLOOR = _ONE * 15  # 15: passes INCLUSIVE — the boundary is pinned in stone, not derived
_AT_CEILING = _ONE * 64  # 64: passes
_OVER_CEILING = _ONE * 65  # 65: PASSES — the ceiling is stated, not enforced
_SPACED = " sword with spaces in it "  # legal length; the spaces are CONTENT
_ACCENTED_15 = "é" * 15  # 15 code points = 30 UTF-8 bytes
_ACCENTED_14 = "é" * 14  # 14 code points = 28 UTF-8 bytes — over 15 BYTES, under the floor
_BLANKS = ["", " ", "   ", "\t", "\n"]


class TestFloorUnit:
    """The decision at the one place that makes it."""

    def test_unset_and_blank_stay_no_passphrase_not_too_short(self, monkeypatch):
        """The #554 posture, asserted unchanged: the floor runs AFTER the blank shape."""
        for blank in [None, *_BLANKS]:
            if blank is None:
                monkeypatch.delenv(_ROOT_ENV, raising=False)
            else:
                monkeypatch.setenv(_ROOT_ENV, blank)
            assert _configured_passphrase(_ROOT_ENV) is None
            assert (
                _passphrase_is_below_floor(_configured_passphrase(_ROOT_ENV)) is False
            ), f"{blank!r} is 'not supplied', never 'too short'"

    @pytest.mark.parametrize("value", [_BELOW, _ACCENTED_14], ids=["14-ascii", "14-accented"])
    def test_below_the_floor_is_flagged(self, monkeypatch, value):
        monkeypatch.setenv(_ROOT_ENV, value)
        assert _passphrase_is_below_floor(_configured_passphrase(_ROOT_ENV)) is True

    @pytest.mark.parametrize(
        "value",
        [_AT_FLOOR, _AT_CEILING, _OVER_CEILING, _SPACED, _ACCENTED_15],
        ids=["at-15", "at-64", "over-65", "meaningful-spaces", "15-accented"],
    )
    def test_at_and_above_the_floor_is_not_flagged(self, monkeypatch, value):
        monkeypatch.setenv(_ROOT_ENV, value)
        assert _configured_passphrase(_ROOT_ENV) == value
        assert _passphrase_is_below_floor(_configured_passphrase(_ROOT_ENV)) is False

    def test_code_points_not_bytes(self):
        """The counting rule, stated as a property of the check rather than of the fixture.

        14 accented characters are 28 UTF-8 bytes: a byte-measuring floor would wave this
        through, and the owner ruled the number in characters.
        """
        assert len(_ACCENTED_14) == 14
        assert len(_ACCENTED_14.encode("utf-8")) == 28
        assert _passphrase_is_below_floor(_ACCENTED_14) is True
        assert _passphrase_is_below_floor(_ACCENTED_15) is False

    def test_the_ruled_numbers_live_in_two_named_constants(self):
        """AC5: one constant per plane carries the floor; the other only states the ceiling."""
        assert MIN_PASSPHRASE_CODE_POINTS == 15
        assert MAX_PASSPHRASE_CODE_POINTS == 64

    def test_the_sentence_carries_the_ruled_digits_as_literals(self):
        """The interpolation proof, pinned with TYPED digits: move MIN and this goes red.

        The shipped text builds the number from the constant the door measures with; this
        cell refuses to derive it, so a constant that drifts away from the owner's 15 (or
        a builder that reverts to a typed "15" while the check moves) is RED here.
        """
        assert _passphrase_is_below_floor(_ONE * 14) is True
        assert _passphrase_is_below_floor(_ONE * 15) is False
        assert "at least 15 characters" in _short_passphrase_refusal(_ROOT_ENV)

    def test_value_and_its_length_are_never_echoed(self, monkeypatch):
        """§6 law: interpolate the NAME, never the value, never its length."""
        typed = "sup3rvaluestring"
        monkeypatch.setenv(_ROOT_ENV, typed)
        message = _short_passphrase_refusal(_ROOT_ENV)
        assert typed not in message
        assert f"{len(typed)} characters" not in message


class TestWriteDoor:
    """Both managers: below floor refuses before ANY filesystem work."""

    @pytest.mark.parametrize("phrase", [_BELOW, _ACCENTED_14], ids=["14-ascii", "14-accented"])
    def test_root_ca_refuses_below_floor_and_creates_nothing(self, tmp_path, monkeypatch, phrase):
        monkeypatch.setenv(_ROOT_ENV, phrase)
        manager = CAManager(str(tmp_path / "ca"))

        assert not manager.ca_dir.exists()
        with pytest.raises(RuntimeError) as excinfo:
            manager.initialize()

        message = str(excinfo.value)
        assert message == _short_passphrase_refusal(_ROOT_ENV), "the write door speaks the blessed block"
        assert "Nothing was written." in message
        assert _ROOT_ENV in message
        assert not manager.ca_dir.exists(), f"a {len(phrase)}-code-point passphrase still made {manager.ca_dir}"

    def test_admin_ca_refuses_below_floor_and_names_the_admin_var(self, tmp_path, monkeypatch):
        """The floor is the same on both managers; the refusal names the var the caller reads."""
        monkeypatch.setenv(_ADMIN_ENV, _BELOW)
        manager = AdminCAManager(tmp_path / "admin-ca")

        with pytest.raises(RuntimeError) as excinfo:
            manager.initialize()

        message = str(excinfo.value)
        assert message == _short_passphrase_refusal(_ADMIN_ENV)
        assert _ADMIN_ENV in message
        assert _ROOT_ENV not in message, "the admin door must not point the operator at the executor var"
        assert not manager.ca_path.exists()

    def test_blank_still_answers_with_the_537_refusal_byte_identical(self, tmp_path, monkeypatch):
        """Paired negative the floor must not steal: 'no passphrase' keeps #537's own words."""
        monkeypatch.setenv(_ROOT_ENV, "   ")
        manager = CAManager(str(tmp_path / "ca"))

        with pytest.raises(RuntimeError) as excinfo:
            manager.initialize()

        assert str(excinfo.value) == _unencrypted_key_refusal(_ROOT_ENV)
        assert "shorter than Venya's minimum" not in str(excinfo.value)

    @pytest.mark.parametrize(
        "phrase",
        [_AT_FLOOR, _AT_CEILING, _OVER_CEILING, _SPACED, _ACCENTED_15],
        ids=["at-15", "at-64", "over-65", "meaningful-spaces", "15-accented"],
    )
    def test_legal_length_mints_and_reloads(self, tmp_path, monkeypatch, phrase):
        """The positive half of every truth-table row, and the non-vacuity of the ceiling."""
        monkeypatch.setenv(_ROOT_ENV, phrase)
        manager = CAManager(str(tmp_path / "ca"))
        manager.initialize()

        key_data = manager.ca_key_path.read_bytes()
        assert b"ENCRYPTED" in key_data
        assert manager.load_ca()[1] is not None, "the value that sealed the key must open it"

    def test_meaningful_spaces_are_delivered_byte_exact(self, tmp_path, monkeypatch):
        """DENY, not TRIM, at legal length: the spaces are the secret, the stripped form is not."""
        monkeypatch.setenv(_ROOT_ENV, _SPACED)
        manager = CAManager(str(tmp_path / "ca"))
        manager.initialize()

        key_data = manager.ca_key_path.read_bytes()
        assert b"ENCRYPTED" in key_data
        assert manager.load_ca()[1] is not None
        with pytest.raises(ValueError):
            serialization.load_pem_private_key(key_data, password=_SPACED.strip().encode("utf-8"))


class TestReadDoor:
    """The read doors speak the same block with exactly one clause dropped."""

    def _mint(self, tmp_path, monkeypatch, env=_ROOT_ENV):
        monkeypatch.setenv(env, _AT_FLOOR)
        manager = CAManager(str(tmp_path / "ca")) if env == _ROOT_ENV else AdminCAManager(tmp_path / "admin-ca")
        manager.initialize()
        monkeypatch.setenv(env, _BELOW)
        return manager

    def test_root_read_refuses_below_floor_and_loads_nothing(self, tmp_path, monkeypatch):
        manager = self._mint(tmp_path, monkeypatch)
        before = manager.ca_key_path.read_bytes()

        with pytest.raises(RuntimeError) as excinfo:
            manager.load_ca()

        message = str(excinfo.value)
        assert message == _short_passphrase_refusal(_ROOT_ENV, read_path=True)
        assert "shorter than Venya's minimum" in message
        assert "Nothing was written." not in message, "the read door drops that clause and only that clause"
        assert "To fix it:" in message and "Reference: docs/" in message, "the block still ships its fix and its docs"
        assert manager.ca_key_path.read_bytes() == before, "the refusal rewrote the incumbent key"
        assert manager.ca_cert_path.read_bytes().startswith(b"-----BEGIN CERTIFICATE-----")

    def test_admin_read_refuses_below_floor(self, tmp_path, monkeypatch):
        monkeypatch.setenv(_ADMIN_ENV, _AT_FLOOR)
        manager = AdminCAManager(tmp_path / "admin-ca")
        manager.initialize()
        monkeypatch.setenv(_ADMIN_ENV, _ACCENTED_14)

        with pytest.raises(RuntimeError) as excinfo:
            manager._load_ca_key()

        message = str(excinfo.value)
        assert message == _short_passphrase_refusal(_ADMIN_ENV, read_path=True)
        assert _ADMIN_ENV in message
        assert "Nothing was written." not in message

    def test_legal_length_read_still_loads_after_a_below_floor_attempt_never_happens(self, tmp_path, monkeypatch):
        """The paired positive on this door: the same key opens when the value is at the floor."""
        monkeypatch.setenv(_ROOT_ENV, _AT_FLOOR)
        manager = CAManager(str(tmp_path / "ca"))
        manager.initialize()

        assert manager.load_ca()[1] is not None

    def test_over_ceiling_passphrase_reads_back(self, tmp_path, monkeypatch):
        """65 code points: accepted on the read door too — the ceiling is a sentence, not a door."""
        monkeypatch.setenv(_ROOT_ENV, _OVER_CEILING)
        manager = CAManager(str(tmp_path / "ca"))
        manager.initialize()
        monkeypatch.setenv(_ROOT_ENV, _OVER_CEILING)

        assert manager.load_ca()[1] is not None


class TestCeilingIsStatedOnly:
    """The stated maximum must be true of the text and absent from the doors."""

    def test_text_states_the_supported_maximum(self):
        message = _short_passphrase_refusal(_ROOT_ENV)
        assert "Venya supports passphrases up to 64 characters" in message
        assert "no maximum below" not in message, "the contradicted clause is replaced, not kept beside the new one"
        assert "always acceptable" not in message

    def test_ceiling_flip_changes_no_refusal(self, tmp_path, monkeypatch):
        """Non-vacuity for §2: MAX 64→63 must move NO door's verdict.

        The ceiling constant exists to interpolate the stated limit; if any cell here
        refused at 64 because of it, this would stay green while the shipped text lied.
        """
        from server import ca

        monkeypatch.setattr(ca, "MAX_PASSPHRASE_CODE_POINTS", 63)
        for phrase in [_AT_CEILING, _OVER_CEILING]:
            monkeypatch.setenv(_ROOT_ENV, phrase)
            manager = CAManager(str(tmp_path / f"ca-{len(phrase)}"))
            manager.initialize()
            assert manager.load_ca()[1] is not None, f"a 63-stated ceiling refused a {len(phrase)}-char value"

    def test_floor_flip_turns_the_stated_number_with_it(self, monkeypatch):
        """The interpolation proof: move MIN and the sentence moves, so it was never typed."""
        from server import ca

        monkeypatch.setattr(ca, "MIN_PASSPHRASE_CODE_POINTS", 5)
        # Re-read through the module so the flipped constant is the one the builder uses.
        message = ca._short_passphrase_refusal(_ROOT_ENV)
        assert "at least 5 characters" in message
        assert "at least 15 characters" not in message
