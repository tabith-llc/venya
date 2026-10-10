# Copyright (c) 2026 Tabith LLC.
# Use of this source code is governed by the Business Source License 1.1
# included in the LICENSE file at the root of this repository. As of the
# Change Date listed there, the work is available under MPL 2.0.
# SPDX-License-Identifier: BUSL-1.1

"""#574 server-ca-key-decrypt-refusal-voice — the truth table for one ruled sentence.

The wrong-passphrase arm of ``_deserialize_key`` used to interpolate the cryptography loader's
own sentence after our colon:

    Failed to decrypt CA key with provided passphrase: Incorrect password, could not decrypt key

The behavior at that line was already fail-closed and correct — a RuntimeError, ``from e`` keeping
the cause, nothing loaded and nothing re-wrapped. What was wrong is the VOICE (#541's blanket rule:
any library sentence reaching an operator is non-compliant), and the class rule that governs the
replacement is R8-ADDENDUM (decisions.md commit dd1de4c): our own words, no mechanism named, the key
path substituted, plus a next-step pointer (#569), aligned to the AMENDED Q4 custody ladder — backup
enrollment is OPTIONAL, so the pointer must not imply a backup always exists.

Paired negatives, both halves in one place, per the house truth-table law: the Venya sentence appears
AND no library substring surfaces; the correct passphrase still LOADS; the sibling no-passphrase arm
keeps its shipped bytes; a caller with no path gets an honest sentence rather than the word "None".

The damaged-key cell from the dispatch's original §4.2 is NOT here — passing it needs the #572
parseability probe, which is a behavior change, and this row is a voice row. That requirement was
struck from this leg and went back to the ticket as its own follow-up (amendment v2 §2(c)).

Everything measured at base 5cb9f8d8eccde773127e5900259f4c8a15c41f2b; the library strings asserted
absent were read off a live probe of cryptography 50.0.0 at that base, not from memory.
"""

import logging
import re
from pathlib import Path

import pytest
from server.ca import (
    AdminCAManager,
    CAManager,
    _ca_key_decrypt_refusal,
    _deserialize_key,
)

_ROOT_ENV = "VENYA_CA_KEY_PASSPHRASE"
_ADMIN_ENV = "VENYA_ADMIN_CA_KEY_PASSPHRASE"
_RIGHT = "correct-passphrase-574"
_WRONG = "wrong-passphrase-574"

#: The library's own sentences, measured at this base with cryptography 50.0.0:
#:   wrong passphrase on an intact encrypted key -> "Incorrect password, could not decrypt key"
#:   damaged / truncated body                   -> "Unable to load PEM file. See https://…"
#: None of these may reach the operator through our refusal.
_LIBRARY_VOICES = (
    "Incorrect password",
    "could not decrypt key",
    "Unable to load PEM file",
    "MalformedFraming",
    "InvalidData",
    "Password was not given",
    "Password was given but private key is not encrypted",
)

#: Our own headline, the ruled class shape with the path slot left open (asserted as a prefix on both
#: planes, so a wording fork between the two managers trips these cells instead of shipping quietly).
_HEADLINE = "could not be decrypted — the passphrase did not match."

#: The four elements R8-ADDENDUM + #569 rule into one sentence family. Checked per cell, not assumed.
_RETRY_POINTER = "Retry with the correct passphrase"
_CONDITIONAL_RESTORE = "when either was made for this key"
_SETUP_ALTERNATIVE = "otherwise re-run the CA setup"


def _assert_class_shape(message: str, expect_path: str | None) -> None:
    """The ruled invariant, as an assertion: our words · no library voice · path named · pointer present."""
    assert _HEADLINE in message, f"the ruled headline is missing: {message!r}"
    for voice in _LIBRARY_VOICES:
        assert voice not in message, f"the library's own sentence leaked into the refusal: {voice!r}"
    assert _RETRY_POINTER in message, "the #569 next-step pointer (retry) is missing"
    assert _CONDITIONAL_RESTORE in message, "the restore pointer is not conditional (Q4-AMENDMENT)"
    assert _SETUP_ALTERNATIVE in message, "the always-true alternative is missing"
    assert "None" not in message, "the literal word None reached the operator"
    if expect_path is not None:
        assert expect_path in message, f"the refusal must name the key it tried to open: {expect_path!r}"
    else:
        assert "The CA key at " not in message, "a no-path refusal must not claim a path it does not have"


@pytest.fixture
def root_manager(tmp_path: Path, monkeypatch) -> CAManager:
    monkeypatch.setenv(_ROOT_ENV, _RIGHT)
    manager = CAManager(str(tmp_path / "ca"))
    manager.initialize()
    return manager


@pytest.fixture
def admin_manager(tmp_path: Path, monkeypatch) -> AdminCAManager:
    monkeypatch.setenv(_ADMIN_ENV, _RIGHT)
    manager = AdminCAManager(tmp_path / "admin-ca")
    manager.initialize()
    return manager


class TestWrongPassphraseRefuses574:
    """AC1 — both planes refuse in our words, each naming the key file it actually tried to open."""

    def test_root_load_refuses_in_the_ruled_shape_with_the_real_path(
        self, root_manager: CAManager, monkeypatch
    ) -> None:
        monkeypatch.setenv(_ROOT_ENV, _WRONG)
        with pytest.raises(RuntimeError) as excinfo:
            root_manager.load_ca()

        message = str(excinfo.value)
        _assert_class_shape(message, expect_path=str(root_manager.ca_key_path))
        assert message.startswith(f"The CA key at {root_manager.ca_key_path} ")
        # The mechanism is NOT lost — it rides the chained cause for a support engineer.
        assert isinstance(excinfo.value.__cause__, ValueError)
        assert "Incorrect password" in str(excinfo.value.__cause__)

    def test_admin_load_refuses_in_the_ruled_shape_with_the_real_path(
        self, admin_manager: AdminCAManager, monkeypatch
    ) -> None:
        monkeypatch.setenv(_ADMIN_ENV, _WRONG)
        with pytest.raises(RuntimeError) as excinfo:
            admin_manager._load_ca_key()

        message = str(excinfo.value)
        _assert_class_shape(message, expect_path=str(admin_manager.ca_key_path))
        assert isinstance(excinfo.value.__cause__, ValueError)

    def test_both_planes_share_one_sentence_modulo_the_path(self, tmp_path: Path, monkeypatch) -> None:
        """R8-ADDENDUM's grep-able invariant: same text across surfaces, path substituted, nothing else."""
        root = CAManager(str(tmp_path / "ca"))
        admin = AdminCAManager(tmp_path / "admin-ca")
        monkeypatch.setenv(_ROOT_ENV, _RIGHT)
        monkeypatch.setenv(_ADMIN_ENV, _RIGHT)
        root.initialize()
        admin.initialize()
        monkeypatch.setenv(_ROOT_ENV, _WRONG)
        monkeypatch.setenv(_ADMIN_ENV, _WRONG)

        with pytest.raises(RuntimeError) as root_exc:
            root.load_ca()
        with pytest.raises(RuntimeError) as admin_exc:
            admin._load_ca_key()

        root_text = str(root_exc.value)
        admin_text = str(admin_exc.value)
        # The ruled invariant is "same text across surfaces, path substituted" (R8-ADDENDUM), so the
        # paths are substituted OUT before comparison — a sentence that differs anywhere else is a fork.
        root_stripped = root_text.replace(str(root.ca_key_path), "<PATH>")
        admin_stripped = admin_text.replace(str(admin.ca_key_path), "<PATH>")
        assert (
            root_stripped == admin_stripped
        ), "the two server planes typed two sentences — the class rule is one, modulo the path"
        assert "<PATH>" in root_stripped, "the path is not the only difference between the planes"

        # And each plane's text is exactly the builder's own output for its own key file.
        assert root_text == _ca_key_decrypt_refusal(root.ca_key_path)
        assert admin_text == _ca_key_decrypt_refusal(admin.ca_key_path)


class TestNoPathFallback574:
    """AC2 — a caller that gives no path gets an honest sentence, not the word None (amendment §2(a))."""

    def test_two_argument_call_refuses_without_a_path(self, root_manager: CAManager) -> None:
        data = root_manager.ca_key_path.read_bytes()
        with pytest.raises(RuntimeError) as excinfo:
            _deserialize_key(data, _WRONG.encode("utf-8"))

        _assert_class_shape(str(excinfo.value), expect_path=None)

    def test_none_and_empty_path_take_the_same_fallback_headline(self) -> None:
        assert _ca_key_decrypt_refusal(None) == _ca_key_decrypt_refusal("")
        assert _ca_key_decrypt_refusal(None).startswith("The CA key could not be decrypted ")


class TestSurfacesCarryNoLibraryVoice574:
    """AC2's other half — the three surfaces the AC names, all in ONE cell.

    The AC reads: "the Venya sentence appears AND no library substring surfaces — stderr, stdout, or
    log. A positive-only cell does not close this AC." The cells above assert the first clause (and,
    at :118-119, that the library sentence still rides the chained cause for support). This cell owns
    the second clause across all three surfaces at once.

    What is true at this base, said plainly so the cell is not mistaken for a bug report: there is NO
    live leak. ``_deserialize_key`` raises and prints nothing, and nothing at that seam logs the
    exception with its cause. So the refusal's own stderr/stdout are empty and the log carries no
    library voice — and that holds BY FACT, not by check, until this cell exists. The regression this
    guards is the next seat adding one line, ``logger.exception("CA key decrypt failed")`` at the raise
    being the obvious candidate: ``logging`` renders a chained cause in full, so that one line would
    put cryptography's sentence into the log record while our own sentence stayed perfect on screen.
    Both red controls in the report for this leg show exactly that happening and going red here.

    Two honesty notes about shape, because a vacuous absence assertion is the failure mode:
      * the log capture is proven LIVE inside the cell (a probe record is asserted PRESENT in
        ``caplog.text`` before anything is asserted absent from it), so "absent from the log" is an
        assertion about a captured stream, not about an empty one;
      * the probe logger is this test's own ``venya.test574.capture_probe``, not a product logger, so
        the cell proves the harness works without inventing product behavior it then depends on.
    """

    def test_all_three_surfaces_carry_our_words_and_no_library_voice(
        self, root_manager: CAManager, monkeypatch, capsys, caplog
    ) -> None:
        monkeypatch.setenv(_ROOT_ENV, _WRONG)
        # Capture at DEBUG on the product logger, so an added logger.info() would be seen too.
        caplog.set_level(logging.DEBUG, logger="venya.ca")
        probe = logging.getLogger("venya.test574.capture_probe")

        with pytest.raises(RuntimeError) as excinfo:
            root_manager.load_ca()

        captured = capsys.readouterr()
        probe.warning("capture-probe-574-live")

        message = str(excinfo.value)
        # First clause of AC2, restated here so the cell is a genuine paired negative in one place.
        _assert_class_shape(message, expect_path=str(root_manager.ca_key_path))

        # Liveness before absence: if the probe record is not in the captured stream, the stream is
        # not being read and the absence assertions below would be vacuous. Fail loudly instead.
        assert "capture-probe-574-live" in caplog.text, (
            "the log surface is not being captured in this cell — the absence assertions below " "would prove nothing"
        )

        # Surface 1 and 2: this seam raises and never prints, so the refusal's own streams are empty.
        # Emptiness is asserted first, then absence-by-containment, so a future print() shows up in
        # the diff as a broken emptiness claim and not just a missing substring.
        assert captured.out == "", f"stdout is not empty on the refusal: {captured.out!r}"
        assert captured.err == "", f"stderr is not empty on the refusal: {captured.err!r}"

        # Surface 3, and the belt-and-braces half of 1 and 2: no library voice anywhere, per surface.
        for voice in _LIBRARY_VOICES:
            assert voice not in captured.out, f"library voice on stdout: {voice!r}"
            assert voice not in captured.err, f"library voice on stderr: {voice!r}"
            assert voice not in caplog.text, (
                f"library voice in the captured log: {voice!r} — a chained cause is being rendered "
                f"to the log record, which is what #541's blanket rule forbids"
            )

        # The mechanism is still preserved internally (this is NOT a traceback-integrity check —
        # :118-119 own that; this line says the surfaces are clean WHILE the cause is intact).
        assert isinstance(excinfo.value.__cause__, ValueError)
        assert "Incorrect password" in str(excinfo.value.__cause__), (
            "precondition: the library sentence really exists in this process — if it does not, the "
            "absence assertions above are vacuous because nothing was there to leak"
        )


class TestDoNotMovePins574:
    """AC3 — the neighbor and the governing standard keep their shipped bytes."""

    def test_sibling_no_passphrase_arm_is_byte_identical(self, root_manager: CAManager) -> None:
        """The `else` arm three lines below keeps the text #541 shipped; this leg does not touch it.

        Reached the only way it is reachable: an encrypted key with NO password raises TypeError
        inside the loader, and #541 keeps that shape on its own branch above — so the arm under
        test fires on bytes the parser cannot read at all, with no passphrase supplied. The
        assertion is on the shipped bytes, not on the exception class.
        """
        unparseable = b"-----BEGIN ENCRYPTED PRIVATE KEY-----\nnot-base64-at-all\n-----END ENCRYPTED PRIVATE KEY-----\n"
        with pytest.raises(RuntimeError) as excinfo:
            _deserialize_key(unparseable, None)

        assert str(excinfo.value) == (
            "Failed to load CA key (may be encrypted but no passphrase provided). "
            "Set the passphrase environment variable."
        )
        assert isinstance(excinfo.value.__cause__, ValueError)

    def test_correct_passphrase_still_loads_on_both_planes(
        self, root_manager: CAManager, admin_manager: AdminCAManager
    ) -> None:
        """The paired negative — a catch that eats success would be worse than the leak it fixed."""
        cert, key = root_manager.load_ca()
        assert key is not None and cert is not None
        assert root_manager.sign_csr is not None  # the loaded key is usable, not a stub
        admin_cert, admin_key = admin_manager._load_ca_cert_and_key()
        assert admin_key is not None and admin_cert is not None


class TestNoLeakAnywhereInFile574:
    """AC4 — prove the census, do not assert it: no library voice survives in ca.py's operator text."""

    def test_no_exception_is_interpolated_into_a_raised_string(self) -> None:
        source = Path(__file__).resolve().parents[1].joinpath("src/server/ca.py").read_text(encoding="utf-8")
        offenders = re.findall(r'raise \w+\(\s*f"[^"]*\{e\}', source)
        assert offenders == [], f"exception text is still interpolated into a raise: {offenders}"

    def test_library_sentences_appear_nowhere_in_the_servers_operator_strings(self) -> None:
        source = Path(__file__).resolve().parents[1].joinpath("src/server/ca.py").read_text(encoding="utf-8")
        for voice in ("Incorrect password", "could not decrypt key", "Unable to load PEM file"):
            assert voice not in source, f"the library sentence is typed into ca.py: {voice!r}"

    def test_the_refusal_has_exactly_one_hand_written_home(self) -> None:
        """#568's single-home shape (the #572 sibling pins the same thing on the CLI side)."""
        source = Path(__file__).resolve().parents[1].joinpath("src/server/ca.py").read_text(encoding="utf-8")
        typed = [line for line in source.splitlines() if _HEADLINE in line and not line.lstrip().startswith("#")]
        assert len(typed) == 2, f"expected the two headline lines in one builder function, found {len(typed)}: {typed}"
