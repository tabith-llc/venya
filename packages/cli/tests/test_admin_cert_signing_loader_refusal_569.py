# Copyright (c) 2026 Tabith LLC.
# Use of this source code is governed by the Business Source License 1.1
# included in the LICENSE file at the root of this repository. As of the
# Change Date listed there, the work is available under MPL 2.0.
# SPDX-License-Identifier: BUSL-1.1

"""#569 — ``venya admin generate-admin-cert`` answers in OUR words, before the loader.

The posture (measured at the base, reproduced before any edit): the admin CA key sits
PLAINTEXT at rest while ``VENYA_ADMIN_CA_KEY_PASSPHRASE`` carries a real value. The only
gate on that read path was ``is_encrypted and not passphrase`` — blank-only — so the
pairing walked straight past it into ``serialization.load_pem_private_key(key_data,
password=passphrase.encode())``, OpenSSL raised, and the blanket
``except Exception`` at the foot of the function handed the operator the library's own
sentence:

    Failed to sign admin certificate: Password was given but private key is not encrypted.

The behavior was already fail-closed and correct — ``rc 1``, nothing written. The defect
is the VOICE. #541 ruled this posture "refuses loudly in OUR words", and until now this
command answered in OpenSSL's. The fix refuses on the ``is_encrypted`` fact that the
read path already computes, so the loader is never reached with the mismatched shape, and
the lines the operator reads are picked out of the shipped #547 refusal — located, not
re-typed and not rewritten (the WORDING is the owner's call per #569, so this leg authors
no new sentence).

Which lines, and why those: the shipped block is 13 lines, and its middle is the
passphrase-NOT-SET repair steps, which would tell this operator to set a variable they
already set. Its headline line and its ``Reference:`` line are both true of THIS posture,
so the picker returns exactly those two and raises if it cannot locate the
``Reference:`` line by prefix — #569's fourth demand is "what to do", and that lives in
shipped bytes (the runbook + BACKUPS pointer), so nothing had to be authored to carry it.

Both halves of the truth table are asserted in the same cell: our sentence appears, and
``"not encrypted"`` — the library's fingerprint — does not surface anywhere. A positive
that only checked our words would stay green if the library sentence were simply
appended to them.
"""

import inspect
import os
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization
from venya_cli.commands import (
    _admin_ca_no_passphrase_refusal,
    _admin_ca_plaintext_key_refusal,
    _admin_leaf_key_no_passphrase_refusal,
    cmd_admin_generate_admin_cert,
    cmd_admin_init_admin_ca,
)

# dev-only test passphrase, the same family the #547/#547a cells already record.
PASSPHRASE = "test_passphrase_569"

# The OpenSSL sentence that used to reach the operator, and the one substring that
# identifies it. Never written out as a whole literal here — the check is on the
# fingerprint.
LIBRARY_FINGERPRINT = "not encrypted"


def _args(ca_dir: Path, out: Path) -> object:
    return type("Args", (), {"identity": "admin@example.com", "ca_dir": str(ca_dir), "output_dir": str(out)})()


def _ca_args(output_dir) -> object:
    return type("Args", (), {"output_dir": str(output_dir)})()


def _admin_ca(tmp_path: Path, phrase: str = PASSPHRASE) -> Path:
    """A real admin CA on disk, minted through the shipped #547 path (key ENCRYPTED)."""
    os.environ["VENYA_ADMIN_CA_KEY_PASSPHRASE"] = phrase
    ca_dir = tmp_path / "admin-ca"
    assert cmd_admin_init_admin_ca(_ca_args(ca_dir)) == 0, "admin CA mint failed"
    return ca_dir


def _flatten_to_plaintext(ca_dir: Path, phrase: str = PASSPHRASE) -> bytes:
    """Rewrite the minted CA key as PLAINTEXT at rest — the #569 operator state.

    Returns the key's plaintext bytes so a cell can prove the refusal did not touch the
    file behind it.
    """
    key_path = ca_dir / "admin-ca.key"
    key = serialization.load_pem_private_key(key_path.read_bytes(), password=phrase.encode())
    plain = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
    key_path.write_bytes(plain)
    assert b"ENCRYPTED" not in plain, "the fixture did not actually flatten the key"
    return plain


@pytest.fixture(autouse=True)
def _clean_env(monkeypatch):
    for var in ("VENYA_ADMIN_CA_KEY_PASSPHRASE", "VENYA_ADMIN_CA_DIR"):
        monkeypatch.delenv(var, raising=False)
    yield


class TestRefusesBeforeTheLoader:
    """N1 + N2 + N3 + N4 + N5 — the plaintext-plus-real-passphrase pairing, refused in
    our words: all four things #569 demands, before the loader, writing nothing, and
    with the wording LOCATED in the shipped block rather than copied out of it."""

    def test_n1_refuses_with_our_sentence_and_the_library_stays_silent(self, tmp_path, capsys):
        """The paired cell: OUR refusal appears AND the library sentence does not.

        Splitting these into two cells would let a half-fix pass — a refusal that prints
        our line and still falls through to the loader would satisfy the positive half.

        #569's Problem asks FOUR things of a refusal, so the cell now demands all four:
        which key, which posture, that nothing was written, AND what to do (the shipped
        ``Reference:`` line, naming both doc paths). The fourth is this leg's addendum —
        the checker measured that dropping the block's tail threw away posture-TRUE bytes.
        """
        ca = _admin_ca(tmp_path)
        _flatten_to_plaintext(ca)
        os.environ["VENYA_ADMIN_CA_KEY_PASSPHRASE"] = PASSPHRASE
        out = tmp_path / "leaf"

        assert cmd_admin_generate_admin_cert(_args(ca, out)) == 1
        captured = capsys.readouterr()
        assert captured.err.startswith(_admin_ca_no_passphrase_refusal().splitlines()[0]), captured.err
        assert "REFUSED" in captured.err
        # the four demands, each one named in the operator's own output
        assert "admin CA key" in captured.err, "demand 1 - which key"
        assert "never be stored unencrypted" in captured.err, "demand 2 - which posture"
        assert "Nothing was written" in captured.err, "demand 3 - that nothing was written"
        assert (
            "Reference: docs/cert-rotation-runbook.md and docs/BACKUPS.md" in captured.err
        ), "demand 4 - what to do, in the shipped reference line"
        # the negative half — OpenSSL's fingerprint must not reach the operator, on either
        # stream, and neither must the blanket handler's own prefix.
        assert LIBRARY_FINGERPRINT not in captured.err, captured.err
        assert LIBRARY_FINGERPRINT not in captured.out, captured.out
        assert "Failed to sign admin certificate" not in captured.err, captured.err

    def test_n2_the_byte_identity_is_asserted_not_claimed(self, tmp_path, capsys):
        """#569's wording law: the shipped lines, character-for-character.

        Both printed lines are compared against ``_admin_ca_no_passphrase_refusal()``
        ITSELF rather than against copies typed into this file, so a future edit to #547's
        wording moves BOTH sides at once instead of silently red-gating a stale literal
        (the #554 precedent: reused, with the equality proven here rather than asserted in
        a comment).
        """
        ca = _admin_ca(tmp_path)
        _flatten_to_plaintext(ca)
        os.environ["VENYA_ADMIN_CA_KEY_PASSPHRASE"] = PASSPHRASE

        assert cmd_admin_generate_admin_cert(_args(ca, tmp_path / "leaf")) == 1
        err = capsys.readouterr().err
        assert err == _admin_ca_plaintext_key_refusal() + "\n", repr(err)
        # the picker's two lines ARE the renderer's headline and Reference lines — so the
        # bytes the operator reads are shipped, and each is located, not copied
        shipped = _admin_ca_no_passphrase_refusal().splitlines()
        reference = next(line for line in shipped if line.startswith("Reference:"))
        assert err == f"{shipped[0]}\n{reference}\n", repr(err)
        # exactly two lines: the off-posture repair steps stay out of the operator's view,
        # and the count pins that no third line crept in
        assert len(err.rstrip("\n").split("\n")) == 2, repr(err)
        assert "To fix it:" not in err
        assert "1. Set VENYA_ADMIN_CA_KEY_PASSPHRASE" not in err
        # and it states this posture, not the blank-passphrase one it shares a renderer
        # with: the CA key is the object, and nothing was written.
        assert "admin CA key must never be stored unencrypted" in err
        assert "Nothing was written" in err

    def test_n3_the_loader_is_never_reached(self, tmp_path, monkeypatch):
        """Mechanism, not message: the fix refuses BEFORE ``load_pem_private_key``.

        A spy on the real entry point proves the sequence, so the cell cannot pass on a
        refusal that merely prints first and calls the loader anyway.
        """
        ca = _admin_ca(tmp_path)
        _flatten_to_plaintext(ca)
        os.environ["VENYA_ADMIN_CA_KEY_PASSPHRASE"] = PASSPHRASE

        calls = []
        real = serialization.load_pem_private_key

        def spy(data, password=None, *a, **kw):
            calls.append(password)
            return real(data, password, *a, **kw)

        monkeypatch.setattr(serialization, "load_pem_private_key", spy)
        assert cmd_admin_generate_admin_cert(_args(ca, tmp_path / "leaf")) == 1
        assert calls == [], "the refusal must land before the loader, not after it"

    def test_n4_nothing_is_written_and_the_ca_key_is_left_alone(self, tmp_path):
        """Fail-closed stayed fail-closed: no output dir, no leaf, and the CA key at rest
        is exactly the bytes the fixture wrote — a refusal does not silently re-encrypt it."""
        ca = _admin_ca(tmp_path)
        plain = _flatten_to_plaintext(ca)
        os.environ["VENYA_ADMIN_CA_KEY_PASSPHRASE"] = PASSPHRASE
        out = tmp_path / "leaf"

        assert cmd_admin_generate_admin_cert(_args(ca, out)) == 1
        assert not out.exists(), f"the refusal created {out}"
        assert (ca / "admin-ca.key").read_bytes() == plain, "the refusal rewrote the CA key"
        assert sorted(p.name for p in ca.iterdir()) == ["admin-ca.crt", "admin-ca.key"]

    def test_n5_the_locator_is_a_locator_not_a_lucky_count(self, tmp_path, monkeypatch, capsys):
        """The addendum's own proof cell: the Reference line is found BY PREFIX, and a
        failed lookup REDS rather than quietly printing a shorter refusal.

        Three in-memory mutations of the shipped renderer, each the opposite of a silent
        fallback, plus the command-level consequence:

        * REMOVED  -> the picker raises; it does not fall back to the headline alone.
        * DOUBLED  -> ambiguous, so it raises rather than picking the first match.
        * MOVED to line 0 -> the headline line and the picked tail are BOTH the Reference
          line now, and each pick still follows the rule (headline is the renderer's line
          0; the tail is the unique Reference-prefixed line). An index-pinned picker would
          have walked off the end of the block here instead of picking by rule.

        Nothing is retyped and no shipped file is edited: the mutations are monkeypatches
        on the module attribute, and the renderer is the real one again after each cell.
        """
        import venya_cli.commands as commands_mod

        shipped = _admin_ca_no_passphrase_refusal().splitlines()
        matches = [line for line in shipped if line.startswith("Reference:")]
        assert len(matches) == 1, f"the fixture premise moved: {matches}"
        reference = matches[0]

        # 1. removed -> loud
        monkeypatch.setattr(
            commands_mod,
            "_admin_ca_no_passphrase_refusal",
            lambda: "\n".join(line for line in shipped if line != reference),
        )
        with pytest.raises(AssertionError, match="expected exactly 1"):
            _admin_ca_plaintext_key_refusal()

        # 2. doubled -> loud, never "first match wins"
        monkeypatch.setattr(
            commands_mod,
            "_admin_ca_no_passphrase_refusal",
            lambda: "\n".join([*shipped, reference]),
        )
        with pytest.raises(AssertionError, match="located 2 "):
            _admin_ca_plaintext_key_refusal()

        # 3. moved to the head -> the picker still selects by rule: index 0 for the
        # headline, and the (now sole) Reference-prefixed line for the tail
        head_moved = [reference, *(line for line in shipped if line != reference)]
        monkeypatch.setattr(
            commands_mod,
            "_admin_ca_no_passphrase_refusal",
            lambda: "\n".join(head_moved),
        )
        picked = _admin_ca_plaintext_key_refusal().splitlines()
        assert picked == [reference, reference], picked

        monkeypatch.undo()
        assert _admin_ca_plaintext_key_refusal() == f"{shipped[0]}\n{reference}"

        # and the loud path is still fail-closed at the command: a broken picker cannot
        # let the loader run or a file appear — it lands in the backstop handler instead.
        monkeypatch.setattr(
            commands_mod,
            "_admin_ca_no_passphrase_refusal",
            lambda: "\n".join(line for line in shipped if line != reference),
        )
        ca = _admin_ca(tmp_path)
        _flatten_to_plaintext(ca)
        os.environ["VENYA_ADMIN_CA_KEY_PASSPHRASE"] = PASSPHRASE
        out = tmp_path / "leaf"
        assert cmd_admin_generate_admin_cert(_args(ca, out)) == 1
        assert not out.exists(), "the loud path signed a certificate anyway"
        err = capsys.readouterr().err
        assert LIBRARY_FINGERPRINT not in err, err
        # Stated plainly, because it is the reason the picker must be loud: with the
        # Reference line gone, the operator gets the backstop handler's prefix around OUR
        # AssertionError text. That is a bug-report shape, not a silent shortening of a
        # ruled refusal — and it is unreachable while the shipped block carries its line.
        assert "refusing to print a shorter refusal" in err, err


class TestTheOtherShapesAreUntouched:
    """P1 + P2 + P3 — the three pairings this leg must NOT move.

    Each pins behavior the new branch sits beside: a correct config still signs, and the
    two blank-passphrase paths still answer with the #547a leaf-key refusal that has
    always fired ahead of the CA read. P2/P3 compare against the shipped renderer instead
    of re-pinning its text, which is the spec's "assert you did not move it".
    """

    def test_p1_encrypted_key_with_the_right_passphrase_still_signs(self, tmp_path, capsys):
        ca = _admin_ca(tmp_path)
        os.environ["VENYA_ADMIN_CA_KEY_PASSPHRASE"] = PASSPHRASE
        out = tmp_path / "leaf"

        assert cmd_admin_generate_admin_cert(_args(ca, out)) == 0
        assert (out / "admin.crt").exists() and (out / "admin.key").exists()
        err = capsys.readouterr().err
        assert LIBRARY_FINGERPRINT not in err
        assert "REFUSED" not in err

    @pytest.mark.parametrize("blank", [None, "", "   "], ids=["unset", "empty", "spaces"])
    def test_p2_encrypted_key_and_no_passphrase_keeps_the_547a_answer(self, tmp_path, monkeypatch, capsys, blank):
        """Unchanged, and unchanged in ORDER: the leaf guard ahead of the CA read answers."""
        ca = _admin_ca(tmp_path)
        if blank is None:
            monkeypatch.delenv("VENYA_ADMIN_CA_KEY_PASSPHRASE", raising=False)
        else:
            monkeypatch.setenv("VENYA_ADMIN_CA_KEY_PASSPHRASE", blank)
        out = tmp_path / "leaf"

        assert cmd_admin_generate_admin_cert(_args(ca, out)) == 1
        assert not out.exists()
        err = capsys.readouterr().err
        assert err == _admin_leaf_key_no_passphrase_refusal("venya admin generate-admin-cert") + "\n", repr(err)

    def test_p3_plaintext_key_and_no_passphrase_keeps_the_547a_answer(self, tmp_path, monkeypatch, capsys):
        """The #547a blank path, reached with a plaintext key behind it: still the leaf
        refusal, still nothing written — the new branch is not in this path at all."""
        ca = _admin_ca(tmp_path)
        _flatten_to_plaintext(ca)
        monkeypatch.delenv("VENYA_ADMIN_CA_KEY_PASSPHRASE", raising=False)
        out = tmp_path / "leaf"

        assert cmd_admin_generate_admin_cert(_args(ca, out)) == 1
        assert not out.exists()
        err = capsys.readouterr().err
        assert err == _admin_leaf_key_no_passphrase_refusal("venya admin generate-admin-cert") + "\n", repr(err)


class TestTheBackstopSurvives:
    """B1 + B2 — the blanket handler stays, and the gate/picker are shaped as ruled."""

    def test_b1_the_blanket_handler_is_still_there(self):
        """#569 does not delete the backstop for genuinely unknown failures; this leg only
        makes the ruled posture unreachable through it. If this leg ever drops the
        handler, this cell is red — the same ``inspect.getsource`` technique #554's N3 and
        #541's suite use to keep a removed warning from coming back."""
        source = inspect.getsource(cmd_admin_generate_admin_cert)
        assert "except Exception as e:" in source, "the blanket backstop was removed"
        assert 'print(f"Failed to sign admin certificate: {e}", file=sys.stderr)' in source
        assert "except RuntimeError as e:" in source

    def test_b2_the_new_gate_sits_on_the_is_encrypted_fact_before_the_load(self):
        """Shape pin, re-aimed by the addendum with the same intent.

        This cell used to look for an inline ``.split`` on the renderer at the call site.
        The wording now lives in one picker, so the drift classes are (a) a shipped line
        retyped anywhere and (b) a Reference line picked by index. Both are checked here,
        on the call site AND on the picker.
        """
        source = inspect.getsource(cmd_admin_generate_admin_cert)
        gate = source.index("if not is_encrypted and passphrase:")
        assert gate < source.index("ca_key = serialization.load_pem_private_key")
        assert (
            source.count("print(_admin_ca_plaintext_key_refusal(), file=sys.stderr)") == 1
        ), "the refusal print must be the one picker call"
        assert "REFUSED:" not in source, "no shipped wording may be retyped at the call site"

        picker = inspect.getsource(_admin_ca_plaintext_key_refusal)
        assert "_admin_ca_no_passphrase_refusal()" in picker, "the picker must derive from the renderer"
        assert ".startswith(" in picker, "the Reference line must be located by PREFIX"
        assert '"Reference:"' in picker, "the picker must name the prefix it looks for"
        assert "Reference: docs" not in picker, "the Reference LINE may not be retyped either"
        assert "cert-rotation-runbook" not in picker, "nor may the doc paths be copied"
        assert "lines[12]" not in picker and ".index(" not in picker, "not a count from the top"
        assert "print(" not in picker, "the picker returns text; it does not print it"
