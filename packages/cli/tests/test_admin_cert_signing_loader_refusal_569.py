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
the sentence the operator reads is the shipped #547 refusal — byte-identical, reused, not
re-typed and not rewritten (the WORDING is the owner's call per #569, so this leg authors
no new sentence).

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
    """N1 + N2 + N3 — the plaintext-plus-real-passphrase pairing, refused in our words."""

    def test_n1_refuses_with_our_sentence_and_the_library_stays_silent(self, tmp_path, capsys):
        """The paired cell: OUR refusal appears AND the library sentence does not.

        Splitting these into two cells would let a half-fix pass — a refusal that prints
        our line and still falls through to the loader would satisfy the positive half.
        """
        ca = _admin_ca(tmp_path)
        _flatten_to_plaintext(ca)
        os.environ["VENYA_ADMIN_CA_KEY_PASSPHRASE"] = PASSPHRASE
        out = tmp_path / "leaf"

        assert cmd_admin_generate_admin_cert(_args(ca, out)) == 1
        captured = capsys.readouterr()
        assert captured.err.startswith(_admin_ca_no_passphrase_refusal().split("\n", 1)[0]), captured.err
        assert "REFUSED" in captured.err
        # the negative half — OpenSSL's fingerprint must not reach the operator, on either
        # stream, and neither must the blanket handler's own prefix.
        assert LIBRARY_FINGERPRINT not in captured.err, captured.err
        assert LIBRARY_FINGERPRINT not in captured.out, captured.out
        assert "Failed to sign admin certificate" not in captured.err, captured.err

    def test_n2_the_byte_identity_is_asserted_not_claimed(self, tmp_path, capsys):
        """#569's wording law: the shipped sentence, character-for-character.

        Compared against ``_admin_ca_no_passphrase_refusal()`` itself rather than a copy
        typed into this file, so a future edit to #547's wording moves BOTH sides at once
        instead of silently red-gating a stale literal (the #554 precedent: reused, with
        the equality proven here rather than asserted in a comment).
        """
        ca = _admin_ca(tmp_path)
        _flatten_to_plaintext(ca)
        os.environ["VENYA_ADMIN_CA_KEY_PASSPHRASE"] = PASSPHRASE

        assert cmd_admin_generate_admin_cert(_args(ca, tmp_path / "leaf")) == 1
        err = capsys.readouterr().err
        shipped_first_line = _admin_ca_no_passphrase_refusal().split("\n", 1)[0]
        assert err == shipped_first_line + "\n", repr(err)
        # and the sentence states this posture, not the blank-passphrase one it shares a
        # renderer with: the CA key is the object, and nothing was written.
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
    """B1 + B2 — the blanket handler stays, and the new gate is where the spec put it."""

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
        """Shape pin: the refusal reads the fact the path already computed, uses the
        shipped renderer, and lands ahead of ``load_pem_private_key``."""
        source = inspect.getsource(cmd_admin_generate_admin_cert)
        gate = source.index("if not is_encrypted and passphrase:")
        assert gate < source.index("ca_key = serialization.load_pem_private_key")
        assert (
            "_admin_ca_no_passphrase_refusal()" in source[gate : gate + 300]
        ), "the refusal must reuse the shipped renderer, not a retyped literal"
        # no new operator-facing sentence on this leg: the refusal print is one call
        assert source.count("_admin_ca_no_passphrase_refusal().split") == 1
