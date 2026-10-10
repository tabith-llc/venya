# Copyright (c) 2026 Tabith LLC.
# Use of this source code is governed by the Business Source License 1.1
# included in the LICENSE file at the root of this repository. As of the
# Change Date listed there, the work is available under MPL 2.0.
# SPDX-License-Identifier: BUSL-1.1

"""#572 — a wrong passphrase on the admin CA key answers in the owner's words, and only when the
file really is an intact encrypted key.

Before this leg, `venya admin generate-admin-cert` with an encrypted `admin-ca.key` and the wrong
passphrase fell through to the command's blanket handler and printed
``Failed to sign admin certificate: <cryptography's sentence>``. The second half is the library
speaking — that is the defect #572 files.

The close is posture-scoped, and the scope is the finding (the lane's measurement, adopted by the
lead's ruling in room wren-37). The shipped `is_encrypted` check is a SUBSTRING test, so a truncated
key, armor kept over a swapped body, and armor kept over a non-base64 body ALL still claim to be
encrypted; printing a passphrase refusal for those would send an operator with a DAMAGED file off to
re-type a correct passphrase forever. So the approved sentence fires only when a passphrase was
supplied AND the marker is present AND a probe says the file parses as an encrypted key. The probe
asks the same loader with NO password and reads the exception CLASS: ``TypeError`` = parseable
encrypted key, ``ValueError`` = damaged. No fragment of the library's message is read in the code or
in these cells.

Truth tables follow the project rule — every positive half carries paired negatives, each red on its
own. `test_probe_classifies_all_six_measured_shapes` is the six-sample table the ruling books as AC
evidence.
"""

from __future__ import annotations

import base64
import re
from pathlib import Path
from typing import Any

import pytest
from venya_cli import commands
from venya_cli.commands import (
    ADMIN_CA_DECRYPT_REFUSAL,
    _admin_ca_plaintext_key_refusal,
    _admin_ca_wrong_passphrase_refusal,
    cmd_admin_generate_admin_cert,
    cmd_admin_init_admin_ca,
)

# Derived from the shipped #569 refusal, never re-typed here (the same no-second-copy rule this
# file already applies to its own approved sentence).
_PLAINTEXT_REFUSAL_HEAD = _admin_ca_plaintext_key_refusal().splitlines()[0]

# Dev-only values written into a tmp_path CA; not secrets and never leave the test.
RIGHT_PASSPHRASE = "right_passphrase_572"  # pragma: allowlist secret
WRONG_PASSPHRASE = "wrong_passphrase_572"  # pragma: allowlist secret

# Per the ruling, NO library sentence is matched anywhere in this file — not even to assert its
# absence. The positive cell instead pins the operator-visible refusal BYTE-FOR-BYTE as the approved
# line plus the derived reference line: a shape that is exactly two named lines cannot also carry
# the library's words, so the absence proof is structural rather than string-matched.
BACKSTOP_PREFIX = "Failed to sign admin certificate:"
KEY_MARKER = b"ENCRYPTED"


class CmdArgs:
    """Minimal stand-in for the argparse namespace these commands read."""

    def __init__(self, **fields: Any) -> None:
        for name, value in fields.items():
            setattr(self, name, value)


def _init_ca(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """Create an admin CA the CLI itself wrote, so the key on disk is the real shipped shape."""
    monkeypatch.setenv("VENYA_ADMIN_CA_KEY_PASSPHRASE", RIGHT_PASSPHRASE)
    ca_dir = tmp_path / "admin-ca"
    ca_dir.mkdir()
    assert cmd_admin_init_admin_ca(CmdArgs(output_dir=str(ca_dir))) == 0
    key = ca_dir / "admin-ca.key"
    assert KEY_MARKER in key.read_bytes(), "the shipped writer must produce an encrypted CA key"
    return ca_dir


def _gen_args(ca_dir: Path, out_dir: Path) -> CmdArgs:
    return CmdArgs(identity="admin@venya.test", ca_dir=str(ca_dir), output_dir=str(out_dir))


def _armor_kept(data: bytes, body: str) -> bytes:
    text = data.decode()
    lines = [line for line in text.splitlines() if line]
    return f"{lines[0]}\n{body}\n{lines[-1]}\n".encode()


def _truncated(data: bytes) -> bytes:
    """Armor intact, most of the body gone — the half-restored-backup / bad-scp shape."""
    lines = [line for line in data.decode().splitlines() if line]
    return ("\n".join(lines[:3]) + "\n" + lines[-1] + "\n").encode()


def _swapped_body(data: bytes) -> bytes:
    """Armor intact, body replaced by valid base64 of bytes that are not the key blob."""
    return _armor_kept(data, base64.b64encode(bytes(40)).decode())


def _non_base64_body(data: bytes) -> bytes:
    """Armor intact, body is not base64 at all."""
    return _armor_kept(data, "!!!not-base64-at-all!!!")


def _unencrypted_key_bytes() -> bytes:
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import ec

    return ec.generate_private_key(ec.SECP256R1()).private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )


def _probe(data: bytes) -> bool:
    from cryptography.hazmat.primitives import serialization

    return commands._encrypted_key_is_parseable(serialization, data)


def _expected_refusal_lines() -> list[str]:
    """The two lines the operator must see, derived (never re-typed) from the shipped homes."""
    return _admin_ca_wrong_passphrase_refusal().splitlines()


# --- positive half: intact encrypted key + a wrong passphrase ---


def test_wrong_passphrase_answers_in_the_owners_words(tmp_path, monkeypatch, capsys) -> None:
    """Approved sentence byte-equal to the named home, Reference line present, library voice absent."""
    ca_dir = _init_ca(tmp_path, monkeypatch)
    out_dir = tmp_path / "admin-out"
    monkeypatch.setenv("VENYA_ADMIN_CA_KEY_PASSPHRASE", WRONG_PASSPHRASE)

    # Drain BEFORE the call under test, so `captured` below holds only what this refusal printed.
    # capsys has been accumulating the FIXTURE's stdout too (cmd_admin_init_admin_ca prints its
    # readout at commands.py:4488); draining after the call would fold the refusal's own output into
    # the pre-call buffer and make the stdout assertion empty no matter what the product did —
    # a vacuous green. The precondition assert below keeps the drain honest: if the setup readout is
    # not what we are clearing, the fixture moved and the cell must say so.
    pre_call = capsys.readouterr()
    assert pre_call.out.startswith("Admin CA initialized at"), (
        f"fixture precondition: the setup readout is what should be in the buffer before the call, "
        f"got {pre_call.out!r}"
    )

    result = cmd_admin_generate_admin_cert(_gen_args(ca_dir, out_dir))
    captured = capsys.readouterr()

    assert result == 1, f"a wrong passphrase must not succeed, got rc={result}"
    assert captured.err.strip().splitlines() == _expected_refusal_lines(), (
        f"the refusal is not exactly the approved line then the reference line — the operator is "
        f"reading something else: {captured.err!r}"
    )
    # AC2's stdout half, the one this file never tested (grep -cE 'captured\.out' was 0 at base).
    # Asserted STRUCTURALLY, on stdout's emptiness, because this file's own rule forbids typing a
    # library sentence even to assert its absence (see the comment above BACKSTOP_PREFIX): an empty
    # stdout cannot carry any sentence, ours or the loader's. So this cell proves BOTH readings of
    # AC2 — the library substring is absent from stdout (nothing is there), and stdout carries
    # nothing the operator should be reading. Every refusal print in this path names file=sys.stderr
    # (commands.py:4775, :4792, :4906), which is what makes emptiness the right assertion rather than
    # a lucky artifact. Scoped by the drain above, so this is the refusal's own stdout, not the
    # fixture's.
    assert captured.out == "", (
        f"stdout is not empty on a refused passphrase — an operator reading the command's normal "
        f"output is being handed text from the failure path: {captured.out!r}"
    )
    first_line = captured.err.splitlines()[0]
    assert first_line == ADMIN_CA_DECRYPT_REFUSAL, (
        f"the refusal opens with {first_line!r}, not the named home "
        f"{ADMIN_CA_DECRYPT_REFUSAL!r} — the owner approved THOSE bytes"
    )
    written = list(out_dir.iterdir()) if out_dir.exists() else []
    assert not written, f"a refused passphrase wrote {written} while saying 'Nothing was written.'"


def test_correct_passphrase_still_signs(tmp_path, monkeypatch, capsys) -> None:
    """The catch does not eat success: right passphrase → rc 0 and a signed pair on disk."""
    ca_dir = _init_ca(tmp_path, monkeypatch)
    out_dir = tmp_path / "admin-out"
    monkeypatch.setenv("VENYA_ADMIN_CA_KEY_PASSPHRASE", RIGHT_PASSPHRASE)

    result = cmd_admin_generate_admin_cert(_gen_args(ca_dir, out_dir))

    assert result == 0, f"a correct passphrase must still sign, got rc={result}: {capsys.readouterr().err}"
    assert (out_dir / "admin.key").exists() and (out_dir / "admin.crt").exists()
    assert ADMIN_CA_DECRYPT_REFUSAL not in capsys.readouterr().err


# --- paired negatives: files that still claim to be encrypted but are damaged ---


@pytest.mark.parametrize(
    "shape,mutate",
    [
        ("truncated", _truncated),
        ("body-swapped", _swapped_body),
        ("non-base64-body", _non_base64_body),
    ],
)
def test_damaged_encrypted_files_are_not_passphrase_failures(tmp_path, monkeypatch, capsys, shape, mutate) -> None:
    """Marker-true but damaged → the untouched backstop, never the approved passphrase sentence.

    This is the half that keeps the close honest: `is_encrypted` alone is True for all three shapes,
    so a marker-only scope would blame the operator's typing for a damaged CA key.
    """
    ca_dir = _init_ca(tmp_path, monkeypatch)
    key = ca_dir / "admin-ca.key"
    mutated = mutate(key.read_bytes())
    assert KEY_MARKER in mutated, f"{shape}: the sample must keep the marker to exercise the scope"
    key.write_bytes(mutated)
    out_dir = tmp_path / "admin-out"
    monkeypatch.setenv("VENYA_ADMIN_CA_KEY_PASSPHRASE", RIGHT_PASSPHRASE)

    result = cmd_admin_generate_admin_cert(_gen_args(ca_dir, out_dir))
    captured = capsys.readouterr()

    assert result == 1, f"{shape}: a damaged key must still fail closed, got rc={result}"
    assert (
        ADMIN_CA_DECRYPT_REFUSAL not in captured.err
    ), f"{shape}: a damaged key was told its passphrase is wrong — {captured.err!r}"
    assert (
        BACKSTOP_PREFIX in captured.err
    ), f"{shape}: the damaged shape stopped reaching the untouched backstop: {captured.err!r}"


def test_markerless_garbage_is_refused_upstream_of_this_leg(tmp_path, monkeypatch, capsys) -> None:
    """COMPOSED tree: markerless garbage belongs to #569, and never to this leg.

    At `c5712bd` (this leg's own base) such a file carried no marker and met no guard, so it walked
    into the loader and the backstop answered. On `dba4868` the #569 guard
    (`not is_encrypted and passphrase`) claims that shape first — measured on dev alone, not
    inferred. What stays pinned about #572 either way: no encrypted marker means this leg's approved
    sentence must not appear.
    """
    ca_dir = _init_ca(tmp_path, monkeypatch)
    (ca_dir / "admin-ca.key").write_bytes(b"not a pem at all")
    out_dir = tmp_path / "admin-out"
    monkeypatch.setenv("VENYA_ADMIN_CA_KEY_PASSPHRASE", RIGHT_PASSPHRASE)

    result = cmd_admin_generate_admin_cert(_gen_args(ca_dir, out_dir))
    captured = capsys.readouterr()

    assert result == 1
    assert (
        ADMIN_CA_DECRYPT_REFUSAL not in captured.err
    ), f"garbage with no marker was called a passphrase failure: {captured.err!r}"
    assert (
        _PLAINTEXT_REFUSAL_HEAD in captured.err
    ), f"the composed tree should answer this shape with the #569 refusal: {captured.err!r}"


def test_unencrypted_key_with_a_passphrase_is_answered_by_569(tmp_path, monkeypatch, capsys) -> None:
    """COMPOSED tree: the plaintext-key posture is #569's refusal, and never enters this catch.

    That branch landed, so this pin moved from "still falls to the backstop" (true at
    `c5712bd`) to the shipped #569 wording. The #572 claim preserved here is the SCOPE: the loader
    raises ``TypeError`` for this pairing, so it can never reach this leg's ``ValueError`` catch and
    the approved wrong-passphrase sentence must stay absent.
    """
    ca_dir = _init_ca(tmp_path, monkeypatch)
    (ca_dir / "admin-ca.key").write_bytes(_unencrypted_key_bytes())
    assert KEY_MARKER not in (ca_dir / "admin-ca.key").read_bytes()
    out_dir = tmp_path / "admin-out"
    monkeypatch.setenv("VENYA_ADMIN_CA_KEY_PASSPHRASE", RIGHT_PASSPHRASE)

    result = cmd_admin_generate_admin_cert(_gen_args(ca_dir, out_dir))
    captured = capsys.readouterr()

    assert result == 1
    assert ADMIN_CA_DECRYPT_REFUSAL not in captured.err, (
        f"the plaintext posture was routed through the passphrase refusal — #569 owns it: " f"{captured.err!r}"
    )
    assert (
        _PLAINTEXT_REFUSAL_HEAD in captured.err
    ), f"the composed tree lost the #569 refusal for this posture: {captured.err!r}"


# --- the probe, with both halves of its own truth table (the ruling's §8(2) widening) ---


def test_probe_classifies_all_six_measured_shapes(tmp_path, monkeypatch) -> None:
    """The six samples the ruling books as AC evidence — exception CLASS only, no message reads."""
    ca_dir = _init_ca(tmp_path, monkeypatch)
    intact = (ca_dir / "admin-ca.key").read_bytes()

    assert _probe(intact) is True, "an intact encrypted key must read as parseable-encrypted"

    damaged = (
        ("truncated", _truncated(intact)),
        ("body-swapped", _swapped_body(intact)),
        ("non-base64-body", _non_base64_body(intact)),
        ("plaintext-garbage", b"not a pem at all"),
        ("unencrypted-key", _unencrypted_key_bytes()),
    )
    for label, data in damaged:
        assert _probe(data) is False, f"{label}: the probe read a non-parseable-encrypted file as encrypted"


def test_probe_scales_across_the_marker_boundary(tmp_path, monkeypatch) -> None:
    """Third probe half: the marker and the probe are different questions, measured side by side.

    The three damaged shapes carry the marker yet fail the probe; the unencrypted key passes neither.
    That divergence is exactly why the scope needs the probe and not `is_encrypted` alone.
    """
    ca_dir = _init_ca(tmp_path, monkeypatch)
    intact = (ca_dir / "admin-ca.key").read_bytes()

    for label, data in (
        ("truncated", _truncated(intact)),
        ("body-swapped", _swapped_body(intact)),
        ("non-base64-body", _non_base64_body(intact)),
    ):
        assert (
            KEY_MARKER in data and _probe(data) is False
        ), f"{label}: marker=True/probe=False is the divergence this leg scopes on"

    unencrypted = _unencrypted_key_bytes()
    assert (
        KEY_MARKER not in unencrypted and _probe(unencrypted) is False
    ), "an unencrypted key must be marker-false AND probe-false — no path to the passphrase sentence"


def test_refusal_is_the_approved_sentence_plus_the_derived_reference_line() -> None:
    """Two lines, each from ONE home: the approved constant and the located shipped reference."""
    lines = _admin_ca_wrong_passphrase_refusal().splitlines()

    assert len(lines) == 2, f"the refusal is the approved line then the reference line: {lines!r}"
    assert lines[0] == ADMIN_CA_DECRYPT_REFUSAL, f"first line drifted: {lines[0]!r}"
    assert lines[1].startswith(commands.REFERENCE_LINE_PREFIX), f"second line is not the reference: {lines[1]!r}"


def test_reference_locator_refuses_any_count_but_one(monkeypatch) -> None:
    """The locator's own negative halves: zero matches and two matches both raise, never guess."""

    def fake_refusal(text: str):
        def _inner() -> str:
            return text

        return _inner

    monkeypatch.setattr(commands, "_admin_ca_no_passphrase_refusal", fake_refusal("no reference line here"))
    with pytest.raises(RuntimeError, match="exactly one doc-reference line"):
        _admin_ca_wrong_passphrase_refusal()

    twice = f"{commands.REFERENCE_LINE_PREFIX} once\n{commands.REFERENCE_LINE_PREFIX} twice"
    monkeypatch.setattr(commands, "_admin_ca_no_passphrase_refusal", fake_refusal(twice))
    with pytest.raises(RuntimeError, match="exactly one doc-reference line"):
        _admin_ca_wrong_passphrase_refusal()

    padded = "  " + commands.REFERENCE_LINE_PREFIX + " padded  "
    monkeypatch.setattr(commands, "_admin_ca_no_passphrase_refusal", fake_refusal(padded))
    assert _admin_ca_wrong_passphrase_refusal().splitlines()[1] == commands.REFERENCE_LINE_PREFIX + " padded"


# --- the single-home pin (#568's discipline, on the owner's bytes) ---


def test_the_approved_sentence_has_exactly_one_hand_written_home() -> None:
    """The approved bytes are typed once in the product tree: the constant definition above."""
    source = Path(commands.__file__).read_text(encoding="utf-8")
    typed = [line.strip() for line in source.splitlines() if ADMIN_CA_DECRYPT_REFUSAL in line]

    assert len(typed) == 1, (
        f"the approved sentence appears on {len(typed)} lines of commands.py — exactly the constant "
        f"definition is allowed, a second hand-written copy is how #553 hid: {typed}"
    )


def test_both_reference_pickers_hold_in_the_composed_tree() -> None:
    """The interlock neither branch could test alone: two pickers, one shared block, both exactly-one.

    #569 picks its reference line by the prefix ``"Reference:"`` and #572 picks by
    ``REFERENCE_LINE_PREFIX``; both scan the shipped #547 block's OWN ``splitlines()``. Across the
    FILE the longer string occurs more than once (the leaf-key refusal carries its own copy, and the
    prefix constant is a line of its own), so scoping — not luck — is what keeps each count at one.
    Both pickers raise rather than guess, so this cell measures the two sides together: if either
    ever loosens its count or drops the block scoping, this goes red on the composition, not on one
    branch.

    The #569 prefix is READ out of that function's source rather than re-typed here, so a future edit
    to either picker is seen as what it is: a change to a shared locator.
    """
    src = Path(commands.__file__).read_text(encoding="utf-8")
    matcher = re.search(r'prefix = "(Reference:[^"]*)"', src)
    assert matcher, "the #569 picker's prefix literal is no longer readable in commands.py — re-check the picker"
    prefix_569 = matcher.group(1)

    block = commands._admin_ca_no_passphrase_refusal().splitlines()
    hits_569 = [line for line in block if line.startswith(prefix_569)]
    hits_572 = [line for line in block if line.strip().startswith(commands.REFERENCE_LINE_PREFIX)]
    assert (
        len(hits_569) == 1
    ), f"the #569 picker found {len(hits_569)} {prefix_569!r} lines inside the #547 block, expected 1"
    assert len(hits_572) == 1, f"the #572 picker found {len(hits_572)} lines, expected 1"

    # Both refusals render, and they agree on the reference line they print.
    refusal_569 = _admin_ca_plaintext_key_refusal()
    refusal_572 = _admin_ca_wrong_passphrase_refusal()
    assert refusal_569.splitlines()[1] == refusal_572.splitlines()[1], (
        "the two postures stopped sharing one shipped reference line: "
        f"{refusal_569.splitlines()[1]!r} vs {refusal_572.splitlines()[1]!r}"
    )
    # The file-wide count is higher: proof the block scoping is load-bearing, not incidental.
    file_wide = [line for line in src.splitlines() if "Reference: docs/cert-rotation-runbook.md" in line]
    assert len(file_wide) > 1, (
        f"only {len(file_wide)} reference line(s) in the whole file — if that ever drops to one, the "
        "block-scoping this cell guards is no longer the thing keeping the counts at one; re-read it"
    )
