# Copyright (c) 2026 Tabith LLC.
# Use of this source code is governed by the Business Source License 1.1
# included in the LICENSE file at the root of this repository. As of the
# Change Date listed there, the work is available under MPL 2.0.
# SPDX-License-Identifier: BUSL-1.1

"""#682 / #481 display guard — `executor list` prints the WHOLE canonical serial.

Why this column is not cosmetics (measured, not inferred — see the leg report): a 16-char slice of a
40-hex serial is a **DIFFERENT INTEGER**, because `canonical_serial` normalises case and padding only;
digits that were never printed cannot be restored. And the #682 cap raise means a 16-hex string is now
ACCEPTED where it used to be refused, so an operator pasting the displayed prefix into a serial-taking
revoke verb gets an answer about the WRONG certificate, not an error about theirs.

The printed form is therefore the ONE canonical serial form the revoke verbs match on — lowercase hex,
zero-padded to a MINIMUM of 16 (a floor, never a mask). NOT a third spelling: this file asserts parity
against the shipped `core.utils.cert_serial.canonical_serial`, because the CLI is barred from importing
it in production (`test_capability_isolation`), so the only guard against drift is a test that DOES
compare them.

Paired negatives are the point (project truth-table rule): no cell in the tree asserted the display form
before this file, so a green suite is not evidence about this column. Each positive is matched by the
render that must redden — the old `[:16]` slice, and a bare verbatim print of the store text. The
truth-table half pins the columns that must NOT change while we are in here.
"""

import pytest
from core.utils.cert_serial import canonical_serial
from venya_cli import commands
from venya_cli.commands import _canonical_serial_text, executor_list

# The measured width-leg specimen. `openssl` prints it zero-padded to its 20-byte width (40 chars);
# the registry stores the SAME integer in canonical form, which is 39 chars because the minimum pad
# is 16 and this value simply needs 39.
SPECIMEN_OPENSSL_40 = "0D3A4D4EF914DC3F81546B106C46B3224E280102"  # pragma: allowlist secret
SPECIMEN_CANONICAL = "d3a4d4ef914dc3f81546b106c46b3224e280102"  # pragma: allowlist secret
SPECIMEN_TRUNCATED_16 = SPECIMEN_CANONICAL[:16]
SPECIMEN_INT = int(SPECIMEN_OPENSSL_40, 16)


class _Args:
    """Stand-in for the argparse namespace `executor_list` reads."""

    def __init__(self, **kw):
        for k, v in kw.items():
            setattr(self, k, v)


class _StubClient:
    """Minimal APIClient stand-in: serves the executor list, nothing else."""

    def __init__(self, executors):
        self._executors = executors

    def get(self, path, timeout=None):
        return {"executors": self._executors}


def _render(executors):
    return executor_list(_StubClient(executors), _Args(json=False))


@pytest.fixture
def quiet_version(monkeypatch):
    """Pin the #324 advisory cache so the version-mismatch nudge cannot print into these cells."""
    monkeypatch.setattr(commands, "_server_version_cache", "0.1.0beta1", raising=False)


# ---- parity with the shipped canonicaliser (the anti-third-form guard) --------


@pytest.mark.parametrize(
    "value",
    [
        SPECIMEN_CANONICAL,
        SPECIMEN_OPENSSL_40,
        SPECIMEN_OPENSSL_40.lower(),
        SPECIMEN_INT,
        f"0x{SPECIMEN_CANONICAL}",
        "abc123",
        "0000000000abc123",
        "a" * 64,
        "  deadbeef  ",
        "0",
        "0000",
        "not-a-hex",
        "NOT-a-hex",
        -3,
        16,
        4095,
    ],
)
def test_canonical_writer_matches_core(value) -> None:
    """The CLI's re-typed writer must agree with `canonical_serial` on every spelling the store or
    an operator can hand it. `venya_cli` may not IMPORT the core function, so without this cell the
    two copies could drift and nothing would say so."""
    assert _canonical_serial_text(value) == canonical_serial(value)


# ---- the renderer's own truth table ------------------------------------------


def test_canonical_text_pads_a_small_serial_to_the_minimum_floor() -> None:
    """A #481-era 8-byte serial keeps its 16-wide form. The width is a floor, not a mask."""
    assert _canonical_serial_text("abc123") == "0000000000abc123"
    assert len(_canonical_serial_text("a" * 64)) == 64  # a long serial keeps every digit


def test_canonical_text_never_shortens_the_40_hex_specimen() -> None:
    """THE defect: the old slice kept 16 of 39. The fix keeps all 39 canonical chars of a value that
    `openssl` prints at 40, and no digit is invented in the process."""
    rendered = _canonical_serial_text(SPECIMEN_CANONICAL)
    assert len(rendered) == 39
    assert rendered == SPECIMEN_CANONICAL
    assert int(rendered, 16) == SPECIMEN_INT  # same integer, so revoke names the right certificate
    assert int(SPECIMEN_TRUNCATED_16, 16) != SPECIMEN_INT  # and the removed slice named a DIFFERENT one


def test_canonical_text_is_total_on_garbage_and_absent() -> None:
    """Paired negative for the renderer: garbage and absence must not raise, must not gain digits,
    and must not silently become the empty string a real serial could render as."""
    assert _canonical_serial_text(None) == ""
    assert _canonical_serial_text("") == ""
    assert _canonical_serial_text("not-a-hex") == "not-a-hex"  # returned casefolded, not fabricated
    assert _canonical_serial_text(-3) == "-3"


# ---- the column itself --------------------------------------------------------


def test_executor_list_prints_the_whole_canonical_serial(capsys, quiet_version) -> None:
    """THE guard: all 39 canonical characters appear, and the 16-hex prefix does not appear as a
    separate cell. Self-sanity first so the assertion below cannot pass by tautology."""
    assert SPECIMEN_TRUNCATED_16 != SPECIMEN_CANONICAL
    rc = _render(
        [
            {
                "executor_id": "venya-exec-4",
                "serial_number": SPECIMEN_CANONICAL,
                "not_after": "2026-11-19T20:18:00+00:00",
                "version": "0.1.0beta1",
            }
        ]
    )
    out = capsys.readouterr().out
    assert rc == 0
    assert SPECIMEN_CANONICAL in out, f"the full canonical serial must be printed, got: {out!r}"
    assert SPECIMEN_TRUNCATED_16 not in out.replace(
        SPECIMEN_CANONICAL, ""
    ), "the serial column must not ALSO render a truncated copy of the same value"


def test_executor_list_printed_value_is_a_value_revoke_accepts(quiet_version, capsys) -> None:
    """Round-trip proof in one line of arithmetic: the string the operator can SELECT off this
    column parses to the certificate's own integer, which is what every revoke lookup keys on."""
    _render(
        [
            {
                "executor_id": "venya-exec-4",
                "serial_number": SPECIMEN_CANONICAL,
                "not_after": "x",
                "version": "0.1.0beta1",
            }
        ]
    )
    line = next(ln for ln in capsys.readouterr().out.splitlines() if "venya-exec-4" in ln)
    shown = line.split()[1]
    assert int(shown, 16) == SPECIMEN_INT
    assert len(shown) <= 64  # the cap the revoke gate enforces: 64 chars, so this string passes


def test_executor_list_old_slice_render_is_caught(capsys, quiet_version, monkeypatch) -> None:
    """PAIRED NEGATIVE by mutation, not by faith: reinstall the shipped `[:16]` behaviour and prove
    the cell above fails against it rather than passing quietly."""
    monkeypatch.setattr(commands, "_canonical_serial_text", lambda v: str(v or "")[:16])
    _render(
        [
            {
                "executor_id": "venya-exec-4",
                "serial_number": SPECIMEN_CANONICAL,
                "not_after": "x",
                "version": "0.1.0beta1",
            }
        ]
    )
    out = capsys.readouterr().out
    assert SPECIMEN_CANONICAL not in out  # this is exactly the condition the real cell asserts on
    assert SPECIMEN_TRUNCATED_16 in out  # the old behaviour is a real, reachable render


def test_executor_list_bare_verbatim_print_is_caught(capsys, quiet_version, monkeypatch) -> None:
    """Second paired negative: dropping the slice alone would print the STORE text verbatim. For a
    padded or upper-case stored spelling that shows a non-canonical form, which the ruled shape
    bars — so the guard must be the canonicaliser, not a widened slice."""
    monkeypatch.setattr(commands, "_canonical_serial_text", lambda v: str(v or ""))
    _render(
        [
            {
                "executor_id": "venya-exec-9",
                "serial_number": "0000000000ABC123",
                "not_after": "x",
                "version": "0.1.0beta1",
            }
        ]
    )
    out = capsys.readouterr().out
    assert "0000000000ABC123" in out  # what a 'just widen it' fix would have shipped
    assert "abc123" not in out  # and this is what the canonicaliser instead prints


def test_executor_list_keeps_the_other_columns_unchanged(capsys, quiet_version) -> None:
    """TRUTH-TABLE half: the columns carrying no serial semantics render exactly as before — id,
    expiry, the dash for an absent expiry, and the pre-B daemon placeholder — so nobody 'improves'
    the table while in here."""
    _render(
        [
            {
                "executor_id": "venya-exec-1",
                "serial_number": "aabbccddee112233",
                "not_after": "2026-11-01T00:00:00+00:00",
                "version": "0.1.0beta1",
            },
            {"executor_id": "venya-exec-2", "serial_number": "aabbccddee112233", "not_after": None, "version": None},
        ]
    )
    out = capsys.readouterr().out
    assert "EXECUTOR_ID" in out and "SERIAL" in out and "NOT_AFTER" in out and "VERSION" in out
    assert "venya-exec-1" in out and "venya-exec-2" in out
    assert "2026-11-01T00:00:00+00:00" in out
    assert "unknown (pre-B daemon)" in out
    assert "aabbccddee112233" in out  # a 16-wide serial is unchanged by the floor: padded, not masked
    table = [ln for ln in out.splitlines() if ln.strip()]
    assert len([ln for ln in table if "venya-exec-" in ln]) == 2  # one row per executor, no doubling


def test_executor_list_empty_and_json_faces_still_short_circuit(capsys, quiet_version) -> None:
    """No-regression half of the same truth table: the empty list and the --json face return before
    the column code runs, so this fix cannot have changed either."""
    assert executor_list(_StubClient([]), _Args(json=False)) == 0
    assert "No executors found." in capsys.readouterr().out
    assert executor_list(_StubClient({"executors": []}), _Args(json=True)) == 0
