# Copyright (c) 2026 Tabith LLC.
# Use of this source code is governed by the Business Source License 1.1
# included in the LICENSE file at the root of this repository. As of the
# Change Date listed there, the work is available under MPL 2.0.
# SPDX-License-Identifier: BUSL-1.1

"""#687 AC5 — the CLI revoke surface displays what the core ASSERTS, not what was typed.

The route half (`383c9f9`, merged `231166f`) corrected the audit event and the HTTP response. The CLI
was the fourth face and the only one left: `executor_cert_revoke` printed its own local `executor_id`
variable on both arms, so an operator who sent a duplicate revoke for serial S under executor B saw
``Executor ID:  exec-b`` returned to them — the claim they made, restated as if it were the finding —
even though the core had just answered ``executor_id: exec-a`` (the owner the revocation row stores).

Truth table, both halves, per the AGENTS paired-negative law (`S` = serial, `A` = stored owner):

| server body | operator typed | CLI prints | note line | vs pre-fix bytes |
|---|---|---|---|---|
| `executor_id=A` | A | A | absent | **byte-identical** |
| `executor_id=A`, `requested_executor_id=B`, `executor_id_mismatch=True` | B | **A** | present, names B | changed on purpose |
| `executor_id=A` (older core, no flag field) | B | **A** | absent | changed on purpose |
| no `executor_id` key at all | B | B | absent | **byte-identical** (fallback = the old answer) |
| identity form, `executor_id=A` | A | A | absent (no mismatch arm exists) | **byte-identical** |

The byte-identity assertions compare the WHOLE captured stdout against literals recorded by a temporary
probe module run at the BASE commit (`169fcad`) before this change, then deleted — not against a
reconstruction of what the old code did. A cell that asserts `in` would pass while the line count moved.
"""

from types import SimpleNamespace
from unittest.mock import MagicMock

from venya_cli.commands import executor_cert_revoke

A = "exec-a"  # the owner the revocation row stores
B = "exec-b"  # the identity an operator aimed the repeat at — NOT the holder
TYPED = "abcd1234"
CANON = "0000abcd1234"
MISSING_CERT = "/nonexistent/executor.crt"  # never read: every cell below passes --executor-id


def _drive(server_body, typed_id, serial=TYPED):
    """Run the shipped handler against a client whose POST returns exactly `server_body`."""
    client = MagicMock()
    client.post.return_value = server_body
    args = SimpleNamespace(serial=serial, executor_id=typed_id, cert_path=MISSING_CERT)
    rc = executor_cert_revoke(args, client=client)
    return rc


# --- The pre-fix face, recorded at base 169fcad by a throwaway probe (deleted before commit). ---
PREFIX_SERIAL_PAIRED = (
    "Certificate serial was already revoked (no change).\n"
    "  Executor ID:  exec-a\n"
    f"  Serial:       {TYPED}\n"
    "  Revoked:      No\n"
)
PREFIX_SERIAL_FRESH = (
    "Certificate serial revoked (identity NOT revoked).\n"
    "  Executor ID:  exec-a\n"
    f"  Serial:       {TYPED}\n"
    "  Revoked:      Yes\n"
)
PREFIX_IDENTITY_REPEAT = (
    "Executor identity was already revoked (no change).\n" "  Executor ID:  exec-a\n" "  Revoked:      No\n"
)
PREFIX_IDENTITY_GENUINE = (
    "Certificate revoked.\n"
    "  Executor ID:  exec-a\n"
    "  Identity:     REVOKED (terminal — re-enrollment requires a NEW executor_id)\n"
    "  Revoked:      Yes\n"
)
# The pre-fix MISMATCH face — what the defect actually printed to an operator's terminal. The framing
# string is asserted ABSENT below, which is what makes those cells fail against the old code.
PREFIX_MISMATCH_LINE = f"  Executor ID:  {B}\n"


class TestMismatchArmIsDisplayed:
    """The negative half: a fabricated pairing must be named on the face, not left in the log."""

    def test_flagged_mismatch_shows_the_stored_owner_and_names_the_claim(self, capsys):
        body = {
            "revoked": False,
            "executor_id": A,
            "serial_number": CANON,
            "requested_executor_id": B,
            "executor_id_mismatch": True,
        }

        assert _drive(body, B) == 0
        out = capsys.readouterr().out

        assert f"  Executor ID:  {A}\n" in out, out
        assert PREFIX_MISMATCH_LINE not in out, f"the CLI still echoes the typed claim: {out}"
        assert "NOTE:" in out and B in out, out
        # the core's own field name is reused, so one fact has one vocabulary across the three surfaces
        assert "executor_id_mismatch" in out, out
        # the no-op reading is untouched (#666): a mismatch does not turn into a success headline
        assert "already revoked (no change)" in out, out
        assert "Certificate serial revoked (identity NOT revoked)" not in out, out

    def test_unflagged_disagreement_still_shows_the_stored_owner(self, capsys):
        """An older core that returns `executor_id` WITHOUT the flag pair: the display rule is the
        same (show what the core asserts), so the operator still sees A rather than their own B."""
        assert _drive({"revoked": False, "executor_id": A}, B) == 0
        out = capsys.readouterr().out

        assert f"  Executor ID:  {A}\n" in out, out
        assert PREFIX_MISMATCH_LINE not in out, out
        assert "NOTE:" not in out, "no flag field, so no note is invented — the display still follows the core"

    def test_the_claim_survives_in_the_note_rather_than_vanishing(self, capsys):
        """The operator's attempted identity is reported, not silently dropped: an audit surface that
        quietly hides what was asked for is the failure the ruled fix exists to avoid."""
        body = {
            "revoked": False,
            "executor_id": A,
            "serial_number": CANON,
            "requested_executor_id": B,
            "executor_id_mismatch": True,
        }
        _drive(body, B)
        out = capsys.readouterr().out

        assert f"this call was made as {B}" in out, out
        assert out.count(A) >= 2, f"the true owner should appear on the ID line and in the note: {out}"


class TestPairedArmIsByteIdentical:
    """The positive half: the ordinary, correctly-paired operator sees EXACTLY what they saw before."""

    def test_serial_repeat_body_is_byte_for_byte_the_pre_fix_output(self, capsys):
        assert _drive({"revoked": False, "executor_id": A, "serial_number": CANON}, A) == 0
        assert capsys.readouterr().out == PREFIX_SERIAL_PAIRED

    def test_serial_fresh_body_is_byte_for_byte_the_pre_fix_output(self, capsys):
        assert _drive({"revoked": True, "executor_id": A, "serial_number": CANON}, A) == 0
        assert capsys.readouterr().out == PREFIX_SERIAL_FRESH

    def test_identity_repeat_is_byte_for_byte_the_pre_fix_output(self, capsys):
        assert _drive({"revoked": False, "executor_id": A, "serial_number": CANON}, A, serial=None) == 0
        assert capsys.readouterr().out == PREFIX_IDENTITY_REPEAT

    def test_identity_genuine_success_is_byte_for_byte_the_pre_fix_output(self, capsys):
        assert _drive({"revoked": True, "executor_id": A, "serial_number": CANON}, A, serial=None) == 0
        assert capsys.readouterr().out == PREFIX_IDENTITY_GENUINE


class TestOlderCoreFallbackIsTheOldAnswer:
    """A body naming no owner at all must not print an empty field or crash the arm."""

    def test_missing_executor_id_falls_back_to_the_typed_value(self, capsys):
        assert _drive({"revoked": False, "serial_number": CANON}, B) == 0
        out = capsys.readouterr().out

        assert PREFIX_MISMATCH_LINE in out, out
        assert "NOTE:" not in out, out
        assert out == (
            "Certificate serial was already revoked (no change).\n"
            f"  Executor ID:  {B}\n"
            f"  Serial:       {TYPED}\n"
            "  Revoked:      No\n"
        )

    def test_empty_body_is_not_read_as_a_crash(self, capsys):
        assert _drive({}, B) == 0
        out = capsys.readouterr().out
        assert f"  Executor ID:  {B}\n" in out, out
        assert "NOTE:" not in out, out


class TestIdentityFormNeverGainsANote:
    """The route has no mismatch arm on the identity form — it resolves the row BY that id — so the
    CLI must not manufacture a second face for a fact that cannot occur there."""

    def test_identity_repeat_with_a_different_asserted_owner_shows_no_note(self, capsys):
        assert _drive({"revoked": False, "executor_id": A}, B, serial=None) == 0
        out = capsys.readouterr().out

        assert f"  Executor ID:  {A}\n" in out, "display rule holds: the core's value wins"
        assert "NOTE:" not in out, "no note on the identity arm — the route has no such face"
