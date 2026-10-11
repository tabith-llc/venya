# Copyright (c) 2026 Tabith LLC.
# Use of this source code is governed by the Business Source License 1.1
# included in the LICENSE file at the root of this repository. As of the
# Change Date listed there, the work is available under MPL 2.0.
# SPDX-License-Identifier: BUSL-1.1

"""#570 — the core installer's DB-passphrase gate reads MATERIALITY, not emptiness.

Same defect, other seam. ``install-venya-core.sh`` decided "did the operator give a
passphrase?" with

    elif [ -z "$DB_PASSPHRASE" ]; then

and `[ -z " " ]` is FALSE — one space is not empty to `test`, so a blank value skipped the
prompt entirely, was written into `/opt/venya/.env` as ``VENYA_DB__PASSPHRASE= ``, and the
core booted a KEK derived from that space. Every DB secret written afterwards is wrapped
under a key anyone who knows the class of the value can reproduce, and the moment the
operator supplies the passphrase they MEANT, those envelopes are unreadable for good
(``backend.py`` ``KekPassphraseMismatchError`` — the doctrine, stated in the product).

The fix keeps the shipped branches and their shipped sentences (TTY → prompt, unattended →
the existing error and exit; zero new operator-facing text) and changes only the QUESTION:
the "was one supplied?" test reads a whitespace-stripped COPY. Two consequences are the
load-bearing cells here:

* **DENY, never TRIM.** The copy decides; the variable that travels is the operator's own
  bytes, so a passphrase with meaningful spaces keeps opening its database. P1 asserts the
  landed env line byte-for-byte — a silent trim here would be its own data-loss story
  wearing the costume of a security fix.
* **"Same path as unset", both halves (the wording of the ruling).** A blank explicit env
  over a stored real passphrase used to trip the ROTATION abort and tell the operator their
  re-run would orphan encrypted rows — when the ladder was about to take the stored value
  verbatim three lines later anyway. Nothing was being rotated. N3 pins the corrected path;
  N5 pins that a REAL disagreement still aborts, byte-for-byte.

Cells run the REAL block lifted out of the git-tracked script between unique anchors and
execute it under `bash` against a fixture install dir — the house installer pattern
(`test_installer_core_ip_hosts_490`, `test_installer_pg_cluster_resolve_496`,
`test_installer_ca_partial_state_505`): exercise the shipped shell, never a
re-implementation. TTY cells allocate a pty, because the branch under test is `[ -t 0 ]`
and a pipe would only ever reach the other half.

The env-write assertion runs against a stand-in file, not the shipped 20-line env block:
the ladder itself writes nothing, and the point of the cells is that a refusal never REACHES
the write step. Proving "the run stopped" is the AC3 bar ("Runs before any system
mutation"), so it is asserted on a file, not on a message.

Test passphrases are dev-only synthetic values in the family the #547/#554/#537 suites
already record; none of them is a live credential.
"""

import os
import pty
import subprocess
import sys
import threading
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[3]
CORE = REPO_ROOT / "install-venya-core.sh"
COMMON = REPO_ROOT / "venya-common.sh"

# Extraction anchors — both asserted unique in _block_source(), so a moved gate reds HERE
# rather than aiming a cell at the wrong region of the script.
BEGIN = 'DB_PASSPHRASE="${VENYA_DB_PASSPHRASE:-}"'
END = "# --- Recovery-code pepper"

# The shipped sentences, taken FROM THE SCRIPT rather than retyped as fixtures: if the
# installer's wording ever moves, these cells move with it instead of passing against a
# stale literal while the operator is handed something else.
_CORE_TEXT = None


def _core_source() -> str:
    global _CORE_TEXT
    if _CORE_TEXT is None:
        _CORE_TEXT = CORE.read_text(encoding="utf-8")
    return _CORE_TEXT


def _sentence(marker: str) -> str:
    """Pull one shipped error sentence out of the installer, verbatim.

    Truncated at the first `$`, because these lines interpolate shell variables: the cell
    must match the bytes the operator actually sees, not the source text with a `$VAR` in
    it. The marker half is what identifies the sentence; the truncated half is what is
    asserted.
    """
    for line in _core_source().splitlines():
        if marker in line and line.strip().startswith("error "):
            text = line.strip()[len("error ") :].strip('"')
            return text.split("$")[0].rstrip()
    raise AssertionError(f"sentence not found in the installer: {marker!r}")


UNATTENDED_ERROR = _sentence("VENYA_DB_PASSPHRASE is required for unattended install")
ROTATION_ABORT = _sentence("VENYA_DB_PASSPHRASE does not match the stored value")
REUSE_INFO_MARK = "reusing stored server passphrase"

REAL = " test db passphrase 570 "  # spaces are CONTENT — the deny-not-trim probe
PADDED_ALT = " different padded passphrase "
BLANKS = [" ", "   ", "\t"]
TYPED = "typed 570 value"


def _block_source() -> str:
    """Lift the real DB-passphrase ladder out of the git-tracked installer."""
    src = _core_source()
    assert src.count(BEGIN) == 1, "block start anchor no longer unique — re-anchor"
    assert src.count(END) == 1, "block end anchor no longer unique — re-anchor"
    start = src.index(BEGIN)
    block = src[start : src.index(END, start)]
    # Guard: both branches a cell can aim at must still be inside the extracted region.
    assert "venya_read_secret_confirm" in block, "the TTY branch moved out of the extracted block"
    assert "VENYA_DB_PASSPHRASE" in block, "the gate moved out of the extracted block"
    return block


def _run_block(
    tmp_path: Path,
    *,
    env_value: str | None,
    stored_line: str | None,
    tty: bool = False,
    answers: str = "",
) -> tuple[int, str, Path]:
    """Run the extracted ladder against a fixture install dir.

    `env_value` and the stored .env line travel as DATA (environment / file content), never
    as interpolated script text. Returns (rc, combined output, install dir).
    """
    install_dir = tmp_path / "opt-venya"
    install_dir.mkdir(parents=True, exist_ok=True)
    # Each run starts from a clean fixture: the stand-in is the evidence, so a leftover
    # file from an earlier iteration would fake a write that never happened.
    (install_dir / "env-standin").unlink(missing_ok=True)
    (install_dir / ".env").unlink(missing_ok=True)
    if stored_line is not None:
        (install_dir / ".env").write_text(stored_line, encoding="utf-8")

    block_path = tmp_path / "db_passphrase_ladder.sh"
    block_path.write_text(_block_source(), encoding="utf-8")

    # INSTALL_DIR is set far earlier in the real script; the harness supplies it, sources
    # the library for the log helpers and the prompt function, runs the REAL block, then
    # STANDS IN for the step the installer performs ~560 lines later: writing the
    # passphrase line into the env file. The stand-in writes its OWN file, so the fixture
    # .env stays exactly as it was handed in and a refusal is provable twice — the stand-in
    # never created, the stored file untouched.
    harness = tmp_path / "harness.sh"
    harness.write_text(
        "set -uo pipefail\n"
        f"source {str(COMMON)!r}\n"
        "venya_print_colors\n"
        f"INSTALL_DIR={str(install_dir)!r}\n"
        f". {str(block_path)!r}\n"
        'echo "CELL-AFTER-LADDER"\n'
        'printf \'VENYA_DB__PASSPHRASE=%s\\n\' "$DB_PASSPHRASE" >> "$INSTALL_DIR/env-standin"\n'
        'echo "CELL-VALUE=[${DB_PASSPHRASE}]"\n',
        encoding="utf-8",
    )

    env = dict(os.environ)
    if env_value is None:
        env.pop("VENYA_DB_PASSPHRASE", None)
    else:
        env["VENYA_DB_PASSPHRASE"] = env_value
    env.pop("VENYA_SKIP_PROMPT", None)

    if tty:
        master, slave = pty.openpty()
        proc = subprocess.Popen(
            ["bash", str(harness)],
            stdin=slave,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            env=env,
            text=True,
        )
        os.close(slave)
        if answers:
            os.write(master, answers.encode())
        # Read on a watchdog: the prompt helper LOOPS, so a wrong-shape answer would block
        # on the TTY forever and a hung cell is worse than a red one.
        chunks: list[str] = []
        reader = threading.Thread(target=lambda: chunks.append(proc.stdout.read()), daemon=True)
        reader.start()
        reader.join(30)
        if reader.is_alive():
            proc.kill()
            reader.join(5)
            os.close(master)
            raise AssertionError(f"the TTY prompt loop hung; output so far: {chunks!r}")
        proc.wait()
        os.close(master)
        return proc.returncode, chunks[0] if chunks else "", install_dir

    proc = subprocess.run(
        ["bash", str(harness)],
        capture_output=True,
        text=True,
        stdin=subprocess.DEVNULL,
        env=env,
        check=False,
    )
    return proc.returncode, proc.stdout + proc.stderr, install_dir


def _stored_lines(install_dir: Path) -> list[str]:
    """The fixture .env as it stands AFTER the run — must never move on a refusal."""
    env_file = install_dir / ".env"
    return [] if not env_file.exists() else env_file.read_text(encoding="utf-8").splitlines()


def _written_lines(install_dir: Path) -> list[str]:
    """The env-write stand-in. Empty list == the run never reached the write step."""
    landed = install_dir / "env-standin"
    return [] if not landed.exists() else landed.read_text(encoding="utf-8").splitlines()


def test_source_pin_the_gate_asks_materiality_not_emptiness():
    """Tripwire for every behavior cell below, and the anti-revert half.

    If the `elif` is ever edited back to the shipped emptiness test, each N-cell still
    passes on its own rc assertion — so the shape is pinned here, once, in the source.
    """
    block = _block_source()
    assert 'elif [ -z "$DB_PASSPHRASE_SUPPLIED" ]; then' in block, "#570 blank-is-unset gate is gone"
    assert (
        'if [ -n "$DB_PASSPHRASE_SUPPLIED" ] && [ "$DB_PASSPHRASE" != "$STORED_DB_PASSPHRASE" ]; then' in block
    ), "the supplied? half of the rotation test must ask materiality too (same path as unset)"
    assert 'DB_PASSPHRASE_SUPPLIED="${DB_PASSPHRASE//[[:space:]]/}"' in _core_source()
    # What TRAVELS is the operator's bytes. A trimmed write is the failure mode.
    write_line = _core_source().split("printf 'VENYA_DB__PASSPHRASE=")[1].splitlines()[0]
    assert write_line.startswith('%s\\n\' "$DB_PASSPHRASE"'), write_line
    assert "DB_PASSPHRASE_SUPPLIED" not in write_line


def test_b1_the_script_still_parses():
    """`bash -n` on the whole shipped file, per the commit policy for shell changes."""
    proc = subprocess.run(["bash", "-n", str(CORE)], capture_output=True, text=True, check=False)
    assert proc.returncode == 0, proc.stderr


class TestBlankRefuses:
    """N1 + N2 + N3 — the whitespace value answers "not supplied", on both branches."""

    def test_n1a_space_unattended_refuses_with_the_shipped_error(self, tmp_path):
        rc, out, install_dir = _run_block(tmp_path, env_value=" ", stored_line=None)
        assert rc != 0, "a one-space passphrase still sailed through the gate"
        assert UNATTENDED_ERROR in out, out
        assert "CELL-AFTER-LADDER" not in out, "the refusal did not stop the run"
        assert _written_lines(install_dir) == [], _written_lines(install_dir)

    def test_n1b_tab_and_multi_space_refuse_identically(self, tmp_path):
        """The parametrized class, in one cell: every blank shape, same answer."""
        for blank in BLANKS:
            rc, out, install_dir = _run_block(tmp_path, env_value=blank, stored_line=None)
            assert rc != 0, f"{blank!r} passed the gate"
            assert UNATTENDED_ERROR in out, f"{blank!r}: {out}"
            assert _written_lines(install_dir) == [], f"{blank!r} wrote {_written_lines(install_dir)}"

    def test_n1c_unset_is_unchanged_and_gives_the_same_sentence(self, tmp_path):
        """The control: unset was already refused, and the sentence is byte-identical.

        Blank and unset now produce the SAME bytes on stderr — which is the whole ruling,
        stated as an equality rather than described.
        """
        rc_blank, out_blank, _ = _run_block(tmp_path / "blank", env_value=" ", stored_line=None)
        rc_unset, out_unset, _ = _run_block(tmp_path / "unset", env_value=None, stored_line=None)
        assert rc_blank != 0 and rc_unset != 0
        assert out_blank == out_unset, "blank and unset must be indistinguishable to the operator"

    def test_n2_tty_blank_goes_to_the_prompt_instead_of_sailing_past(self, tmp_path):
        """The TTY half. Before the fix this branch was UNREACHABLE for a blank value:
        `[ -z " " ]` was false, the prompt never printed, and the space went straight to
        the env file. Now the operator is asked, and what lands is what they typed — fed
        twice because ``venya_read_secret_confirm`` loops until both entries match.
        """
        rc, out, install_dir = _run_block(
            tmp_path, env_value=" ", stored_line=None, tty=True, answers=f"{TYPED}\n{TYPED}\n"
        )
        assert "Enter server encryption passphrase" in out, f"no prompt on the TTY path: {out!r}"
        assert rc == 0, out
        assert f"CELL-VALUE=[{TYPED}]" in out, out
        assert _written_lines(install_dir) == [f"VENYA_DB__PASSPHRASE={TYPED}"], _written_lines(install_dir)

    def test_n3_blank_explicit_env_over_a_stored_value_takes_the_reuse_path(self, tmp_path):
        """ "Same path as unset", literally — the half the ruling names and the ship missed.

        Unset over a stored real passphrase reuses it. A blank one used to abort with
        "Rotating it would make existing encrypted DB secrets undecryptable" — a rotation
        warning for a value that was about to be IGNORED three lines later. The alarm was
        wrong and it blocked a healthy re-run. Now: reuse, no abort, stored bytes intact.
        """
        stored = f"VENYA_DB__PASSPHRASE={REAL}\n"
        rc, out, install_dir = _run_block(tmp_path, env_value=" ", stored_line=stored)
        assert rc == 0, out
        assert REUSE_INFO_MARK in out, out
        assert ROTATION_ABORT not in out, "the wrong rotation alarm fired again"
        assert _stored_lines(install_dir) == [f"VENYA_DB__PASSPHRASE={REAL}"], _stored_lines(install_dir)
        assert _written_lines(install_dir) == [f"VENYA_DB__PASSPHRASE={REAL}"], _written_lines(install_dir)


class TestStoredBlankIsPreservedNotRotated:
    """N4 + N5 — AC4, stated in code instead of left to inference."""

    def test_n4_a_blank_stored_line_is_reused_unchanged(self, tmp_path):
        """A blank line already in .env is PRESERVED, not replaced.

        Replacing it IS a rotation, and a rotation orphans every envelope already wrapped
        under the space-derived KEK — the exact failure this ladder exists to prevent. So
        the re-run reuses it and the refusal lands one step later, at the boot gate
        (`BackendConfig`, #570 core side), where it cannot silently rewrite a key.
        Repairing that install is then a deliberate act, not a side effect of re-running
        an installer.
        """
        stored = "VENYA_DB__PASSPHRASE= \n"
        rc, out, install_dir = _run_block(tmp_path, env_value=None, stored_line=stored)
        assert rc == 0, out
        assert REUSE_INFO_MARK in out, out
        assert _stored_lines(install_dir) == ["VENYA_DB__PASSPHRASE= "], "the re-run rewrote the stored blank"
        assert _written_lines(install_dir) == ["VENYA_DB__PASSPHRASE= "], _written_lines(install_dir)

    def test_n5_a_real_disagreement_still_aborts_byte_for_byte(self, tmp_path):
        """The paired negative of N3: the right half of that test is still a REAL compare.

        Making blank read as "not supplied" must not soften the rotation guard for two
        different passphrases — including ones that differ only in their padding, and one
        where the stored line is blank and the operator supplies a real value (that IS a
        rotation, and it still aborts with nothing written).
        """
        stored = f"VENYA_DB__PASSPHRASE={PADDED_ALT}\n"
        rc, out, install_dir = _run_block(tmp_path, env_value=REAL, stored_line=stored)
        assert rc != 0, out
        assert ROTATION_ABORT in out, out
        assert _stored_lines(install_dir) == [f"VENYA_DB__PASSPHRASE={PADDED_ALT}"], "the abort rewrote .env"
        assert _written_lines(install_dir) == [], "the aborted run reached the env write"

        stored_blank = "VENYA_DB__PASSPHRASE= \n"
        rc2, out2, _ = _run_block(tmp_path / "blankstored", env_value=REAL, stored_line=stored_blank)
        assert rc2 != 0, out2
        assert ROTATION_ABORT in out2, out2


class TestRealPassphrasesAreUntouched:
    """P1 + P2 — DENY, never TRIM."""

    def test_p1_real_passphrase_lands_byte_for_byte(self, tmp_path):
        """The deny-not-trim proof, on the line the core will read.

        `REAL` has real material AND leading/trailing spaces that are part of the secret.
        The copy decides "supplied?"; what travels is the operator's bytes. If anything ever
        trimmed here, the env line would hold a different secret than the one that sealed
        the database and the deployment would not boot at all.
        """
        rc, out, install_dir = _run_block(tmp_path, env_value=REAL, stored_line=None)
        assert rc == 0, out
        assert _written_lines(install_dir) == [f"VENYA_DB__PASSPHRASE={REAL}"], _written_lines(install_dir)
        assert f"CELL-VALUE=[{REAL}]" in out, out

    def test_p2_stored_real_value_reused_when_it_matches(self, tmp_path):
        """The positive half of N5: a matching stored value is taken verbatim."""
        stored = f"VENYA_DB__PASSPHRASE={REAL}\n"
        rc, out, install_dir = _run_block(tmp_path, env_value=REAL, stored_line=stored)
        assert rc == 0, out
        assert REUSE_INFO_MARK in out, out
        assert _written_lines(install_dir) == [f"VENYA_DB__PASSPHRASE={REAL}"], _written_lines(install_dir)


class TestTheRecordStaysHonest:
    """B2 + B3 — the comment this ticket calls a trap, and the cell it must not break."""

    def test_b2_the_trap_comment_no_longer_claims_tree_wide_validation(self):
        """The installer used to comment "Either way validated non-empty" over a `-z` test.

        A careful reader could take that as coverage, and blankness was NOT covered — in
        either block. The text now states what the gate actually tests, and the claim is
        gone from the file.
        """
        src = _core_source()
        assert "Either way validated non-empty" not in src, "the stale coverage claim shipped again"
        assert "tests EMPTINESS" in src, "the corrected comment must name what that gate checks"
        assert "#570 blank-is-unset" in src, "the DB gate must carry its own ticket reference"

    def test_b3_the_empty_string_cell_still_holds(self):
        """§2.3's named existing cell, run rather than assumed.

        ``packages/server/tests/test_passphrase_startup.py``
        ``test_empty_string_passphrase_fails_in_production`` pins the EMPTY-STRING half at
        the server gate (`if not config.db.passphrase`). This leg touches neither that
        sentence nor that falsiness test — whitespace is refused one layer down, in
        ``BackendConfig`` — so it must stay green. Subprocess run so the record shows it was
        checked at this tip, not inferred from a comment.
        """
        target = REPO_ROOT / "packages" / "server" / "tests" / "test_passphrase_startup.py"
        proc = subprocess.run(
            [
                sys.executable,
                "-m",
                "pytest",
                str(target),
                "-q",
                "-k",
                "test_empty_string_passphrase_fails_in_production",
            ],
            capture_output=True,
            text=True,
            check=False,
            cwd=str(REPO_ROOT / "packages" / "server"),
        )
        assert proc.returncode == 0, proc.stdout + proc.stderr
        assert "1 passed" in proc.stdout, proc.stdout
