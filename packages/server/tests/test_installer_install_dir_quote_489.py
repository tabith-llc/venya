# Copyright (c) 2026 Tabith LLC.
# Use of this source code is governed by the Business Source License 1.1
# included in the LICENSE file at the root of this repository. As of the
# Change Date listed there, the work is available under MPL 2.0.
# SPDX-License-Identifier: BUSL-1.1

"""#489 install-dir interpolation into ``bash -c`` — the AC2 paired-negative cell.

``venya_create_venv`` in ``venya-common.sh`` used to hand the bytecode-cleanup
subshell a payload the PARENT shell assembled in DOUBLE quotes, with the install
directory interpolated inside the payload's own single-quoted path literal. A
parent-side double-quoted payload means the variable is expanded into the SCRIPT
TEXT before the subshell ever sees it. An install directory whose name contains a single quote closes the
payload's own quoting and the rest of the name is parsed as commands, run as the
``venya`` user. The fix (``4e964ab``) passes the directory as a POSITIONAL and
single-quotes the script, so nothing in the path is expanded or split::

    bash -c 'find "$1/.venv" ...' _ "$INSTALL_DIR"

That fix is one line and merged without a test of its own. This file is the AC2
coverage that was missing (ticket #489, acceptance criterion 2); it adds no
product change.

Cells run the REAL cleanup command extracted from the git-tracked library (the
#505/#519/#491 precedent: exercise real script logic, never a re-implementation).
The single substitution is the ``sudo -H -u venya`` privilege drop, which a unit
cell cannot perform and which is not what is under test — the quoting under test
is copied verbatim. Cells run as the current user inside a pytest tmp dir: no
sudo, no ``/opt/venya``, no VM.

The differential cells are the half that makes this worth merging. They rebuild
the pre-#489 parent-interpolation form FROM THE SHIPPED LINE (a quote flip, so
the vulnerable text is never committed) and show the same input creating the
marker there — without them the shipped-form cell would pass on both shapes.

Marker payloads are a ``touch`` of one file inside the run directory; nothing
here writes or deletes outside its own tmp fixture.
"""

import subprocess
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[3]
COMMON = REPO_ROOT / "venya-common.sh"

#: The privilege drop a unit cell cannot perform. It is the ONLY text removed
#: from the extracted line before it runs.
SUDO_PREFIX = "sudo -H -u venya "

#: Injection-marker name, always relative to the run directory so the payload
#: needs no path quoting of its own.
MARKER = "PWNED-489"

#: Stale-bytecode files each fixture venv starts with.
PYC_COUNT = 2

#: Install-directory names carrying a single quote. The first is the innocent
#: shape (an apostrophe in a path); the others carry a ``touch <marker>``
#: breakout and are the paired negative AC2 asks for.
QUOTED_NAMES = [
    "o'brien",
    "pwn'; touch PWNED-489; '",
    "sp ace'; touch PWNED-489; '",
]

#: Breakout shapes only — the innocent apostrophe has no payload to run, so it
#: belongs to the "cleanup is lost" differential rather than the marker one.
BREAKOUT_NAMES = QUOTED_NAMES[1:]

#: Names made of expansion syntax but NOT quoting syntax. A directory literally
#: named ``$(touch ...)`` is not a vector, because the parent's parameter
#: expansion result is never re-expanded. Recorded so a later reader does not
#: go looking for a second class in this line.
NON_QUOTING_NAMES = ["$(touch PWNED-489)", "tick`touch PWNED-489`"]


def _create_venv_body() -> str:
    """The body of ``venya_create_venv`` as it stands in the library."""
    src = COMMON.read_text()
    assert src.count("venya_create_venv() {") == 1, "function anchor no longer unique — re-anchor"
    return src.split("venya_create_venv() {", 1)[1].split("\n}", 1)[0]


def _cleanup_line() -> str:
    """The shipped bytecode-cleanup command, extracted verbatim (never re-typed)."""
    hits = [ln.strip() for ln in _create_venv_body().splitlines() if "find" in ln and "__pycache__" in ln]
    assert len(hits) == 1, f"expected exactly one cleanup command, found {len(hits)}: {hits}"
    return hits[0]


def _runnable(line: str) -> str:
    """Drop the privilege-drop prefix — the single, documented substitution."""
    assert line.startswith(SUDO_PREFIX), f"cleanup line no longer starts with {SUDO_PREFIX!r}: {line}"
    return line[len(SUDO_PREFIX) :]


def _as_parent_interpolated(line: str) -> str:
    """Rebuild the pre-#489 form from the shipped line: a quote flip.

    ``find "$1/.venv" ...`` (positional, payload single-quoted) becomes
    ``find '$INSTALL_DIR/.venv' ...`` (path interpolated into a double-quoted
    payload). Checked at authoring time against ``git show 4e964ab^:venya-common.sh``
    — the built text matched the pre-fix line quote for quote — which is why the
    vulnerable form is DERIVED here instead of typed into this file: it must
    never be committed.
    """
    head, sep, tail = line.partition("bash -c '")
    assert sep, f"cleanup line is no longer a single-quoted bash -c payload: {line}"
    tail_marker = '\' _ "$INSTALL_DIR"'
    assert tail.endswith(tail_marker), f"positional tail changed: {line}"
    inner = tail[: -len(tail_marker)]
    flipped = inner.replace('"', "'").replace("$1/.venv", "$INSTALL_DIR/.venv")
    return f'{head}bash -c "{flipped}"'


def _command(form: str) -> str:
    """The extracted cleanup command in the shipped form or the rebuilt old one."""
    line = _cleanup_line()
    if form == "shipped":
        return _runnable(line)
    if form == "pre489":
        return _runnable(_as_parent_interpolated(line))
    raise AssertionError(f"unknown form {form!r}")


def _run(command: str, install_dir: Path, run_dir: Path) -> subprocess.CompletedProcess:
    """Run an extracted cleanup command the way the installer calls it.

    ``INSTALL_DIR`` is set from an argv element — the installer holds it as a
    shell variable too — so the harness never performs the quoting that is
    under test. ``set -u`` only: the exit status of both shapes must stay
    observable.
    """
    script = 'set -u\nINSTALL_DIR="$1"\n' + command + "\n"
    return subprocess.run(
        ["bash", "-c", script, "bash", str(install_dir)],
        cwd=str(run_dir),
        capture_output=True,
        text=True,
        check=False,
    )


def _fixture(tmp_path: Path, name: str) -> tuple[Path, Path]:
    """A scratch install dir called ``name``, holding what a built venv holds.

    Returns ``(run_dir, install_dir)``. The run directory is the subprocess cwd,
    so a breakout marker lands there and nowhere else.
    """
    run_dir = tmp_path / "run"
    run_dir.mkdir(parents=True, exist_ok=True)
    install_dir = run_dir / name
    pycache = install_dir / ".venv" / "lib" / "site-packages" / "__pycache__"
    pycache.mkdir(parents=True)
    (pycache / "mod.pyc").write_text("stale bytecode")
    (install_dir / ".venv" / "lib" / "site-packages" / "keep.pyc").write_text("stale bytecode")
    return run_dir, install_dir


def _leftovers(run_dir: Path) -> list[str]:
    """Bytecode the cleanup left behind, relative to the fixture."""
    return sorted(str(p.relative_to(run_dir)) for p in run_dir.rglob("*.pyc"))


class TestInstallerInstallDirQuote489:
    """#489 AC2 — a quoted install-directory name must not reach the shell."""

    def test_source_pin_the_cleanup_is_the_positional_form(self):
        """Trip-wire (#530 style): the mechanism AC2 relies on stays visible.

        If the directory ever moves back into the payload, this fails at the pin
        as well as in the behavioural cells below, so the change becomes visible
        rather than quiet.
        """
        line = _cleanup_line()
        assert line.startswith(SUDO_PREFIX), "cleanup no longer runs through the venya privilege drop"
        payload = line[len(SUDO_PREFIX) :]
        assert payload.startswith("bash -c '"), f"cleanup payload is no longer single-quoted: {payload}"
        assert payload.endswith('\' _ "$INSTALL_DIR"'), f"directory is no longer passed as a positional: {payload}"
        assert '"$1/.venv"' in payload, "the subshell no longer reads the directory from $1"

    def test_source_pin_no_bash_c_payload_interpolates_the_install_dir(self):
        """Paired negative of the pin: the interpolated shape must not come back.

        Any ``bash -c "..."`` line that mentions the install directory can put
        path-controlled text into script position — the whole of #489. Checked
        across the file, not only at the cleanup site.
        """
        src = COMMON.read_text()
        offenders = [
            (n, ln.strip()) for n, ln in enumerate(src.splitlines(), 1) if 'bash -c "' in ln and "INSTALL_DIR" in ln
        ]
        assert not offenders, f"install dir inside a double-quoted bash -c payload again: {offenders}"
        assert "'$INSTALL_DIR" not in src, "quoted interpolation of the install dir appeared"

    def test_harness_substitution_is_the_privilege_drop_only(self):
        """The behavioural cells run the shipped text with ONE removal.

        Guards against the harness quietly becoming a re-implementation: the
        runnable command is the extracted line minus the prefix, and the
        differential form is a quote flip of it — not a hand-typed string, and
        not something the library contains.
        """
        line = _cleanup_line()
        assert _runnable(line) == line.replace(SUDO_PREFIX, "", 1)
        vulnerable = _as_parent_interpolated(line)
        assert vulnerable != line, "the quote flip changed nothing — the differential proves nothing"
        assert "'$INSTALL_DIR/.venv'" in vulnerable, "the rebuilt pre-#489 form lost the interpolation"
        assert "bash -c '$INSTALL_DIR" not in vulnerable
        src = COMMON.read_text()
        assert vulnerable not in src, "the vulnerable form must not be present in the library"

    @pytest.mark.parametrize("name", QUOTED_NAMES)
    def test_quoted_install_dir_is_treated_literally(self, tmp_path: Path, name: str):
        """AC2 paired negative, shipped form: no injection, and the name literal.

        Observed behaviour, asserted rather than assumed: the cleanup runs to
        completion AT THE LITERAL PATH — the stale bytecode is removed — exits 0
        and writes nothing to stderr. Treating the name literally is the
        "instead" that AC2 requires of the fixed form.
        """
        run_dir, install_dir = _fixture(tmp_path, name)
        proc = _run(_command("shipped"), install_dir, run_dir)
        assert not (run_dir / MARKER).exists(), (
            f"an injected command ran for install dir {name!r}: marker {MARKER} was created "
            f"(rc={proc.returncode} stdout={proc.stdout!r} stderr={proc.stderr!r})"
        )
        leftovers = _leftovers(run_dir)
        assert leftovers == [], f"cleanup did not treat {name!r} literally; bytecode left: {leftovers}"
        assert not list(run_dir.rglob("__pycache__")), f"__pycache__ survived for {name!r}"
        assert (install_dir / ".venv" / "lib" / "site-packages").is_dir(), "the venv tree itself was disturbed"
        assert proc.returncode == 0, f"cleanup exited {proc.returncode} for {name!r}: {proc.stderr!r}"
        assert proc.stderr == "", f"cleanup was noisy for {name!r}: {proc.stderr!r}"
        assert proc.stdout == "", f"cleanup printed for {name!r}: {proc.stdout!r}"

    def test_benign_install_dir_still_cleans(self, tmp_path: Path):
        """No collateral breakage: an ordinary quote-free path still cleans up."""
        run_dir, install_dir = _fixture(tmp_path, "plain-install-dir")
        proc = _run(_command("shipped"), install_dir, run_dir)
        assert _leftovers(run_dir) == [], "an ordinary install dir stopped being cleaned"
        assert not list(run_dir.rglob("__pycache__")), "__pycache__ survived an ordinary path"
        assert not (run_dir / MARKER).exists()
        assert (proc.returncode, proc.stderr, proc.stdout) == (0, "", "")

    @pytest.mark.parametrize("name", BREAKOUT_NAMES)
    def test_differential_the_payload_runs_under_the_pre489_form(self, tmp_path: Path, name: str):
        """The differential that makes the cell above worth having.

        Same fixture, same input, same harness — only the quoting mechanism
        reverts to the pre-#489 form, and the marker appears. So the cell above
        fails on a regression instead of passing on both shapes.
        """
        run_dir, install_dir = _fixture(tmp_path, name)
        proc = _run(_command("pre489"), install_dir, run_dir)
        assert (run_dir / MARKER).exists(), (
            f"the rebuilt pre-#489 form did NOT execute the payload for {name!r} — the differential "
            f"is vacuous (rc={proc.returncode} stderr={proc.stderr!r})"
        )

    @pytest.mark.parametrize("name", QUOTED_NAMES)
    def test_differential_the_cleanup_is_lost_under_the_pre489_form(self, tmp_path: Path, name: str):
        """The second consequence, including the innocent apostrophe: with the
        path interpolated, the quoting breaks and ``find`` never sees the real
        directory — the cleanup silently does nothing (``|| true`` hides it).
        The shipped form removes exactly these files (cell above)."""
        run_dir, install_dir = _fixture(tmp_path, name)
        proc = _run(_command("pre489"), install_dir, run_dir)
        leftovers = _leftovers(run_dir)
        assert len(leftovers) == PYC_COUNT, (
            f"expected the pre-#489 form to leave the fixture's {PYC_COUNT} bytecode files "
            f"for {name!r}, got {leftovers} (rc={proc.returncode})"
        )

    @pytest.mark.parametrize("form", ["shipped", "pre489"])
    @pytest.mark.parametrize("name", NON_QUOTING_NAMES)
    def test_expansion_syntax_in_a_name_is_not_a_vector(self, tmp_path: Path, name: str, form: str):
        """Negative control: only the QUOTE class reaches script position.

        A directory named ``$(...)`` or with backticks runs nothing under either
        form — a parameter expansion result is never re-expanded — so #489 is
        specifically the quoting bug it was fixed as, not an expansion hole.
        """
        run_dir, install_dir = _fixture(tmp_path, name)
        proc = _run(_command(form), install_dir, run_dir)
        assert not (run_dir / MARKER).exists(), f"{form} form executed {name!r}"
        assert proc.returncode == 0, f"{form} form exited {proc.returncode} for {name!r}: {proc.stderr!r}"
