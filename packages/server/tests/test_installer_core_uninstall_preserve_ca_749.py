# Copyright (c) 2026 Tabith LLC.
# Use of this source code is governed by the Business Source License 1.1
# included in the LICENSE file at the root of this repository. As of the
# Change Date listed there, the work is available under MPL 2.0.
# SPDX-License-Identifier: BUSL-1.1

"""Behavioral + static cells: the core uninstaller keeps the estate CA (#749).

install-venya-core.sh puts the estate trust material under /var/lib/venya/ca —
the root CA (ca.key/ca.crt) and the admin CA (admin-ca/admin-ca.key). The core
uninstaller took that down with one line, `rm -rf /opt/venya /etc/venya
/var/lib/venya /var/log/venya`, and the only confirmation in the script sat
inside the VENYA_SKIP_PROMPT test, whose non-TTY branch tells the operator to
set that flag. So the documented scripted form reached the rm with no
confirmation at all, and dropping one core's service untrusted every host that
was enrolled against its CA.

Ruled shape, three parts: (a) removing the CA needs its own opt-in, named for
what it removes — VENYA_PURGE_CA — and it is not VENYA_SKIP_PROMPT; (b)
/var/lib/venya/ca is kept by default while the service's own state around it
still goes; (c) the run prints the directory path it left behind so an operator
can finish deliberately.

Harness: `_RootHarness` from the #396 module — the real script text with its
absolute prefixes rebased into a tmp fake root and every decision command
stubbed. The CA files are marker files in that tmp tree; no real path under
/var/lib/venya is ever opened, listed, or read.

Truth table, both arms: default run -> CA present, siblings gone, rc 0, kept
path printed, no [ERROR]; VENYA_PURGE_CA=yes run -> /var/lib/venya gone, rc 0,
removal announced. Paired negatives: the skip-prompt flag alone never touches
the keys; the purge flag never skips the prompt (TTY + "n" -> nothing removed);
a value that is not exactly "yes" preserves; a leftover that is not the CA is
named and fails the run; and the verify block reports the CA missing when the
preserve branch is deliberately broken out of the script.
"""

import re
import tempfile
from pathlib import Path

import pytest

from tests.test_installer_core_uninstall_backup_residue_394 import _rm_targets
from tests.test_installer_server_uninstallers_verify_396 import _RootHarness

REPO_ROOT = Path(__file__).resolve().parents[3]
SCRIPT = REPO_ROOT / "uninstall-venya-core.sh"

_CA_KEY = "var/lib/venya/ca/ca.key"
_ADMIN_CA_KEY = "var/lib/venya/ca/admin-ca/admin-ca.key"


def _core(tmp: str) -> _RootHarness:
    h = _RootHarness(tmp, "uninstall-venya-core.sh")
    h.seed_installed_tree("core")
    return h


def _source() -> str:
    return SCRIPT.read_text(encoding="utf-8")


def _break_preserve_guard(h: _RootHarness) -> None:
    """Deliberate break: put the pre-#749 unconditional removal back into the
    harness's copy of the script. The preserve cells must redden against this
    text — a cell that passes both ways is not guarding anything."""
    text = h.script.read_text(encoding="utf-8")
    broken = re.sub(
        r"^ *find [^\n]*/var/lib/venya -mindepth 1 -maxdepth 1 ! -name ca[^\n]*$",
        f"    rm -rf {h.root}/var/lib/venya",
        text,
        count=1,
        flags=re.MULTILINE,
    )
    assert broken != text, "preserve branch not found — the break did not happen"
    h.script.write_text(broken, encoding="utf-8")


# --- (b) kept by default, on the scripted form that used to destroy it ---


def test_scripted_uninstall_keeps_the_ca_keys() -> None:
    """The paired negative that blocks merge: the documented
    VENYA_SKIP_PROMPT=yes form must NOT delete CA keys."""
    with tempfile.TemporaryDirectory() as tmp:
        h = _core(tmp)
        r = h.run()  # skip=yes, VENYA_PURGE_CA absent
        assert r.returncode == 0, r.stdout + r.stderr
        assert "Venya Core uninstalled." in r.stdout
        assert (h.root / _CA_KEY).exists(), "root CA key removed without the opt-in"
        assert (h.root / _ADMIN_CA_KEY).exists(), "admin CA key removed without the opt-in"
        assert (h.root / "var/lib/venya/ca/ca.crt").exists()


def test_service_state_around_the_ca_still_goes() -> None:
    """Keeping the CA is not keeping the directory: the service's own state next
    to it is removed, and the kept path is the only thing left under it."""
    with tempfile.TemporaryDirectory() as tmp:
        h = _core(tmp)
        r = h.run()
        assert r.returncode == 0, r.stdout + r.stderr
        assert not (h.root / "var/lib/venya/payload").exists()
        assert not (h.root / "var/lib/venya/stray-state").exists()
        assert not (h.root / "opt/venya").exists()
        assert not (h.root / "etc/venya").exists()
        assert not (h.root / "var/log/venya").exists()
        survivors = sorted(p.name for p in (h.root / "var/lib/venya").iterdir())
        assert survivors == ["ca"], survivors


# --- (c) the run says what it left ---


def test_kept_directory_path_is_printed() -> None:
    """§2(c): the operator reads the path, not the contents — no file name from
    inside the CA is ever echoed."""
    with tempfile.TemporaryDirectory() as tmp:
        h = _core(tmp)
        r = h.run()
        kept_line = next((line for line in r.stdout.splitlines() if "Left in place:" in line), "")
        assert kept_line, r.stdout
        assert str(h.root / "var/lib/venya/ca") in kept_line, kept_line
        assert "ca.key" not in r.stdout
        assert "admin-ca" not in r.stdout


def test_shipped_bytes_print_the_real_path() -> None:
    """Static half of the same claim, at the face an operator runs: the echo
    names /var/lib/venya/ca and the flag that finishes the job."""
    src = _source()
    assert 'echo "Left in place: /var/lib/venya/ca' in src, src
    assert "VENYA_PURGE_CA=yes" in src


# --- (a) the distinct opt-in, and what it does not bypass ---


def test_purge_ca_opt_in_removes_the_ca() -> None:
    """The opt-in works: naming it takes /var/lib/venya down whole."""
    with tempfile.TemporaryDirectory() as tmp:
        h = _core(tmp)
        r = h.run(purge="yes")
        assert r.returncode == 0, r.stdout + r.stderr
        assert not (h.root / "var/lib/venya").exists()
        assert "including the estate CA" in r.stdout
        assert "Removed as asked" in r.stdout
        assert "Left in place" not in r.stdout


@pytest.mark.parametrize("value", ["", "no", "YES", "Yes", "1", "y", "true"])
def test_only_the_exact_yes_value_purges(value: str) -> None:
    """Paired negative on the knob's own spelling: anything that is not exactly
    "yes" preserves, so a half-set variable cannot destroy the CA."""
    with tempfile.TemporaryDirectory() as tmp:
        h = _core(tmp)
        r = h.run(purge=value)
        assert r.returncode == 0, r.stdout + r.stderr
        assert (h.root / _CA_KEY).exists(), f"VENYA_PURGE_CA={value!r} removed the CA"
        assert not (h.root / "var/lib/venya/stray-state").exists()


def test_purge_flag_does_not_skip_the_prompt() -> None:
    """The two knobs stay separate: VENYA_PURGE_CA=yes on a TTY answered "n"
    removes nothing, so the new flag cannot become a second bypass."""
    with tempfile.TemporaryDirectory() as tmp:
        h = _core(tmp)
        r = h.run(skip="", answer="n", purge="yes")
        assert r.returncode == 0, r.stdout + r.stderr
        assert "Aborted." in r.stdout
        assert h.calls() == "", "a refusal must precede every removal call"
        assert (h.root / _CA_KEY).exists()
        assert (h.root / "opt/venya/payload").exists()


def test_purge_confirmed_interactively_removes_the_keys() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        h = _core(tmp)
        r = h.run(answer="y", purge="yes")
        assert r.returncode == 0, r.stdout + r.stderr
        assert not (h.root / "var/lib/venya").exists()


def test_tty_prompt_names_the_ca_choice() -> None:
    """The interactive operator reads the CA decision before answering, which is
    the half the scripted form never printed."""
    with tempfile.TemporaryDirectory() as tmp:
        h = _core(tmp)
        r = h.run(skip="", answer="n")
        assert "VENYA_PURGE_CA" in r.stdout, r.stdout
        assert "/var/lib/venya/ca" in r.stdout.replace(str(h.root), ""), r.stdout


# --- the existing gates stay armed ---


def test_skip_prompt_gate_and_read_are_untouched() -> None:
    """No weakening: the #399 non-TTY refusal and the interactive read are still
    in the shipped bytes."""
    src = _source()
    assert 'error "non-interactive session: set VENYA_SKIP_PROMPT=yes to confirm removal"' in src
    assert 'if [ "${VENYA_SKIP_PROMPT:-}" != "yes" ]; then' in src
    assert "read -r -p" in src


def test_no_rm_target_names_the_ca_path() -> None:
    """Static negative on the removal surface: the trust directory itself is
    never an rm target — only its parent, and only behind the opt-in."""
    targets = _rm_targets(_source())
    assert not [t for t in targets if "/var/lib/venya/ca" in t], targets
    purge_lines = [ln for ln in _source().splitlines() if ln.strip().startswith("rm -rf /var/lib/venya")]
    assert purge_lines == ["    rm -rf /var/lib/venya"], purge_lines


def test_non_ca_survivor_under_the_state_dir_fails_the_run() -> None:
    """The preserve branch is verified, not assumed: an injected survivor that is
    not the CA is named and the success claim is withheld."""
    with tempfile.TemporaryDirectory() as tmp:
        h = _core(tmp)
        r = h.run(rm_skip="stray-state")
        assert r.returncode != 0, r.stdout
        assert "stray-state still present" in r.stdout, r.stdout
        assert "Venya Core uninstalled." not in r.stdout


# --- deliberate break: proof that the guard is what makes the cells pass ---


def test_guard_removed_leaves_no_ca_and_the_verifier_says_so() -> None:
    """Rewind the script to the unconditional rm. The CA goes (so the preserve
    cells above have teeth) and the verify block reports it instead of claiming
    a clean uninstall."""
    with tempfile.TemporaryDirectory() as tmp:
        h = _core(tmp)
        _break_preserve_guard(h)
        r = h.run()
        assert not (h.root / _CA_KEY).exists(), "the break did not reach the CA"
        assert r.returncode != 0, r.stdout
        assert "estate CA missing at" in r.stdout, r.stdout
        assert "Venya Core uninstalled." not in r.stdout
