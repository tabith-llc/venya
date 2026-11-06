# Copyright (c) 2026 Tabith LLC.
# Use of this source code is governed by the Business Source License 1.1
# included in the LICENSE file at the root of this repository. As of the
# Change Date listed there, the work is available under MPL 2.0.
# SPDX-License-Identifier: BUSL-1.1

"""Behavioral + static cells: the core uninstaller refuses a symlinked state path (#755).

Mechanism, measured before it was written down. `find` with the default `-P` does not follow a symlink
given as its starting point, and `rm -rf` on a symlink unlinks the NAME, not the tree it points at. So when
`/var/lib/venya` is a symlink instead of a directory, the #749 preserve sweep (`find ... -mindepth 1
-maxdepth 1 ! -name ca -exec rm -rf {} +`) removes nothing, the survivor probe names nothing, and the run
prints "Venya Core uninstalled." over a state tree it never touched. On the VENYA_PURGE_CA=yes arm the same
shape reads the other way: `rm -rf /var/lib/venya` takes the link, the closing `[ -e ]` verify answers GONE,
and the estate CA — ca.key and admin-ca/admin-ca.key included — is still on disk at the target while the run
reports a purge that did not happen. Either way the operator is told the machine is clean.

Ruled shape: refuse before any removal. A type check (`-L`, the same test #327 uses for a symlinked `file://`
tarball in venya-common.sh, and an lstat so a dangling link is caught where `-e` reads "gone") on
`/var/lib/venya` and on `/var/lib/venya/ca`, both refused paths printed, the resolved target named when
`readlink -f` can read one, then exit nonzero having touched nothing. The verifier is hardened in the same
change: a leftover that is a dangling symlink is a survivor, not a success.

Harness: `_RootHarness` from the #396 module — the real script text with its absolute prefixes rebased into a
tmp fake root and every decision command stubbed. The links point at marker trees inside that tmpdir; no real
path under /var/lib/venya is ever opened, listed, read, or linked to.

Cells: the positive on both arms (a real directory with a real ca/ proceeds exactly as it did before #755),
and as its own cell each — the state dir a symlink, the ca entry a symlink out, the PURGE_CA=yes arm against
either link, a dangling state-dir link, both links at once (AC1 asks for both paths named in one run), and a
survivor that is a dangling symlink under the verify loop. The purge negatives assert the key material is
STILL PRESENT at the target after the refused run: that is the point of the refusal, and an exit code alone
does not show it. `h.calls()` is asserted empty on every refusal — a refusal must precede every removal call.
The last cell rewinds the guard out of the harness's copy and shows the false success come back, so the cells
above have teeth.
"""

import os
import re
import shutil
import tempfile
from pathlib import Path

import pytest

from tests.test_installer_server_uninstallers_verify_396 import _RootHarness

REPO_ROOT = Path(__file__).resolve().parents[3]
SCRIPT = REPO_ROOT / "uninstall-venya-core.sh"

_STATE = "var/lib/venya"
_CA_DIR = "ca"
_CA_KEY = "ca.key"
_ADMIN_KEY = "admin-ca/admin-ca.key"


def _core(tmp: str) -> _RootHarness:
    h = _RootHarness(tmp, "uninstall-venya-core.sh")
    h.seed_installed_tree("core")
    return h


def _source() -> str:
    return SCRIPT.read_text(encoding="utf-8")


def _link_state_dir(h: _RootHarness, *, dangling: bool = False) -> Path:
    """Make /var/lib/venya a symlink. Returns the TARGET tree — the state this run
    is being asked to remove, keys included, somewhere the script is not looking."""
    state = h.root / _STATE
    real = h.root / "outside-state"
    if dangling:
        shutil.rmtree(state)
        os.symlink(str(h.root / "no-such-target"), str(state))
        return real
    shutil.move(str(state), str(real))
    state.parent.mkdir(parents=True, exist_ok=True)
    os.symlink(str(real), str(state))
    return real


def _link_ca_entry(h: _RootHarness) -> Path:
    """The state directory stays a real directory; only the CA entry links out.
    Returns the CA tree at its real location."""
    ca = h.root / _STATE / _CA_DIR
    real = h.root / "outside-ca"
    shutil.move(str(ca), str(real))
    os.symlink(str(real), str(ca))
    return real


def _break_symlink_guard(h: _RootHarness) -> None:
    """Deliberate break: take the #755 refusal back out of the harness's copy of
    the script. The refusal cells must redden against this text, and this text
    must reproduce the old false success — that is the proof the guard is what
    stops it, not a message printed alongside a working removal."""
    text = h.script.read_text(encoding="utf-8")
    broken = re.sub('^STATE_TYPE_REFUSED=""$\n.*?^fi$\n', "", text, count=1, flags=re.MULTILINE | re.DOTALL)
    assert broken != text, "guard block not found — the break did not happen"
    assert "STATE_TYPE_REFUSED" not in broken, "the break left part of the guard behind"
    h.script.write_text(broken, encoding="utf-8")


# --- AC2 positive: real directories are not refused, on either arm ---


def test_real_state_dir_and_real_ca_are_not_refused() -> None:
    """No false positive on the preserve arm: a real /var/lib/venya with a real
    ca/ inside runs the whole uninstall, keeps the CA, never mentions a refusal."""
    with tempfile.TemporaryDirectory() as tmp:
        h = _core(tmp)
        r = h.run()
        assert r.returncode == 0, r.stdout + r.stderr
        assert "refusing to follow it" not in r.stdout, r.stdout
        assert "Venya Core uninstalled." in r.stdout
        assert (h.root / _STATE / _CA_DIR / _CA_KEY).exists()
        assert not (h.root / _STATE / "payload").exists()


def test_real_state_dir_still_purges_on_the_opt_in() -> None:
    """No false positive on the other arm: the guard does not blunt a legitimate
    VENYA_PURGE_CA=yes run against real directories."""
    with tempfile.TemporaryDirectory() as tmp:
        h = _core(tmp)
        r = h.run(purge="yes")
        assert r.returncode == 0, r.stdout + r.stderr
        assert not (h.root / _STATE).exists()
        assert "Removed as asked" in r.stdout
        assert "refusing to follow it" not in r.stdout


# --- AC2 negatives, one cell each ---


def test_state_dir_symlink_refuses_before_any_removal() -> None:
    """The measured case: the sweep would have removed nothing and the run would
    have claimed success. The type check stops it, and stops it first."""
    with tempfile.TemporaryDirectory() as tmp:
        h = _core(tmp)
        real = _link_state_dir(h)
        r = h.run()
        assert r.returncode != 0, r.stdout
        assert f"{h.root / _STATE} -> {real}" in r.stdout, r.stdout
        assert "Venya Core uninstalled." not in r.stdout
        assert h.calls() == "", "a refusal must precede every removal call"
        assert (real / _CA_DIR / _CA_KEY).exists()
        assert (real / "payload").exists(), "the state tree was touched on a refused run"
        assert (h.root / "opt/venya/payload").exists(), "removals ran before the refusal"


def test_ca_entry_symlink_refuses_before_any_removal() -> None:
    """The CA entry alone is enough to refuse: a linked ca/ means the trust
    material this run is told to keep is not where the run thinks it is."""
    with tempfile.TemporaryDirectory() as tmp:
        h = _core(tmp)
        real = _link_ca_entry(h)
        r = h.run()
        assert r.returncode != 0, r.stdout
        assert f"{h.root / _STATE / _CA_DIR} -> {real}" in r.stdout, r.stdout
        assert "Venya Core uninstalled." not in r.stdout
        assert h.calls() == "", "a refusal must precede every removal call"
        assert (real / _CA_KEY).exists()
        assert (h.root / _STATE / "payload").exists()


def test_both_refused_paths_are_printed_in_one_run() -> None:
    """AC1 asks for BOTH paths it refused on: the state dir is a link and the ca
    inside its target is a link too, so one run names two paths."""
    with tempfile.TemporaryDirectory() as tmp:
        h = _core(tmp)
        real = _link_state_dir(h)
        vault = h.root / "ca-vault"
        vault.mkdir()
        (vault / _CA_KEY).write_text("k\n", encoding="utf-8")
        shutil.move(str(real / _CA_DIR), str(h.root / "ca-moved-aside"))
        os.symlink(str(vault), str(real / _CA_DIR))
        r = h.run()
        assert r.returncode != 0, r.stdout
        refused = [ln for ln in r.stdout.splitlines() if "State path is a symlink:" in ln]
        assert len(refused) == 2, r.stdout
        assert "Nothing was removed:" in r.stdout, r.stdout
        assert str(h.root / _STATE) in r.stdout and str(h.root / _STATE / _CA_DIR) in r.stdout
        assert (vault / _CA_KEY).exists()


@pytest.mark.parametrize("which", ["state-dir", "ca-entry"])
def test_purge_ca_arm_refuses_and_key_material_survives_at_the_target(which: str) -> None:
    """AC2's purge negative, against either link. The run this guard replaces
    announced a CA purge that never happened, so the assertion that matters sits
    at the TARGET: the key material is still on disk after the refused run."""
    with tempfile.TemporaryDirectory() as tmp:
        h = _core(tmp)
        if which == "state-dir":
            ca_tree = _link_state_dir(h) / _CA_DIR
        else:
            ca_tree = _link_ca_entry(h)
        r = h.run(purge="yes")
        assert r.returncode != 0, r.stdout
        assert "refusing to follow it (#755)" in r.stdout, r.stdout
        assert "Removed as asked" not in r.stdout, "a purge was announced on a refused run"
        assert "including the estate CA" not in r.stdout
        assert "Venya Core uninstalled." not in r.stdout
        assert h.calls() == "", "a refusal must precede every removal call"
        assert (ca_tree / _CA_KEY).exists(), f"root CA key material gone on the {which} refusal"
        assert (ca_tree / _ADMIN_KEY).exists(), f"admin CA key material gone on the {which} refusal"


def test_dangling_state_dir_link_is_refused_not_called_gone() -> None:
    """A link whose target is missing reads absent to -d and -e, which is how the
    old run saw no state directory at all. -L is an lstat, so it is refused."""
    with tempfile.TemporaryDirectory() as tmp:
        h = _core(tmp)
        _link_state_dir(h, dangling=True)
        r = h.run()
        assert r.returncode != 0, r.stdout
        assert "State path is a symlink:" in r.stdout, r.stdout
        assert "Venya Core uninstalled." not in r.stdout
        assert h.calls() == "", "a refusal must precede every removal call"


def test_dangling_symlink_survivor_is_not_reported_as_removed() -> None:
    """AC3's verifier half, on a path the guard does not cover: a leftover that is
    a dangling symlink is invisible to [ -e ] alone, so the closing loop used to
    call it removed and print the success line. Injected with the same rm-skip
    marker the #394/#396 cells use, on /var/log/venya."""
    with tempfile.TemporaryDirectory() as tmp:
        h = _core(tmp)
        victim = h.root / "var/log/venya"
        shutil.rmtree(victim)
        os.symlink(str(h.root / "no-such-target"), str(victim))
        r = h.run(rm_skip="var/log/venya")
        assert r.returncode != 0, r.stdout
        assert f"still present at {victim}" in r.stdout, r.stdout
        assert "Venya Core uninstalled." not in r.stdout, r.stdout


# --- static halves on the shipped bytes ---


def test_shipped_bytes_guard_both_paths_and_the_ticket() -> None:
    """The refusal is judged against the literal paths an operator's machine holds,
    not a rebased tmp copy, and it cites the ticket it closes."""
    src = _source()
    assert "for state_path in /var/lib/venya /var/lib/venya/ca; do" in src, src
    assert '[ -L "$state_path" ] || continue' in src, src
    assert "#755" in src
    assert "Nothing was removed:" in src


def test_guard_precedes_every_removal_line() -> None:
    """Position is part of the guard: it must sit before the first removal in the
    script, or it is a report and not a refusal."""
    src = _source()
    guard = src.index("for state_path in /var/lib/venya /var/lib/venya/ca; do")
    first_rm = min(src.index(m) for m in ("rm -f /etc/systemd", "rm -rf /opt/venya", "rm -rf /var/lib/venya"))
    assert guard < first_rm, "the guard sits after a removal"
    assert src.index("exit 1", guard) < first_rm


def test_verifier_uses_the_e_or_l_idiom() -> None:
    """The shipped idiom is reused, not reinvented — the same pair
    cleanup_install_temps uses in venya-common.sh."""
    src = _source()
    assert '[ -e "$path_item" ] || [ -L "$path_item" ]' in src, src
    assert "[ -e /var/lib/venya ] || [ -L /var/lib/venya ]" in src, src


# --- deliberate break: proof the guard is what makes the cells pass ---


def test_guard_removed_reproduces_the_false_success() -> None:
    """Rewind the refusal. Against a symlinked state dir the shipped run exits 0,
    prints the success line, and leaves the whole tree standing — the exact false
    fact #755 was filed for, and the reason the cells above are not decoration."""
    with tempfile.TemporaryDirectory() as tmp:
        h = _core(tmp)
        real = _link_state_dir(h)
        _break_symlink_guard(h)
        r = h.run()
        assert r.returncode == 0, r.stdout + r.stderr
        assert "Venya Core uninstalled." in r.stdout, r.stdout
        assert "refusing to follow it" not in r.stdout
        assert (real / _CA_DIR / _CA_KEY).exists(), "the break reached the CA key it used to miss"
        assert (real / "stray-state").exists(), "proof the sweep never reached the linked tree"
