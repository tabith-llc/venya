# Copyright (c) 2026 Tabith LLC.
# Use of this source code is governed by the Business Source License 1.1
# included in the LICENSE file at the root of this repository. As of the
# Change Date listed there, the work is available under MPL 2.0.
# SPDX-License-Identifier: BUSL-1.1

"""Behavioral + static cells: the CLI uninstaller proves its `Removed` line (#758).

Mechanism, two false arms and one that was already fine. Inside `if [ "$PURGE" = "yes" ]`, shipped `dev` did
`rm -rf "$VENYA_CONFIG_DIR"` and then `info "Removed $VENYA_CONFIG_DIR."` with **no probe of any kind between
them** — the only later checks in the file are `command -v`, a PATH test, not a directory test. So a path that
was never there answers `rm -f` semantics with rc 0 and the line printed for a directory that did not exist;
and a path that is a **symlink** is unlinked as a NAME by `rm -rf`, which also succeeds, so the line printed
while the server URL and the stored access token at the target stood untouched. The third arm — a removal that
genuinely fails — already aborted at rc 1 on `set -euo pipefail` before the echo, and is left exactly as it was.

Ruled shape: (a) refuse a symlinked config dir before anything touches it, on the `-L` test venya-common.sh
ships for a symlinked `file://` tarball (#327) and that #755 put on the core uninstaller's state paths;
(b) read absence after the removal with `[ -e ] || [ -L ]` and make the success line conditional on that proof,
so a dangling link can never be counted as removed; (c) when there was nothing to remove, say that instead of
saying "Removed".

Harness: the #390 module's `_Harness` — the REAL script, `HOME` in a tmpdir, `uv` stubbed — extended with the
one knob it never had: `VENYA_PURGE_CONFIG`. Both existing cli harnesses on this face hardcode that value to
"no", which is precisely why this block never got a probe. Cells that need a removal to succeed while the name
stands use the house marker-stub idiom from #394/#396 (`rm` on PATH, forwarding to `/bin/rm`, skipping the
marked operand) — the product is not weakened to reach them. All state stays in the tmpdir; the real
`~/.config/venya` is never opened, and the platform case block is asserted, not rearranged.

Cells: a real dir is removed and the line prints only after the proof; a never-present dir says there was
nothing to remove; the purge-off path does not enter the block, with a real dir or a linked one; a linked dir
is refused with the token material asserted STILL PRESENT at the target and the link name not unlinked; a
dangling link is refused where `-e` would read "gone"; a surviving name fails the run; and two deliberate
breaks — probe stripped, guard stripped — reproduce each old false fact from this same harness, which is what
makes the two cells above teeth rather than decoration. Plus the statics: the reused idiom, the guard's
position before the removal, and AC4's platform pin against
`venya_cli.api_client.default_config_dir()`.
"""

import os
import shutil
import subprocess
import tempfile
from pathlib import Path

from tests.test_installer_cli_uninstall_complete_390 import SCRIPT, _Harness

# The rm marker stub: forwards to /bin/rm except for an operand containing RM_SKIP_SUB, which "succeeds"
# while the name stands. The same injection idiom the #394/#396 uninstaller cells use.
_STUB_RM = """#!/bin/bash
for a in "$@"; do
    if [ -n "${RM_SKIP_SUB:-}" ] && [[ "$a" == *"${RM_SKIP_SUB}"* ]]; then exit 0; fi
done
exec /bin/rm "$@"
"""

_CONFIG_REL = Path(".config") / "venya"
_TOKEN = "access-token"
_URL_FILE = "config.json"
_NOTHING_LINE = "nothing to remove."


class _Cli(_Harness):
    """The #390 harness with the purge arm wired, an optional standing-name rm stub, and the platform
    config dir as the script itself resolves it under HOME."""

    def __init__(self, tmp: str, *, rm_stub: bool = False) -> None:
        super().__init__(tmp)
        self.config = self.home / _CONFIG_REL
        if rm_stub:
            p = self.stub / "rm"
            p.write_text(_STUB_RM, encoding="utf-8")
            p.chmod(0o755)

    def seed_config(self, tree: Path | None = None) -> Path:
        """A real config dir holding the two files a customer's token lives in."""
        d = tree or self.config
        d.mkdir(parents=True, exist_ok=True)
        (d / _URL_FILE).write_text('{"server_url": "https://venya.example"}\n', encoding="utf-8")
        (d / _TOKEN).write_text("tok\n", encoding="utf-8")
        return d

    def link_config_out(self, *, dangling: bool = False) -> Path:
        """Point ~/.config/venya at a tree elsewhere. Returns the target path."""
        real = self.tmp / "outside-config"
        if self.config.is_symlink():
            self.config.unlink()
        elif self.config.exists():
            shutil.rmtree(self.config)
        self.config.parent.mkdir(parents=True, exist_ok=True)
        if dangling:
            os.symlink(str(self.tmp / "no-such-target"), str(self.config))
        else:
            self.seed_config(real)
            os.symlink(str(real), str(self.config))
        return real

    def run(
        self, purge: str = "yes", skip: str = "yes", rm_skip: str = "", script: Path | None = None
    ) -> subprocess.CompletedProcess:
        env = {
            "HOME": str(self.home),
            "PATH": f"{self.stub}:{os.defpath}:/usr/bin:/bin",
            "STUB_LOG": str(self.log),
            "TOOLS_DIR": str(self.tools),
            "RC_DIR": str(self.rc_dir),
            "RM_SKIP_SUB": rm_skip,
            "VENYA_SKIP_PROMPT": skip,
            "VENYA_PURGE_CONFIG": purge,
        }
        return subprocess.run(
            ["/bin/bash", str(script or SCRIPT)],
            capture_output=True,
            text=True,
            timeout=30,
            env=env,
            stdin=subprocess.DEVNULL,
            check=False,
        )


def _cli(tmp: str, *, rm_stub: bool = False) -> _Cli:
    h = _Cli(tmp, rm_stub=rm_stub)
    h.install_tree()
    return h


def _copy_without(tmp: str, start_marker: str, end_marker: str, replacement: str = "") -> Path:
    """Deliberate break: ship the harness a copy of the real script with one shipped block cut out — the
    span from `start_marker` up to `end_marker`, replaced by `replacement`. The cut is asserted to have
    happened and asserted to have cut only that block: a break that silently fails is how a cell passes
    for the wrong reason."""
    text = SCRIPT.read_text(encoding="utf-8")
    start = text.index(start_marker)
    end = text.index(end_marker, start)
    assert start < end, f"{start_marker!r} does not precede {end_marker!r}"
    broken = text[:start] + replacement + text[end:]
    assert broken != text, "the cut removed nothing"
    tag = start_marker.strip().lstrip("#").strip("()ab ").replace('"', "").replace(" ", "")[:18]
    p = Path(tmp) / f"cut-{tag}.sh"
    p.write_text(broken, encoding="utf-8")
    return p


# --- AC3 first half + AC2 positive: a real config dir goes, and the line is proved ---


def test_real_config_dir_is_removed_and_the_line_is_proved() -> None:
    """The paired negative of the refusal: a real directory is still removed, the run still says so,
    and no refusal fires."""
    with tempfile.TemporaryDirectory() as tmp:
        h = _cli(tmp)
        h.seed_config()
        r = h.run()
        assert r.returncode == 0, r.stdout + r.stderr
        assert f"Removed {h.config}." in r.stdout, r.stdout
        assert "refusing to follow it" not in r.stdout
        assert _NOTHING_LINE not in r.stdout
        assert not h.config.exists(), "a real config dir survived a removal the run proved"
        assert "Venya CLI uninstalled" in r.stdout


# --- AC3 second half: never-present is not reported as deleted ---


def test_never_present_config_dir_is_not_reported_as_deleted() -> None:
    """The first false arm: `rm -f` semantics answer rc 0 for a missing operand, so the shipped line
    printed for a directory that was never there. The run now names the path and says there was nothing
    to remove — and still exits 0, because nothing is wrong."""
    with tempfile.TemporaryDirectory() as tmp:
        h = _cli(tmp)
        assert not h.config.exists()
        r = h.run()
        assert r.returncode == 0, r.stdout + r.stderr
        assert f"No config dir at {h.config} — {_NOTHING_LINE}" in r.stdout, r.stdout
        assert "Removed" not in r.stdout, r.stdout
        assert not h.config.exists()


# --- AC3 third clause: the purge-off path must not reach the block at all ---


def test_purge_off_path_never_enters_the_config_block() -> None:
    """Without VENYA_PURGE_CONFIG=yes the block does not run: a real config dir is untouched and neither
    a removal, a nothing-to-remove line, nor a refusal is printed."""
    with tempfile.TemporaryDirectory() as tmp:
        h = _cli(tmp)
        h.seed_config()
        r = h.run(purge="no")
        assert r.returncode == 0, r.stdout + r.stderr
        assert (h.config / _TOKEN).exists(), "the purge-off path removed the config dir"
        assert "Removed" not in r.stdout, r.stdout
        assert _NOTHING_LINE not in r.stdout, r.stdout
        assert "refusing to follow it" not in r.stdout


def test_purge_off_path_ignores_a_symlinked_config_dir() -> None:
    """The guard lives inside the opt-in, so a purge-off run against a linked config dir sees no new
    refusal — the path that removes no config stays as it was."""
    with tempfile.TemporaryDirectory() as tmp:
        h = _cli(tmp)
        real = h.link_config_out()
        r = h.run(purge="no")
        assert r.returncode == 0, r.stdout + r.stderr
        assert "refusing to follow it" not in r.stdout, r.stdout
        assert _NOTHING_LINE not in r.stdout
        assert h.config.is_symlink() and (real / _TOKEN).exists()


# --- AC1: refuse a symlinked config dir before touching it ---


def test_symlinked_config_dir_is_refused_and_token_material_survives() -> None:
    """The measured false completion: `rm -rf` on a symlink unlinks the NAME and succeeds, so the run
    announced a removal while the token tree at the target stood untouched. Now rc!=0, the path and its
    resolved target are named, the link is NOT unlinked, and the material is asserted present at target."""
    with tempfile.TemporaryDirectory() as tmp:
        h = _cli(tmp)
        real = h.link_config_out()
        r = h.run()
        assert r.returncode != 0, r.stdout
        assert "Config dir is a symlink:" in r.stdout, r.stdout
        assert f"{h.config} -> {real}" in r.stdout, r.stdout
        assert "refusing to follow it (#758)" in r.stdout
        assert "Removed" not in r.stdout, "a refusal still announced the removal"
        assert "Venya CLI uninstalled" not in r.stdout
        assert h.config.is_symlink(), "the refusal unlinked the name anyway"
        assert (real / _TOKEN).exists(), "access token gone at the target"
        assert (real / _URL_FILE).exists(), "server URL gone at the target"


def test_dangling_config_dir_symlink_is_refused_not_called_gone() -> None:
    """A link with no target reads absent to -d and -e. -L is an lstat, so this is refused too instead of
    being unlinked and reported as a deletion."""
    with tempfile.TemporaryDirectory() as tmp:
        h = _cli(tmp)
        h.link_config_out(dangling=True)
        r = h.run()
        assert r.returncode != 0, r.stdout
        assert "Config dir is a symlink:" in r.stdout, r.stdout
        assert "Removed" not in r.stdout
        assert h.config.is_symlink(), "the dangling name was unlinked, not refused"


# --- AC2: the verifier fails the run when the name is still there ---


def test_surviving_name_fails_the_run_when_the_removal_did_nothing() -> None:
    """The proof behind the line: with the removal made to succeed while the directory stands
    (marker-stubbed rm, the house idiom), the run must not claim it removed anything — it names the
    survivor and exits nonzero."""
    with tempfile.TemporaryDirectory() as tmp:
        h = _cli(tmp, rm_stub=True)
        h.seed_config()
        r = h.run(rm_skip=str(_CONFIG_REL))
        assert r.returncode != 0, r.stdout
        assert f"{h.config} still present after removal" in r.stdout, r.stdout
        assert "Removed" not in r.stdout, r.stdout
        assert "Venya CLI uninstalled" not in r.stdout
        assert (h.config / _TOKEN).exists()


# --- deliberate breaks: each old false fact must be reachable from this harness ---


def test_probe_stripped_reproduces_the_false_removed_line() -> None:
    """Cut the absence proof out (the type guard stays). With the removal a no-op, the script exits 0 and
    prints "Removed …" over a directory that is still standing — the false fact #758 was filed for,
    produced by this same harness, which is why the cell above has teeth."""
    with tempfile.TemporaryDirectory() as tmp:
        h = _cli(tmp, rm_stub=True)
        h.seed_config()
        cut = _copy_without(
            tmp,
            start_marker='    CONFIG_DIR_PRESENT="no"',
            end_marker="if command -v venya > /dev/null 2>&1; then",
            replacement='    rm -rf "$VENYA_CONFIG_DIR"\n    info "Removed $VENYA_CONFIG_DIR."\nfi\n\n',
        )
        text = cut.read_text(encoding="utf-8")
        assert "still present after removal" not in text, "the probe survived the cut"
        assert "refusing to follow it" in text, "the type guard was cut too, so this is not the probe break"
        r = h.run(rm_skip=str(_CONFIG_REL), script=cut)
        assert r.returncode == 0, r.stdout + r.stderr
        assert f"Removed {h.config}." in r.stdout, r.stdout
        assert (h.config / _TOKEN).exists(), "the cut removed the tree, so this is not the old shape"


def test_guard_stripped_reproduces_the_unlinked_name() -> None:
    """Cut the type guard out (the absence proof stays, because after unlinking a link the name really is
    gone and the proof passes). rc 0, "Removed" printed, and the token tree survives at the target: the
    state the operator was told was deleted."""
    with tempfile.TemporaryDirectory() as tmp:
        h = _cli(tmp)
        real = h.link_config_out()
        cut = _copy_without(tmp, start_marker="    # #758 (a):", end_marker="    # #758 (b):")
        text = cut.read_text(encoding="utf-8")
        assert "refusing to follow it" not in text, "the guard survived the cut"
        assert "still present after removal" in text, "the probe was cut too, so this is not the guard break"
        r = h.run(script=cut)
        assert r.returncode == 0, r.stdout + r.stderr
        assert f"Removed {h.config}." in r.stdout, r.stdout
        assert not h.config.is_symlink(), "the link name stood, so the removal did not reach it"
        assert (real / _TOKEN).exists(), "the token tree went, so this is not the old shape"


# --- statics: the idiom, the position, and the platform matrix ---


def test_guard_ships_the_reused_idiom_and_the_ticket() -> None:
    """Not an invented test: the same -L shape #327 and #755 ship, the target is named through
    readlink -f, and both the guard and the proof cite the absence pair."""
    src = SCRIPT.read_text(encoding="utf-8")
    assert '[ -L "$VENYA_CONFIG_DIR" ]' in src, src
    assert 'link_target="$(readlink -f -- "$VENYA_CONFIG_DIR" 2> /dev/null || true)"' in src, src
    assert "#758" in src
    assert '[ -e "$VENYA_CONFIG_DIR" ] || [ -L "$VENYA_CONFIG_DIR" ]' in src, src


def test_guard_precedes_the_removal_and_the_line_follows_the_proof() -> None:
    """Position is half the AC: the -L refusal sits before `rm -rf`, and the `Removed` echo sits after
    the absence test — a line printed beside the rm is an assertion, not a report."""
    src = SCRIPT.read_text(encoding="utf-8")
    rm = src.index('rm -rf "$VENYA_CONFIG_DIR"')
    assert src.index('[ -L "$VENYA_CONFIG_DIR" ]') < rm, "the type guard sits after the removal"
    assert src.index('info "Removed $VENYA_CONFIG_DIR."') > rm, "the success line precedes the removal"
    assert src.index("still present after removal") > rm
    # "nothing to remove" also appears in the pre-existing uv warn line, so the position is pinned on the
    # unambiguous half of my own sentence.
    assert src.index("No config dir at $") > rm
    assert src.index('if [ -L "$VENYA_CONFIG_DIR" ]') < src.index('CONFIG_DIR_PRESENT="no"')


def test_platform_matrix_still_matches_the_library_face() -> None:
    """AC4: the case block was not reordered or "simplified", and the path it resolves is the path
    `default_config_dir()` names. The comparison is a text read of the CLI's own module — the house form
    for a server test looking at the CLI face (`test_version_tuple_parity.py` does the same to this file),
    chosen over an import so a peer venue whose `uv sync` pruned the cli member still runs this cell. The
    POSIX face is also proven physically: `test_real_config_dir_is_removed_and_the_line_is_proved` removes
    exactly `$HOME/.config/venya`. Windows tokens belong to uninstall-venya-cli.ps1 — unreachable from here
    (R-2761), and no Windows arm may enter this matrix."""
    src = SCRIPT.read_text(encoding="utf-8")
    case_block = src[src.index('    case "$(uname -s)" in') : src.index("    # #758 (a):")]
    arms = [ln for ln in case_block.splitlines() if ln.rstrip().endswith(";;")]
    assert len(arms) == 2, case_block
    assert "%APPDATA%" not in case_block, case_block

    lib = (Path(__file__).resolve().parents[2] / "cli" / "src" / "venya_cli" / "api_client.py").read_text(
        encoding="utf-8"
    )
    body = lib[lib.index("def default_config_dir(") :]
    body = body[: body.index("\ndef ", 1)] if "\ndef " in body[1:] else body
    assert 'Path.home() / "Library" / "Application Support" / "venya"' in body, body
    assert 'Path.home() / ".config" / "venya"' in body, body
    assert 'Darwin) VENYA_CONFIG_DIR="$HOME/Library/Application Support/venya" ;;' in case_block, case_block
    assert '*)      VENYA_CONFIG_DIR="$HOME/.config/venya" ;;' in case_block, case_block
