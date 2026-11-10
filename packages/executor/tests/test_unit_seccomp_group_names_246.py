# Copyright (c) 2026 Tabith LLC.
# Use of this source code is governed by the Business Source License 1.1
# included in the LICENSE file at the root of this repository. As of the
# Change Date listed there, the work is available under MPL 2.0.
# SPDX-License-Identifier: BUSL-1.1

"""#246 — every name in the shipped executor unit's seccomp deny list resolves.

``systemd/venya-executor.service`` carried ``@chroot`` and ``@ptrace``. Neither is a systemd
filter group on any systemd this fleet ships to — the loader prints
``Unknown system call group, ignoring: @chroot`` on every load and builds the filter without
it, so the unit claimed a deny it did not install. Coverage did not change (``chroot`` sits in
``@mount``, ``ptrace`` in ``@debug``, both proven below from the platform's own tool), but a
stated guarantee that depends on two other groups staying in the list is not a guarantee.

The durable half is this file: the shipped unit is passed through the platform's own parser and
the suite fails on **any** name the parser drops — group or syscall. That is the class of defect
the branch fixes, and it fires again the day anyone adds a name the target systemd does not
know.

Why ``systemd-analyze verify`` and not ``systemd-analyze syscall-filter NAME``: the latter answers
``Filter set "chroot" not found.`` for a perfectly valid single syscall, because it only knows
groups — a gate built on it would refuse the fix this branch ships. ``verify`` parses a unit the
way the loader does and reports each dropped name. Its exit code is **0 while it reports drops**,
so the text is the signal, never the rc — and that is why each positive cell here is paired with a
synthetic unit that must produce the message.

Method is the house shape for installer/unit cells: read the tracked artifact, run the platform
tool on a copy in ``tmp_path``, no VM, no service touched. On a host without ``systemd-analyze``
every cell here SKIPS with a named reason: an unrun gate is never reported as green.
"""

import re
import shutil
import subprocess
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[3]
UNIT = REPO_ROOT / "systemd" / "venya-executor.service"

#: the two signatures the loader prints when it discards a name, and the names this branch removed
DROP_GROUP = "Unknown system call group, ignoring"
DROP_SYSCALL = "is not known, ignoring"
DEAD_NAMES = ("@chroot", "@ptrace")


def _systemd_analyze() -> str:
    exe = shutil.which("systemd-analyze")
    if not exe:
        pytest.skip("systemd-analyze is not on PATH here — this gate is UNRUN, not green")
    return exe


def _unit_text() -> str:
    return UNIT.read_text(encoding="utf-8")


def _filter_names() -> list[str]:
    """The names in the shipped SystemCallFilter line, `~` and all, in file order."""
    line = re.search(r"^SystemCallFilter=(.+)$", _unit_text(), re.MULTILINE)
    assert line, "the shipped executor unit lost its SystemCallFilter line — re-read this file"
    names: list[str] = []
    for token in line.group(1).split():
        names.append(token.removeprefix("~"))
    return names


def _verify(tmp_path: Path, text: str) -> str:
    """Run the platform parser over a unit and answer its combined output.

    rc is deliberately not consulted: `systemd-analyze verify` exits 0 while reporting dropped
    names (measured on systemd 257), so an rc-based assertion would pass on the broken unit.
    """
    path = tmp_path / "venya-executor.service"
    path.write_text(text, encoding="utf-8")
    out = subprocess.run(
        [_systemd_analyze(), "verify", str(path)],
        cwd=str(tmp_path),
        capture_output=True,
        text=True,
        check=False,
        timeout=120,
    )
    return out.stdout + out.stderr


def _dropped(output: str) -> list[str]:
    return [ln for ln in output.splitlines() if DROP_GROUP in ln or DROP_SYSCALL in ln]


def _write(tmp_path: Path, names: str) -> str:
    """A minimal unit carrying exactly the deny names under test."""
    return "[Unit]\nDescription=gate probe\n\n[Service]\nExecStart=/bin/sleep 100\n" f"SystemCallFilter=~{names}\n"


# ------------------------------------------------------------------- the gate on the artifact


def test_shipped_unit_loses_no_name_to_the_platform_parser(tmp_path):
    """The branch's criterion: every name in the shipped unit is one the loader installs."""
    output = _verify(tmp_path, _unit_text())
    assert _dropped(output) == [], "\n".join(_dropped(output))


def test_every_group_name_in_the_unit_resolves_in_the_platform_census():
    """The same claim from the vocabulary side, printed per name so a failure is self-explaining."""
    census = subprocess.run(
        [_systemd_analyze(), "syscall-filter"], capture_output=True, text=True, check=False, timeout=120
    ).stdout
    known = set(re.findall(r"^\s*(@\S+)", census, re.MULTILINE))
    groups = [n for n in _filter_names() if n.startswith("@")]
    assert groups, "no group names left to check — re-read the unit, do not trust an empty pass"
    unknown = [n for n in groups if n not in known]
    assert unknown == [], f"groups the platform does not know: {unknown}; census knows: {sorted(known)}"


def test_membership_proof_the_two_syscalls_are_still_denied_by_the_groups():
    """The finding's 'no coverage delta', read from the tool rather than inherited from a report."""
    exe = _systemd_analyze()
    for group, syscall in (("@mount", "chroot"), ("@debug", "ptrace")):
        members = subprocess.run(
            [exe, "syscall-filter", group], capture_output=True, text=True, check=False, timeout=120
        ).stdout
        assert syscall in members.split(), f"{syscall} is no longer a member of {group} — re-derive the fix"


# ------------------------------------------------------------------ the gate must be able to fail


def test_the_gate_fires_on_the_two_names_this_branch_removed(tmp_path):
    """Negative control: the check is not vacuous — the removed names produce both messages."""
    output = _verify(tmp_path, _write(tmp_path, "@cpu-emulation @chroot @mount @ptrace"))
    dropped = _dropped(output)
    assert any(DROP_GROUP in ln and "@chroot" in ln for ln in dropped), output
    assert any(DROP_GROUP in ln and "@ptrace" in ln for ln in dropped), output
    assert len(dropped) == 2, output


def test_the_gate_fires_on_an_unknown_syscall_name(tmp_path):
    """A bare name is checked too, so the fix cannot be 'fixed' back into a typo."""
    output = _verify(tmp_path, _write(tmp_path, "@mount nosuchsyscallatall chroot"))
    dropped = _dropped(output)
    assert len(dropped) == 1, output
    assert DROP_SYSCALL in dropped[0] and "nosuchsyscallatall" in dropped[0], output


def test_a_valid_group_and_syscall_mix_produces_no_drop(tmp_path):
    """The control on the control: the same harness with only real names stays clean."""
    assert _dropped(_verify(tmp_path, _write(tmp_path, "@mount @debug chroot ptrace"))) == []


# ----------------------------------------------------------- the shipped text, without the tool


def test_the_dropped_names_never_return_to_the_shipped_unit():
    """Version-independent half: the dead names stay out, the live names stay in, in one line."""
    names = _filter_names()
    for dead in DEAD_NAMES:
        assert dead not in names, f"{dead} is not a systemd filter group on the target platform — see #246"
    assert "chroot" in names and "ptrace" in names, names
    assert "~" in re.search(r"^SystemCallFilter=\S+", _unit_text(), re.MULTILINE).group(
        0
    ), "the deny arm must stay a deny"


def test_the_comment_names_the_profile_paths_the_installer_actually_writes():
    """The stale coordinate in the same block: no code reads /etc/venya/systemd, so say what is true."""
    text = _unit_text()
    assert "/etc/venya/systemd" not in text, "no installer writes that path — re-derive before restoring it"
    # both real paths, because the file has two homes: the install tree it ships in, and the
    # directory the executor installer installs it into
    assert "/opt/venya/systemd" in text
    assert "/etc/systemd/system/venya-executor.seccomp" in text
    installer = (REPO_ROOT / "install-venya-executor.sh").read_text(encoding="utf-8")
    assert 'SYSTEMD_DIR="/etc/systemd/system"' in installer
    assert 'install -m 0600 "$INSTALL_DIR/systemd/venya-executor.seccomp" "$SYSTEMD_DIR/"' in installer
