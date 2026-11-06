# Copyright (c) 2026 Tabith LLC.
# Use of this source code is governed by the Business Source License 1.1
# included in the LICENSE file at the root of this repository. As of the
# Change Date listed there, the work is available under MPL 2.0.
# SPDX-License-Identifier: BUSL-1.1

"""FIDO-class scoping cells for install-venya-cli.sh (ticket #748).

The shipped check looped over ANY /dev/hidraw* and called the result a security
key, so an unreachable keyboard answered for a FIDO key — and because an
unmatched glob runs the loop body once with the literal pattern, a host with no
HID nodes at all warned too. The remedy it printed wrote
`KERNEL=="hidraw*", MODE="0660", GROUP="plugdev"`, which grants group read-write
on every HID raw device on the bus, keyboards included.

Behavioral cells execute the real FIDO fragment extracted from the script (house
pattern: test_cli_sh_login_shell_verify_744.py). The fragment reads two sysfs
roots that default to /sys/class/hidraw and /dev and are env-overridable for
exactly this purpose, so a fixture can present a FIDO node, a keyboard node, or
no node at all without hardware. A fixture node is a regular file standing in
for the char device: the branch under test is the classification and the
-r/-w probe, neither of which distinguishes the two.

Truth table. Silent: no HID class dir, an empty class dir, a keyboard-only node
that is unreachable, a FIDO node this user can read and write. Loud (the paired
negative, root AGENTS.md §2): a FIDO-class node that is present and NOT
reachable still warns, names the device identity, and offers a grant scoped to
that one node.

Redness measured, not asserted: with the pre-fix fragment from 412ef72b put back
in place on this host (which has no /sys/class/hidraw at all), all 10 cells in
this file fail — `pytest tests/test_cli_sh_fido_hid_scope_748.py -q` → "10 failed
in 0.91s". The script was restored in the same command; the tip is green at 10
passed.
"""

import subprocess
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[3]
SCRIPT = REPO_ROOT / "install-venya-cli.sh"

BEGIN = "# --- FIDO2 access check"
END = "# Platform-appropriate config dir"

PRELUDE = "set -euo pipefail\n" 'warn() { echo "[WARN] $*"; }\n' 'info() { echo "[INFO] $*"; }\n'

# HID short item: 06 D0 F1 = Usage Page (0xF1D0, FIDO), then Usage (0x01),
# Collection (Application), a vendor report, End Collection.
FIDO_RDESC = bytes([0x06, 0xD0, 0xF1, 0x09, 0x01, 0xA1, 0x01, 0x09, 0x20, 0x15, 0x00, 0x25, 0xFF, 0xC0])
# Generic Desktop (0x01) / Keyboard (0x06) — no FIDO usage page anywhere.
KBD_RDESC = bytes([0x05, 0x01, 0x09, 0x06, 0xA1, 0x08, 0x05, 0x07, 0x19, 0xE0, 0x29, 0xE7, 0xC0])
MODALIAS = "hid:b0003g0001v00001050p00000402"

UNREACHABLE = 0o000  # not the owner's uid's file bits: -r and -w both fail
REACHABLE = 0o600


def _src() -> str:
    return SCRIPT.read_text(encoding="utf-8")


def _fragment(src: str) -> str:
    return src[src.index(BEGIN) : src.index(END)]


def _add_node(root: Path, name: str, rdesc: bytes, mode: int, modalias: str | None = MODALIAS) -> Path:
    """One hidraw entry: sysfs classification files plus the /dev stand-in."""
    device = root / "sys" / "class" / "hidraw" / name / "device"
    device.mkdir(parents=True)
    (device / "report_descriptor").write_bytes(rdesc)
    if modalias is not None:
        (device / "modalias").write_text(modalias, encoding="utf-8")
    node = root / "dev" / name
    node.parent.mkdir(parents=True, exist_ok=True)
    node.touch()
    node.chmod(mode)
    return node


def _run(root: Path) -> tuple[int, str]:
    root.mkdir(parents=True, exist_ok=True)
    script = root / "fido_cell.sh"
    script.write_text(PRELUDE + _fragment(_src()), encoding="utf-8")
    env = {
        "PATH": "/usr/bin:/bin",
        "VENYA_HIDRAW_CLASS_DIR": str(root / "sys" / "class" / "hidraw"),
        "VENYA_HIDRAW_DEV_DIR": str(root / "dev"),
    }
    proc = subprocess.run(
        ["bash", str(script)],
        capture_output=True,
        text=True,
        env=env,
        timeout=60,
        check=False,
    )
    return proc.returncode, proc.stdout + proc.stderr


def test_no_hid_class_directory_is_silent(tmp_path: Path) -> None:
    """AC1: a host with no /sys/class/hidraw at all must say nothing, not warn."""
    rc, out = _run(tmp_path / "nohid")
    assert rc == 0, out
    assert out.strip() == "", out


def test_empty_hid_class_directory_is_silent(tmp_path: Path) -> None:
    """AC1: the class dir existing with no nodes in it is the same silence."""
    root = tmp_path / "empty"
    (root / "sys" / "class" / "hidraw").mkdir(parents=True)
    out = _run(root)[1]
    assert out.strip() == "", out


def test_keyboard_on_the_bus_is_not_reported_as_a_security_key(tmp_path: Path) -> None:
    """The scope half: an unreachable non-FIDO node must not trip a key warning."""
    root = tmp_path / "kbd"
    _add_node(root, "hidraw0", KBD_RDESC, UNREACHABLE)
    rc, out = _run(root)
    assert rc == 0, out
    assert out.strip() == "", out


def test_reachable_security_key_is_stated_not_warned(tmp_path: Path) -> None:
    """The good case says what it proved, in one line, and warns about nothing."""
    root = tmp_path / "ok"
    _add_node(root, "hidraw3", FIDO_RDESC, REACHABLE)
    rc, out = _run(root)
    assert rc == 0, out
    assert "[INFO] FIDO2 key reachable at" in out, out
    assert "hidraw3" in out, out
    assert "[WARN]" not in out, out


def test_reachable_key_wins_when_a_second_node_is_blocked(tmp_path: Path) -> None:
    """Two FIDO nodes, one blocked then one usable: venya can reach a key, so no warning."""
    root = tmp_path / "two"
    _add_node(root, "hidraw4", FIDO_RDESC, UNREACHABLE)
    _add_node(root, "hidraw5", FIDO_RDESC, REACHABLE)
    rc, out = _run(root)
    assert rc == 0, out
    assert "[WARN]" not in out, out
    assert "hidraw5" in out, out


def test_present_but_unreadable_key_still_warns_and_names_the_device(tmp_path: Path) -> None:
    """AC3, the paired negative: the check is scoped, not deleted."""
    root = tmp_path / "blocked"
    _add_node(root, "hidraw6", FIDO_RDESC, UNREACHABLE)
    rc, out = _run(root)
    assert rc == 0, out
    assert "FIDO2 key present at" in out, out
    assert "hidraw6" in out, out
    assert MODALIAS in out, out  # a device identity, so the operator sees which device
    assert "not readable/writable" in out, out


def test_unreadable_key_warns_with_the_node_when_sysfs_has_no_modalias(tmp_path: Path) -> None:
    """No modalias file: the warning still fires and names the node, with no empty identity."""
    root = tmp_path / "nomodal"
    _add_node(root, "hidraw7", FIDO_RDESC, UNREACHABLE, modalias=None)
    rc, out = _run(root)
    assert rc == 0, out
    assert "FIDO2 key present at" in out, out
    assert "hidraw7" in out, out
    assert "()" not in out, out


def test_remedy_grants_one_named_device_and_never_the_whole_bus(tmp_path: Path) -> None:
    """The printed remedy may not widen access past the device it found."""
    root = tmp_path / "remedy"
    _add_node(root, "hidraw6", FIDO_RDESC, UNREACHABLE)
    out = _run(root)[1]
    assert "sudo chown" in out, out
    assert "hidraw6" in out, out
    assert "udev" not in out.replace("needs no udev rule", ""), out


def test_bus_wide_grant_strings_are_gone_from_the_installer() -> None:
    """AC2: no group-and-mode rule for every hidraw node remains anywhere in the file."""
    src = _src()
    assert 'MODE="0660", GROUP="plugdev"' not in src
    assert "plugdev" not in src
    assert 'KERNEL=="hidraw*"' not in src
    assert "60-fido2.rules" not in src
    assert "usermod" not in src


def test_fido_scope_uses_the_usage_page_not_the_device_name() -> None:
    """The classification is the 0xF1D0 usage page; a name-based match is the defect."""
    src = _src()
    block = src[src.index(BEGIN) : src.index(END)]
    assert "report_descriptor" in block
    assert "$'\\x06\\xd0\\xf1'" in block
    assert "for d in /dev/hidraw*" not in src
