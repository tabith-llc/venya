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

The macOS arm is covered by the same fragment with a `uname` stub that answers
Darwin, so the real dispatch runs on a Linux runner. It used to print a two-line
assertion ("FIDO2 on macOS uses IOKit HID — no udev rules or root required")
without reading anything, so a physical macOS run scored the banner and not the
check. It now classifies the IOKit registry the way the Linux arm classifies
sysfs: usage page 0xF1D0, printed by `ioreg -l` in decimal as 61904. The source
is overridable with VENYA_IOREG_FILE (a saved ioreg dump) for exactly this
purpose; the default is the live call.

macOS truth table. Silent: an empty registry, a registry whose only pages are
61440 (0xF000 — the wrong page, which reads 0 with or without a key), a missing
fixture file, no ioreg on PATH at all. Loud: one or more 61904 nodes, counted.
The banner sentence may not appear on any silent path.
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


# --- macOS arm: the same classifier, read out of IOKit -----------------------

# One line of real `ioreg -r -c IOHIDDevice -l` output per device. 61904 is
# 0xF1D0 (FIDO); 61440 is 0xF000, a vendor-defined page that a keyboard answers
# to and that reads 0 whether or not a key is plugged in.
IOREG_FIDO = '  "PrimaryUsagePage" = 61904\n  "PrimaryUsage" = 1\n  "Product" = "Security Key C NFC"\n'
IOREG_WRONG_PAGE = '  "PrimaryUsagePage" = 61440\n  "PrimaryUsage" = 6\n  "Product" = "Keyboard"\n'


def _run_mac(root: Path, ioreg_file: Path | None = None) -> tuple[int, str]:
    """Run the shipped fragment as if on macOS. ioreg_file=None leaves the seam unset,
    so the branch falls back to the live `ioreg`, which does not exist on this runner."""
    root.mkdir(parents=True, exist_ok=True)
    stub = root / "bin"
    stub.mkdir(parents=True, exist_ok=True)
    uname = stub / "uname"
    uname.write_text('#!/bin/sh\n[ "$1" = "-s" ] && echo Darwin\n', encoding="utf-8")
    uname.chmod(0o755)
    script = root / "fido_mac_cell.sh"
    script.write_text(PRELUDE + _fragment(_src()), encoding="utf-8")
    env = {"PATH": f"{stub}:/usr/bin:/bin"}
    if ioreg_file is not None:
        env["VENYA_IOREG_FILE"] = str(ioreg_file)
    proc = subprocess.run(
        ["bash", str(script)],
        capture_output=True,
        text=True,
        env=env,
        timeout=60,
        check=False,
    )
    return proc.returncode, proc.stdout + proc.stderr


def _fixture(root: Path, body: str) -> Path:
    f = root / "ioreg.txt"
    f.parent.mkdir(parents=True, exist_ok=True)
    f.write_text(body, encoding="utf-8")
    return f


def test_macos_no_hid_devices_at_all_is_silent(tmp_path: Path) -> None:
    """The defect this leg fixes: an empty registry must print NOTHING, not reassurance."""
    root = tmp_path / "mac-empty"
    rc, out = _run_mac(root, _fixture(root, ""))
    assert rc == 0, out
    assert out.strip() == "", out
    assert "udev" not in out, out


def test_macos_wrong_usage_page_is_not_reported_as_a_security_key(tmp_path: Path) -> None:
    """The paired negative: 61440 (0xF000) is not 0xF1D0, so a keyboard stays silent."""
    root = tmp_path / "mac-kbd"
    rc, out = _run_mac(root, _fixture(root, IOREG_WRONG_PAGE))
    assert rc == 0, out
    assert out.strip() == "", out


def test_macos_unreadable_ioreg_source_is_silent(tmp_path: Path) -> None:
    """A fixture path that does not exist is the same silence, and does not abort the installer."""
    root = tmp_path / "mac-missing"
    rc, out = _run_mac(root, root / "no-such-dump.txt")
    assert rc == 0, out
    assert out.strip() == "", out


def test_macos_no_ioreg_command_is_silent(tmp_path: Path) -> None:
    """With the seam unset and no ioreg on PATH, the default call fails soft, not loud."""
    rc, out = _run_mac(tmp_path / "mac-nocommand")
    assert rc == 0, out
    assert out.strip() == "", out


def test_macos_fido_key_is_reported_with_its_count(tmp_path: Path) -> None:
    """The good case states what it proved: a FIDO-class node, counted."""
    root = tmp_path / "mac-one"
    rc, out = _run_mac(root, _fixture(root, IOREG_FIDO))
    assert rc == 0, out
    assert "0xF1D0" in out, out
    assert "matched 1 node(s)" in out, out
    assert "[WARN]" not in out, out


def test_macos_two_fido_nodes_are_both_counted(tmp_path: Path) -> None:
    """Positive with a different cardinality, so the count is not a fixed string."""
    root = tmp_path / "mac-two"
    rc, out = _run_mac(root, _fixture(root, IOREG_FIDO + IOREG_WRONG_PAGE + IOREG_FIDO))
    assert rc == 0, out
    assert "matched 2 node(s)" in out, out
    assert "Keyboard" not in out, out


def test_macos_arm_ignores_the_linux_hidraw_seams(tmp_path: Path) -> None:
    """Dispatch is real: on Linux the macOS fixture must not be consulted."""
    root = tmp_path / "linux-not-mac"
    root.mkdir(parents=True, exist_ok=True)
    script = root / "fido_cell.sh"
    script.write_text(PRELUDE + _fragment(_src()), encoding="utf-8")
    proc = subprocess.run(
        ["bash", str(script)],
        capture_output=True,
        text=True,
        env={
            "PATH": "/usr/bin:/bin",
            "VENYA_IOREG_FILE": str(_fixture(root, IOREG_FIDO)),
            "VENYA_HIDRAW_CLASS_DIR": str(root / "no-such-class-dir"),
            "VENYA_HIDRAW_DEV_DIR": str(root / "no-such-dev"),
        },
        timeout=60,
        check=False,
    )
    out = proc.stdout + proc.stderr
    assert proc.returncode == 0, out
    assert out.strip() == "", out


def test_shipped_installer_reads_the_ioreg_registry() -> None:
    """The state that made a physical macOS run meaningless was `grep -c ioreg` == 0."""
    src = _src()
    block = src[src.index(BEGIN) : src.index(END)]
    assert src.count("ioreg") >= 1
    assert "ioreg -r -c IOHIDDevice -l" in block
    assert "61904" in block
    assert "FIDO2 on macOS uses IOKit HID" not in src, "the unconditional banner is back"


def test_linux_arm_keeps_its_own_seams(tmp_path: Path) -> None:
    """Guard against a unifying refactor: the four booked Linux arms keep their roots."""
    block = _fragment(_src())
    assert "VENYA_HIDRAW_CLASS_DIR" in block
    assert "VENYA_HIDRAW_DEV_DIR" in block
    assert "$'\\x06\\xd0\\xf1'" in block
