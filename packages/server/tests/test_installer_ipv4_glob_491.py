# Copyright (c) 2026 Tabith LLC.
# Use of this source code is governed by the Business Source License 1.1
# included in the LICENSE file at the root of this repository. As of the
# Change Date listed there, the work is available under MPL 2.0.
# SPDX-License-Identifier: BUSL-1.1

"""#491 IPv4 validator glob false-accept — CWD-independence cells.

``_venya_valid_ipv4`` in ``venya-common.sh`` split its input with an unquoted
``for o in $ip`` under ``IFS=.``. Bash word-splits AND then pathname-expands
each field, so in a directory that happens to hold a file named ``4`` the
string ``1.2.3.*`` produced the four digit tokens ``1 2 3 4`` and validated.
The same string in an empty directory was correctly rejected — one input, two
verdicts, decided by the working directory. The accepted value is then used
verbatim downstream (the egress allowlist, and the ``VENYA_DNS_RESOLVER``
probe that the #428 placement pin says only a validated address can reach),
so the guard cell here is CWD-INDEPENDENCE: same input, same verdict, hostile
directory and empty directory.

Ruled shape (s77-ruling-491-recon R2/R3): ``IFS=. read -r -a`` plus a quoted
array expansion removes both word splitting and globbing, and an alphabet
guard keeps ``read`` — which stops at the first line — from accepting a
multi-line value the old loop rejected.

Cells run the REAL functions extracted from the git-tracked library (the #505
/#519 precedent: exercise real script logic, never a re-implementation) from
inside fixture directories. No VMs: the fixtures are plain files.
"""

import subprocess
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[3]
COMMON = REPO_ROOT / "venya-common.sh"

# Inputs the validator must accept in every directory (legitimate addresses).
# RFC 5737 documentation ranges only — the tree-wide RFC1918 guard in
# executor/tests/test_installer_no_private_literals.py scans packages/ and
# rejects private-range literals anywhere in the tree.
VALID_INPUTS = [
    "1.2.3.4",
    "198.51.100.53",
    "203.0.113.0",
    "192.0.2.11",
    "0.0.0.0",
    "255.255.255.255",
    "1.2.3.04",
    "1.2.3.255",
]

# Malformed shapes that were rejected before this change and stay rejected.
MALFORMED_INPUTS = [
    "1.2.3",
    "1.2.3.4.5",
    "1.2.3.256",
    "1.2.3.999",
    "1.2.3.04x",
    "1..2.3",
    "",
    "1.2.3.",
    ".1.2.3",
    "1.2.3.-1",
    "a.b.c.d",
]

# Wildcard-octet inputs: rejected outright in an empty directory, and ACCEPTED
# by the old unquoted loop in a directory holding a file named `4`. The false
# accept is the RED half of this file.
WILDCARD_INPUTS = [
    "1.2.3.*",
    "*.*.*.*",
    "1.2.*.*",
    "203.0.113.*",
    "1.2.3.4*",
]

# Inputs whose verdict must not depend on the directory either, and which the
# alphabet guard rejects before any split happens (`read` reads one line only,
# so without that guard a trailing line would slip past the four-octet rule).
MULTILINE_INPUTS = ["1.2.3.4\n5", "1.2.3.4\n5.6.7.8", "1.2.3.4\r"]

ALL_INPUTS = VALID_INPUTS + MALFORMED_INPUTS + WILDCARD_INPUTS + MULTILINE_INPUTS


def _empty_dir(tmp_path: Path) -> Path:
    d = tmp_path / "empty"
    d.mkdir(exist_ok=True)
    return d


def _hostile_dir(tmp_path: Path) -> Path:
    """A directory holding exactly one file named ``4`` — the seed that made
    ``1.2.3.*`` split-and-glob into four digit tokens."""
    d = tmp_path / "hostile"
    d.mkdir(exist_ok=True)
    (d / "4").write_text("")
    return d


def _mixed_dir(tmp_path: Path) -> Path:
    """Digit-named files plus an ordinary one — the shape that used to spin the
    loop over directory entries before the digit guard returned."""
    d = tmp_path / "mixed"
    d.mkdir(exist_ok=True)
    for name in ["1", "2", "3", "4", "5", "6", "7", "8", "README"]:
        (d / name).write_text("")
    return d


def _run(func: str, value: str, cwd: Path) -> subprocess.CompletedProcess:
    """Call a REAL validator function from the git-tracked library.

    Only the library is sourced (its top level is pure function definitions —
    guarded by test_common_lib_still_pure_definitions in the #519 cells); the
    value travels as an argv so nothing here depends on shell quoting, and the
    process runs with the fixture directory as its cwd.
    """
    script = (
        "set -euo pipefail\n" f"source {str(COMMON)!r}\n" f'if {func} "$1"; then echo VALID; else echo INVALID; fi\n'
    )
    return subprocess.run(
        ["bash", "-c", script, "bash", value],
        cwd=str(cwd),
        capture_output=True,
        text=True,
        check=False,
    )


def _verdict(func: str, value: str, cwd: Path) -> str:
    proc = _run(func, value, cwd)
    out = proc.stdout.strip()
    assert out in ("VALID", "INVALID"), (
        f"{func}({value!r}) from {cwd.name} produced no verdict: "
        f"rc={proc.returncode} stdout={proc.stdout!r} stderr={proc.stderr!r}"
    )
    return out


def test_validator_source_shape_pins() -> None:
    """Tripwire for the ruled mechanism: the split must stay a quoted array
    read, and the unquoted expansion that made the verdict directory-dependent
    must not come back. Pair only — the behavioural cells below are the proof."""
    src = COMMON.read_text()
    assert src.count("_venya_valid_ipv4() {") == 1, "validator anchor no longer unique — re-anchor"
    body = src.split("_venya_valid_ipv4() {", 1)[1].split("\n}", 1)[0]
    assert 'IFS=. read -r -a octets <<< "$ip"' in body, "split is no longer the read -a form"
    assert 'for o in "${octets[@]}"' in body, "array iteration is no longer quoted"
    assert "for o in $ip" not in body, "unquoted expansion is back — glob class reopens"
    assert "local IFS=." not in body, "IFS alteration escaped to the function body"


@pytest.mark.parametrize("value", WILDCARD_INPUTS)
def test_wildcard_octet_rejected_in_hostile_dir(tmp_path: Path, value: str) -> None:
    """RED at the parent commit: a directory containing the file ``4`` made the
    wildcard field glob-expand into a digit token and the value validated.
    The verdict must be INVALID there, with nothing on stderr."""
    hostile = _hostile_dir(tmp_path)
    proc = _run("_venya_valid_ipv4", value, hostile)
    assert proc.stdout.strip() == "INVALID", (
        f"{value!r} was accepted in a directory holding a file named 4 — "
        f"the glob false accept is back (stdout={proc.stdout!r})"
    )
    assert proc.stderr == "", f"{value!r} produced noise: {proc.stderr!r}"


@pytest.mark.parametrize("value", ALL_INPUTS)
def test_verdict_is_cwd_independent(tmp_path: Path, value: str) -> None:
    """The guard cell (R5a): one input, one verdict, regardless of what the
    working directory contains. This is what "fixed" means for #491."""
    empty, hostile = _empty_dir(tmp_path), _hostile_dir(tmp_path)
    mixed = _mixed_dir(tmp_path)
    verdicts = {d.name: _verdict("_venya_valid_ipv4", value, d) for d in (empty, hostile, mixed)}
    assert len(set(verdicts.values())) == 1, f"{value!r} verdict depends on the directory: {verdicts}"


@pytest.mark.parametrize("value", VALID_INPUTS)
def test_valid_addresses_still_accept_everywhere(tmp_path: Path, value: str) -> None:
    """AC3 / R5b — no legitimate address loses its verdict on the way."""
    for d in (_empty_dir(tmp_path), _hostile_dir(tmp_path), _mixed_dir(tmp_path)):
        assert _verdict("_venya_valid_ipv4", value, d) == "VALID", f"{value!r} rejected in {d.name}"


@pytest.mark.parametrize("value", MALFORMED_INPUTS)
def test_malformed_shapes_still_reject(tmp_path: Path, value: str) -> None:
    """Paired negatives: the shapes that were rejected before stay rejected, and
    the rejection is silent (no glob noise, no arithmetic complaint)."""
    for d in (_empty_dir(tmp_path), _hostile_dir(tmp_path)):
        proc = _run("_venya_valid_ipv4", value, d)
        assert proc.stdout.strip() == "INVALID", f"{value!r} accepted in {d.name}"
        assert proc.stderr == "", f"{value!r} produced noise in {d.name}: {proc.stderr!r}"


@pytest.mark.parametrize("value", MULTILINE_INPUTS)
def test_multiline_value_is_rejected(tmp_path: Path, value: str) -> None:
    """`read` stops at the first line, so the array form would otherwise see
    four clean octets in ``1.2.3.4\\n...`` where the old loop saw an
    unparseable fifth token. The alphabet guard keeps the VALID set exactly
    where it was."""
    for d in (_empty_dir(tmp_path), _hostile_dir(tmp_path)):
        assert (
            _verdict("_venya_valid_ipv4", value, d) == "INVALID"
        ), f"{value!r} accepted in {d.name} — the multiline class widened the VALID set"


@pytest.mark.parametrize("value", WILDCARD_INPUTS)
def test_rejection_is_silent_among_digit_named_files(tmp_path: Path, value: str) -> None:
    """The original ticket's noise framing, kept as a cell: with digit-named
    files around, the old loop visited directory entries before the digit guard
    returned. No visit, no noise — stderr stays empty either way."""
    proc = _run("_venya_valid_ipv4", value, _mixed_dir(tmp_path))
    assert proc.stdout.strip() == "INVALID", f"{value!r} accepted in the mixed directory"
    assert proc.stderr == "", f"{value!r} produced noise: {proc.stderr!r}"


# Egress entries, checked through the caller. ``x.y.z.*/nn`` reaches the
# validator through the CIDR arm; a bare wildcard entry does not (the hostname
# arm diverts it first), so both arms are covered here.
EGRESS_ENTRIES = ["1.2.3.*/24", "1.2.3.*", "203.0.113.5/24", "1.2.3.4", "198.51.100.0/24"]


@pytest.mark.parametrize("entry", EGRESS_ENTRIES)
def test_egress_entry_verdict_is_cwd_independent(tmp_path: Path, entry: str) -> None:
    """The caller path that feeds /etc/venya/egress-allowlist.txt: at the parent
    commit ``1.2.3.*/24`` was a valid entry in a directory holding ``4`` and an
    invalid one in an empty directory."""
    empty, hostile = _empty_dir(tmp_path), _hostile_dir(tmp_path)
    empty_v = _verdict("venya_validate_egress_entry", entry, empty)
    hostile_v = _verdict("venya_validate_egress_entry", entry, hostile)
    assert empty_v == hostile_v, f"egress entry {entry!r} verdict depends on the directory: {empty_v} vs {hostile_v}"
    if entry in ("1.2.3.*/24", "1.2.3.*"):
        assert empty_v == "INVALID", f"{entry!r} must not be a valid egress entry"
    else:
        assert empty_v == "VALID", f"{entry!r} must stay a valid egress entry"


def test_no_pathname_expansion_left_in_the_library_validator() -> None:
    """R2 rejected the scoped ``set -f`` shape on purpose: the fix removes the
    mechanism instead of suppressing one consequence of it, so nothing in the
    validator may depend on globbing being turned off at the call site."""
    src = COMMON.read_text()
    assert "set -f" not in src, "scoped globbing suppression appeared in the library"
    assert "noglob" not in src, "scoped globbing suppression appeared in the library"
