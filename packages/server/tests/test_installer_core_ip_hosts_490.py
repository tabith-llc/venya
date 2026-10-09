# Copyright (c) 2026 Tabith LLC.
# Use of this source code is governed by the Business Source License 1.1
# included in the LICENSE file at the root of this repository. As of the
# Change Date listed there, the work is available under MPL 2.0.
# SPDX-License-Identifier: BUSL-1.1

"""#490 validated core IP + field-based hosts edit — installer cells.

``install-venya-executor.sh`` wrote an operator-supplied ``VENYA_CORE_IP`` into
the hosts file as root with no validation, and deleted the incumbent entry with
``sed -i "/ ${CORE_HOSTNAME}$/d"`` after reading it with
``grep " ${CORE_HOSTNAME}$"``. Both halves interpolate an operator value into
PATTERN syntax: a ``/`` (a sed delimiter) in a hostname derived from the
operator's own ``VENYA_SERVER_URL`` aborted the install mid-run, a ``.`` or ``*``
matched rows the operator never named (an unrelated host mapping deleted), and an
IP carrying a space or a newline wrote EXTRA host mappings into a file every
process on the machine reads.

Ruled shape (``wave12-specs-20261008/s77-ruling-490-recon.md`` R1-R8): read and
delete are ONE defect class (R1); both move to a whitespace-separated FIELD 2
equality test in awk, no sed on hosts lines, every other line byte-preserving
(R2); ``VENYA_CORE_IP`` is gated by ``_venya_valid_ipv4`` ALONE — no second
injection guard (R3); ``VENYA_HOSTS_FILE`` is the test seam, default
``/etc/hosts`` (R4); a supplied value that is not a bare IPv4 HARD-FAILS (R5).

R3's interlock: the validator alone is sufficient only because #491 landed (the
glob false-accept fix, dev commit ``fdaad66``). The wildcard cell below re-proves
that half through the installer's own gate, in a directory holding a file named
``4`` — a pre-#491 validator accepts ``1.2.3.*`` there and writes it.

Cells run the REAL block, extracted from the git-tracked installer and sourced by
a harness that supplies the helpers it calls (the #491/#505/#519 precedent:
extract and execute, never re-implement) against a fixture hosts file. No VMs, no
root, and the real ``/etc/hosts`` is never a target.
"""

import os
import re
import subprocess
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[3]
INSTALLER = REPO_ROOT / "install-venya-executor.sh"
COMMON = REPO_ROOT / "venya-common.sh"
DOC_REF = REPO_ROOT / "docs" / "installation.md"

# Extraction anchors (both unique in the script — asserted in _block_source).
BEGIN = "# Ensure the core hostname is resolvable"
END = "# --- Install Venya CA into system trust store"

# RFC 5737 documentation ranges only: the tree-wide RFC1918 guard in
# executor/tests/test_installer_no_private_literals.py scans packages/ and docs/
# and rejects private-range literals anywhere in the tree.
CORE_IP = "198.51.100.53"
INCUMBENT_IP = "192.0.2.9"
ALIAS_IP = "203.0.113.7"

BASE_HOSTS = (
    "127.0.0.1 localhost\n"
    "::1 localhost ip6-localhost\n"
    "# a comment line naming venya-core-1 must survive\n"
    f"{ALIAS_IP} venya-core-10\n"
    f"{INCUMBENT_IP} venya-core-1\n"
)

# Operator-supplied values that every one of which the base commit wrote into the
# hosts file. Each must now be refused with nothing written.
HOSTILE_IPS = [
    "1.2.3.4 5.6.7.8",  # space form — two addresses on one row
    "1.2.3.4;rm",  # shell metacharacter
    "1.2.3.4$(id)",
    "1.2.3.4`id`",
    "1.2.3.4\n5.6.7.8 venya-core-9",  # newline — an EXTRA host mapping
    "1.2.3.4\r",
    "1.2.3.*/",
    "not-an-ip",
    "1.2.3",
    "1.2.3.4.5",
    "1.2.3.256",
]

# The value interpolated into the old grep/sed pattern. CORE_HOSTNAME is
# injection-guarded against quote/backslash/space (installer :342) but NOT
# against / . * [ ] & $ — and it is derived from the operator's own
# VENYA_SERVER_URL host component, so these are reachable values.
PATTERN_UNSAFE_HOSTS = [
    "venya-core/1",
    "venya-core.1",
    "venya-core-1*",
    "venya-core-1[0]",
    "venya-core-1&",
    "venya-core-1$",
]


def _installer_source() -> str:
    return INSTALLER.read_text(encoding="utf-8")


def _header_source() -> str:
    """The script's own env-var header block (everything before the first call)."""
    src = _installer_source()
    return src[: src.index("venya_print_colors")]


def _block_source() -> str:
    """Lift the real core-entries block out of the git-tracked installer."""
    src = _installer_source()
    assert src.count(BEGIN) == 1, "block start anchor no longer unique — re-anchor"
    assert src.count(END) == 1, "block end anchor no longer unique — re-anchor"
    start = src.index(BEGIN)
    block = src[start : src.index(END, start)]
    # Guard: if the seam ever moves out of the extracted region, a cell would aim
    # at the real /etc/hosts. Fail here, never there.
    assert "VENYA_HOSTS_FILE" in block, "the seam moved out of the extracted block"
    return block


def _code_lines(block: str) -> str:
    """The block with comment lines dropped — pins must read code, not prose."""
    return "\n".join(l for l in block.splitlines() if not l.lstrip().startswith("#"))


def _fixture_dirs(tmp_path: Path) -> tuple[Path, Path]:
    """An empty directory and the #491 hostile one (holds a file named ``4``)."""
    empty = tmp_path / "cwd_empty"
    empty.mkdir()
    hostile = tmp_path / "cwd_hostile"
    hostile.mkdir()
    (hostile / "4").write_text("")
    return empty, hostile


def _run_block(
    tmp_path: Path,
    *,
    hosts_text: str,
    core_hostname: str = "venya-core-1",
    core_ip: str | None = CORE_IP,
    cwd: Path | None = None,
) -> subprocess.CompletedProcess:
    """Execute the extracted block against a fixture hosts file.

    Values travel as ENV, never as interpolated script text — the point of the
    negative cells is that hostile bytes reach the shipped code unchanged. The
    library is sourced for the log helpers and the REAL ``_venya_valid_ipv4``
    (its top level is pure function definitions, a premise the #519 cell guards).
    """
    block_path = tmp_path / "core_hosts_block.sh"
    block_path.write_text(_block_source(), encoding="utf-8")

    hosts = tmp_path / "hosts"
    hosts.write_text(hosts_text, encoding="utf-8")

    harness = tmp_path / "harness.sh"
    harness.write_text(
        "set -euo pipefail\n"
        f"source {str(COMMON)!r}\n"
        "venya_print_colors\n"
        'CORE_HOSTNAME="${CELL_CORE:?}"\n'
        f". {str(block_path)!r}\n",
        encoding="utf-8",
    )

    env = dict(os.environ)
    env["CELL_CORE"] = core_hostname
    if core_ip is None:
        env.pop("VENYA_CORE_IP", None)
    else:
        env["VENYA_CORE_IP"] = core_ip
    env["VENYA_HOSTS_FILE"] = str(hosts)

    proc = subprocess.run(
        ["bash", str(harness)],
        cwd=str(cwd or tmp_path),
        capture_output=True,
        text=True,
        env=env,
        check=False,
    )
    proc.hosts_path = hosts  # type: ignore[attr-defined]
    return proc


def _hosts(proc: subprocess.CompletedProcess) -> str:
    return proc.hosts_path.read_text(encoding="utf-8")  # type: ignore[attr-defined]


class TestRuledShapePins:
    """Source tripwires for R2/R3/R4/R5 — the pairs for the behaviour cells below."""

    def test_no_sed_and_no_pattern_grep_on_the_hosts_lines(self) -> None:
        code = _code_lines(_block_source())
        assert not re.search(r"\bsed\b", code), "a sed invocation is back on the hosts edit (R2)"
        assert not re.search(r"\bgrep\b", code), "a grep-over-the-whole-line read is back (R2)"
        assert "$CORE_HOSTNAME}$" not in code, "the hostname is being interpolated into an anchored pattern"

    def test_read_and_delete_are_field_two_equality(self) -> None:
        """R2: FIELD 2 equality on BOTH halves, comments exempt on BOTH halves, and a
        single seam default."""
        block = _block_source()
        assert "$2 == host" in block, "the field-based read is gone"
        assert "$2 != host" in block, "the field-based delete is gone"
        assert block.count('substr($1, 1, 1) != "#"') == 1, (
            "the read must skip hosts(5) comments — a comment naming the hostname is not "
            "an entry, and reading it as one makes `#` the incumbent IP"
        )
        assert (
            block.count('substr($1, 1, 1) == "#"') == 1
        ), "the delete must KEEP comment lines — the same guard on the other half (R2)"
        assert block.count("HOSTS_FILE=") == 1, "the seam assignment duplicated"

    def test_append_lands_on_its_own_line(self) -> None:
        """The ruled nuance, pinned in code: a hosts file whose last line has no
        trailing newline is given exactly the ONE newline it lacks before an append,
        so the new row is never concatenated onto the incumbent row."""
        block = _block_source()
        assert 'tail -c 1 "$HOSTS_FILE"' in block, "the trailing-newline guard is gone"
        assert _code_lines(block).count("printf '%s\\n'") == 2, "both writes must be printf, not echo"

    def test_seam_default_is_the_system_hosts_file(self) -> None:
        assert 'HOSTS_FILE="${VENYA_HOSTS_FILE:-/etc/hosts}"' in _block_source()

    def test_gate_is_the_validator_alone(self) -> None:
        """R3: no second injection check on VENYA_CORE_IP — the validator subsumes it."""
        code = _code_lines(_block_source())
        assert "_venya_valid_ipv4" in code, "the validator gate is gone"
        assert "venya_guard_injection" not in code, (
            "an injection guard appeared in the hosts block: R3 rules the validator ALONE, "
            "and a check with no reachable fail path is ceremonial code"
        )

    def test_refused_value_is_not_echoed_back(self, tmp_path: Path) -> None:
        """R5 names the knob; replaying the hostile value into the terminal the operator
        reads would re-inject it (that is the class this ticket closes)."""
        marker = "490-MARKER-INJECT"
        proc = _run_block(tmp_path, hosts_text=BASE_HOSTS, core_ip=f"1.2.3.4\n{marker}")
        assert proc.returncode != 0
        assert marker not in proc.stdout, f"the refused value was echoed: {proc.stdout!r}"


class TestPositiveCells:
    def test_matching_entry_is_left_alone(self, tmp_path: Path) -> None:
        """Valid IP + an entry that already carries it: the file is not rewritten."""
        hosts_text = BASE_HOSTS.replace(f"{INCUMBENT_IP} venya-core-1", f"{CORE_IP} venya-core-1")
        proc = _run_block(tmp_path, hosts_text=hosts_text, core_ip=CORE_IP)
        assert proc.returncode == 0, proc.stdout + proc.stderr
        assert _hosts(proc) == hosts_text, "the file changed although the entry already matched"
        assert "matches VENYA_CORE_IP" in proc.stdout

    def test_differing_entry_replaced_everything_else_byte_identical(self, tmp_path: Path) -> None:
        """R2 byte-preservation, asserted on the WHOLE file: the incumbent row is
        replaced in place, and the comments, the localhost rows and the
        ``venya-core-10`` alias line are byte-identical."""
        proc = _run_block(tmp_path, hosts_text=BASE_HOSTS, core_ip=CORE_IP)
        assert proc.returncode == 0, proc.stdout + proc.stderr
        expected = BASE_HOSTS.replace(f"{INCUMBENT_IP} venya-core-1\n", f"{CORE_IP} venya-core-1\n")
        assert _hosts(proc) == expected
        assert "venya-core-10" in _hosts(proc), "the alias row was deleted — substring matching is back"
        assert "# a comment line naming venya-core-1 must survive" in _hosts(proc)

    def test_no_entry_appends(self, tmp_path: Path) -> None:
        """Valid IP + no field-2 match: exactly one row appended, nothing else moved."""
        hosts_text = BASE_HOSTS.replace(f"{INCUMBENT_IP} venya-core-1\n", "")
        proc = _run_block(tmp_path, hosts_text=hosts_text, core_ip=CORE_IP)
        assert proc.returncode == 0, proc.stdout + proc.stderr
        assert _hosts(proc) == hosts_text + f"{CORE_IP} venya-core-1\n"
        assert "Adding venya-core-1" in proc.stdout

    def test_append_onto_a_file_without_trailing_newline(self, tmp_path: Path) -> None:
        """The ruled awk nuance, made explicit: a hosts file whose last line has no
        newline gains exactly ONE newline in total, so the appended row can never be
        concatenated onto the incumbent line (which is what a blind ``>>`` does)."""
        hosts_text = f"127.0.0.1 localhost\n{ALIAS_IP} otherhost"
        proc = _run_block(tmp_path, hosts_text=hosts_text, core_ip=CORE_IP)
        assert proc.returncode == 0, proc.stdout + proc.stderr
        assert _hosts(proc) == f"127.0.0.1 localhost\n{ALIAS_IP} otherhost\n{CORE_IP} venya-core-1\n"

    def test_comment_naming_the_host_is_not_an_entry(self, tmp_path: Path) -> None:
        """hosts(5) comments are not mappings. A file whose ONLY mention of the name is
        a comment must (a) not be read as an incumbent entry — else the value `#` is
        compared against the IP and the installer believes the row exists — and
        (b) keep the comment byte-identical while appending the real row."""
        hosts_text = "127.0.0.1 localhost\n# venya-core-1 provisioning note\n"
        proc = _run_block(tmp_path, hosts_text=hosts_text, core_ip=CORE_IP)
        assert proc.returncode == 0, proc.stdout + proc.stderr
        assert (
            _hosts(proc) == hosts_text + f"{CORE_IP} venya-core-1\n"
        ), f"the comment was read as an entry or rewritten:\n{_hosts(proc)}"
        assert "Adding venya-core-1" in proc.stdout

    def test_provisioned_entry_kept_when_no_ip_supplied(self, tmp_path: Path) -> None:
        """Precedence 2 stays true: no explicit IP + a provisioned entry -> KEEP it."""
        proc = _run_block(tmp_path, hosts_text=BASE_HOSTS, core_ip=None)
        assert proc.returncode == 0, proc.stdout + proc.stderr
        assert _hosts(proc) == BASE_HOSTS, "the provisioned entry was touched with no explicit IP"
        assert "Using provisioned" in proc.stdout


class TestNegativeHostileIpValues:
    @pytest.mark.parametrize("bad_ip", HOSTILE_IPS)
    def test_hostile_value_refused_and_nothing_written(self, tmp_path: Path, bad_ip: str) -> None:
        """R5: an operator who SUPPLIES a bad value is refused — hard-fail, no coercion,
        no skip, and the file stays byte-identical. RED at the base commit, where every
        one of these was written into the hosts file."""
        proc = _run_block(tmp_path, hosts_text=BASE_HOSTS, core_ip=bad_ip)
        assert (
            proc.returncode != 0
        ), f"{bad_ip!r} was ACCEPTED (rc=0) — the unvalidated write is back. File now:\n{_hosts(proc)}"
        assert _hosts(proc) == BASE_HOSTS, f"{bad_ip!r} reached the hosts file:\n{_hosts(proc)}"
        assert "VENYA_CORE_IP" in proc.stdout, f"{bad_ip!r} refused without naming the knob"

    @pytest.mark.parametrize("bad_ip", HOSTILE_IPS)
    def test_refusal_carries_an_actionable_remedy(self, tmp_path: Path, bad_ip: str) -> None:
        """R5: named AND actionable — the operator is told what a valid value looks like."""
        proc = _run_block(tmp_path, hosts_text=BASE_HOSTS, core_ip=bad_ip)
        assert "bare IPv4" in proc.stdout, f"{bad_ip!r}: not actionable: {proc.stdout!r}"

    def test_wildcard_octet_refused_in_both_directories(self, tmp_path: Path) -> None:
        """The #491 interlock half, through the installer's own gate: ``1.2.3.*`` is
        refused in a directory holding a file named ``4`` exactly as in an empty one.
        Against a pre-#491 validator THIS is the cell that fails in the hostile
        directory only — the false accept would then reach the hosts file."""
        empty, hostile = _fixture_dirs(tmp_path)
        text = BASE_HOSTS.replace(f"{INCUMBENT_IP} venya-core-1\n", "")
        got = {}
        for d in (empty, hostile):
            proc = _run_block(d, hosts_text=text, core_ip="1.2.3.*", cwd=d)
            got[d.name] = (proc.returncode != 0, _hosts(proc) == text)
        assert got == {"cwd_empty": (True, True), "cwd_hostile": (True, True)}, got

    def test_valid_ip_still_accepted_in_both_directories(self, tmp_path: Path) -> None:
        """Paired positive: the gate refuses wildcards without also refusing real
        addresses in the same directories."""
        empty, hostile = _fixture_dirs(tmp_path)
        for d in (empty, hostile):
            proc = _run_block(d, hosts_text=BASE_HOSTS, core_ip=CORE_IP, cwd=d)
            assert proc.returncode == 0, f"{d.name}: {proc.stdout}{proc.stderr}"


class TestPatternUnsafeHostnames:
    """R1/R2, hostname half: the value the old grep/sed pattern was built from."""

    @pytest.mark.parametrize("host", PATTERN_UNSAFE_HOSTS)
    def test_delete_does_not_abort_and_removes_only_the_named_row(self, tmp_path: Path, host: str) -> None:
        """The `/` case killed sed at the base commit (`unknown command`) and the `.`
        case matched the decoy row; here the install completes and only the exact
        field-2 row moves."""
        hosts_text = (
            "127.0.0.1 localhost\n"
            "# comment\n"
            f"{ALIAS_IP} venya-coreX1\n"  # the '.' decoy the old regex matched
            f"{ALIAS_IP} {host}-suffix\n"
            f"{INCUMBENT_IP} {host}\n"
        )
        proc = _run_block(tmp_path, hosts_text=hosts_text, core_hostname=host, core_ip=CORE_IP)
        assert proc.returncode == 0, f"host={host!r} aborted the install:\n{proc.stdout}{proc.stderr}"
        expected = hosts_text.replace(f"{INCUMBENT_IP} {host}\n", f"{CORE_IP} {host}\n")
        assert _hosts(proc) == expected, f"host={host!r}: other rows moved\nGOT:\n{_hosts(proc)}\nWANT:\n{expected}"

    def test_field_two_substring_and_alias_rows_survive(self, tmp_path: Path) -> None:
        """The paired negative that catches a substring filter (R2). Rows whose field 2
        CONTAINS the name, ENDS WITH the name, and a row where the name sits in field 3
        as an alias, all survive — only the exact field-2 match is removed."""
        host = "venya-core-1"
        hosts_text = (
            "127.0.0.1 localhost\n"
            "# venya-core-1 in a comment\n"
            "203.0.113.8 other venya-core-1\n"
            "203.0.113.9 venya-core-10\n"
            "203.0.113.10 xvenya-core-1\n"
            f"{INCUMBENT_IP} {host}\n"
        )
        proc = _run_block(tmp_path, hosts_text=hosts_text, core_hostname=host, core_ip=CORE_IP)
        assert proc.returncode == 0, proc.stdout + proc.stderr
        expected = hosts_text.replace(f"{INCUMBENT_IP} {host}\n", f"{CORE_IP} {host}\n")
        assert _hosts(proc) == expected
        kept = _hosts(proc)
        for survivor in ("203.0.113.8 other venya-core-1", "203.0.113.9 venya-core-10", "203.0.113.10 xvenya-core-1"):
            assert survivor in kept, f"{survivor} was deleted — the filter is not field-2 equality"

    def test_duplicate_primary_rows_all_removed(self, tmp_path: Path) -> None:
        """Every exact field-2 match goes (the deleted `sed /…/d` removed all matches
        too), then one validated row is written — no duplicate survives the update."""
        host = "venya-core-1"
        hosts_text = f"127.0.0.1 localhost\n{ALIAS_IP} {host}\n{INCUMBENT_IP} {host}\n"
        proc = _run_block(tmp_path, hosts_text=hosts_text, core_hostname=host, core_ip=CORE_IP)
        assert proc.returncode == 0, proc.stdout + proc.stderr
        assert _hosts(proc) == f"127.0.0.1 localhost\n{CORE_IP} {host}\n"


class TestRemedyHintsAndDocs:
    """R6 plus the R4 consequence: shipped advice and the env-var reference."""

    def test_no_hint_teaches_a_blind_append(self) -> None:
        src = _installer_source()
        assert 'echo \\"<executor-ip>' not in src, (
            "a remedy hint still teaches a blind `echo >> /etc/hosts` append — "
            "advice that contradicts the shipped replace-the-row mechanism"
        )

    def test_remedy_hints_state_the_field_two_shape(self) -> None:
        """R6 names four sites (installer :476, :547, :553, :826-827)."""
        src = _installer_source()
        assert (
            src.count("SECOND field") >= 4
        ), f"expected the aligned advice at the four R6 sites, found {src.count('SECOND field')}"

    def test_venya_hosts_file_documented_in_the_env_reference(self) -> None:
        """R4 consequence: a seam that is not documented is config drift."""
        assert "VENYA_HOSTS_FILE" in DOC_REF.read_text(
            encoding="utf-8"
        ), "VENYA_HOSTS_FILE is missing from docs/installation.md"
        assert (
            "VENYA_HOSTS_FILE" in _header_source()
        ), "VENYA_HOSTS_FILE is missing from the installer's own header block"

    def test_venya_core_ip_header_states_the_validated_shape(self) -> None:
        header = _header_source()
        assert (
            "STRICT" in header and "dot-separated" in header
        ), "the VENYA_CORE_IP header entry does not state the validated shape"


def test_bash_syntax_clean() -> None:
    proc = subprocess.run(["bash", "-n", str(INSTALLER)], capture_output=True, text=True, check=False)
    assert proc.returncode == 0, proc.stdout + proc.stderr
