# Copyright (c) 2026 Tabith LLC.
# Use of this source code is governed by the Business Source License 1.1
# included in the LICENSE file at the root of this repository. As of the
# Change Date listed there, the work is available under MPL 2.0.
# SPDX-License-Identifier: BUSL-1.1

"""#746 — an unattended executor re-run refuses to change the executor's identity.

``install-venya-executor.sh`` derives ``EXECUTOR_ID`` from ``hostname`` when the operator
named nothing, and the config writer rebuilds ``/etc/venya/executor.toml`` through a
truncating redirect with no copy of the previous face kept anywhere in the script. The
unattended branch printed the value it had CHOSEN and never the value it was about to
overwrite, so a re-run to pick up a new build could hand this executor a new relay dial
hostname and client-cert SAN, and the only record of the old one was the file it had just
destroyed.

The ruled shape is a refusal, not a carry-forward: an unattended run (skip flag, or no
terminal) whose derived id differs from the installed one exits non-zero, names both
values, and writes nothing. Reuse-the-stored-id was refused because #738 AC2 names
``server_url``, ``executor_id``, ``ca_bundle`` and ``[mtls]`` as installer-authoritative,
and making the stored id win would delete a name from that list — weakening a check. So
these cells pin both halves: the stop, and the fact that a re-run which DOES write takes
the installer's value for all four keys.

Harness: the #745 module's idiom — lift the REAL region out of the installer between
unique anchors and run it against PATH stubs in a tmpdir (``hostname`` answers the derived
name), with the toml path rebased into the tmpdir. No VM, no sudo, no install, nothing
outside the tmpdir. Order is pinned against the source the operator actually runs.

Truth table: differing derived id + unattended -> rc 1, both values named, incumbent bytes
untouched, and the stop sits before the first write to the host. Paired negatives: equal id
-> completes; operator-named id that differs -> honoured, not refused; no incumbent file
(fresh install) -> completes; incumbent with no readable id -> completes (a rebuild is the
installer's job, and refusing there would block a recovery re-run); interactive + differing
id -> warned, not stopped, exactly as #745 left it.
"""

import os
import pty
import subprocess
from pathlib import Path

from tests.test_installer_dial_contract_order_745 import (
    FIRST_WRITE,
    _region,
    _source,
)

GATE_HEADER = "# --- Re-run identity stop (#746) ---"
# The config writer's truncating redirect — the line the stop exists to make unreachable.
TOML_REDIRECT = "} > /etc/venya/executor.toml"
WRITER_FIRST_LINE = """printf 'server_url = "%s"\\n' "$SERVER_URL\""""

STORED_ID = "installed-executor-name"
DERIVED_ID = "exec-hostname-changed"

_PRELUDE = (
    "set -uo pipefail\n"
    'info()  { echo "[INFO] $*"; }\n'
    'warn()  { echo "[WARN] $*"; }\n'
    'error() { echo "[ERROR] $*"; }\n'
    'EXECUTOR_ID="__DERIVED__"\n'
)
_END = 'echo "REACHED_END=1"\n'


def _gate(tmp_path: Path, derived: str = DERIVED_ID, incumbent: str | None = STORED_ID) -> tuple[str, Path]:
    """The real gate block with its toml path rebased into `tmp_path`, plus the file."""
    block = _region(_source(), GATE_HEADER, "\nfi\n").replace(
        "/etc/venya/executor.toml", str(tmp_path / "executor.toml")
    )
    toml = tmp_path / "executor.toml"
    if incumbent is not None:
        toml.write_text(f'executor_id = "{incumbent}"\nlog_level = "info"\n', encoding="utf-8")
    return _PRELUDE.replace("__DERIVED__", derived) + block + "\n" + _END, toml


def _exec_script(script: str, tmp_path: Path, env: dict, tty: bool = False) -> subprocess.CompletedProcess:
    """Run `script` with stdin on a pipe (no terminal) or on a pty slave (terminal) — the
    two shapes the gate branches on. Feeding then closing the master is what makes the tty
    case deterministic (the #396 uninstaller-harness idiom)."""
    path = tmp_path / "run.sh"
    path.write_text(script, encoding="utf-8")
    argv = ["/bin/bash", str(path)]
    if not tty:
        return subprocess.run(
            argv, env=env, capture_output=True, text=True, check=False, timeout=60, stdin=subprocess.DEVNULL
        )
    master, slave = pty.openpty()
    try:
        proc = subprocess.Popen(argv, stdin=slave, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, env=env)
        os.close(slave)
        out = proc.communicate(timeout=60)[0]
    finally:
        os.close(master)
    return subprocess.CompletedProcess(argv, proc.returncode, out, "")


def _env(tmp_path: Path, **extra: str) -> dict:
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir(exist_ok=True)
    host = bin_dir / "hostname"
    host.write_text(f'#!/bin/bash\nprintf "{DERIVED_ID}\\n"\n', encoding="utf-8")
    host.chmod(0o755)
    return {"PATH": f"{bin_dir}:/usr/bin:/bin", "HOME": str(tmp_path), **extra}


class TestTheStop:
    """AC1 — executed: refuse, name both values, write nothing."""

    def test_unattended_rerun_with_a_changed_id_refuses_and_names_both(self, tmp_path):
        script, _toml = _gate(tmp_path)
        proc = _exec_script(script, tmp_path, _env(tmp_path, VENYA_SKIP_PROMPT="yes"))
        assert proc.returncode != 0, f"the stop did not fire: rc={proc.returncode} {proc.stdout}"
        assert "REACHED_END=1" not in proc.stdout, proc.stdout
        assert STORED_ID in proc.stdout, f"the installed value is not named: {proc.stdout}"
        assert DERIVED_ID in proc.stdout, f"the value this run would write is not named: {proc.stdout}"

    def test_the_piped_non_tty_run_refuses_with_no_flag_at_all(self, tmp_path):
        """A `curl | sudo bash` install is the shape that carries no terminal; the skip flag
        is not needed to make it unattended, so it cannot be the only arm."""
        script, _toml = _gate(tmp_path)
        proc = _exec_script(script, tmp_path, _env(tmp_path))
        assert proc.returncode != 0, proc.stdout
        assert STORED_ID in proc.stdout and DERIVED_ID in proc.stdout, proc.stdout

    def test_nothing_is_written_to_the_incumbent_file(self, tmp_path):
        script, toml = _gate(tmp_path)
        before = toml.read_bytes()
        proc = _exec_script(script, tmp_path, _env(tmp_path, VENYA_SKIP_PROMPT="yes"))
        assert proc.returncode != 0, proc.stdout
        assert toml.read_bytes() == before, "the refused run modified the config it refused to rewrite"
        assert "writing nothing" in proc.stdout, proc.stdout

    def test_the_refusal_names_the_two_ways_to_consent(self, tmp_path):
        """The remedy has to be actionable from the refusal alone: the operator reads the two
        names and the two ways to consent to one of them."""
        script, _toml = _gate(tmp_path)
        proc = _exec_script(script, tmp_path, _env(tmp_path, VENYA_SKIP_PROMPT="yes"))
        assert "VENYA_EXECUTOR_ID='" + STORED_ID + "'" in proc.stdout, proc.stdout
        assert "VENYA_EXECUTOR_ID='" + DERIVED_ID + "'" in proc.stdout, proc.stdout

    def test_the_stop_precedes_the_first_write_to_the_host(self):
        """Order pin against the shipped source: the refusal cannot be a post-mortem. The
        pre-#746 file had no line between the guards and this stop, so this reddens on the
        old face by having nothing to compare."""
        src = _source()
        assert src.count(GATE_HEADER) == 1, "the stop is missing or duplicated"
        stop = src.index(GATE_HEADER)
        assert src.count(TOML_REDIRECT) == 1, f"the writer redirect is no longer unique: {src.count(TOML_REDIRECT)}"
        assert stop < src.index(TOML_REDIRECT), "the stop sits after the truncating write it exists to prevent"
        assert stop < src.index(FIRST_WRITE), "the stop sits after the first write to the host"

    def test_the_guarded_value_is_the_final_one(self):
        """The injection gate still runs on the value before any comparison or write, and the
        stop runs after it — so the refused string and the written string are the same one."""
        src = _source()
        assert src.index('venya_guard_injection "EXECUTOR_ID"') < src.index(GATE_HEADER)


class TestThePairedNegatives:
    """AC2 — the arms that must still complete, exactly as before."""

    def test_equal_id_completes(self, tmp_path):
        script, _toml = _gate(tmp_path, derived=STORED_ID, incumbent=STORED_ID)
        proc = _exec_script(script, tmp_path, _env(tmp_path, VENYA_SKIP_PROMPT="yes"))
        assert proc.returncode == 0, proc.stdout
        assert "REACHED_END=1" in proc.stdout, proc.stdout
        assert "[ERROR]" not in proc.stdout, proc.stdout

    def test_operator_named_id_is_never_refused(self, tmp_path):
        """Naming an id IS the consent, so the differing value is honoured, not stopped."""
        script, _toml = _gate(tmp_path)
        env = _env(tmp_path, VENYA_SKIP_PROMPT="yes", VENYA_EXECUTOR_ID="named-by-operator")
        proc = _exec_script(script, tmp_path, env)
        assert proc.returncode == 0, proc.stdout
        assert "REACHED_END=1" in proc.stdout, proc.stdout

    def test_a_fresh_install_with_no_incumbent_file_completes(self, tmp_path):
        script, toml = _gate(tmp_path, incumbent=None)
        proc = _exec_script(script, tmp_path, _env(tmp_path, VENYA_SKIP_PROMPT="yes"))
        assert proc.returncode == 0, proc.stdout
        assert "REACHED_END=1" in proc.stdout, proc.stdout
        assert not toml.exists(), "the gate created a file it only reads"

    def test_an_unreadable_incumbent_is_not_a_refusal(self, tmp_path):
        """Deliberate scope, pinned so it cannot drift quietly: a file with no readable
        executor_id does not stop the run — that rebuild is the installer's ordinary job, and
        refusing it would block the recovery path this operator needs."""
        script, _toml = _gate(tmp_path, incumbent=None)
        (tmp_path / "executor.toml").write_text('log_level = "info"\n', encoding="utf-8")
        proc = _exec_script(script, tmp_path, _env(tmp_path, VENYA_SKIP_PROMPT="yes"))
        assert proc.returncode == 0, proc.stdout
        assert "REACHED_END=1" in proc.stdout, proc.stdout

    def test_only_the_first_stored_line_is_read(self, tmp_path):
        """`head -1` is the house reader (`venya-common.sh`, the dns_resolver reuse). A file
        carrying two id lines is compared against the first, never against a concatenation."""
        script, _toml = _gate(tmp_path, incumbent=None)
        (tmp_path / "executor.toml").write_text(
            f'executor_id = "{STORED_ID}"\nexecutor_id = "second-line-name"\n', encoding="utf-8"
        )
        proc = _exec_script(script, tmp_path, _env(tmp_path, VENYA_SKIP_PROMPT="yes"))
        assert proc.returncode != 0, proc.stdout
        assert STORED_ID in proc.stdout, proc.stdout
        assert "second-line-name" not in proc.stdout, proc.stdout

    def test_interactive_run_is_warned_and_not_stopped(self, tmp_path):
        """The #745 confirmation is left exactly as landed: a human at a terminal is told what
        the re-run changes and the run carries on. A stop here would be a second gate the
        ruling did not ask for."""
        script, _toml = _gate(tmp_path)
        proc = _exec_script(script, tmp_path, _env(tmp_path), tty=True)
        assert proc.returncode == 0, proc.stdout
        assert "REACHED_END=1" in proc.stdout, proc.stdout
        assert f"'{STORED_ID}' -> '{DERIVED_ID}'" in proc.stdout, proc.stdout
        assert "writing nothing" not in proc.stdout, proc.stdout

    def test_the_745_confirmation_block_is_untouched(self):
        """Nothing in the block the lead told this lane not to soften changed shape: the
        TTY-gated read, its skip-prompt condition, and its unattended sentence all still read
        as #745 landed them."""
        src = _source()
        confirm = src[src.index("# --- Confirm a defaulted executor ID (#745) ---") :]
        window = confirm[: confirm.index(GATE_HEADER)]
        assert 'if [ -z "${VENYA_EXECUTOR_ID:-}" ]' in window, window
        assert '[ -t 0 ] && [ "${VENYA_SKIP_PROMPT:-}" != "yes" ]' in window, window
        assert "Unattended install: executor ID defaults to this host's own name" in window, window
        assert window.count("read -r -p") == 1, "the confirmation gained or lost a read"


class TestTheGuardIsLoadBearing:
    """Deliberate breaks, so no cell above passes because of the harness.

    Each one mutates the REAL lifted block in exactly the way a careless lane could, and the
    mutation asserts its own success — a no-op break would silently 'prove' nothing.
    """

    def _broken(self, tmp_path: Path, kind: str) -> str:
        script, _toml = _gate(tmp_path)
        if kind == "no_exit":
            # the message stays, the refusal goes: both values named, the run carries on.
            broken = script.replace("            exit 1\n", "", 1)
        else:
            # the consent test inverted: a named id is treated as a derived one.
            broken = script.replace('[ -z "${VENYA_EXECUTOR_ID:-}" ]', '[ -n "${VENYA_EXECUTOR_ID:-}" ]', 1)
        assert broken != script, f"the {kind} break did not apply — the proof would be a lie"
        return broken

    def test_naming_both_values_is_not_the_guard(self, tmp_path):
        """With the `exit 1` stripped, the unattended re-run walks past its own refusal — so
        AC1's rc is what the cell tests, not the text."""
        proc = _exec_script(self._broken(tmp_path, "no_exit"), tmp_path, _env(tmp_path, VENYA_SKIP_PROMPT="yes"))
        assert proc.returncode == 0, proc.stdout
        assert "REACHED_END=1" in proc.stdout, proc.stdout
        assert STORED_ID in proc.stdout, "the break also lost the message — the mutation is not the one claimed"

    def test_the_consent_test_is_what_lets_a_named_id_through(self, tmp_path):
        """Invert the 'operator named one' test and the honoured-id arm refuses instead —
        so that arm fails for the reason the ruling gives, not for free."""
        env = _env(tmp_path, VENYA_SKIP_PROMPT="yes", VENYA_EXECUTOR_ID="named-by-operator")
        proc = _exec_script(self._broken(tmp_path, "consent_inverted"), tmp_path, env)
        assert proc.returncode != 0, proc.stdout
        assert "REACHED_END=1" not in proc.stdout, proc.stdout


class TestInstallerAuthoritativeKeysStillWin:
    """AC3's proof that #738 AC2 was not softened.

    #738 AC2 names `server_url`, `executor_id`, `ca_bundle` and `[mtls]` as keys that must
    take the INSTALLER's value after a re-run. Carry-forward was refused precisely because
    implementing it would delete `executor_id` from that list, so this class pins the
    predicate on this tip: a re-run that does write writes the installer's values, and no
    read-back of the stored identity exists anywhere in the script.

    Deliberately NOT pinned here: what happens to a key the installer does NOT own. That is
    #738 AC1's obligation, and a cell asserting the current drop-behaviour would become a
    check the next leg has to weaken.
    """

    INSTALLER_SERVER_URL = "https://core.example:8443"
    INSTALLER_ID = "named-by-operator-new-name"
    INSTALLER_CA_BUNDLE = "/etc/venya/ca-bundle.crt"
    INSTALLER_DNS = "198.51.100.53"
    INSTALLER_CORE_HOST = "venya-core-1"

    def _writer(self, tmp_path: Path, executor_id: str) -> tuple[str, Path]:
        region = _region(_source(), WRITER_FIRST_LINE, TOML_REDIRECT)
        out = tmp_path / "executor.toml"
        prelude = (
            "set -uo pipefail\n"
            f'SERVER_URL="{self.INSTALLER_SERVER_URL}"\n'
            f'EXECUTOR_ID="{executor_id}"\n'
            f'CA_BUNDLE_PATH="{self.INSTALLER_CA_BUNDLE}"\n'
            f'DNS_RESOLVER="{self.INSTALLER_DNS}"\n'
            f'CORE_HOSTNAME="{self.INSTALLER_CORE_HOST}"\n'
            "CA_INSTALLED=true\n"
        )
        script = prelude + "{\n" + region.replace(str(TOML_REDIRECT), f"}} > {out}") + "\necho WROTE=1\n"
        return script, out

    def test_a_writing_rerun_takes_the_installers_value_for_every_named_key(self, tmp_path):
        """The consent path (operator named an id) still lands the installer's four values —
        the stored identity is not carried forward."""
        (tmp_path / "executor.toml").write_text(f'executor_id = "{STORED_ID}"\n', encoding="utf-8")
        script, out = self._writer(tmp_path, self.INSTALLER_ID)
        proc = _exec_script(script, tmp_path, _env(tmp_path))
        assert proc.returncode == 0, proc.stdout + proc.stderr
        assert "WROTE=1" in proc.stdout, proc.stdout
        written = out.read_text(encoding="utf-8")
        assert f'server_url = "{self.INSTALLER_SERVER_URL}"' in written, written
        assert f'executor_id = "{self.INSTALLER_ID}"' in written, written
        assert STORED_ID not in written, f"the stored id survived the write — carry-forward crept in: {written}"
        assert f'ca_bundle = "{self.INSTALLER_CA_BUNDLE}"' in written, written
        assert "[mtls]" in written, written
        assert 'cert = "/etc/venya/executor/executor.crt"' in written, written

    def test_the_config_writer_never_reads_the_incumbent_file(self, tmp_path):
        """Static half: the value written is the variable the guards already validated, so no
        re-run can mix an incumbent line into an installer-owned key."""
        writer = _region(_source(), WRITER_FIRST_LINE, TOML_REDIRECT)
        assert "executor.toml" in writer, "the writer no longer targets the config file by path"
        assert "INSTALLED_EXECUTOR_ID" not in writer, "the identity the gate read is being written back"
        assert "$(sed" not in writer, "the writer grew a read-back of its own file"

    def test_no_carry_forward_assignment_exists_anywhere_in_the_installer(self):
        """Every write to EXECUTOR_ID is one of the three #745 sources: derive from the host,
        the empty-name fallback, or a typed interactive reply. A fourth that reads the stored
        file is the refused shape, and it would break #738 AC2."""
        allowed = {
            'EXECUTOR_ID="${VENYA_EXECUTOR_ID:-$(hostname)}"',
            'EXECUTOR_ID="venya-exec-1"',
            'EXECUTOR_ID="$_executor_id_reply"',
        }
        src = _source()
        lines = [ln.strip() for ln in src.splitlines() if ln.strip().startswith("EXECUTOR_ID=")]
        assert set(lines) <= allowed, f"a new EXECUTOR_ID assignment appeared: {sorted(set(lines) - allowed)}"
        assert 'EXECUTOR_ID="$INSTALLED_EXECUTOR_ID"' not in src, "the gate adopted the identity it read"
        gate = _region(src, GATE_HEADER, "\nfi\n")
        assert src.count("INSTALLED_EXECUTOR_ID") == gate.count(
            "INSTALLED_EXECUTOR_ID"
        ), "the value read from the incumbent file is used outside the gate"
