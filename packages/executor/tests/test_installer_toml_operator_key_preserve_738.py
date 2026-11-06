# Copyright (c) 2026 Tabith LLC.
# Use of this source code is governed by the Business Source License 1.1
# included in the LICENSE file at the root of this repository. As of the
# Change Date listed there, the work is available under MPL 2.0.
# SPDX-License-Identifier: BUSL-1.1

"""#738 — a re-run keeps the executor settings the operator put in ``executor.toml``.

``install-venya-executor.sh`` rebuilt ``/etc/venya/executor.toml`` from its own values
through a truncating redirect, keeping exactly one carried-forward key (``dns_resolver``,
via ``venya_resolve_dns_resolver``). An operator who set ``[executor]
max_concurrent_commands = 4`` — which ``docs/deployment-config.md`` tells them to do, in
the file the precedence table puts ABOVE the environment — lost it on the next re-run,
and the run closed with ``Installation verified successfully``.

The fix is the core plane's idiom, not a second mechanism: capture the lines the installer
does not own before the redirect, re-append them after it, and name what was carried and
what was dropped in the run's output (``install-venya-core.sh``, ``operator-added keys
preserved across re-run``). ``[mtls]`` and ``[audit]`` stay installer-owned end to end —
AC2's paired negative — so an operator key that sits INSIDE one of those tables cannot be
carried without fighting the installer's own value for that table; it is dropped, and named.

Harness: the #745/#746 idiom — lift the REAL region out of the installer between unique
anchors, rebase its paths into a tmpdir, run it against ``set -u``. No VM, no sudo, no
install, nothing outside the tmpdir. One cell goes further and loads the written file
through the shipped ``ExecutorConfig.from_file``, then reads the admission cap the way the
relay listener does, which is the boot-line number the guest showed.

Truth table: incumbent with an operator table -> carried, named, and reloaded as 4;
incumbent with a documented top-level key (``sandbox_memory_mb``) -> parsed at top level,
not inside ``[mtls]`` or ``[audit]``, and the name the run printed agrees with where the
shipped loader parses it; installer-owned keys in the incumbent -> the installer's value
wins, no stale survivor; operator key inside ``[mtls]`` -> dropped and named; second re-run
-> byte-identical (no accumulation); no incumbent file (fresh install) -> nothing carried,
nothing claimed; EnvironmentFile carrier -> operator ``VENYA_`` line survives,
``VENYA_EXECUTOR_KEY_PASSPHRASE`` does not, and the run says so.

**Leg 1060 rework.** The first shape computed the carried lines early and appended them all
at the end, and a non-author peer re-run (leg 1058) caught what TOML then does: a file whose
last line opens a table has no end-of-table, so an appended top-level key parses as a member
of that table, ``extra="ignore"`` drops it, and the run still printed ``Preserved …``. Every
placement cell below therefore joins two things that version kept apart — the label the run
PRINTED and where the shipped LOADER PARSES that label — and one control moves the emission
back to the pre-fix position to prove the join is what catches it.
"""

import subprocess
import tomllib
from pathlib import Path
from types import SimpleNamespace

from executor.config import ExecutorConfig
from executor.relay_listener import RelayListener

REPO_ROOT = Path(__file__).resolve().parents[3]
INSTALLER = REPO_ROOT / "install-venya-executor.sh"

# --- anchors: the two carrier regions, lifted from the shipped bytes ---
TOML_REGION_START = 'MANAGED_TOML_KEYS="server_url'
TOML_WRITER_END = 'info "Executor config written to /etc/venya/executor.toml"'
ENV_REGION_START = 'MANAGED_ENV_KEYS="VENYA_EXECUTOR_KEY_PASSPHRASE"'
ENV_WRITER_END = 'info "Executor key passphrase delivered via /etc/venya/venya-executor.env (0640 root:venya)."'
TOML_REDIRECT = "} > /etc/venya/executor.toml"
ENV_READ_BACK = "PRESERVED_ENV_LINES=$(awk -F="

# The installer's own values, chosen so no substring collides with the incumbent's.
INSTALLER_SERVER_URL = "https://core.example:8443"
INSTALLER_ID = "exec-new-name"
INSTALLER_CA_BUNDLE = "/etc/venya/ca-bundle.crt"
INSTALLER_DNS = "198.51.100.53"
INSTALLER_CORE_HOST = "venya-core-1"
INSTALLER_PASSPHRASE = "installer-new-passphrase"

# An incumbent face: the operator's `[executor]` table and `[network]` table, a stale copy of
# every installer-owned key, and a stray inside the installer-owned `[mtls]` table.
INCUMBENT_TOML = """\
server_url = "https://stale-core:9999"
executor_id = "stale-executor-name"
ca_bundle = "/etc/venya/stale-bundle.crt"
dns_resolver = "198.51.100.99"

[executor]
max_concurrent_commands = 4
allowlist_hosts = [
  "build.example",
  "registry.example",
]

[network]
connect_timeout = 9.5

[mtls]
ca_cert = "/etc/venya/stale/ca.crt"
cert = "/etc/venya/stale/executor.crt"
key = "/etc/venya/stale/executor.key"
operator_stray = true
"""


def _source() -> str:
    return INSTALLER.read_text(encoding="utf-8")


# The carried top-level emission and the table header it must precede, as the shipped bytes
# write them. Both anchors are used to move the emission to the pre-fix position, so a
# break that does not apply cannot silently 'prove' nothing.
TOP_EMIT = (
    '    if [ -n "${PRESERVED_TOML_TOP:-}" ]; then\n'
    "        printf '\\n'\n"
    "        echo '# --- operator-added top-level keys preserved across re-run (installer, #738) ---'\n"
    "        printf '%s\\n' \"$PRESERVED_TOML_TOP\"\n"
    "    fi\n"
)
MTLS_OPEN = "    printf '\\n'\n    printf '[mtls]\\n'\n"

# `sandbox_memory_mb` because docs/deployment-config.md names it as a TOP-LEVEL field whose
# file value wins — the exact promise the append-after-a-table shape falsified.
INCUMBENT_TOP_KEY = """\
server_url = "https://stale-core:9999"
sandbox_memory_mb = 2048

[executor]
max_concurrent_commands = 4

[mtls]
ca_cert = "/etc/venya/stale/ca.crt"
cert = "/etc/venya/stale/executor.crt"
key = "/etc/venya/stale/executor.key"
"""


def _carried_labels(stdout: str) -> list[str]:
    """The names the run promised, read out of its own `Preserved …` line."""
    line = [ln for ln in stdout.splitlines() if ln.startswith("[INFO] Preserved")]
    assert len(line) == 1, stdout
    return line[0].split(":", 1)[1].split()


def _disagreements(stdout: str, data: dict) -> list[str]:
    """Every place the run's promise and the parsed file disagree.

    A bracketed label must be a table in the document; a bare label must sit at top level
    and inside no table. An empty list is what makes the line the operator read trustworthy.
    """
    out: list[str] = []
    for label in _carried_labels(stdout):
        if label.startswith("["):
            name = label.strip("[]")
            if not isinstance(data.get(name), dict):
                out.append(f"{label} promised, not a table in the file")
            continue
        if label not in data:
            out.append(f"{label} promised, absent at top level")
        for table, values in data.items():
            if isinstance(values, dict) and label in values:
                out.append(f"{label} promised at top level, parsed inside [{table}]")
    return out


def _region(text: str, start: str, end: str) -> str:
    """Lift a real region between two anchors, refusing ambiguity (the #745 helper)."""
    assert text.count(start) == 1, f"start anchor not unique in install-venya-executor.sh: {start!r}"
    assert text.count(end) == 1, f"end anchor not unique in install-venya-executor.sh: {end!r}"
    i = text.index(start)
    j = text.index(end, i) + len(end)
    return text[i:j]


_PRELUDE = (
    "set -uo pipefail\n"
    'info()  { echo "[INFO] $*"; }\n'
    'warn()  { echo "[WARN] $*"; }\n'
    'error() { echo "[ERROR] $*"; }\n'
    'TOML="$WORK/executor.toml"\n'
    'ENVF="$WORK/venya-executor.env"\n'
    f'SERVER_URL="{INSTALLER_SERVER_URL}"\n'
    f'EXECUTOR_ID="{INSTALLER_ID}"\n'
    f'CA_BUNDLE_PATH="{INSTALLER_CA_BUNDLE}"\n'
    f'DNS_RESOLVER="{INSTALLER_DNS}"\n'
    f'CORE_HOSTNAME="{INSTALLER_CORE_HOST}"\n'
    "CA_INSTALLED=true\n"
    f'EXECUTOR_KEY_PASSPHRASE="{INSTALLER_PASSPHRASE}"\n'
)
_END = 'echo "REACHED_END=1"\n'


def _writer_script(tmp_path: Path, incumbent: str | None, ca_installed: bool = True) -> str:
    """The real capture + rebuild + re-append region, with both toml paths rebased.

    ``ca_installed=False`` skips the conditional ``[audit]`` block, which is what the loader
    cells use: `AuditForwarderConfig` refuses a ``ca_cert_path`` that does not exist, and no
    cell here writes to ``/etc/venya``.
    """
    region = _region(_source(), TOML_REGION_START, TOML_WRITER_END).replace("/etc/venya/executor.toml", "$TOML")
    toml = tmp_path / "executor.toml"
    if incumbent is None:
        toml.unlink(missing_ok=True)
    else:
        toml.write_text(incumbent, encoding="utf-8")
    prelude = _PRELUDE.replace("$WORK", str(tmp_path))
    if not ca_installed:
        prelude = prelude.replace("CA_INSTALLED=true\n", "CA_INSTALLED=false\n")
    return prelude + region + "\n" + _END


def _env_script(tmp_path: Path, incumbent: str | None) -> str:
    """The real EnvironmentFile capture + rewrite + re-append region, paths rebased."""
    region = (
        _region(_source(), ENV_REGION_START, ENV_WRITER_END)
        .replace("/etc/venya/venya-executor.env", "$ENVF")
        .replace("chown root:venya", "true")
        .replace("chmod 0640", "true")
    )
    envf = tmp_path / "venya-executor.env"
    if incumbent is not None:
        envf.write_text(incumbent, encoding="utf-8")
    return _PRELUDE.replace("$WORK", str(tmp_path)) + region + "\n" + _END


def _run(script: str, tmp_path: Path) -> subprocess.CompletedProcess:
    path = tmp_path / "run.sh"
    path.write_text(script, encoding="utf-8")
    return subprocess.run(
        ["/bin/bash", str(path)],
        cwd=str(tmp_path),
        env={"PATH": "/usr/bin:/bin", "HOME": str(tmp_path), "WORK": str(tmp_path)},
        capture_output=True,
        text=True,
        check=False,
        timeout=60,
    )


def _rerun(tmp_path: Path, incumbent: str | None, ca_installed: bool = True) -> tuple[subprocess.CompletedProcess, str]:
    """One re-run over `incumbent`, returning its output and the file it left behind."""
    proc = _run(_writer_script(tmp_path, incumbent, ca_installed), tmp_path)
    assert proc.returncode == 0, proc.stdout + proc.stderr
    return proc, (tmp_path / "executor.toml").read_text(encoding="utf-8")


class TestAC1Preserve:
    """AC1 — a non-managed table or key survives the re-run, read back BEFORE the redirect."""

    def test_the_operator_table_survives_the_rebuild(self, tmp_path):
        _proc, written = _rerun(tmp_path, INCUMBENT_TOML)
        assert "[executor]" in written, written
        assert "max_concurrent_commands = 4" in written, written
        assert "[network]" in written and "connect_timeout = 9.5" in written, written

    def test_a_multi_line_operator_value_survives_whole(self, tmp_path):
        """Section bodies travel verbatim, so an array spanning lines is not cut in half —
        a half-carried array would make the file unparseable and stop the daemon."""
        _proc, written = _rerun(tmp_path, INCUMBENT_TOML, ca_installed=False)
        assert '  "registry.example",' in written, written
        assert ExecutorConfig.from_file(tmp_path / "executor.toml") is not None, written

    def test_the_read_back_precedes_the_truncating_redirect(self):
        """The proof the AC asks for, at the shipped source: both captures sit before the
        `} > /etc/venya/executor.toml` that destroys the file, never after it."""
        src = _source()
        assert src.count(TOML_REDIRECT) == 1, f"the writer redirect is no longer unique: {src.count(TOML_REDIRECT)}"
        capture = src.index(TOML_REGION_START)
        assert capture < src.index(TOML_REDIRECT), "the read-back runs after the write it is meant to protect"
        assert src.count(TOML_REGION_START) == 1, "the managed-key list appears twice"
        for mode in ("top", "sect"):
            assert src.index(f"$(venya_toml_scan {mode} ") < src.index(TOML_REDIRECT), f"the {mode} scan runs late"

    def test_a_second_re_run_is_byte_identical(self, tmp_path):
        """No accumulation: the carried block is read from the incumbent and rewritten once,
        so re-running N times leaves the same file re-running N+1 times leaves."""
        first = _run(_writer_script(tmp_path, INCUMBENT_TOML), tmp_path)
        assert first.returncode == 0, first.stdout + first.stderr
        after_one = (tmp_path / "executor.toml").read_text(encoding="utf-8")
        second = _run(_writer_script(tmp_path, after_one), tmp_path)
        assert second.returncode == 0, second.stdout + second.stderr
        after_two = (tmp_path / "executor.toml").read_text(encoding="utf-8")
        assert after_two == after_one, "the carried block grew on the second run"


class TestAC1PlacementAndPromise:
    """Leg 1060 AC1 — the cell that was missing: a carried top-level key has to parse where
    the promise says it parsed, and the proof runs through the shipped loader."""

    def _both(self, tmp_path):
        proc, written = _rerun(tmp_path, INCUMBENT_TOP_KEY, ca_installed=False)
        return proc, written, tomllib.loads(written)

    def test_the_documented_top_level_key_parses_at_top_level(self, tmp_path):
        proc, written, data = self._both(tmp_path)
        assert data["sandbox_memory_mb"] == 2048, written
        assert ExecutorConfig.from_file(tmp_path / "executor.toml").sandbox_memory_mb == 2048, proc.stdout

    def test_the_key_is_not_absorbed_by_a_table_the_installer_writes(self, tmp_path):
        """TOML has no end-of-table, so this is the whole defect: the key survives the
        rebuild and disappears in the parse."""
        _proc, written, data = self._both(tmp_path)
        for table in ("mtls", "audit", "executor"):
            assert "sandbox_memory_mb" not in data.get(table, {}), f"absorbed into [{table}]: {written}"

    def test_the_printed_name_and_the_parsed_placement_agree(self, tmp_path):
        """The join leg 1054 never made, over both classes at once: `sandbox_memory_mb`
        (bare, top level) and `[executor]` (bracketed, a table)."""
        proc, written, data = self._both(tmp_path)
        assert _disagreements(proc.stdout, data) == [], (proc.stdout, written, sorted(data))

    def test_a_carried_top_level_key_is_written_before_the_first_table_header(self):
        """Source-order pin: the emission sits inside the generated block and ahead of
        `[mtls]`, so moving it back to the append is a visible change, not a quiet one."""
        src = _source()
        assert src.count(TOP_EMIT) == 1, "the carried top-level emission is missing or duplicated"
        assert src.count(MTLS_OPEN) == 1, "the first table header is no longer unique"
        assert src.index(TOP_EMIT) < src.index(MTLS_OPEN), "the top-level carry sits after a table header"
        assert src.index(TOP_EMIT) < src.index(TOML_REDIRECT), "the carry escaped the generated block"


class TestAC2InstallerStillWins:
    """AC2 — the paired negative. A preserve that also preserved the installer's own keys
    would be a cache, not a preserve."""

    def test_every_key_the_row_names_takes_the_installers_value(self, tmp_path):
        _proc, written = _rerun(tmp_path, INCUMBENT_TOML)
        assert f'server_url = "{INSTALLER_SERVER_URL}"' in written, written
        assert f'executor_id = "{INSTALLER_ID}"' in written, written
        assert f'ca_bundle = "{INSTALLER_CA_BUNDLE}"' in written, written
        assert "[mtls]" in written, written
        assert 'cert = "/etc/venya/executor/executor.crt"' in written, written

    def test_no_stale_installer_owned_line_survives(self, tmp_path):
        _proc, written = _rerun(tmp_path, INCUMBENT_TOML)
        for stale in ("https://stale-core:9999", "stale-executor-name", "/etc/venya/stale-bundle.crt"):
            assert stale not in written, f"{stale} survived a rebuild that owns it"

    def test_the_managed_dns_resolver_is_not_double_written(self, tmp_path):
        """`dns_resolver` is both installer-written and the one key with a stored-reuse read;
        it must appear exactly once in the rebuilt file."""
        _proc, written = _rerun(tmp_path, INCUMBENT_TOML)
        assert written.count("dns_resolver =") == 1, written


class TestAC3Loud:
    """AC3 — every carried or dropped operator key is named in the run's output."""

    def test_a_carried_setting_is_counted_and_named(self, tmp_path):
        proc, _written = _rerun(tmp_path, INCUMBENT_TOML)
        carried = [ln for ln in proc.stdout.splitlines() if ln.startswith("[INFO] Preserved")]
        assert len(carried) == 1, proc.stdout
        assert "Preserved 2" in carried[0], carried[0]
        assert "[executor]" in carried[0] and "[network]" in carried[0], carried[0]

    def test_a_dropped_operator_key_inside_an_installer_table_is_named(self, tmp_path):
        """`[mtls]` is installer-owned, so `operator_stray` cannot be carried without
        carrying a second value for a table the installer writes. Silence here is the defect."""
        proc, written = _rerun(tmp_path, INCUMBENT_TOML)
        dropped = [ln for ln in proc.stdout.splitlines() if ln.startswith("[WARN] Dropped")]
        assert len(dropped) == 1, proc.stdout
        assert "mtls.operator_stray" in dropped[0], dropped[0]
        assert "operator_stray" not in written, "the named drop did not actually drop"

    def test_a_run_with_nothing_to_say_stays_quiet(self, tmp_path):
        """Fresh install: no incumbent, so no carry and no claim of one. A preserve line here
        would be a count of nothing."""
        (tmp_path / "executor.toml").unlink(missing_ok=True)
        proc = _run(_writer_script(tmp_path, None), tmp_path)
        assert proc.returncode == 0, proc.stdout + proc.stderr
        assert "REACHED_END=1" in proc.stdout, proc.stdout
        assert "operator-added" not in proc.stdout, proc.stdout
        assert "Dropped" not in proc.stdout, proc.stdout


class TestAC4BothCarriers:
    """AC4 — the EnvironmentFile follows the same rule, so the operator is never left
    guessing which of the two files they edited."""

    INCUMBENT_ENV = (
        "VENYA_EXECUTOR_KEY_PASSPHRASE=old-passphrase-that-is-not-this-one\n"  # pragma: allowlist secret — a fixture value for the incumbent face, never a real key passphrase
        "VENYA_EXECUTOR__MAX_CONCURRENT_COMMANDS=4\n"
        "VENYA_EXECUTOR_NETWORK__CONNECT_TIMEOUT=9.5\n"
        "# a comment the installer does not own\n"
    )

    def test_an_operator_env_line_survives_the_rewrite(self, tmp_path):
        script = _env_script(tmp_path, self.INCUMBENT_ENV)
        proc = _run(script, tmp_path)
        assert proc.returncode == 0, proc.stdout + proc.stderr
        written = (tmp_path / "venya-executor.env").read_text(encoding="utf-8")
        assert "VENYA_EXECUTOR__MAX_CONCURRENT_COMMANDS=4" in written, written
        assert "VENYA_EXECUTOR_NETWORK__CONNECT_TIMEOUT=9.5" in written, written

    def test_the_installers_passphrase_is_the_one_written(self, tmp_path):
        """Paired negative on this carrier: the managed line takes the installer's value, and
        the preserve mechanism does not carry the incumbent copy of it back in."""
        script = _env_script(tmp_path, self.INCUMBENT_ENV)
        _proc = _run(script, tmp_path)
        written = (tmp_path / "venya-executor.env").read_text(encoding="utf-8")
        assert f"VENYA_EXECUTOR_KEY_PASSPHRASE={INSTALLER_PASSPHRASE}" in written, written
        assert "old-passphrase-that-is-not-this-one" not in written, written

    def test_the_run_names_the_carried_env_keys(self, tmp_path):
        script = _env_script(tmp_path, self.INCUMBENT_ENV)
        proc = _run(script, tmp_path)
        line = [ln for ln in proc.stdout.splitlines() if "operator-added EnvironmentFile key(s)" in ln]
        assert len(line) == 1, proc.stdout
        assert "VENYA_EXECUTOR__MAX_CONCURRENT_COMMANDS" in line[0], line[0]

    def test_the_env_read_back_precedes_the_delete(self):
        src = _source()
        assert src.count(ENV_READ_BACK) == 1, "the EnvironmentFile read-back is missing or duplicated"
        assert src.index(ENV_READ_BACK) < src.index(
            "rm -f /etc/venya/venya-executor.env"
        ), "the read-back runs after the file it reads is deleted"

    def test_the_env_carrier_has_no_table_syntax_to_absorb_a_carried_key(self, tmp_path):
        """Leg 1060 AC3 — parity checked, not assumed. The EnvironmentFile is a flat
        `KEY=VALUE` list, so the executor.toml absorption shape cannot arise there, and each
        carried key lands as its own pair carrying its own value."""
        proc = _run(_env_script(tmp_path, self.INCUMBENT_ENV), tmp_path)
        assert proc.returncode == 0, proc.stdout + proc.stderr
        written = (tmp_path / "venya-executor.env").read_text(encoding="utf-8")
        lines = [ln for ln in written.splitlines() if ln and not ln.startswith("#")]
        assert not any(ln.startswith("[") for ln in lines), f"a table header appeared: {written}"
        pairs = dict(ln.split("=", 1) for ln in lines)
        assert pairs["VENYA_EXECUTOR__MAX_CONCURRENT_COMMANDS"] == "4", written
        assert pairs["VENYA_EXECUTOR_NETWORK__CONNECT_TIMEOUT"] == "9.5", written
        assert pairs["VENYA_EXECUTOR_KEY_PASSPHRASE"] == INSTALLER_PASSPHRASE, written


class TestAC5TheBootLine:
    """AC5 — the observable the guest showed: the daemon's relay-listener line reads the
    number out of the file the installer just rebuilt."""

    def test_the_shipped_loader_reads_the_rebuilt_file_as_four(self, tmp_path):
        _proc, _written = _rerun(tmp_path, INCUMBENT_TOML, ca_installed=False)
        cfg = ExecutorConfig.from_file(tmp_path / "executor.toml")
        assert cfg.executor.max_concurrent_commands == 4, cfg.executor

    def test_the_cap_the_listener_announces_is_four(self, tmp_path):
        """`_read_cap` is what feeds `max_concurrent_commands=%d` in the listener's start
        line (`relay_listener.py`), so this is the guest's boot line, computed from the
        rebuilt file rather than asserted as text."""
        _proc, _written = _rerun(tmp_path, INCUMBENT_TOML, ca_installed=False)
        cfg = ExecutorConfig.from_file(tmp_path / "executor.toml")
        cap = RelayListener._read_cap(SimpleNamespace(_config=cfg))
        assert f"max_concurrent_commands={cap}" == "max_concurrent_commands=4", cap

    def test_the_announcement_format_still_names_the_knob(self):
        """The line the operator reads exists and is fed by the cap — the AC5 observable
        cannot be satisfied by a loader that keeps the value invisible."""
        src = (REPO_ROOT / "packages/executor/src/executor/relay_listener.py").read_text(encoding="utf-8")
        assert "max_concurrent_commands=%d" in src, src
        assert "self._cap," in src[src.index("max_concurrent_commands=%d") :], "the cap is not what is printed"


class TestTheGuardIsLoadBearing:
    """Deliberate breaks, so nothing above passes because of the harness."""

    def _broken(self, tmp_path: Path, kind: str) -> str:
        script = _writer_script(tmp_path, INCUMBENT_TOML)
        if kind == "no_append":
            broken = script.replace("    } >> $TOML\n", "    }\n", 1)
        elif kind == "carry_managed":
            broken = script.replace(TOML_REGION_START, 'MANAGED_TOML_KEYS="')
        else:  # `no_scan`: every read-back asks for a mode the program does not implement
            broken = script
            for mode in ("top", "sect", "name"):
                broken = broken.replace(f"venya_toml_scan {mode}", "venya_toml_scan nomode", 1)
        assert broken != script, f"the {kind} break did not apply — the proof would be a lie"
        return broken

    def test_the_re_append_is_what_carries_the_table(self, tmp_path):
        """Strip the re-append and the operator table is gone again — so AC1 tests the write,
        not the tmpdir fixture."""
        proc = _run(self._broken(tmp_path, "no_append"), tmp_path)
        assert proc.returncode == 0, proc.stdout + proc.stderr
        assert "max_concurrent_commands" not in (tmp_path / "executor.toml").read_text(encoding="utf-8")

    def test_the_managed_list_is_what_keeps_the_installer_authoritative(self, tmp_path):
        """Empty the managed-key list and the incumbent `server_url` is carried too, which is
        AC2's failure: the preserve turns into a cache."""
        proc = _run(self._broken(tmp_path, "carry_managed"), tmp_path)
        assert proc.returncode == 0, proc.stdout + proc.stderr
        written = (tmp_path / "executor.toml").read_text(encoding="utf-8")
        assert "https://stale-core:9999" in written, written

    def test_the_capture_is_what_names_the_key(self, tmp_path):
        """With the read-back pointed at a mode the program does not have, nothing is carried
        and nothing is claimed — the loudness is produced by the scan, not by the prelude."""
        proc = _run(self._broken(tmp_path, "no_scan"), tmp_path)
        assert proc.returncode == 0, proc.stdout + proc.stderr
        assert "Preserved" not in proc.stdout, proc.stdout
        assert "max_concurrent_commands" not in (tmp_path / "executor.toml").read_text(encoding="utf-8")

    def _placement_break(self, tmp_path: Path, kind: str) -> str:
        """The two ways the carried top-level key can be lost, each asserted to have applied."""
        script = _writer_script(tmp_path, INCUMBENT_TOP_KEY, ca_installed=False)
        if kind == "after_table":  # leg 1054's shipped shape: emit below `[mtls]`
            broken = script.replace(TOP_EMIT + MTLS_OPEN, MTLS_OPEN + TOP_EMIT, 1)
        else:  # `no_top_emit`: the carry is computed and never written
            broken = script.replace(TOP_EMIT, "", 1)
        assert broken != script, f"the {kind} break did not apply — the proof would be a lie"
        return broken

    def test_the_append_below_a_table_header_reproduces_the_defect(self, tmp_path):
        """Move the emission back where leg 1054 put it and watch what a bytes-only check
        misses: the key is still in the file, still promised, and gone from the config. That
        disagreement is the defect, so `test_the_printed_name_and_the_parsed_placement_agree`
        is what catches it — not a grep for the key."""
        proc = _run(self._placement_break(tmp_path, "after_table"), tmp_path)
        assert proc.returncode == 0, proc.stdout + proc.stderr
        written = (tmp_path / "executor.toml").read_text(encoding="utf-8")
        data = tomllib.loads(written)
        assert "sandbox_memory_mb" in written, written
        assert "sandbox_memory_mb" in _carried_labels(proc.stdout), proc.stdout
        assert data["mtls"].get("sandbox_memory_mb") == 2048, f"not absorbed after all: {written}"
        # The field's shipped default (SANDBOX_MEMORY_DEFAULT_MB = 1024, #589) is what the
        # operator gets instead of what they wrote — a changed value, not a missing one.
        assert ExecutorConfig.from_file(tmp_path / "executor.toml").sandbox_memory_mb != 2048, written
        assert _disagreements(proc.stdout, data), "the agreement cell would not have fired"

    def test_the_top_level_emit_is_what_places_the_key(self, tmp_path):
        """Delete the emission instead: the promise still names the key while the file does
        not carry it, which is the same false claim by a different route."""
        proc = _run(self._placement_break(tmp_path, "no_top_emit"), tmp_path)
        assert proc.returncode == 0, proc.stdout + proc.stderr
        written = (tmp_path / "executor.toml").read_text(encoding="utf-8")
        data = tomllib.loads(written)
        assert "sandbox_memory_mb" not in data, written
        assert "sandbox_memory_mb" in _carried_labels(proc.stdout), proc.stdout
        assert _disagreements(proc.stdout, data), "the agreement cell would not have fired"
