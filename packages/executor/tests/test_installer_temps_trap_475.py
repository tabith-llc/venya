# Copyright (c) 2026 Tabith LLC.
# Use of this source code is governed by the Business Source License 1.1
# included in the LICENSE file at the root of this repository. As of the
# Change Date listed there, the work is available under MPL 2.0.
# SPDX-License-Identifier: BUSL-1.1

"""Installer #475: temps must survive an abort by being REGISTERED, not by an
inline ``rm`` that only the success path reaches.

Shape before the fix (``install-venya-core.sh``)::

    FETCH_DIR="$(mktemp -d)"
    trap 'rm -rf "$FETCH_DIR"' EXIT          # the ONLY exit trap
    ...
    SERVER_CSR=$(mktemp /tmp/venya-server-XXXXXX.csr)
    openssl req ... && openssl x509 -req ...
    rm -f "$SERVER_CSR"                        # reached only when the sign works

Under ``set -euo pipefail`` an abort between creation and that inline cleanup left
the file behind -- the #317 CSRs and a tarball on the order of 100 MB per aborted
run.

Ruled shape (ticket #475 AC-1..AC-4): ``venya-common.sh`` carries a registry
(``INSTALL_CLEANUP_TEMPS`` with ``register_install_temp`` / ``cleanup_install_temps``),
every installer temp is registered, and each installer sets exactly ONE exit trap
right after the library is sourced. Per-file traps are not the mechanism and cannot
be made one: bash keeps a single EXIT trap per shell, so a second ``trap ... EXIT``
REPLACES the first (``test_per_file_trap_replaces_the_first_one`` demonstrates it on
plain bash rather than arguing about it). That is also why the pre-existing
``FETCH_DIR`` trap stays -- it is the only thing covering the window before the
library exists -- and why ``FETCH_DIR`` is handed to the list inside the ``else``
branch, immediately after the ``source`` whose trap replaces it.

AC-3 is the half that decides what must NOT be registered, because reaping a file
the install still needs is a worse bug than the leak: ``venya_apt``'s log survives on
purpose so the operator can open the path the failure message printed, and the
executor's warm-sandbox directory belongs to the service user and is retired by its
own non-fatal ``rmdir``.

Cells run the SHIPPED bash, extracted verbatim from the git-tracked root scripts
(house pattern: #457/#505/#519), against real ``mktemp`` files in a pytest tmpdir.
No installer is executed, nothing is installed, no VM and no root is involved, and
``apt-get`` is a shell function stub of the same name. The truth table runs both
ways: the pre-fix sequence is replayed too and must leak, so a green run is not a
vacuous one.
"""

import os
import re
import subprocess
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[3]
CORE = REPO_ROOT / "install-venya-core.sh"
EXECUTOR = REPO_ROOT / "install-venya-executor.sh"
COMMON = REPO_ROOT / "venya-common.sh"

REGISTRY_START = "# --- 0. Installer temp registry"
REGISTRY_END = "# --- 1. Colors and logging"

# The shipped installer sequence, replayed with real temps. $W (scratch dir) and
# $S (the extracted registry file) arrive through the environment, so this text
# needs no interpolation and stays byte-stable.
_DRIVER = """set -euo pipefail
# --- what the installers do BEFORE the common library exists ---
FETCH_DIR="$(mktemp -d "$W/fetch.XXXXXX")"
trap 'rm -rf "$FETCH_DIR"' EXIT
ABORT_AT="${1:-}"
n=0
: > "$FETCH_DIR/venya-common.sh"              # stand-in for the fetched library
# shellcheck source=/dev/null
source "$S"                                    # the installer sources venya-common.sh here
register_install_temp "$FETCH_DIR"
# --- the ONE exit trap the installers set (core:117, executor:129) ---
trap 'cleanup_install_temps' EXIT
newcsr() { mktemp "$W/venya-$1-XXXXXX.csr"; }
SERVER_CSR="$(newcsr server)"; register_install_temp "$SERVER_CSR"
n=$((n+1)); [ "$ABORT_AT" = "$n" ] && { echo "ABORT after temp $n (server csr)"; exit 1; }
rm -f "$SERVER_CSR"                            # shipped inline cleanup
TAR="$(mktemp "$W/venya-install-XXXXXX.tar.gz")"; register_install_temp "$TAR"
n=$((n+1)); [ "$ABORT_AT" = "$n" ] && { echo "ABORT after temp $n (tarball)"; exit 1; }
RELAY_CSR="$(newcsr relay)"; register_install_temp "$RELAY_CSR"
n=$((n+1)); [ "$ABORT_AT" = "$n" ] && { echo "ABORT after temp $n (relay csr)"; exit 1; }
INNER_CSR="$(newcsr inner)"; register_install_temp "$INNER_CSR"
n=$((n+1)); [ "$ABORT_AT" = "$n" ] && { echo "ABORT after temp $n (inner csr)"; exit 1; }
rm -f "$RELAY_CSR" "$INNER_CSR"                # shipped inline cleanup
printf 'operator-readable\\n' > "$W/kept-after-install.log"
echo "success path reached"
"""

# The same sequence at the pre-fix shape: one FETCH_DIR trap, inline cleanup only.
_RED_PARENT = """set -euo pipefail
FETCH_DIR="$(mktemp -d "$W/fetch.XXXXXX")"
trap 'rm -rf "$FETCH_DIR"' EXIT
ABORT_AT="${1:-}"
n=0
: > "$FETCH_DIR/venya-common.sh"
newcsr() { mktemp "$W/venya-$1-XXXXXX.csr"; }
SERVER_CSR="$(newcsr server)"
n=$((n+1)); [ "$ABORT_AT" = "$n" ] && { echo "ABORT after temp $n (server csr)"; exit 1; }
rm -f "$SERVER_CSR"
TAR="$(mktemp "$W/venya-install-XXXXXX.tar.gz")"
n=$((n+1)); [ "$ABORT_AT" = "$n" ] && { echo "ABORT after temp $n (tarball)"; exit 1; }
RELAY_CSR="$(newcsr relay)"
n=$((n+1)); [ "$ABORT_AT" = "$n" ] && { echo "ABORT after temp $n (relay csr)"; exit 1; }
INNER_CSR="$(newcsr inner)"
n=$((n+1)); [ "$ABORT_AT" = "$n" ] && { echo "ABORT after temp $n (inner csr)"; exit 1; }
rm -f "$RELAY_CSR" "$INNER_CSR"
echo "success path reached"
"""

# venya_apt, run against a stubbed apt-get, with the ONE exit trap armed.
_APT_DRIVER = """set -euo pipefail
source "$S"
source "$C"
source "$A"
trap 'cleanup_install_temps' EXIT
apt-get() { echo "simulated apt lock contention (exit 100)" >&2; return 100; }
venya_print_colors
venya_apt install -y -qq docker-sbx || { echo "installer aborts on the apt failure"; exit 1; }
echo "success path reached"
"""

_APT_DRIVER_OK = """set -euo pipefail
source "$S"
source "$C"
source "$A"
trap 'cleanup_install_temps' EXIT
apt-get() { echo "simulated apt success"; return 0; }
venya_print_colors
venya_apt install -y -qq docker-sbx
echo "success path reached"
"""


def _code(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def _code_lines(path: Path) -> list[str]:
    return _code(path).splitlines()


def _registry_text() -> str:
    """The registry section, verbatim, exactly as it ships in venya-common.sh."""
    lines = _code_lines(COMMON)
    try:
        start = next(i for i, line in enumerate(lines) if line.startswith(REGISTRY_START))
    except StopIteration:  # pragma: no cover - the section is the fix
        pytest.fail("the installer temp registry section is missing from venya-common.sh")
    end = next(i for i, line in enumerate(lines) if i > start and line.startswith(REGISTRY_END))
    return "\n".join(lines[start:end]) + "\n"


def _function(name: str) -> str:
    """One whole library function, verbatim — the same extraction the #375/#327
    interlock (packages/server/tests/test_installer_origin_pin_posture.py) uses."""
    m = re.search(rf"{name}\(\) \{{.*?\n\}}", _code(COMMON), re.DOTALL)
    assert m, f"{name} not found in venya-common.sh"
    return m.group(0) + "\n"


def _write(path: Path, text: str) -> Path:
    path.write_text(text, encoding="utf-8")
    return path


def _run(
    script: Path, tmp_path: Path, arg: str = "", extra: dict[str, str] | None = None
) -> subprocess.CompletedProcess:
    env = dict(os.environ)
    env["W"] = str(tmp_path)
    env.update(extra or {})
    return subprocess.run(
        ["bash", str(script), arg],
        capture_output=True,
        text=True,
        check=False,
        env=env,
        timeout=120,
    )


def _scratch(tmp_path: Path, name: str) -> Path:
    w = tmp_path / name
    w.mkdir(parents=True, exist_ok=True)
    return w


def _leftovers(w: Path) -> list[str]:
    """Installer temps the run created and left behind (the driver's own files excluded).

    The patterns overlap — a ``.csr`` matches both ``venya-*`` and ``*.csr`` — so the
    result is a set: a count read off this list is a count of FILES, not of matches.
    """
    patterns = ("venya-*", "fetch.*", "*.csr", "*.tar.gz")
    found: set[Path] = set()
    for pattern in patterns:
        found.update(w.glob(pattern))
    return sorted(str(p) for p in found)


def _traps(script: Path) -> list[str]:
    """EXIT trap statements, comment lines dropped — the count that must not grow."""
    return [
        line.strip()
        for line in _code_lines(script)
        if not line.lstrip().startswith("#") and re.search(r"\btrap\b.*\bEXIT\b", line)
    ]


class TestInstallerTempsSurviveAbort475:
    # ---------------------------------------------------------------- static ----
    def test_bash_syntax_clean_on_the_three_scripts(self) -> None:
        for script in (CORE, EXECUTOR, COMMON):
            proc = subprocess.run(["bash", "-n", str(script)], capture_output=True, text=True, check=False)
            assert proc.returncode == 0, (script.name, proc.stderr)

    def test_every_mktemp_site_is_registered_or_documently_excluded(self) -> None:
        """T5: no temp may sit outside the list without a reason printed on the spot.

        Counts are lineage, not a wish: 12 mktemp sites existed at ``fb2fd97`` and 12
        remain, 10 registered + 2 documented exclusions. A NEW unregistered temp fails
        the uncovered assertion; a new legitimate temp only fails the count, with this
        comment as the explanation.
        """
        registered, excluded, uncovered = [], [], []
        for script in (CORE, EXECUTOR, COMMON):
            lines = _code_lines(script)
            for i, line in enumerate(lines):
                if "mktemp" not in line or line.lstrip().startswith("#"):
                    continue
                site = f"{script.name}:{i + 1}"
                following = "\n".join(lines[i + 1 : i + 4])
                nearby = "\n".join(lines[i : i + 8])
                if "WARM_WS=" in line or "venya-apt-" in line:
                    assert "#475" in nearby, f"{site}: an exclusion must be documented on the spot"
                    assert "register_install_temp" not in following, f"{site}: excluded site got registered"
                    excluded.append(site)
                elif "FETCH_DIR=" in line:
                    tail = "\n".join(lines[i : i + 80])
                    assert re.search(
                        r'source "\$FETCH_DIR/venya-common\.sh"\s*\n(?:\s*#[^\n]*\n)*\s*register_install_temp "\$FETCH_DIR"',
                        tail,
                    ), f"{site}: FETCH_DIR is never handed to the list after the source"
                    registered.append(site)
                else:
                    var = re.search(r"([A-Za-z_][A-Za-z_0-9]*)=\$?\(?(?:sudo .* )?mktemp", line)
                    name = var.group(1) if var else None
                    if name and re.search(rf'register_install_temp "\${name}"', following):
                        registered.append(site)
                    else:
                        uncovered.append(site)
        assert uncovered == [], f"unregistered installer temps: {uncovered}"
        assert len(registered) == 10, registered
        assert len(excluded) == 2, excluded

    def test_exclusions_are_the_apt_log_and_the_service_user_workspace(self) -> None:
        """AC-3, static half: the two files that must stay off the list, named."""
        apt_body = _function("venya_apt")
        assert "log=$(mktemp /tmp/venya-apt-XXXXXX.log)" in apt_body
        assert 'error "Full apt log: $log"' in apt_body
        assert (
            "register_install_temp" not in apt_body
        ), "registering the apt log deletes the diagnostic the log line names"
        warm = _code(EXECUTOR)
        warm_block = warm[warm.index("WARM_WS=") : warm.index("WARM_WS=") + 1600]
        assert "register_install_temp" not in warm_block
        assert "sudo -H -u venya rmdir" in warm_block

    def test_one_list_trap_per_installer_and_no_per_file_trap(self) -> None:
        """The regression class #475 exists to close, gated.

        Exactly two EXIT traps per installer: the ``FETCH_DIR`` bootstrap (the only
        thing that covers the pre-source window) and ``cleanup_install_temps``. A third
        would silently REPLACE one of them, and a trap that names a single temp is the
        per-file shape that started this.
        """
        for script in (CORE, EXECUTOR):
            traps = _traps(script)
            assert len(traps) == 2, (script.name, traps)
            assert any("trap 'rm -rf \"$FETCH_DIR\"' EXIT" == t for t in traps), (script.name, traps)
            assert any(t == "trap 'cleanup_install_temps' EXIT" for t in traps), (script.name, traps)
        assert _traps(COMMON) == [], "the library sets no trap; the installer that sources it owns the single trap"

    def test_library_registrations_are_guarded_for_standalone_extraction(self) -> None:
        """venya_download_tarball is exec'd standalone by a server interlock, so the
        helper call inside it has to stay optional (rc 127 otherwise)."""
        body = _function("venya_download_tarball")
        assert "TARBALL_FILE=$(mktemp /tmp/venya-install-XXXXXX.tar.gz)" in body
        assert 'register_install_temp "$TARBALL_FILE"' in body
        assert 'register_install_temp "$SIDECAR_FILE"' in body
        guards = re.findall(r"command -v register_install_temp", body)
        assert len(guards) == 2, f"both registrations must be guarded, found {len(guards)}"

    def test_fetch_dir_registration_sits_in_the_else_branch_after_the_source(self) -> None:
        """The hand-off point, pinned: after the ``source`` whose trap replaces the
        bootstrap, before the ``fi`` that closes the ``else`` it belongs to."""
        for script in (CORE, EXECUTOR):
            lines = _code_lines(script)
            source_at = next(i for i, l in enumerate(lines) if 'source "$FETCH_DIR/venya-common.sh"' in l)
            close_at = next(i for i, l in enumerate(lines) if i > source_at and l.strip() == "fi")
            window = lines[source_at + 1 : close_at]
            assert any('register_install_temp "$FETCH_DIR"' in l for l in window), script.name
            assert any(l.strip().startswith("else") for l in lines[:source_at]), script.name

    def test_the_trap_body_never_exits_and_restores_the_status(self) -> None:
        body = _function("cleanup_install_temps")
        assert "local rc=$?" in body
        assert 'return "$rc"' in body
        assert not re.search(r"^\s*exit\b", body, re.MULTILINE), "an exit inside an EXIT trap overwrites the real one"
        assert "|| true" in body

    # ------------------------------------------------------- bash semantics ----
    def test_per_file_trap_replaces_the_first_one(self, tmp_path: Path) -> None:
        """WHY a list and not a per-file trap — plain bash, nothing imported."""
        w = _scratch(tmp_path, "onetrap")
        script = _write(
            w / "d.sh",
            "set -euo pipefail\n"
            f'A="$(mktemp "{w}/first.XXXXXX")"\n'
            "trap 'echo first >&2; rm -f \"$A\"' EXIT\n"
            f'B="$(mktemp "{w}/second.XXXXXX")"\n'
            "trap 'echo second >&2; rm -f \"$B\"' EXIT\n",
        )
        proc = _run(script, w)
        assert "first" not in proc.stderr, "the first trap did not run: a later trap replaced it"
        assert "second" in proc.stderr
        assert list(w.glob("first.*")), "the first temp was removed, so the replacement premise is wrong"

    # --------------------------------------------------------------- T2, abort ----
    @pytest.mark.parametrize("abort_after", [1, 2, 3, 4])
    def test_t2_abort_after_each_temp_leaves_nothing(self, tmp_path: Path, abort_after: int) -> None:
        w = _scratch(tmp_path, f"t2-{abort_after}")
        registry = _write(w / "registry.sh", _registry_text())
        script = _write(w / "driver.sh", _DRIVER)
        proc = _run(script, w, str(abort_after), extra={"S": str(registry)})
        assert proc.returncode == 1, proc.stdout + proc.stderr
        assert f"ABORT after temp {abort_after}" in proc.stdout
        assert _leftovers(w) == [], f"temps survived the abort: {_leftovers(w)}"

    @pytest.mark.parametrize("abort_after", [1, 3, 4])
    def test_t2_pre_fix_shape_leaks_so_this_cell_has_teeth(self, tmp_path: Path, abort_after: int) -> None:
        """Paired negative for the cells above: the same driver at the #475 shape leaks.

        The counts are the ones measured by hand at fb2fd97: an abort after temp 1 loses
        the server CSR, after 3 the tarball and the relay CSR, after 4 three files.
        """
        w = _scratch(tmp_path, f"red-{abort_after}")
        script = _write(w / "driver.sh", _RED_PARENT)
        proc = _run(script, w, str(abort_after))
        assert proc.returncode == 1, proc.stdout + proc.stderr
        leaked = _leftovers(w)
        assert leaked, "the pre-fix shape left nothing behind — the abort cells prove nothing"
        expected = {1: 1, 3: 2, 4: 3}[abort_after]
        assert len(leaked) == expected, leaked

    # ------------------------------------------------------------ T3, AC-3 ----
    def test_t3_success_path_cleans_temps_and_keeps_the_post_install_file(self, tmp_path: Path) -> None:
        w = _scratch(tmp_path, "t3")
        registry = _write(w / "registry.sh", _registry_text())
        script = _write(w / "driver.sh", _DRIVER)
        proc = _run(script, w, "", extra={"S": str(registry)})
        assert proc.returncode == 0, proc.stdout + proc.stderr
        assert "success path reached" in proc.stdout
        assert _leftovers(w) == [], _leftovers(w)
        kept = w / "kept-after-install.log"
        assert (
            kept.read_text(encoding="utf-8") == "operator-readable\n"
        ), "the trap reaped a file the install still needs"

    def test_t3_apt_log_survives_the_failed_install_it_was_named_for(self, tmp_path: Path) -> None:
        w = _scratch(tmp_path, "apt-fail")
        registry = _write(w / "registry.sh", _registry_text())
        _write(w / "colors.sh", _function("venya_print_colors"))
        _write(w / "apt.sh", _function("venya_apt"))
        script = _write(w / "apt.sh.driver", _APT_DRIVER)
        m = None
        proc = _run(
            script,
            w,
            "",
            extra={"S": str(registry), "C": str(w / "colors.sh"), "A": str(w / "apt.sh")},
        )
        try:
            assert proc.returncode == 1, proc.stdout + proc.stderr
            m = re.search(r"Full apt log: (\S+)", proc.stdout + proc.stderr)
            assert m, proc.stdout + proc.stderr
            assert Path(
                m.group(1)
            ).exists(), "the EXIT trap deleted the apt log the failure message told the operator to open"
        finally:
            if m is not None:
                Path(m.group(1)).unlink(missing_ok=True)

    def test_t3_apt_log_is_removed_on_the_success_path(self, tmp_path: Path) -> None:
        w = _scratch(tmp_path, "apt-ok")
        registry = _write(w / "registry.sh", _registry_text())
        _write(w / "colors.sh", _function("venya_print_colors"))
        _write(w / "apt.sh", _function("venya_apt"))
        script = _write(w / "apt.sh.driver", _APT_DRIVER_OK)
        before = set(Path("/tmp").glob("venya-apt-*.log"))
        proc = _run(
            script,
            w,
            "",
            extra={"S": str(registry), "C": str(w / "colors.sh"), "A": str(w / "apt.sh")},
        )
        assert proc.returncode == 0, proc.stdout + proc.stderr
        created = set(Path("/tmp").glob("venya-apt-*.log")) - before
        assert created == set(), f"the success path used to leave these: {sorted(map(str, created))}"

    # ----------------------------------------------------------- T4, status ----
    def test_t4_abort_status_survives_the_trap(self, tmp_path: Path) -> None:
        w = _scratch(tmp_path, "t4a")
        registry = _write(w / "registry.sh", _registry_text())
        script = _write(w / "driver.sh", _DRIVER)
        proc = _run(script, w, "3", extra={"S": str(registry)})
        assert proc.returncode == 1, proc.stdout + proc.stderr
        assert _leftovers(w) == []

    def test_t4_a_failing_cleanup_does_not_fail_a_finished_install(self, tmp_path: Path) -> None:
        locked = _scratch(tmp_path, "t4b") / "locked"
        locked.mkdir()
        registry = _write(tmp_path / "registry.sh", _registry_text())
        script = _write(
            tmp_path / "d.sh",
            "set -euo pipefail\n"
            'source "$S"\n'
            "trap 'cleanup_install_temps' EXIT\n"
            'D="$W/locked"\n'
            'T="$(mktemp "$D/venya-stuck-XXXXXX.csr")"\n'
            'register_install_temp "$T"\n'
            'chmod 500 "$D"\n'
            'echo "install finished"\n',
        )
        try:
            proc = _run(script, locked.parent, "", extra={"S": str(registry)})
            assert proc.returncode == 0, proc.stdout + proc.stderr
            assert "install finished" in proc.stdout
        finally:
            os.chmod(locked, 0o700)

    def test_t4_a_failing_cleanup_does_not_mask_the_real_abort(self, tmp_path: Path) -> None:
        locked = _scratch(tmp_path, "t4c") / "locked"
        locked.mkdir()
        registry = _write(tmp_path / "registry.sh", _registry_text())
        script = _write(
            tmp_path / "d.sh",
            "set -euo pipefail\n"
            'source "$S"\n'
            "trap 'cleanup_install_temps' EXIT\n"
            'D="$W/locked"\n'
            'T="$(mktemp "$D/venya-stuck-XXXXXX.csr")"\n'
            'register_install_temp "$T"\n'
            'chmod 500 "$D"\n'
            'echo "failing at the real step" >&2\n'
            "exit 7\n",
        )
        try:
            proc = _run(script, locked.parent, "", extra={"S": str(registry)})
            assert proc.returncode == 7, proc.stdout + proc.stderr
        finally:
            os.chmod(locked, 0o700)

    def test_t4_an_empty_list_is_safe_under_set_u(self, tmp_path: Path) -> None:
        w = _scratch(tmp_path, "t4d")
        registry = _write(w / "registry.sh", _registry_text())
        script = _write(
            w / "d.sh",
            "set -euo pipefail\n"
            'source "$S"\n'
            "trap 'cleanup_install_temps' EXIT\n"
            'echo "clean install, no temps registered"\n',
        )
        proc = _run(script, w, "", extra={"S": str(registry)})
        assert proc.returncode == 0, proc.stdout + proc.stderr
        assert "unbound variable" not in proc.stdout + proc.stderr

    def test_t4_duplicate_and_already_removed_registrations_are_tolerated(self, tmp_path: Path) -> None:
        w = _scratch(tmp_path, "t4e")
        registry = _write(w / "registry.sh", _registry_text())
        script = _write(
            w / "d.sh",
            "set -euo pipefail\n"
            'source "$S"\n'
            "trap 'cleanup_install_temps' EXIT\n"
            'T="$(mktemp "$W/venya-dup-XXXXXX.csr")"\n'
            'register_install_temp "$T"\n'
            'register_install_temp "$T"\n'
            'register_install_temp ""\n'
            'echo "list length: ${#INSTALL_CLEANUP_TEMPS[@]}"\n'
            'rm -f "$T"\n'
            'echo "inline-cleaned before the trap ran"\n',
        )
        proc = _run(script, w, "", extra={"S": str(registry)})
        assert proc.returncode == 0, proc.stdout + proc.stderr
        assert "list length: 1" in proc.stdout, proc.stdout
