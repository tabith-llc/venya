# Copyright (c) 2026 Tabith LLC.
# Use of this source code is governed by the Business Source License 1.1
# included in the LICENSE file at the root of this repository. As of the
# Change Date listed there, the work is available under MPL 2.0.
# SPDX-License-Identifier: BUSL-1.1

"""Behavioral cells: core/executor uninstallers verify removals before the
success claim (#396).

Root cause (ticket server-uninstallers-unverified-success-claim): both server
uninstallers printed "Venya <X> uninstalled." and exited 0 through warn-only
DB drops, silently swallowed userdel failures, and file survivors — the
opposite of the cli-uninstaller-incomplete-rc0 contract (verify + exit 1
before claiming). These cells run the REAL script text with its absolute
filesystem prefixes (/etc/, /opt/, /var/, /usr/local/) rebased into a tmp
fake root and every decision command stubbed (id/systemctl/sudo/psql/userdel/
rm/nginx/update-ca-certificates) — all state stays in the tmpdir; nothing is
executed against the real system.

Harness idiom per test_installer_cli_uninstall_complete_390.py (stub-bin
PATH + marker-driven failure injection) extended with the fake-root rebase
because these scripts are root-scoped: the `id` stub answers `-u` (caller)
as root so venya_check_root passes, and `-u venya` from a user-present
marker file. psql DROPs consume the db-count/role-count state markers;
verify SELECTs read them (1 = survivor). userdel consumes user-present on
success; rc-userdel makes it fail. RM_SKIP_SUB makes the rm stub skip
matching args — deterministic file survivors.

Truth table, both halves, per script: clean tree -> rc 0 + success claim +
no [ERROR]; each injected survivor (DB drop failure, userdel failure, file
survivor) -> [ERROR] naming the survivor + rc!=0 + NO success claim.
Paired negative on core: postgres-not-active skips the DB verify entirely
(warn + rc 0 + claim, no false DB error).
"""

import os
import subprocess
import tempfile
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[3]

_STUB_ID = """#!/bin/bash
if [ "$1" = "-u" ]; then
    if [ "$#" -eq 1 ]; then echo 0; exit 0; fi
    if [ "$2" = "venya" ]; then
        if [ -f "$RC_DIR/user-present" ]; then echo 1000; exit 0; else exit 1; fi
    fi
fi
exit 1
"""

_STUB_SYSTEMCTL = """#!/bin/bash
echo "systemctl $*" >> "$STUB_LOG"
if [ "$1" = "is-active" ] && [ -f "$RC_DIR/pg-not-active" ]; then exit 3; fi
exit 0
"""

_STUB_SUDO = """#!/bin/bash
if [ "$1" = "-u" ]; then shift 2; fi
exec "$@"
"""

_STUB_PSQL = """#!/bin/bash
echo "psql $*" >> "$STUB_LOG"
sql="${@: -1}"
case "$sql" in
    "DROP DATABASE IF EXISTS venya;")
        if [ -f "$RC_DIR/rc-drop-db" ]; then exit 1; fi
        /bin/rm -f "$RC_DIR/db-count"; exit 0 ;;
    "DROP ROLE IF EXISTS venya;")
        if [ -f "$RC_DIR/rc-drop-role" ]; then exit 1; fi
        /bin/rm -f "$RC_DIR/role-count"; exit 0 ;;
    "DROP ROLE IF EXISTS venya_audit;")
        if [ -f "$RC_DIR/rc-drop-role-audit" ]; then exit 1; fi
        /bin/rm -f "$RC_DIR/role-count"; exit 0 ;;
    *pg_database*)
        if [ -f "$RC_DIR/db-count" ]; then cat "$RC_DIR/db-count"; else echo 0; fi
        exit 0 ;;
    *pg_roles*)
        if [ -f "$RC_DIR/role-count" ]; then cat "$RC_DIR/role-count"; else echo 0; fi
        exit 0 ;;
    *pg_reload_conf*)
        if [ -f "$RC_DIR/rc-reload" ]; then exit 1; fi
        exit 0 ;;
esac
exit 0
"""

_STUB_USERDEL = """#!/bin/bash
echo "userdel $*" >> "$STUB_LOG"
if [ -f "$RC_DIR/rc-userdel" ]; then exit 1; fi
/bin/rm -f "$RC_DIR/user-present"
exit 0
"""

_STUB_RM = """#!/bin/bash
args=()
for a in "$@"; do
    if [ -n "${RM_SKIP_SUB:-}" ] && [[ "$a" == *"${RM_SKIP_SUB}"* ]]; then continue; fi
    args+=("$a")
done
if [ "${#args[@]}" -gt 0 ]; then /bin/rm "${args[@]}"; fi
exit 0
"""

_STUB_OK = "#!/bin/bash\nexit 0\n"

_PREFIXES = ("/etc/", "/opt/", "/var/", "/usr/local/")


class _RootHarness:
    """Runs a real root-scoped uninstaller against a fake-root tmpdir tree."""

    def __init__(self, tmp: str, script_name: str) -> None:
        self.tmp = Path(tmp)
        self.root = self.tmp / "froot"
        self.stub = self.tmp / "stubbin"
        self.rc = self.tmp / "rc"
        self.log = self.tmp / "calls.log"
        for d in (self.root, self.stub, self.rc):
            d.mkdir(parents=True)
        self.log.write_text("", encoding="utf-8")
        for name, body in (
            ("id", _STUB_ID),
            ("systemctl", _STUB_SYSTEMCTL),
            ("sudo", _STUB_SUDO),
            ("psql", _STUB_PSQL),
            ("userdel", _STUB_USERDEL),
            ("rm", _STUB_RM),
            ("nginx", _STUB_OK),
            ("update-ca-certificates", _STUB_OK),
        ):
            p = self.stub / name
            p.write_text(body, encoding="utf-8")
            p.chmod(0o755)
        text = (REPO_ROOT / script_name).read_text(encoding="utf-8")
        for prefix in _PREFIXES:
            text = text.replace(prefix, str(self.root) + prefix)
        self.script = self.tmp / "run.sh"
        self.script.write_text(text, encoding="utf-8")

    def _mk(self, rel: str, content: str = "x\n") -> None:
        p = self.root / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(content, encoding="utf-8")

    def seed_installed_tree(self, variant: str) -> None:
        """Create the uninstaller's removal targets + live-state markers."""
        for d in ("opt/venya", "etc/venya", "var/lib/venya", "var/log/venya"):
            self._mk(f"{d}/payload")
        (self.root / "opt/venya").mkdir(exist_ok=True)
        if variant == "core":
            self._mk("etc/systemd/system/venya-core.service", "[Unit]\n")
            self._mk("var/www/.well-known/venya-ca.crt")
        else:
            for unit in (
                "venya-executor.service",
                "tmp-venya_secrets.mount",
                "venya-executor.seccomp",
                "venya-sandboxd.service",
            ):
                self._mk(f"etc/systemd/system/{unit}", "[Unit]\n")
            self._mk("etc/systemd/system/venya-executor.service.d/10-sandboxd.conf", "[Unit]\n")
        self._mk("usr/local/share/ca-certificates/venya-root-ca.crt")
        self._mk("usr/local/share/ca-certificates/venya-local-ca.crt")
        if variant == "core":
            self._mk("etc/postgresql/16/main/pg_hba.conf", "local venya venya_audit peer map=venya_map\n")
            self._mk("etc/postgresql/16/main/pg_ident.conf", "venya_map venya venya_audit\n")
            self._mk("etc/nginx/ssl/client-ca-bundle.crt")
            self._mk("etc/nginx/sites-enabled/venya")
            self._mk("etc/nginx/sites-available/venya")
        self.rc.joinpath("user-present").write_text("1", encoding="utf-8")
        self.rc.joinpath("db-count").write_text("1", encoding="utf-8")
        self.rc.joinpath("role-count").write_text("1", encoding="utf-8")

    def run(self, rm_skip: str = "") -> subprocess.CompletedProcess:
        env = {
            "HOME": str(self.tmp),
            "PATH": f"{self.stub}:{os.defpath}:/usr/bin:/bin",
            "RC_DIR": str(self.rc),
            "STUB_LOG": str(self.log),
            "RM_SKIP_SUB": rm_skip,
            "VENYA_SKIP_PROMPT": "yes",
        }
        return subprocess.run(
            ["/bin/bash", str(self.script)],
            capture_output=True,
            text=True,
            timeout=60,
            env=env,
            stdin=subprocess.DEVNULL,
            check=False,
        )

    def calls(self) -> str:
        return self.log.read_text(encoding="utf-8")


def _core(tmp: str) -> _RootHarness:
    h = _RootHarness(tmp, "uninstall-venya-core.sh")
    h.seed_installed_tree("core")
    return h


def _exec_h(tmp: str) -> _RootHarness:
    h = _RootHarness(tmp, "uninstall-venya-executor.sh")
    h.seed_installed_tree("executor")
    return h


# --- core uninstaller ---


def test_core_clean_uninstall_rc0_and_claim() -> None:
    """AC-1 positive: installed tree + healthy psql/userdel -> removals land,
    verify passes, rc 0, success claim, no [ERROR]."""
    with tempfile.TemporaryDirectory() as tmp:
        h = _core(tmp)
        r = h.run()
        assert r.returncode == 0, r.stdout + r.stderr
        assert "Venya Core uninstalled." in r.stdout
        assert "[ERROR]" not in r.stdout
        assert not (h.root / "etc/systemd/system/venya-core.service").exists()
        for d in ("opt/venya", "etc/venya", "var/lib/venya", "var/log/venya"):
            assert not (h.root / d).exists(), f"survivor: {d}"
        assert not (h.root / "usr/local/share/ca-certificates/venya-root-ca.crt").exists()
        assert "userdel -r venya" in h.calls()


def test_core_db_drop_failure_survivor_errors_nonzero() -> None:
    """AC-1 negative: injected DROP DATABASE failure (warn) must be caught by
    the verify probe — [ERROR] naming the DB, rc!=0, NO success claim."""
    with tempfile.TemporaryDirectory() as tmp:
        h = _core(tmp)
        h.rc.joinpath("rc-drop-db").write_text("1", encoding="utf-8")
        r = h.run()
        assert r.returncode != 0
        assert "database still present" in r.stdout, r.stdout
        assert "Venya Core uninstalled." not in r.stdout


def test_core_userdel_failure_survivor_errors_nonzero() -> None:
    """AC-1 negative: swallowed userdel failure -> verify names the surviving
    service account; rc!=0; no claim."""
    with tempfile.TemporaryDirectory() as tmp:
        h = _core(tmp)
        h.rc.joinpath("rc-userdel").write_text("1", encoding="utf-8")
        r = h.run()
        assert r.returncode != 0
        assert "venya user still present" in r.stdout, r.stdout
        assert "Venya Core uninstalled." not in r.stdout


def test_core_trust_file_survivor_errors_nonzero() -> None:
    """AC-1 negative: file survivor via rm-arg injection -> [ERROR] naming
    the path; rc!=0; no claim."""
    with tempfile.TemporaryDirectory() as tmp:
        h = _core(tmp)
        r = h.run(rm_skip="ca-certificates/venya-root-ca.crt")
        assert r.returncode != 0
        assert "venya-root-ca.crt still present" in r.stdout, r.stdout
        assert "Venya Core uninstalled." not in r.stdout


def test_core_postgres_inactive_skips_db_verify_and_passes() -> None:
    """Paired negative: postgres NOT active -> drop step skipped (warn), and
    the DB verify must NOT fire false errors — rc 0 + claim."""
    with tempfile.TemporaryDirectory() as tmp:
        h = _core(tmp)
        h.rc.joinpath("pg-not-active").write_text("1", encoding="utf-8")
        r = h.run()
        assert r.returncode == 0, r.stdout + r.stderr
        assert "skipped DB/role drop" in r.stdout
        assert "database still present" not in r.stdout
        assert "cannot verify" not in r.stdout
        assert "Venya Core uninstalled." in r.stdout


# --- executor uninstaller ---


def test_executor_clean_uninstall_rc0_and_claim() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        h = _exec_h(tmp)
        r = h.run()
        assert r.returncode == 0, r.stdout + r.stderr
        assert "Venya Executor uninstalled." in r.stdout
        assert "[ERROR]" not in r.stdout
        for unit in (
            "venya-executor.service",
            "tmp-venya_secrets.mount",
            "venya-executor.seccomp",
            "venya-sandboxd.service",
        ):
            assert not (h.root / f"etc/systemd/system/{unit}").exists(), unit
        assert not (h.root / "etc/systemd/system/venya-executor.service.d").exists()
        assert not (h.root / "usr/local/share/ca-certificates/venya-local-ca.crt").exists()


def test_executor_unit_file_survivor_errors_nonzero() -> None:
    """AC-1 negative: injected survivor on the unit-file rm line -> verify
    names it; rc!=0; no success claim (RED-at-base: claim printed, rc 0)."""
    with tempfile.TemporaryDirectory() as tmp:
        h = _exec_h(tmp)
        r = h.run(rm_skip="systemd/system/venya-executor.")
        assert r.returncode != 0
        assert "venya-executor.service still present" in r.stdout, r.stdout
        assert "Venya Executor uninstalled." not in r.stdout


def test_executor_userdel_failure_survivor_errors_nonzero() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        h = _exec_h(tmp)
        h.rc.joinpath("rc-userdel").write_text("1", encoding="utf-8")
        r = h.run()
        assert r.returncode != 0
        assert "venya user still present" in r.stdout, r.stdout
        assert "Venya Executor uninstalled." not in r.stdout
