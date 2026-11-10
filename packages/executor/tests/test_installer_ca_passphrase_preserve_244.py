# Copyright (c) 2026 Tabith LLC.
# Use of this source code is governed by the Business Source License 1.1
# included in the LICENSE file at the root of this repository. As of the
# Change Date listed there, the work is available under MPL 2.0.
# SPDX-License-Identifier: BUSL-1.1

"""Finding 244 — a preserved CA and the passphrase that opens it are kept as one pair.

``uninstall-venya-core.sh`` keeps ``/var/lib/venya/ca`` (#749) and removes ``/etc/venya``,
which is where ``install-venya-core.sh`` persists the two CA-key passphrases. The published
unattended reinstall then minted a fresh passphrase beside its own "Admin CA already exists -
preserved", stopped at admin-cert signing, and left a half-built core: venv deployed, config
partly written, no unit. Two guarantees, each with its paired negative:

* the uninstaller carries both passphrase lines into the directory it keeps, BEFORE removing
  anything, and stops before touching state when it cannot (purge arm: unchanged — both go);
* the installer resolves a passphrase from any of its three sources (explicit env > the live
  EnvironmentFile > the file kept beside a preserved CA) and refuses a key it cannot open
  before the service account, the packages, the venv and the database.

Method is the house shape from ``test_installer_schema_face_compare_750.py``: the REAL region
lifted out of the shipped script between two anchors and run in ``tmp_path``. The only
substitution is the four absolute paths, swapped by name and refused if the swap does not
land, so the logic under test is the shipped logic. The key is encrypted by the same
``cryptography`` call the product makes. No VM, no sudo, nothing written outside ``tmp_path``.
"""

import os
import pty
import re
import subprocess
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

REPO_ROOT = Path(__file__).resolve().parents[3]
INSTALLER = REPO_ROOT / "install-venya-core.sh"
UNINSTALLER = REPO_ROOT / "uninstall-venya-core.sh"

UNINSTALL_START = "# --- Finding 244: keep what unlocks the CA this run keeps"
UNINSTALL_END = 'CA_PRESERVED_STATE="absent"\n    fi\nfi\n'
PRECHECK_START = "# --- CA key passphrase sources, and the key check BEFORE any mutation"
PRECHECK_END = (
    'venya_ca_key_precheck "admin" "$ADMIN_CA_KEY_PATH" "$ADMIN_CA_KEY_PRECHECK" '
    '"VENYA_ADMIN_CA_PASSPHRASE" "$CA_PROMPT_DOOR"\nfi\n'
)
VERIFY_START = 'if [ "$CA_PRESERVED_STATE" = "yes" ] || [ "$CA_PRESERVED_STATE" = "already" ]; then'
VERIFY_END = "            VERIFY_FAILED=1\n        fi\n    fi\n"

#: shipped absolute path -> the tmp_path equivalent the harness runs against
UNINSTALL_PATHS = {
    'CA_PRESERVED_FILE="/var/lib/venya/ca/ca-key-passphrases.env"': 'CA_PRESERVED_FILE="$TEST_CA_DIR/ca-key-passphrases.env"',
    'CORE_ENV_FILE="/etc/venya/venya-core.env"': 'CORE_ENV_FILE="$TEST_ETC_DIR/venya-core.env"',
}
INSTALL_PATHS = {
    'CORE_ENV_FILE="/etc/venya/venya-core.env"': 'CORE_ENV_FILE="$TEST_ETC_DIR/venya-core.env"',
    'CA_PRESERVED_FILE="/var/lib/venya/ca/ca-key-passphrases.env"': 'CA_PRESERVED_FILE="$TEST_CA_DIR/ca-key-passphrases.env"',
    'ROOT_CA_KEY_PATH="/var/lib/venya/ca/ca.key"': 'ROOT_CA_KEY_PATH="$TEST_CA_DIR/ca.key"',
    'ADMIN_CA_KEY_PATH="/var/lib/venya/ca/admin-ca/admin-ca.key"': 'ADMIN_CA_KEY_PATH="$TEST_CA_DIR/admin-ca/admin-ca.key"',
}

GOOD_PP = "correct-horse-battery-staple-1"
ADMIN_PP = "correct-horse-battery-staple-2-admin"
WRONG_PP = "not-the-passphrase-at-all-3"


def _source(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def _region(text: str, start: str, end: str, label: str, swaps: dict[str, str]) -> str:
    """Lift the real region between two anchors and swap only its path constants.

    Every swap must land: a silent rename in the script fails here rather than leaving a
    cell that quietly tests nothing against ``/var/lib/venya``.
    """
    assert text.count(start) == 1, f"start anchor not unique in {label}: {start!r}"
    assert end in text[text.index(start) :], f"end anchor not found after the start in {label}"
    i = text.index(start)
    out = text[i : text.index(end, i) + len(end)]
    for old, new in swaps.items():
        assert out.count(old) == 1, f"{label}: path constant not found to swap: {old!r}"
        out = out.replace(old, new)
    return out


def uninstall_region() -> str:
    return _region(_source(UNINSTALLER), UNINSTALL_START, UNINSTALL_END, "uninstall-venya-core.sh", UNINSTALL_PATHS)


def precheck_region() -> str:
    return _region(_source(INSTALLER), PRECHECK_START, PRECHECK_END, "install-venya-core.sh", INSTALL_PATHS)


def verify_region() -> str:
    """The closing pair-verification block, lifted from the shipped script (no paths inside it)."""
    return _region(_source(UNINSTALLER), VERIFY_START, VERIFY_END, "uninstall-venya-core.sh (verify)", {})


def _encrypted_key(path: Path, passphrase: str) -> None:
    """A key in the shape the product writes: PKCS#8, EC P-256, BestAvailableEncryption."""
    path.parent.mkdir(parents=True, exist_ok=True)
    key = ec.generate_private_key(ec.SECP256R1())
    path.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.BestAvailableEncryption(passphrase.encode()),
        )
    )
    path.chmod(0o600)


def _stub_bin(tmp_path: Path) -> Path:
    """PATH stubs: the region's ownership pin needs root, and a cell does not run as root."""
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir(exist_ok=True)
    chown = bin_dir / "chown"
    chown.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    chown.chmod(0o755)
    return bin_dir


def _run(script: str, tmp_path: Path, env: dict[str, str], *, tty: bool = False) -> subprocess.CompletedProcess:
    """Run the harness. ``tty=True`` gives stdin a real pty, which is what ``[ -t 0 ]`` reads."""
    path = tmp_path / "run.sh"
    path.write_text(script, encoding="utf-8")
    full_env = {"PATH": f"{_stub_bin(tmp_path)}:/usr/bin:/bin", "HOME": str(tmp_path), **env}
    if not tty:
        return subprocess.run(
            ["/bin/bash", str(path)],
            cwd=str(tmp_path),
            env=full_env,
            capture_output=True,
            text=True,
            check=False,
            timeout=120,
        )
    master, slave = pty.openpty()
    try:
        proc = subprocess.run(
            ["/bin/bash", str(path)],
            cwd=str(tmp_path),
            env=full_env,
            stdin=slave,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            check=False,
            timeout=120,
        )
    finally:
        os.close(slave)
        os.close(master)
    return proc


def _harness(body: str, tmp_path: Path, env: dict[str, str], *, tty: bool = False) -> subprocess.CompletedProcess:
    """The helpers the lifted regions expect, plus a sentinel that says a mutation was reached."""
    script = (
        "set -euo pipefail\n"
        'info()  { echo "[INFO] $*"; }\n'
        'warn()  { echo "[WARN] $*"; }\n'
        'error() { echo "[ERROR] $*"; }\n'
        'venya_read_secret_confirm() { echo "PROMPTED $2"; }\n'
        "DB_PASSPHRASE_FLOOR=15\n"
        'ADMIN_MTLS_ENABLED="${TEST_ADMIN_MTLS:-true}"\n'
        'VENYA_SKIP_PROMPT="${TEST_SKIP_PROMPT:-}"\n'
        'VENYA_CA_KEY_PASSPHRASE="${TEST_VENYA_CA_KEY_PASSPHRASE:-}"\n'
        'VENYA_ADMIN_CA_PASSPHRASE="${TEST_VENYA_ADMIN_CA_PASSPHRASE:-}"\n'
        'mkdir_sentinel() { echo "MUTATED"; }\n'
        f"{body}\n"
        'echo "REACHED_END=1"\n'
    )
    return _run(script, tmp_path, env, tty=tty)


def _dirs(tmp_path: Path) -> dict[str, str]:
    (tmp_path / "etc-venya").mkdir(parents=True, exist_ok=True)
    (tmp_path / "ca").mkdir(parents=True, exist_ok=True)
    return {"TEST_ETC_DIR": str(tmp_path / "etc-venya"), "TEST_CA_DIR": str(tmp_path / "ca")}


def _env_file(tmp_path: Path, text: str) -> Path:
    p = tmp_path / "etc-venya" / "venya-core.env"
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(text, encoding="utf-8")
    return p


def _uninstall_run(tmp_path: Path, *, purge: str, ca_present: str) -> subprocess.CompletedProcess:
    body = f"""
PURGE_CA="{purge}"
CA_PRESENT="{ca_present}"
{uninstall_region()}
echo "KEPT=$CA_PRESERVED_STATE LINES=$CA_PRESERVED_LINES"
mkdir_sentinel
"""
    return _harness(body, tmp_path, _dirs(tmp_path))


# ---------------------------------------------------------------- the uninstaller side


def test_uninstaller_carries_both_passphrases_when_the_ca_is_kept(tmp_path):
    _env_file(tmp_path, f"VENYA_CA_KEY_PASSPHRASE={GOOD_PP}\nVENYA_ADMIN_CA_KEY_PASSPHRASE={ADMIN_PP}\nOTHER=1\n")
    out = _uninstall_run(tmp_path, purge="no", ca_present="yes")
    assert out.returncode == 0, out.stdout
    kept = tmp_path / "ca" / "ca-key-passphrases.env"
    assert (
        kept.read_text(encoding="utf-8")
        == f"VENYA_CA_KEY_PASSPHRASE={GOOD_PP}\nVENYA_ADMIN_CA_KEY_PASSPHRASE={ADMIN_PP}\n"
    )
    assert "OTHER=1" not in kept.read_text(
        encoding="utf-8"
    ), "the carried file holds the passphrase lines and nothing else"
    assert "MUTATED" in out.stdout
    assert oct(kept.stat().st_mode & 0o777) == "0o600", "a CA passphrase is not broadly readable"


def test_uninstaller_writes_the_file_before_any_removal(tmp_path):
    """Ordering is the guarantee: a refusal discovered after the removals is not a prevention."""
    text = _source(UNINSTALLER)
    assert text.index(UNINSTALL_START) < text.index("rm -rf /opt/venya /etc/venya /var/log/venya")
    assert text.index(UNINSTALL_START) < text.index('info "Stopping venya-core..."')


def test_uninstaller_preserves_nothing_on_the_purge_arm(tmp_path):
    """Paired negative: VENYA_PURGE_CA=yes still takes the CA and its passphrase down together."""
    _env_file(tmp_path, f"VENYA_CA_KEY_PASSPHRASE={GOOD_PP}\n")
    out = _uninstall_run(tmp_path, purge="yes", ca_present="yes")
    assert out.returncode == 0, out.stdout
    assert "KEPT=no LINES=0" in out.stdout
    assert not (tmp_path / "ca" / "ca-key-passphrases.env").exists()


def test_uninstaller_refuses_before_touching_state_when_the_source_is_a_symlink(tmp_path):
    """Paired negative, the #755 shape: a symlinked passphrase source stops the run early."""
    real = tmp_path / "elsewhere.env"
    real.write_text(f"VENYA_CA_KEY_PASSPHRASE={GOOD_PP}\n", encoding="utf-8")
    (tmp_path / "etc-venya").mkdir(parents=True, exist_ok=True)
    (tmp_path / "etc-venya" / "venya-core.env").symlink_to(real)
    out = _uninstall_run(tmp_path, purge="no", ca_present="yes")
    assert out.returncode == 1, out.stdout
    assert "refusing to read a CA key passphrase through it" in out.stdout
    assert "Nothing was removed" in out.stdout
    assert "VENYA_PURGE_CA=yes" in out.stdout, "the refusal names the remedies, not just the error"
    assert "MUTATED" not in out.stdout
    assert not (tmp_path / "ca" / "ca-key-passphrases.env").exists()


def test_uninstaller_refuses_before_touching_state_when_the_sink_is_a_symlink(tmp_path):
    """Paired negative, D-1 (leg 1206): the write side of #755. A `>` follows a symlinked
    destination, so a link planted at the preserved-file name by the service account would
    take both passphrases outside the CA directory — refuse on lstat before any removal."""
    _env_file(tmp_path, f"VENYA_CA_KEY_PASSPHRASE={GOOD_PP}\nVENYA_ADMIN_CA_KEY_PASSPHRASE={ADMIN_PP}\n")
    canary = tmp_path / "outside-the-ca-dir"
    canary.write_text("CANARY-ORIGINAL-CONTENT\n", encoding="utf-8")
    sink = tmp_path / "ca" / "ca-key-passphrases.env"
    sink.parent.mkdir(parents=True, exist_ok=True)
    sink.symlink_to(canary)
    out = _uninstall_run(tmp_path, purge="no", ca_present="yes")
    assert out.returncode == 1, out.stdout
    assert "refusing to write a CA key passphrase through it" in out.stdout
    assert "Nothing was removed" in out.stdout
    assert "VENYA_PURGE_CA=yes" in out.stdout, "the refusal names the remedies, not just the error"
    assert "MUTATED" not in out.stdout, "the run stops before the mutation sentinel"
    # Nit N-3 (leg 1213): the lifted region ENDS above the script's `Left in place` lines,
    # so asserting the string's absence in THIS run's stdout could never fail. The claim
    # is real but its mechanism is the exit: the refusal is ABOVE every report print in
    # the shipped file, so assert the order in the full script instead.
    text = _source(UNINSTALLER)
    assert 0 < text.index("refusing to write a CA key passphrase through it") < text.index("Left in place:")
    assert canary.read_text(encoding="utf-8") == "CANARY-ORIGINAL-CONTENT\n", "the link target keeps its bytes"
    assert sink.is_symlink(), "the refusal names the link, it does not delete or follow it"


def test_uninstaller_replaces_a_preexisting_regular_sink_file_on_a_fresh_inode(tmp_path):
    """Paired negative, D-2 (leg 1213): `>` truncates and REUSES the inode already at the
    destination, so a regular file the directory's owning account created and still holds
    open takes both passphrase lines and then passes every end-state check the block
    makes. The write must land on a fresh inode: house #381 form, mv -T variant."""
    _env_file(tmp_path, f"VENYA_CA_KEY_PASSPHRASE={GOOD_PP}\nVENYA_ADMIN_CA_KEY_PASSPHRASE={ADMIN_PP}\n")
    sink = tmp_path / "ca" / "ca-key-passphrases.env"
    sink.parent.mkdir(parents=True, exist_ok=True)
    sink.write_text("OLD\n", encoding="utf-8")
    inode_before = sink.stat().st_ino
    with sink.open("r+", encoding="utf-8") as held:  # the descriptor opened before the run
        out = _uninstall_run(tmp_path, purge="no", ca_present="yes")
        assert out.returncode == 0, out.stdout
        assert "KEPT=yes LINES=2" in out.stdout
        held.seek(0)
        seen = held.read()
    assert sink.stat().st_ino != inode_before, "the preserved file is created fresh, not written into"
    assert "PASSPHRASE" not in seen, "a descriptor opened before the run never sees the carried lines"
    assert seen == "OLD\n", "the pre-existing inode keeps exactly its own bytes"
    assert sink.read_text(encoding="utf-8") == (
        f"VENYA_CA_KEY_PASSPHRASE={GOOD_PP}\nVENYA_ADMIN_CA_KEY_PASSPHRASE={ADMIN_PP}\n"
    ), "the new inode holds the carried pair"
    assert sorted(p.name for p in (tmp_path / "ca").iterdir()) == [
        "ca-key-passphrases.env"
    ], "the fresh temp name is consumed by the rename — no stray file left in the CA dir"
    assert oct(sink.stat().st_mode & 0o777) == "0o600"


def test_uninstaller_pair_verify_refuses_a_symlinked_sink_without_following_it(tmp_path):
    """Reporting half of D-1: [ -f ] and stat -c '%a' both FOLLOW a link, so the pair check
    must test -L first — a 0600 target outside the CA dir must not certify as the pair."""
    victim = tmp_path / "victim"
    victim.write_text("x\n", encoding="utf-8")
    victim.chmod(0o600)
    sink = tmp_path / "ca" / "ca-key-passphrases.env"
    sink.parent.mkdir(parents=True, exist_ok=True)
    sink.symlink_to(victim)
    body = f"""
CA_PRESERVED_FILE="$TEST_CA_DIR/ca-key-passphrases.env"
CA_PRESERVED_STATE="already"
VERIFY_FAILED=0
{verify_region()}
echo "VERIFY_FAILED=$VERIFY_FAILED"
"""
    out = _harness(body, tmp_path, _dirs(tmp_path))
    assert out.returncode == 0, out.stdout
    assert "VERIFY_FAILED=1" in out.stdout, "a symlinked sink is refused, not certified through the link"
    assert "is a symlink" in out.stdout


def test_uninstaller_reports_already_preserved_on_a_second_run(tmp_path):
    """No /etc/venya left, the kept file there: the host is still uninstallable, and hears the truth."""
    kept = tmp_path / "ca" / "ca-key-passphrases.env"
    kept.parent.mkdir(parents=True, exist_ok=True)
    kept.write_text(f"VENYA_CA_KEY_PASSPHRASE={GOOD_PP}\n", encoding="utf-8")
    out = _uninstall_run(tmp_path, purge="no", ca_present="yes")
    assert out.returncode == 0, out.stdout
    assert "KEPT=already" in out.stdout
    assert kept.read_text(encoding="utf-8").count("\n") == 1, "an earlier run's file is not widened"
    assert "MUTATED" in out.stdout


def test_uninstaller_writes_no_empty_file_when_there_is_nothing_to_carry(tmp_path):
    """Paired negative: an already-stranded host is uninstallable and is told what a reinstall needs."""
    out = _uninstall_run(tmp_path, purge="no", ca_present="yes")
    assert out.returncode == 0, out.stdout
    assert "KEPT=absent LINES=0" in out.stdout
    assert not (tmp_path / "ca" / "ca-key-passphrases.env").exists()


def test_uninstaller_does_nothing_when_no_ca_was_ever_installed(tmp_path):
    """Paired negative: a host this script never wrote keeps its old behavior exactly."""
    out = _uninstall_run(tmp_path, purge="no", ca_present="no")
    assert out.returncode == 0, out.stdout
    assert "KEPT=no LINES=0" in out.stdout


def test_the_two_scripts_name_one_preserved_path():
    """Interlock: the writer and the reader must agree, or the pair is never reunited."""
    written = re.search(r'^CA_PRESERVED_FILE="([^"]+)"', _source(UNINSTALLER), re.MULTILINE).group(1)
    read = re.search(r'^CA_PRESERVED_FILE="([^"]+)"', _source(INSTALLER), re.MULTILINE).group(1)
    assert written == read == "/var/lib/venya/ca/ca-key-passphrases.env"


# ------------------------------------------------------------------ the installer side


def _precheck_run(
    tmp_path: Path, *, admin_mtls: str = "true", extra_env: dict[str, str] | None = None, tty: bool = False
) -> subprocess.CompletedProcess:
    body = f"""
{precheck_region()}
mkdir_sentinel
"""
    env = _dirs(tmp_path)
    env["TEST_ADMIN_MTLS"] = admin_mtls
    env.update(extra_env or {})
    return _harness(body, tmp_path, env, tty=tty)


def _keys(tmp_path: Path, *, root_pp: str = GOOD_PP, admin_pp: str = ADMIN_PP) -> None:
    _encrypted_key(tmp_path / "ca" / "ca.key", root_pp)
    _encrypted_key(tmp_path / "ca" / "admin-ca" / "admin-ca.key", admin_pp)


def test_installer_refuses_a_wrong_passphrase_before_any_mutation(tmp_path):
    _keys(tmp_path)
    out = _precheck_run(tmp_path, extra_env={"TEST_VENYA_CA_KEY_PASSPHRASE": WRONG_PP})
    assert out.returncode == 1, out.stdout
    assert "does not open" in out.stdout
    assert "Nothing else has been changed" in out.stdout
    assert "VENYA_PURGE_CA=yes" in out.stdout
    assert "MUTATED" not in out.stdout, "the refusal lands before the mutation sentinel"


def test_installer_accepts_the_passphrases_kept_beside_a_preserved_ca(tmp_path):
    """The 244 close: after a default uninstall, a reinstall with no env override opens both keys."""
    _keys(tmp_path)
    (tmp_path / "ca").mkdir(parents=True, exist_ok=True)
    (tmp_path / "ca" / "ca-key-passphrases.env").write_text(
        f"VENYA_CA_KEY_PASSPHRASE={GOOD_PP}\nVENYA_ADMIN_CA_KEY_PASSPHRASE={ADMIN_PP}\n", encoding="utf-8"
    )
    out = _precheck_run(tmp_path)
    assert out.returncode == 0, out.stdout
    assert "root CA key opens with the passphrase" in out.stdout
    assert "admin CA key opens with the passphrase" in out.stdout
    assert "MUTATED" in out.stdout


def test_installer_prefers_the_live_env_file_over_the_preserved_copy(tmp_path):
    """Precedence: an in-place re-run reads its own EnvironmentFile; the kept file is the fallback."""
    _encrypted_key(tmp_path / "ca" / "ca.key", GOOD_PP)
    _env_file(tmp_path, f"VENYA_CA_KEY_PASSPHRASE={GOOD_PP}\n")
    (tmp_path / "ca" / "ca-key-passphrases.env").write_text("VENYA_CA_KEY_PASSPHRASE=stale-value\n", encoding="utf-8")
    out = _precheck_run(tmp_path, admin_mtls="false")
    assert out.returncode == 0, out.stdout
    assert "root CA key opens" in out.stdout


def test_installer_refuses_when_a_key_exists_and_no_passphrase_is_available(tmp_path):
    """The unattended door, which used to mint a random passphrase and die later in the run."""
    _encrypted_key(tmp_path / "ca" / "ca.key", GOOD_PP)
    out = _precheck_run(tmp_path, admin_mtls="false")
    assert out.returncode == 1, out.stdout
    assert "no passphrase for it" in out.stdout
    assert "re-run with VENYA_CA_KEY_PASSPHRASE" in out.stdout
    assert "MUTATED" not in out.stdout


def test_installer_defers_to_the_prompt_on_an_interactive_door(tmp_path):
    """Paired negative: a TTY run keeps its prompt — the early check must not pre-empt a human."""
    _encrypted_key(tmp_path / "ca" / "ca.key", GOOD_PP)
    out = _precheck_run(tmp_path, admin_mtls="false", tty=True)
    assert out.returncode == 0, out.stdout
    assert "no passphrase for it" not in out.stdout
    assert "this run prompts for one below" in out.stdout
    assert "MUTATED" in out.stdout


def test_installer_is_a_noop_when_no_ca_key_exists(tmp_path):
    """Paired negative: a fresh install is untouched by this check — no key, nothing to open."""
    out = _precheck_run(tmp_path)
    assert out.returncode == 0, out.stdout
    assert "CA key opens" not in out.stdout
    assert "MUTATED" in out.stdout


def test_installer_skips_the_admin_plane_when_admin_mtls_is_off(tmp_path):
    """Paired negative: the admin probe runs only where the admin block runs."""
    _keys(tmp_path)
    (tmp_path / "ca" / "ca-key-passphrases.env").write_text(f"VENYA_CA_KEY_PASSPHRASE={GOOD_PP}\n", encoding="utf-8")
    out = _precheck_run(tmp_path, admin_mtls="false")
    assert out.returncode == 0, out.stdout
    assert "admin CA key" not in out.stdout


def test_installer_refuses_a_symlinked_passphrase_source(tmp_path):
    """#755 carried to the reader too: a symlink is not a secret store, so nothing is read."""
    _encrypted_key(tmp_path / "ca" / "ca.key", GOOD_PP)
    real = tmp_path / "elsewhere.env"
    real.write_text(f"VENYA_CA_KEY_PASSPHRASE={GOOD_PP}\n", encoding="utf-8")
    (tmp_path / "ca").mkdir(parents=True, exist_ok=True)
    (tmp_path / "ca" / "ca-key-passphrases.env").symlink_to(real)
    out = _precheck_run(tmp_path, admin_mtls="false")
    assert out.returncode == 1, out.stdout
    # The notice goes to stderr: this function's stdout is the answer, and a warn mixed into
    # it is read back as a filename (the first draft of this cell caught exactly that).
    assert "not reading a CA passphrase through it" in out.stderr
    assert "no passphrase for it" in out.stdout
    assert "can't read" not in out.stderr, out.stderr
    assert "MUTATED" not in out.stdout


def test_installer_check_runs_before_the_first_mutation():
    """Ordering on the shipped file, not only in the lifted region."""
    text = _source(INSTALLER)
    assert text.index('venya_ca_key_precheck "root"') < text.index("venya_create_user")
    assert text.index('venya_ca_key_precheck "root"') < text.index("venya_create_venv")
    assert text.index('venya_ca_key_precheck "root"') < text.index("Installing PostgreSQL")


def test_installer_drops_the_preserved_copy_once_the_env_file_holds_both_again():
    """One plaintext copy per live install: the kept file spans the gap an uninstall opens."""
    text = _source(INSTALLER)
    assert text.index('rm -f "$CA_PRESERVED_FILE"') > text.index("chmod 0640 /etc/venya/venya-core.env")
    assert text.count("$(venya_ca_passphrase_source VENYA_ADMIN_CA_KEY_PASSPHRASE || true)") == 1
    assert text.count("$(venya_ca_passphrase_source VENYA_CA_KEY_PASSPHRASE || true)") == 1
    assert text.count('venya_ca_passphrase_source "$line_name"') == 1
