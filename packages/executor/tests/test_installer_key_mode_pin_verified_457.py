# Copyright (c) 2026 Tabith LLC.
# Use of this source code is governed by the Business Source License 1.1
# included in the LICENSE file at the root of this repository. As of the
# Change Date listed there, the work is available under MPL 2.0.
# SPDX-License-Identifier: BUSL-1.1

"""Executor installer #457: the key-material mode pin must be VERIFIED, not assumed.

Incumbent shape (``install-venya-executor.sh`` hardening block)::

    find /etc/venya/executor -name '*.key' -exec   chmod 600 {} \\; 2>/dev/null || true
    find /etc/venya/executor -name '*.crt' -exec   chmod 644 {} \\; 2>/dev/null || true
    info "Executor credentials hardened (venya:venya, dir 700, key 600, cert 644)"

``2>/dev/null || true`` discarded chmod's stderr AND its exit status, and nothing
re-read the modes afterwards, so a pin that silently no-op'd still printed the
"credentials hardened" success line -- on the exact file class whose
``:600 -> :602`` exposure window this same script documents.

Ruled shape (ticket #457 AC-1/AC-2): the chmod pass keeps its diagnostics, its
exit status is captured (``|| RC=$?``, the REG_EXIT house pattern -- a bare
failing command would otherwise die mid-pass under ``set -e`` with no path or
mode named), and every ``*.key`` / ``*.crt`` file is re-read with ``stat -c '%a'``.
Any mode that does not match the pin is a loud ``[ERROR]`` naming the path and
the mode found, and the install exits 1 -- never a warning, never silence.

Cells run the REAL block, extracted from the git-tracked root installer (house
pattern: #505/#519 execute real script logic against fixtures; #28 extracts a
between-anchors fragment and redirects the absolute path), under the installer's
own ``set -euo pipefail``. The credential dir is redirected to a tmp fixture, so
no VM, no install and no root is involved. Truth-table rule: every accept (a
correctly-pinned install completes) has its paired reject (a bad mode refuses),
and the rejects cover BOTH failure channels -- a chmod that fails, and a chmod
that lies (exits 0 having changed nothing).
"""

import os
import stat
import subprocess
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[3]
INSTALLER = REPO_ROOT / "install-venya-executor.sh"

BEGIN = "# --- #457: the mode pin is not believed until stat() says so"
END = 'info "Executor credentials hardened (venya:venya, dir 700, key 600, cert 644)"'
CRED_DIR = "/etc/venya/executor"
DONE_SENTINEL = "HARDENING-BLOCK-COMPLETED"

# The incumbent discard shape, verbatim from the pre-fix tip (AC-1 / cell T4).
OLD_KEY_PIN = "find /etc/venya/executor -name '*.key' -exec   chmod 600 {} \\; 2>/dev/null || true"
OLD_CRT_PIN = "find /etc/venya/executor -name '*.crt' -exec   chmod 644 {} \\; 2>/dev/null || true"


def _installer_source() -> str:
    return INSTALLER.read_text(encoding="utf-8")


def _fragment() -> str:
    """The real hardening/verification block, anchors inclusive."""
    src = _installer_source()
    assert BEGIN in src, "verification block anchor moved -- re-anchor this cell"
    assert END in src, "success-line anchor moved -- re-anchor this cell"
    start = src.index(BEGIN)
    stop = src.index(END, start) + len(END)
    block = src[start:stop]
    assert CRED_DIR in block, "block must reference the credential dir to be redirected"
    return block


def _make_tree(root: Path, spec: dict[str, int]) -> Path:
    """Create the credential dir and the named files at the given modes."""
    cred = root / "executor"
    cred.mkdir(parents=True, exist_ok=True)
    for name, mode in spec.items():
        path = cred / name
        path.write_bytes(b"material\n")
        os.chmod(path, mode)
    return cred


def _run_block(cred_dir: Path, tmp_path: Path, extra_path: Path | None = None) -> subprocess.CompletedProcess:
    """Execute the extracted block against the fixture dir.

    ``extra_path`` prepends a directory to PATH (used to install a stub
    ``chmod``); the block runs under the installers' own ``set -euo pipefail``
    with the info/error names ``venya_print_colors`` provides.
    """
    body = _fragment().replace(CRED_DIR, f"{str(cred_dir)!r}")
    script = tmp_path / "harden_block.sh"
    script.write_text(
        "set -euo pipefail\n"
        'info()  { echo "[INFO]  $*"; }\n'
        'error() { echo "[ERROR] $*"; }\n'
        f"{body}\n"
        f'echo "{DONE_SENTINEL}"\n',
        encoding="utf-8",
    )
    env = dict(os.environ)
    if extra_path is not None:
        env["PATH"] = f"{extra_path}{os.pathsep}{env['PATH']}"
    return subprocess.run(
        ["bash", str(script)],
        capture_output=True,
        text=True,
        check=False,
        env=env,
    )


def _stub_chmod(tmp_path: Path, *, exit_code: int, touch: bool) -> Path:
    """PATH stub for chmod: no-op with a chosen status (``touch=True`` still
    applies the mode, i.e. an honest pass; ``touch=False`` changes nothing)."""
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir(exist_ok=True)
    stub = bin_dir / "chmod"
    body = "#!/bin/sh\n"
    if touch:
        body += '/bin/chmod "$@"\n'
    body += f"exit {exit_code}\n"
    stub.write_text(body, encoding="utf-8")
    stub.chmod(stub.stat().st_mode | stat.S_IEXEC | stat.S_IXGRP | stat.S_IXOTH)
    return bin_dir


def _modes(cred_dir: Path) -> dict[str, str]:
    return {p.name: oct(p.stat().st_mode & 0o777)[2:] for p in sorted(cred_dir.iterdir())}


class TestExecutorKeyModePinVerified457:
    # ------------------------------------------------------------------ source
    def test_bash_syntax_clean(self) -> None:
        """AC-3: the installer parses clean."""
        proc = subprocess.run(["bash", "-n", str(INSTALLER)], capture_output=True, text=True, check=False)
        assert proc.returncode == 0, proc.stdout + proc.stderr

    def test_t4_incumbent_discard_shape_is_gone(self) -> None:
        """AC-1 / cell T4: both `2>/dev/null || true` pin lines are gone from the
        git-tracked root copy, and the new pin lines carry no stderr discard."""
        src = _installer_source()
        assert OLD_KEY_PIN not in src, "old key pin (stderr+status discarded) survived"
        assert OLD_CRT_PIN not in src, "old cert pin (stderr+status discarded) survived"
        for line in _fragment().splitlines():
            if line.strip().startswith("find ") and "-exec chmod" in line:
                assert "2>/dev/null" not in line, f"pin pass still discards stderr: {line}"
                assert "|| true" not in line, f"pin pass still swallows status: {line}"

    def test_verification_sits_between_the_pin_and_the_success_line(self) -> None:
        """Ordering pin (house style of test_installer_mode_preservation_381):
        pin -> stat verification -> only then the success claim."""
        src = _installer_source()
        pin = "find /etc/venya/executor -name '*.key' -exec chmod 600 {} + || KEY_PIN_RC=$?"
        verify = "done < <(find /etc/venya/executor -type f -name '*.key' -print0)"
        refuse = 'error "Executor credential hardening FAILED with $CRED_ERRORS error(s)'
        assert pin in src and verify in src and refuse in src
        assert src.index(pin) < src.index(verify) < src.index(refuse) < src.index(END)

    def test_pass_is_mode_only_and_sets_no_ownership(self) -> None:
        """The daemon (User=venya, ReadOnlyPaths=/etc/venya) must READ these
        files: the block re-checks MODES only and never chowns, so a correct
        install keeps the venya:venya ownership the chown -R above it sets.
        (The incumbent bug class is a silently unapplied pin; tightening
        ownership here would be a different, false-refusing change.)"""
        for line in _fragment().splitlines():
            stripped = line.strip()
            if stripped.startswith("#"):
                continue
            assert "chown" not in stripped, f"verification block runs chown: {stripped}"

    def test_pin_pass_uses_the_batch_exec_form_that_propagates_failure(self) -> None:
        """Measured regression pin: `find ... -exec chmod 600 {} \\;` exits 0
        even when chmod exits 1, so the `\\;` form would keep swallowing the
        failure behind `|| RC=$?`. The pins must use the `+` batch form."""
        src = _installer_source()
        assert "-exec chmod 600 {} + || KEY_PIN_RC=$?" in src
        assert "-exec chmod 644 {} + || CRT_PIN_RC=$?" in src
        # negative half, command lines only: the block's own comment quotes the
        # old `\;` shape as history, which is text, not an executed pin.
        for line in src.splitlines():
            if line.strip().startswith("#"):
                continue
            assert "-exec chmod 600 {} \\;" not in line, f"per-file pin survived: {line}"
            assert "-exec chmod 644 {} \\;" not in line, f"per-file pin survived: {line}"

    # ------------------------------------------------------------------ accepts
    def test_t2_correctly_pinned_install_completes(self, tmp_path: Path) -> None:
        """AC-2 paired negative (the point of the fix): key 600 + certs 644,
        real chmod -- the block completes, claims success exactly once, and
        touches no mode."""
        cred = _make_tree(tmp_path, {"executor.key": 0o600, "executor.crt": 0o644, "ca.crt": 0o644})
        before = _modes(cred)
        proc = _run_block(cred, tmp_path)
        out = proc.stdout + proc.stderr
        assert proc.returncode == 0, out
        assert DONE_SENTINEL in out, f"block aborted a correct install: {out}"
        assert out.count("Executor credentials hardened") == 1, out
        assert "[ERROR]" not in out, out
        assert _modes(cred) == before == {"ca.crt": "644", "executor.crt": "644", "executor.key": "600"}

    def test_t2_ownership_survives_the_pass(self, tmp_path: Path) -> None:
        """The paired negative also proves the service user is not locked out:
        uid/gid are byte-identical across the pass (mode-only verification)."""
        cred = _make_tree(tmp_path, {"executor.key": 0o600, "executor.crt": 0o644})
        before = {p.name: (p.stat().st_uid, p.stat().st_gid) for p in cred.iterdir()}
        proc = _run_block(cred, tmp_path)
        assert proc.returncode == 0, proc.stdout + proc.stderr
        after = {p.name: (p.stat().st_uid, p.stat().st_gid) for p in cred.iterdir()}
        assert after == before

    def test_t2_loose_modes_are_pinned_and_then_accepted(self, tmp_path: Path) -> None:
        """A re-install over a loose tree is FIXED, not refused: key lands 600,
        cert lands 644, then verification passes (the pin is the repair; the
        verification only refuses a pin that did not land)."""
        cred = _make_tree(tmp_path, {"executor.key": 0o644, "executor.crt": 0o600})
        proc = _run_block(cred, tmp_path)
        out = proc.stdout + proc.stderr
        assert proc.returncode == 0, out
        assert _modes(cred) == {"executor.crt": "644", "executor.key": "600"}, out

    def test_t7_no_key_material_deferred_registration_completes(self, tmp_path: Path) -> None:
        """A host that deferred registration (CA not installed -> no cert/key
        yet) has nothing to verify and must still complete -- the pass refuses a
        bad mode, never an absent file."""
        cred = _make_tree(tmp_path, {})
        (cred / "readme.txt").write_text("no key material yet\n")
        proc = _run_block(cred, tmp_path)
        out = proc.stdout + proc.stderr
        assert proc.returncode == 0, out
        assert DONE_SENTINEL in out, out

    # ------------------------------------------------------------------ rejects
    def test_t3_key_left_loose_by_a_failing_chmod_is_refused(self, tmp_path: Path) -> None:
        """T3 (headline): chmod fails outright and the key stays 644 -- the
        verification pass must exit non-zero, name the path and the mode found,
        and issue NO success claim."""
        cred = _make_tree(tmp_path, {"executor.key": 0o644, "executor.crt": 0o644})
        stub = _stub_chmod(tmp_path, exit_code=1, touch=False)
        proc = _run_block(cred, tmp_path, extra_path=stub)
        out = proc.stdout + proc.stderr
        assert proc.returncode != 0, f"loose key accepted: {out}"
        assert DONE_SENTINEL not in out, out
        assert "Executor credentials hardened" not in out, f"success claim on a failed pin: {out}"
        assert "Executor key material is not mode 600" in out, out
        assert "is mode 644" in out, out
        assert "executor.key" in out, out
        # the pass status is no longer discarded either:
        assert "chmod 600 pass over" in out, out

    def test_chmod_that_lies_is_still_refused(self, tmp_path: Path) -> None:
        """The second failure channel: chmod exits 0 having changed NOTHING
        (the incumbent silent no-op). The pin status looks fine, so only the
        stat() verification can catch it -- and it does."""
        cred = _make_tree(tmp_path, {"executor.key": 0o600, "executor.crt": 0o644})
        os.chmod(cred / "executor.key", 0o640)
        stub = _stub_chmod(tmp_path, exit_code=0, touch=False)
        proc = _run_block(cred, tmp_path, extra_path=stub)
        out = proc.stdout + proc.stderr
        assert proc.returncode != 0, f"lying chmod accepted: {out}"
        assert "Executor key material is not mode 600" in out, out
        assert "is mode 640" in out, out
        assert "Executor credentials hardened" not in out, out
        assert _modes(cred)["executor.key"] == "640", "stub must not have touched the mode"

    def test_cert_pinned_loose_is_refused_too(self, tmp_path: Path) -> None:
        """The sibling `.crt` line carries the same discard shape and is IN
        scope (see report): a cert that ends up off its documented 644 is
        refused, named by path and mode -- and the key line is NOT blamed."""
        cred = _make_tree(tmp_path, {"executor.key": 0o600, "executor.crt": 0o600})
        stub = _stub_chmod(tmp_path, exit_code=0, touch=False)
        proc = _run_block(cred, tmp_path, extra_path=stub)
        out = proc.stdout + proc.stderr
        assert proc.returncode != 0, f"loose cert accepted: {out}"
        assert "Executor certificate is not mode 644" in out, out
        assert "executor.crt" in out, out
        assert "key material is not mode" not in out, out

    def test_every_offending_file_is_named_not_just_the_first(self, tmp_path: Path) -> None:
        """The error counter reports every offender and the total, so an
        operator sees the whole exposure instead of one file at a time."""
        cred = _make_tree(
            tmp_path,
            {"executor.key": 0o644, "ca.key": 0o666, "executor.crt": 0o600},
        )
        stub = _stub_chmod(tmp_path, exit_code=0, touch=False)
        proc = _run_block(cred, tmp_path, extra_path=stub)
        out = proc.stdout + proc.stderr
        assert proc.returncode != 0, out
        assert "executor.key" in out and "ca.key" in out and "executor.crt" in out, out
        assert "3 error(s)" in out, out

    def test_t5_non_key_material_is_never_inspected(self, tmp_path: Path) -> None:
        """T5: the globs are extension-specific. With the REAL chmod pass over a
        tree that also holds a deliberate 0640 `.pub`, a 0666 `.txt` and a 0600
        `.pem`, the install completes, none of those files is ever named, and
        each keeps its own mode -- proof the pass cannot widen past `*.key` /
        `*.crt` (which is where a false refusal would come from) and that no
        `.crt` is caught by the key check or vice versa."""
        cred = _make_tree(
            tmp_path,
            {
                "executor.key": 0o600,
                "executor.crt": 0o644,
                "ca.crt": 0o644,
                "executor.pub": 0o640,
                "notes.txt": 0o666,
                "legacy.pem": 0o600,
            },
        )
        proc = _run_block(cred, tmp_path)
        out = proc.stdout + proc.stderr
        assert proc.returncode == 0, f"non-key material caught by the check: {out}"
        for innocent in ("executor.pub", "notes.txt", "legacy.pem"):
            assert innocent not in out, f"block named a file outside its globs: {innocent} in {out}"
        assert _modes(cred) == {
            "ca.crt": "644",
            "executor.crt": "644",
            "executor.key": "600",
            "executor.pub": "640",
            "legacy.pem": "600",
            "notes.txt": "666",
        }, "the block widened past its globs"
        assert DONE_SENTINEL in out, out

    def test_block_uses_stat_and_fails_loudly_not_with_a_warning(self) -> None:
        """The ruled shape: the check is a hard error + exit 1, never a warn.
        Converting it to a warning is a violation class here, not a fix."""
        block = _fragment()
        assert "stat -c '%a'" in block, "verification must re-read the mode with stat(1)"
        assert "exit 1" in block, "a failed verification must fail the install"
        assert "warn " not in block, "verification failure reported as a warning"

    def test_fragment_executes_under_installer_shell_options(self, tmp_path: Path) -> None:
        """Harness guard: the fixture runs the block under the installer's own
        `set -euo pipefail`, so an unset-variable or errexit regression inside
        the block fails here rather than on a VM."""
        assert "set -euo pipefail" in _installer_source().splitlines(), "installer shell options changed"
        cred = _make_tree(tmp_path, {"executor.key": 0o600})
        proc = _run_block(cred, tmp_path)
        assert proc.returncode == 0, proc.stdout + proc.stderr
        # the harness script really declares them (not just the source):
        scripts = list(tmp_path.glob("harden_block.sh"))
        assert scripts and scripts[0].read_text().startswith("set -euo pipefail\n")

    def test_empty_credential_dir_does_not_vacuously_claim_a_verified_pin(self, tmp_path: Path) -> None:
        """The vacuous-pass trap this block must not introduce: if the credential
        dir is MISSING, the find in the process substitution yields no files --
        but the chmod pass still sees find's non-zero status, so the install
        fails loudly instead of passing on zero iterations."""
        missing = tmp_path / "not-here"
        body = _fragment().replace(CRED_DIR, f"{str(missing)!r}")
        script = tmp_path / "missing_dir.sh"
        script.write_text(
            "set -euo pipefail\n"
            'info()  { echo "[INFO]  $*"; }\n'
            'error() { echo "[ERROR] $*"; }\n'
            f"{body}\n"
            f'echo "{DONE_SENTINEL}"\n',
            encoding="utf-8",
        )
        proc = subprocess.run(["bash", str(script)], capture_output=True, text=True, check=False)
        out = proc.stdout + proc.stderr
        assert proc.returncode != 0, f"missing credential dir accepted: {out}"
        assert DONE_SENTINEL not in out, out


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(pytest.main([__file__, "-v"]))
