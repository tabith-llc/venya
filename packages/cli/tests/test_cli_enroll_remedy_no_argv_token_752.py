# Copyright (c) 2026 Tabith LLC.
# Use of this source code is governed by the Business Source License 1.1
# included in the LICENSE file at the root of this repository. As of the
# Change Date listed there, the work is available under MPL 2.0.
# SPDX-License-Identifier: BUSL-1.1

"""#752 — the enroll remedy must not put the one-use token on argv, and must not
stage the bundle in /tmp.

`venya admin executor-enroll --output-dir` prints the operator's next step. The
shipped text put the token assignment in the same `VAR=value` position after
`sudo` as the server URL and the executor id. The shell expands that assignment
before `sudo` runs, so the value becomes one of `sudo`'s ARGUMENTS, readable in
/proc/<pid>/cmdline for the whole install window — which for a one-use token is
its entire lifetime. `install-venya-executor.sh` states the opposite rule about
the executor key passphrase it carries: that one arrives by environment, because
argv would put the live value in /proc/*/cmdline, and its register call
prefixes `VENYA_EXECUTOR_ENROLLMENT_TOKEN="${...:-}"` on the child. The same block
scp'd the token-bearing bundle to `:/tmp/`, a world-writable directory on the
target, after the mint protected that same token on the source with
`os.fchmod(0o600)` before `os.replace`.

Precedent cited, not re-opened: #151/#89 (this verb hides the token behind
`--show-sensitive`) and #149/#87 (the receiving side passes it explicitly).

Two arms, both required by the ticket's paired negative, in one changeset:

1. STATIC — read the printed block: no `sudo VAR=` assignment form, no `/tmp`
   staging, no hard-coded ssh account, every interpolated path quoted, and the
   minted value never echoed.
2. BEHAVIORAL — EXECUTE the printed invocation with a stand-in curl and a
   stand-in installer that records its own argv from /proc/<pid>/cmdline, then
   assert the value is in NO recorded argv while it DID reach the child's
   environment.
   A merely quiet remedy is not what is tested: delivery is asserted too.

Positive control: the same probe against the legacy shape must SEE the value in
argv. Without it, an empty probe log and a safe shape are indistinguishable and a
zero is believed for no reason.

PROBE is a sentinel, not a credential. No cell here holds or prints a real token,
and the shipped text is asserted never to print one.

Substitution disclosed: the behavioral arm replaces the printed staging prefix
`/home/<executor-ssh-user>/.venya-enroll/` with a real directory, because a unit
test has no remote host and no second account. The assignment structure, the
`$(cat "$ENROLL_DIR/token")` shape and the child it launches are the shipped
bytes — that is the property under test.
"""

import re
import subprocess
from pathlib import Path
from unittest.mock import MagicMock

from test_cli_enroll_token_bundle import _args, _make_client, _make_response
from venya_cli.commands import cmd_admin_executor_enroll

PROBE = "PROBE-not-a-credential-752"
EXECUTOR_ID = "venya-exec-9"
STAGE_PREFIX = "/home/<executor-ssh-user>/.venya-enroll/"

_INSTALLER_STUB = """#!/bin/bash
{ printf 'ARGV='; tr '\\0' ' ' < "/proc/$$/cmdline"; printf '\\n'; } >> "$PROBE_LOG"
printf 'ENV_PRESENT=%s\\n' "${VENYA_EXECUTOR_ENROLLMENT_TOKEN:+yes}" >> "$PROBE_LOG"
printf 'VALUE_MATCH=%s\\n' "$([ "$VENYA_EXECUTOR_ENROLLMENT_TOKEN" = "$EXPECT_PROBE" ] && echo yes)" >> "$PROBE_LOG"
printf 'CA_SEEN=%s\\n' "${VENYA_VENYA_CA_FILE:+yes}" >> "$PROBE_LOG"
"""

_CURL_STUB = """#!/bin/bash
args=("$@"); i=0
while [ $i -lt ${#args[@]} ]; do
  if [ "${args[$i]}" = "-o" ]; then cp "$FAKE_INSTALLER" "${args[$((i+1))]}"; fi
  i=$((i+1))
done
"""

_SUDO_STUB = """#!/bin/bash
{ printf 'ARGV='; tr '\\0' ' ' < "/proc/$$/cmdline"; printf '\\n'; } >> "$PROBE_LOG"
"""

_LEGACY_SHAPE = (
    "curl -fsSL http://example.invalid/install-venya-executor.sh | "
    'sudo VENYA_EXECUTOR_ENROLLMENT_TOKEN="$(cat "$ENROLL_DIR/token")" bash -s\n'
)


def _print_remedy(tmp_path, monkeypatch, capsys, ca=True):
    """Run the real mint against a stubbed server; hand back its printed stdout."""
    fake_ca = tmp_path / "source-ca.crt"
    fake_ca.write_bytes(b"-----BEGIN CERTIFICATE-----\nSTUB\n-----END CERTIFICATE-----\n")
    monkeypatch.setattr("venya_cli.commands._BUNDLE_CORE_CA", fake_ca if ca else tmp_path / "absent.crt")
    monkeypatch.setattr("venya_cli.commands._BUNDLE_ADMIN_CA", tmp_path / "absent-admin.crt")
    client, config_file = _make_client()
    try:
        client._http = MagicMock()
        client._http.request.return_value = _make_response(200, {"enrollment_token": PROBE, "expires_in_seconds": 1800})
        assert cmd_admin_executor_enroll(client, _args(tmp_path, executor_id=EXECUTOR_ID)) == 0
    finally:
        client.close()
        config_file.unlink()
    return capsys.readouterr().out


def _install_snippet(out: str, stage_root: Path) -> str:
    """Extract the printed installer invocation, verbatim, and re-point only the
    staging prefix at a real directory. Refuses if the markers are not unique."""
    lines = out.splitlines()
    begins = [i for i, ln in enumerate(lines) if ln.strip().startswith("ENROLL_DIR=")]
    ends = [i for i, ln in enumerate(lines) if ln.strip() == "bash install-venya-executor.sh"]
    assert len(begins) == 1, f"expected exactly one ENROLL_DIR line, found {len(begins)}"
    assert len(ends) == 1, f"expected exactly one installer terminator line, found {len(ends)}"
    b, e = begins[0], ends[0]
    assert b < e, "the invocation must start at ENROLL_DIR and end at the installer line"
    snippet = "\n".join(ln.strip() for ln in lines[b : e + 1])
    assert STAGE_PREFIX in snippet, snippet
    staged = stage_root / "bundle"
    staged.mkdir(parents=True, exist_ok=True)
    (staged / "token").write_text(PROBE, encoding="utf-8")
    return snippet.replace(STAGE_PREFIX, f"{stage_root}/")


def _probe_env(tmp_path: Path) -> dict:
    """Stub bin + probe log. Each stub records its own argv from /proc/<pid>/cmdline."""
    bindir = tmp_path / "bin"
    bindir.mkdir(exist_ok=True)
    for name, body in (("curl", _CURL_STUB), ("sudo", _SUDO_STUB)):
        script = bindir / name
        script.write_text(body, encoding="utf-8")
        script.chmod(0o755)
    installer = tmp_path / "installer-standin.sh"
    installer.write_text(_INSTALLER_STUB, encoding="utf-8")
    installer.chmod(0o755)
    log = tmp_path / "probe.log"
    log.touch()
    return {
        "PATH": f"{bindir}:/usr/bin:/bin",
        "PROBE_LOG": str(log),
        "FAKE_INSTALLER": str(installer),
        "EXPECT_PROBE": PROBE,
    }


def _argv_records(tmp_path: Path) -> list[str]:
    return [ln for ln in (tmp_path / "probe.log").read_text(encoding="utf-8").splitlines() if ln.startswith("ARGV=")]


# --- arm 1: static, on the printed block ---------------------------------------------------


def test_no_variable_assignment_follows_sudo(tmp_path, monkeypatch, capsys):
    """`sudo VAR=value` is the defect: the value becomes sudo's argument."""
    out = _print_remedy(tmp_path, monkeypatch, capsys)
    assert not re.search(r"\bsudo\b[^\n]*\b[A-Z][A-Z_0-9]+=", out), out


def test_no_tmp_staging_of_the_token_bearing_bundle(tmp_path, monkeypatch, capsys):
    """Two predicates, and both are about STAGING, not the word.

    The remedy names /tmp once, in a comment, precisely to refuse it; and the
    bundle's own path on the mint host is pytest's tmp_path, which lives under
    /tmp by construction. Both are masked or split out so the assertion is about
    the destination the operator is told to write to.
    """
    out = _print_remedy(tmp_path, monkeypatch, capsys)
    masked = out.replace(str(tmp_path), "<bundle-dir-on-the-mint-host>")
    commands = [ln.strip() for ln in masked.splitlines() if ln.strip() and not ln.strip().startswith("#")]
    assert not [c for c in commands if "/tmp" in c], masked
    assert ":/tmp/" not in masked, "the shipped defect form — a remote /tmp target"
    # the named private staging dir is what those commands actually use, and it closes
    assert ".venya-enroll/" in masked, masked
    assert "rm -rf" in masked, "the staged copy must be closed, not left behind"


def test_ssh_account_is_named_not_hard_coded(tmp_path, monkeypatch, capsys):
    """`bot@` is one fleet's provisioning; the remedy must not guess an account."""
    out = _print_remedy(tmp_path, monkeypatch, capsys)
    assert "bot@" not in out, out
    assert "<executor-ssh-user>" in out, out


def test_every_interpolated_path_is_quoted(tmp_path, monkeypatch, capsys):
    out = _print_remedy(tmp_path, monkeypatch, capsys)
    assert f'scp -r "{tmp_path / "bundle"}"' in out, out
    assert 'VENYA_EXECUTOR_ENROLLMENT_TOKEN="$(cat "$ENROLL_DIR/token")"' in out, out
    assert 'VENYA_VENYA_CA_FILE="$ENROLL_DIR/core-server-ca.crt"' in out, out
    assert f'ENROLL_DIR="{STAGE_PREFIX}' in out, out


def test_the_minted_value_is_never_echoed(tmp_path, monkeypatch, capsys):
    """#151/#89 carried forward: the verb that hides the token behind
    --show-sensitive must not reprint it inside a pasted command line."""
    out = _print_remedy(tmp_path, monkeypatch, capsys)
    assert PROBE not in out, out


def test_real_ids_still_reach_the_remedy(tmp_path, monkeypatch, capsys):
    """Not a regression of the earlier cell's purpose: the minted executor id and
    the configured server are interpolated, template hosts are not."""
    out = _print_remedy(tmp_path, monkeypatch, capsys)
    assert f"{EXECUTOR_ID}:" in out and "venya-exec-1" not in out, out
    assert 'VENYA_SERVER_URL="https://test-core.example"' in out, out


# --- arm 2: behavioral, running the printed invocation -------------------------------------


def test_running_the_printed_shape_keeps_the_token_out_of_argv(tmp_path, monkeypatch, capsys):
    """The paired negative, executed: the value reaches the installer's environment
    and appears in no process argv."""
    out = _print_remedy(tmp_path, monkeypatch, capsys)
    snippet = _install_snippet(out, tmp_path / "stage")
    env = _probe_env(tmp_path)
    proc = subprocess.run(
        ["bash", "-c", snippet],
        capture_output=True,
        text=True,
        env=env,
        cwd=str(tmp_path),
        timeout=60,
        check=False,
    )
    assert proc.returncode == 0, proc.stdout + proc.stderr
    # the printed command line, as TEXT, carries a path and never the value
    assert PROBE not in snippet, snippet
    log = (tmp_path / "probe.log").read_text(encoding="utf-8")
    # delivery works, so a quiet probe is not an inert one
    assert "ENV_PRESENT=yes" in log, log
    assert "VALUE_MATCH=yes" in log, log
    assert "CA_SEEN=yes" in log, log
    # and the value never became an argument
    records = _argv_records(tmp_path)
    assert records, "the probe recorded no cmdline at all — the instrument is not running"
    assert not [r for r in records if PROBE in r], records


def test_legacy_sudo_shape_does_put_the_value_in_argv(tmp_path):
    """POSITIVE CONTROL: the same probe, same log, must SEE the value when the
    assignment follows sudo. Without it, the green above proves nothing."""
    env = _probe_env(tmp_path)
    stage = tmp_path / "stage" / "bundle"
    stage.mkdir(parents=True)
    (stage / "token").write_text(PROBE, encoding="utf-8")
    snippet = f'ENROLL_DIR="{stage}"\n{_LEGACY_SHAPE}'
    proc = subprocess.run(
        ["bash", "-c", snippet],
        capture_output=True,
        text=True,
        env=env,
        cwd=str(tmp_path),
        timeout=60,
        check=False,
    )
    assert proc.returncode == 0, proc.stdout + proc.stderr
    records = _argv_records(tmp_path)
    assert [r for r in records if PROBE in r], f"the detector failed to see the value in argv: {records}"


def test_ca_missing_case_omits_the_staged_ca_line_without_breaking_the_shape(tmp_path, monkeypatch, capsys):
    """The CA-conditional branch of the same print block still refuses to reference
    a file that was never bundled."""
    out = _print_remedy(tmp_path, monkeypatch, capsys, ca=False)
    assert "VENYA_VENYA_CA_FILE" not in out, out
    assert "INCOMPLETE" in out, out
    # and the invocation still extracts and runs, with no CA prefix line
    snippet = _install_snippet(out, tmp_path / "stage")
    assert "core-server-ca.crt" not in snippet, snippet
