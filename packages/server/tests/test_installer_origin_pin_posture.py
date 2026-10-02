# Copyright (c) 2026 Tabith LLC.
# Use of this source code is governed by the Business Source License 1.1
# included in the LICENSE file at the root of the repository. As of the
# Change Date listed there, the work is available under MPL 2.0.
# SPDX-License-Identifier: BUSL-1.1

"""Interlock: non-https tarball origins REQUIRE the operator pin (#375, #328).

ticket installer-insecure-origin-pin-required (ruled B 2026-10-02): a tarball
origin whose scheme is not https (file://, plain http://) must ABORT BEFORE any
fetch or write when VENYA_TARBALL_SHA256 is unset — the same-origin sidecar is
self-attesting on an unauthenticated origin (#327's file:// rule, extended to
every non-https scheme). https origins keep the shipped sidecar-fallback +
pin-wins chain (#360/#368), untouched here.

Harness idiom (established by test_installer_common_hash.py): exec the REAL
venya_download_tarball function body from venya-common.sh against a stubbed
origin — curl/info/error/log are stub bins, so the decision logic runs while
network and filesystem writes stay inside the test tmpdir. The lib-hash guard
(#360/#368, installers) is a DIFFERENT guard and is not exercised here.

Truth table, both halves: file+no-pin ABORT (zero state), http+no-pin ABORT,
http+correct-pin PROCEED (no sidecar), https+no-pin PROCEED via sidecar
(CONTROL), wrong-pin ABORT on every scheme (paired negative), operator
override of an https default to http CAUGHT. ps1 gets static-review cells
(no pwsh runner on montana — recorded honestly).
"""

import re
import subprocess
import tarfile
import tempfile
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[3]
COMMON = REPO_ROOT / "venya-common.sh"


def _download_fn() -> str:
    src = COMMON.read_text(encoding="utf-8")
    m = re.search(r"venya_download_tarball\(\) \{.*?\n\}", src, re.DOTALL)
    assert m, "venya_download_tarball not found in venya-common.sh"
    return m.group(0)


_STUB_CURL = """#!/bin/bash
log="$STUB_LOG"; prev=""; out=""
for a in "$@"; do
    if [ "$prev" = "-o" ]; then out="$a"; fi
    prev="$a"
done
echo "curl $*" >> "$log"
# the URL is the last arg that is not the -o target
url=""
for a in "$@"; do
    case "$a" in
        http://*|https://*|file://*) if [ "$a" != "$out" ]; then url="$a"; fi ;;
    esac
done
[ -n "$url" ] || exit 22
src="$ORIGIN/$(basename "$url")"
if [ -f "$src" ]; then cp "$src" "$out"; exit 0; fi
exit 22
"""

_STUB_LOGFN = '#!/bin/bash\necho "$1" >> "$STUB_LOG"; exit ${2:-0}\n'


class _Harness:
    """Runs the real download function against a stub origin."""

    def __init__(self, tmp: str, scheme: str, sidecar: bool) -> None:
        self.tmp = Path(tmp)
        self.origin = self.tmp / "origin"
        self.origin.mkdir()
        self.stub = self.tmp / "stubbin"
        self.stub.mkdir()
        self.log = self.tmp / "calls.log"
        self.log.write_text("", encoding="utf-8")

        payload = self.tmp / "stub"
        payload.mkdir()
        (payload / "payload.txt").write_text("x\n", encoding="utf-8")
        self.tarball = self.origin / "venya-core-install.tar.gz"
        with tarfile.open(self.tarball, "w:gz") as tf:
            tf.add(payload, arcname="stub")
        self.sha = _sha256_file(str(self.tarball))
        if sidecar:
            (self.origin / "venya-core-install.tar.gz.sha256").write_text(self.sha + "\n", encoding="utf-8")

        for name, body in (("curl", _STUB_CURL), ("info", _STUB_LOGFN), ("error", _STUB_LOGFN)):
            p = self.stub / name
            p.write_text(body, encoding="utf-8")
            p.chmod(0o755)

        if scheme == "file":
            self.url = f"file://{self.tarball}"
        elif scheme == "http":
            self.url = f"http://stub.invalid/pkg/{self.tarball.name}"
        elif scheme == "https":
            self.url = f"https://github.com/tabith-llc/venya/releases/latest/download/{self.tarball.name}"
        elif scheme == "https-override-http":
            # default stays https; the operator override points the FINAL URL at
            # a plain-http LAN mirror (203.0.113.10 = RFC5737 doc space, #331 interlock)
            self.url = f"http://203.0.113.10:8080/{self.tarball.name}"
            self.scheme_override = True
        else:  # pragma: no cover
            raise ValueError(scheme)

    def run(self, pin: str | None, tarball_env: str | None = None) -> subprocess.CompletedProcess:
        script = self.tmp / "run.sh"
        # the installers assign TARBALL_URL from VENYA_TARBALL before sourcing;
        # the function consumes the final effective URL either way.
        body = (
            "set -euo pipefail\n"
            f'TARBALL_URL="{tarball_env if tarball_env is not None else self.url}"\n'
            + _download_fn()
            + "\nvenya_download_tarball core\n"
            'echo "REACHED_END file=$TARBALL_FILE"\n'
        )
        script.write_text(body, encoding="utf-8")
        env = {
            "PATH": f"{self.stub}:/usr/bin:/bin:/usr/sbin:/sbin",
            "ORIGIN": str(self.origin),
            "STUB_LOG": str(self.log),
        }
        if pin is not None:
            env["VENYA_TARBALL_SHA256"] = pin
        return subprocess.run(
            ["/bin/bash", str(script)], capture_output=True, text=True, timeout=30, env=env, check=False
        )

    def calls(self) -> str:
        return self.log.read_text(encoding="utf-8")

    def tarball_fetches(self) -> int:
        return len(re.findall(r"curl \S+ -fsSL -o \S+ \S+", self.calls()))


def _sha256_file(path: str) -> str:
    out = subprocess.run(["/usr/bin/sha256sum", path], capture_output=True, text=True, check=True)
    return out.stdout.split()[0]


# --- negative half: non-https + no pin = abort before any fetch/write ---


def test_file_origin_no_pin_aborts_zero_state() -> None:
    """CONTROL-paired (#327 half): file:// + no pin must abort BEFORE the
    download line — no cp, no mktemp'd tarball."""
    with tempfile.TemporaryDirectory() as tmp:
        h = _Harness(tmp, "file", sidecar=True)
        r = h.run(pin=None)
        assert r.returncode == 1, r.stdout + r.stderr
        assert "not https" in h.calls() and "#375" in h.calls(), h.calls()
        assert "Downloading tarball" not in h.calls()
        assert "curl" not in h.calls()


def test_http_origin_no_pin_aborts_zero_state() -> None:
    """#375 RED->GREEN: plain http:// + no pin used to proceed via the
    same-origin sidecar; now it aborts before any curl of the tarball."""
    before = set(Path("/tmp").glob("venya-install-*"))
    with tempfile.TemporaryDirectory() as tmp:
        h = _Harness(tmp, "http", sidecar=True)
        r = h.run(pin=None)
        assert r.returncode == 1, f"http+no-pin proceeded (sidecar self-attested): {h.calls()}"
        assert "not https" in h.calls(), h.calls()
        assert "Downloading tarball" not in h.calls()
        # zero state: the stub log holds only the guard's error lines — no curl,
        # no mktemp'd tarball, no fetch
        assert "curl" not in h.calls(), h.calls()
        assert set(Path("/tmp").glob("venya-install-*")) == before, "abort path wrote state"


def test_https_default_overridden_to_http_is_caught() -> None:
    """Operator override (VENYA_TARBALL=http://...) of an https default is IN
    SCOPE — the scheme check runs on the FINAL effective URL."""
    with tempfile.TemporaryDirectory() as tmp:
        h = _Harness(tmp, "https", sidecar=True)
        r = h.run(pin=None, tarball_env=f"http://203.0.113.10:8080/{h.tarball.name}")
        assert r.returncode == 1, f"override-to-http not caught: {h.calls()}"
        assert "not https" in h.calls()
        assert "curl" not in h.calls()


def test_wrong_pin_aborts_on_every_scheme() -> None:
    """Paired negative across all three schemes: a wrong pin always aborts —
    non-https at the #375 guard (no fetch), https at the existing hash
    mismatch — and never consults the sidecar when pinned."""
    for scheme in ("file", "http", "https"):
        with tempfile.TemporaryDirectory() as tmp:
            h = _Harness(tmp, scheme, sidecar=True)
            r = h.run(pin="0" * 64)
            assert r.returncode == 1, (scheme, r.stdout)
            assert "SHA-256 mismatch" in h.calls(), scheme
            assert "venya-core-install.tar.gz.sha256" not in h.calls(), f"{scheme}: sidecar consulted while pinned"


# --- positive half ---


def test_http_origin_with_correct_pin_proceeds_no_sidecar() -> None:
    """#375 paired positive: http + CORRECT pin proceeds — pin breaks the
    origin trust chain; the sidecar stays untouched."""
    with tempfile.TemporaryDirectory() as tmp:
        h = _Harness(tmp, "http", sidecar=True)
        r = h.run(pin=h.sha)
        assert r.returncode == 0, r.stdout + r.stderr + h.calls()
        assert "SHA-256 verified" in h.calls()
        assert ".sha256" not in h.calls(), "sidecar fetched despite operator pin"
        assert "REACHED_END" in r.stdout


def test_file_origin_with_correct_pin_proceeds() -> None:
    """#327 paired positive (control, must stay green): file:// + correct pin
    proceeds via the local cp path."""
    with tempfile.TemporaryDirectory() as tmp:
        h = _Harness(tmp, "file", sidecar=False)
        r = h.run(pin=h.sha)
        assert r.returncode == 0, r.stdout + r.stderr + h.calls()
        assert "SHA-256 verified" in h.calls()


def test_https_origin_no_pin_proceeds_via_sidecar() -> None:
    """CONTROL (shipped behavior, byte-for-behavior unchanged): https + no pin
    keeps the sidecar fallback + verify chain."""
    with tempfile.TemporaryDirectory() as tmp:
        h = _Harness(tmp, "https", sidecar=True)
        r = h.run(pin=None)
        assert r.returncode == 0, r.stdout + r.stderr + h.calls()
        assert "not set — fetching checksum sidecar" in h.calls()
        assert "SHA-256 verified" in h.calls()


# --- static pins: both platforms carry the rule ---


def test_common_sh_carries_the_scheme_guard() -> None:
    src = COMMON.read_text(encoding="utf-8")
    m = re.search(r"venya_download_tarball\(\) \{.*?\n\}", src, re.DOTALL)
    assert m
    body = m.group(0)
    assert '"$TARBALL_URL" != https://*' in body, "scheme check not at the guard site"
    assert '&& -z "${VENYA_TARBALL_SHA256:-}"' not in body or '-z "${VENYA_TARBALL_SHA256:-}"' in body
    assert "#375" in body
    # the guard must precede the download line (zero-state abort)
    assert body.index("!= https://*") < body.index('info "Downloading tarball')
    # the #360/#368 lib-hash guard is a SEPARATE mechanism — not weakened:
    installers_src = "\n".join((REPO_ROOT / f).read_text(encoding="utf-8") for f in ("install-venya-core.sh",))
    assert "'__VENYA''_COMMON_SHA256__'" in installers_src


def test_ps1_guard_lands_before_any_download_state() -> None:
    """ps1 static review (no pwsh runner on montana — execution UNVERIFIED,
    #328 ruling): the scheme guard sits after the $tarballUrl assignment and
    before prompt, workDir creation, and every curl."""
    src = (REPO_ROOT / "install-venya-cli.ps1").read_text(encoding="utf-8")
    guard = src.index("-notmatch '^https://'")
    assert src.index("VENYA_TARBALL_SHA256 is not set") > src.index("$tarballUrl = if")
    assert guard < src.index("$workDir = Join-Path"), "ps1 guard must precede workDir creation"
    assert guard < src.index("Read-Host"), "ps1 guard must precede the prompt"
    assert guard < src.index("# --- Download + verify the tarball"), "ps1 guard must precede any fetch"
    # https sidecar branch textually intact
    assert "fetching checksum sidecar from origin" in src
    assert src.count("-notmatch '^https://'") == 1


def test_all_shell_installers_route_through_the_common_guard() -> None:
    """The three sh installers share venya_download_tarball — no per-script
    sidecar bypass may exist at their fetch sites."""
    for name in ("install-venya-core.sh", "install-venya-executor.sh", "install-venya-cli.sh"):
        src = (REPO_ROOT / name).read_text(encoding="utf-8")
        assert "venya_download_tarball" in src, name
        # the only sidecar fetches live in venya-common.sh (guarded), not here
        assert "checksum sidecar" not in src, f"{name}: unguarded sidecar path outside common.sh"
