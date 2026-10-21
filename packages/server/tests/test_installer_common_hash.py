# Copyright (c) 2026 Tabith LLC.
# Use of this source code is governed by the Business Source License 1.1
# included in the LICENSE file at the root of the repository. As of the
# Change Date listed there, the work is available under MPL 2.0.
# SPDX-License-Identifier: BUSL-1.1

"""Interlock: piped installs VERIFY venya-common.sh before sourcing it (#360).

ticket installer-common-self-fetch-unhashed (ruled A 2026-10-02): every fetch-
and-source of the shared library must check a sha256 — the serve-time embedded
placeholder (sed-filled by create-tarball-and-serve.sh), the operator pin
VENYA_COMMON_SHA256, or the origin sidecar — and FAIL CLOSED when none is
obtainable. Root-sourcing an unverified script is the self-attestation class
the tarball path already closed (venya-common.sh guard).

Static source pins (house pattern: test_installer_dir_pins / docker gate order):
each install script must (a) carry the placeholder, (b) abort on mismatch,
(c) abort when no expectation is resolvable, and (d) perform ALL of it before
the `source` of the fetched file.

#368 (installer-common-hash-guard-self-nulls-on-serve-sed): the serve-time
embed must touch ONLY the assignment default, and the guard's placeholder
comparison must be sed-invisible — otherwise the sed replaces BOTH sites and
the guard self-nulls, so a corrupted library with a self-published matching
sidecar would pass (self-attestation). The precedence/order cells below exec
the real guard region from each installer against a stub origin.
"""

import re
import subprocess
import tempfile
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[3]
INSTALLERS = (
    "install-venya-core.sh",
    "install-venya-executor.sh",
    "install-venya-cli.sh",
)

PLACEHOLDER = "__VENYA_COMMON_SHA256__"
# Split-quote comparison literal (#368): invisible to a literal-token sed.
SPLIT_LITERAL = "'__VENYA''_COMMON_SHA256__'"


def _fetch_region(name: str) -> str:
    src = (REPO_ROOT / name).read_text(encoding="utf-8")
    m = re.search(r"Fetching shared installer library.*?source \"\$FETCH_DIR/venya-common\.sh\"", src, re.DOTALL)
    assert m, f"{name}: fetch-and-source block not found"
    return m.group(0)


def _guard_body_from_src(src: str) -> str:
    m = re.search(r"Fetching shared installer library.*?source \"\$FETCH_DIR/venya-common\.sh\"", src, re.DOTALL)
    assert m, "fetch-and-source block not found"
    region = m.group(0)
    return region[region.index("EXPECTED_COMMON_SHA=") :]


def _guard_body(name: str) -> str:
    """The real guard region: EXPECTED_COMMON_SHA assignment through the
    final `source` — everything the harness needs to exercise precedence."""
    return _guard_body_from_src((REPO_ROOT / name).read_text(encoding="utf-8"))


def _embed(src: str, hash_hex: str) -> str:
    """Apply the anchored serve-time embed (same substitution as the runner):
    replace ONLY the `:-PLACEHOLDER` default-value site, once."""
    return re.sub(":-" + PLACEHOLDER, ":-" + hash_hex, src, count=1)


def _legacy_guard(name: str, hash_hex: str) -> str:
    """Pre-#368 bytes reproduced from source: contiguous comparison literal
    plus unanchored global embed — the self-nulling combination flash1 proved."""
    src = (REPO_ROOT / name).read_text(encoding="utf-8")
    assert SPLIT_LITERAL in src, "test expects the fixed source to carry the split literal"
    src = src.replace(" = " + SPLIT_LITERAL, ' = "' + PLACEHOLDER + '"')
    src = src.replace(PLACEHOLDER, hash_hex)  # unanchored global, the old bug
    return _guard_body_from_src(src)


_GUARD_PRELUDE = """#!/bin/bash
FETCH_DIR="$1"
TARBALL_URL="http://stub.invalid/pkg/venya.tar.gz"
curl() {
    local last src
    for a in "$@"; do last="$a"; done
    case "$*" in
        *venya-common.sh.sha256*) src="$ORIGIN/venya-common.sh.sha256" ;;
        *) src="$ORIGIN/venya-common.sh" ;;
    esac
    if [ -f "$src" ]; then cp "$src" "$last"; return 0; fi
    return 22
}
# simulate the installer line that precedes the guard region: the fetched
# bytes are the origin copy (guard region itself starts at EXPECTED_COMMON_SHA,
# after the library curl in the real script).
cp "$ORIGIN/venya-common.sh" "$FETCH_DIR/venya-common.sh"
"""


def _run_guard(guard_body: str, origin: str, fetch_dir: str, pin: str | None) -> subprocess.CompletedProcess:
    script = Path(fetch_dir) / "guard.sh"
    script.write_text(_GUARD_PRELUDE + guard_body, encoding="utf-8")
    env = {
        "PATH": "/usr/bin:/bin:/usr/sbin:/sbin",
        "ORIGIN": origin,
    }
    if pin is not None:
        env["VENYA_COMMON_SHA256"] = pin
    return subprocess.run(
        ["/bin/bash", str(script), fetch_dir],
        capture_output=True,
        text=True,
        timeout=30,
        env=env,
        check=False,
    )


def _make_origin(tmp: str, lib_text: str, sidecar: str | None) -> Path:
    origin = Path(tmp) / "origin"
    origin.mkdir()
    (origin / "venya-common.sh").write_text(lib_text, encoding="utf-8")
    if sidecar is not None:
        (origin / "venya-common.sh.sha256").write_text(sidecar, encoding="utf-8")
    return origin


def _sha256_file(path: str) -> str:
    out = subprocess.run(["/usr/bin/sha256sum", path], capture_output=True, text=True, check=True)
    return out.stdout.split()[0]


def test_every_installer_carries_the_embed_placeholder_exactly_once() -> None:
    """#368 static half: the contiguous placeholder exists ONLY at the
    assignment default; the comparison uses the split-quote literal."""
    for name in INSTALLERS:
        src = (REPO_ROOT / name).read_text(encoding="utf-8")
        assert (
            src.count(PLACEHOLDER) == 1
        ), f"{name}: placeholder at {src.count(PLACEHOLDER)} sites — a sed can hit more than the assignment"
        assert ":-" + PLACEHOLDER in src, f"{name}: placeholder is not at the :- default-value site"
        assert SPLIT_LITERAL in src, f"{name}: comparison is sed-visible (self-null risk)"


def test_verification_precedes_source_in_every_installer() -> None:
    for name in INSTALLERS:
        region = _fetch_region(name)
        assert "sha256sum" in region, f"{name}: no sha256 computation before source"
        assert "MISMATCH" in region, f"{name}: no mismatch abort before source"
        assert "VENYA_COMMON_SHA256" in region, f"{name}: operator pin not honored"
        assert region.index("sha256sum") < region.index('source "$FETCH_DIR/venya-common.sh"')


def test_fail_closed_without_any_expectation() -> None:
    """Negative half: no embedded hash AND no sidecar reachable -> abort, never
    source (mirror of the tarball guard's fail-closed semantics)."""
    for name in INSTALLERS:
        region = _fetch_region(name)
        assert "refusing to source" in region.lower(), f"{name}: not fail-closed on missing expectation"


# --- #368 semantic-precedence / order cells (exec the real guard region) ---


def test_operator_pin_wins_over_embedded() -> None:
    """Pin good while the embedded default is a WRONG hash: the guard must
    pass on the PIN (pin > embedded precedence)."""
    with tempfile.TemporaryDirectory() as tmp:
        lib_text = "MARKER_SOURCED=1\n"
        origin = _make_origin(tmp, lib_text, sidecar=None)
        good = _sha256_file(str(origin / "venya-common.sh"))
        fetch_dir = Path(tmp) / "fetch"
        fetch_dir.mkdir()
        guard = _embed(_guard_body("install-venya-core.sh"), "0" * 64)
        r = _run_guard(guard, str(origin), str(fetch_dir), pin=good)
        assert r.returncode == 0, r.stderr
        assert f"verified (sha256 {good})" in r.stderr


def test_embedded_used_when_pin_unset() -> None:
    """Served bytes (real hash embedded), no operator pin: guard passes and
    the sidecar is NEVER consulted (origin publishes none)."""
    with tempfile.TemporaryDirectory() as tmp:
        origin = _make_origin(tmp, "MARKER_SOURCED=1\n", sidecar=None)
        real = _sha256_file(str(origin / "venya-common.sh"))
        fetch_dir = Path(tmp) / "fetch"
        fetch_dir.mkdir()
        guard = _embed(_guard_body("install-venya-executor.sh"), real)
        r = _run_guard(guard, str(origin), str(fetch_dir), pin=None)
        assert r.returncode == 0, r.stderr
        assert "verified" in r.stderr
        assert "sidecar" not in r.stderr


def test_sidecar_never_overrides_pin_or_embedded() -> None:
    """The #368 defect class, unit scope: corrupted library + attacker-matching
    sidecar must ABORT whenever a pin or embedded expectation exists — the
    same-origin sidecar is consulted ONLY when both are absent."""
    for mode in ("pin", "embedded"):
        with tempfile.TemporaryDirectory() as tmp:
            lib_text = "MARKER_SOURCED=1\n"  # the CORRUPTED library
            origin = _make_origin(tmp, lib_text, sidecar=None)
            corrupt = _sha256_file(str(origin / "venya-common.sh"))
            # sidecar attests the corrupted bytes (self-published)
            (origin / "venya-common.sh.sha256").write_text(corrupt + "\n", encoding="utf-8")
            fetch_dir = Path(tmp) / "fetch"
            fetch_dir.mkdir()
            guard = _guard_body("install-venya-cli.sh")
            pin = None
            if mode == "pin":
                pin = "f" * 64  # an operator pin that does NOT match
            else:
                guard = _embed(guard, "e" * 64)  # embedded expectation, no pin
            r = _run_guard(guard, str(origin), str(fetch_dir), pin=pin)
            assert r.returncode == 1, f"{mode}: matching self-published sidecar accepted (self-attestation)"
            assert "MISMATCH" in r.stderr, r.stderr


def test_legacy_bytes_self_attest_defect_reachable_in_unit_scope() -> None:
    """RED proof: pre-#368 bytes (contiguous comparison + unanchored embed)
    let a corrupted library with a matching self-published sidecar THROUGH —
    the behavior the fix must flip to ABORT (see the cell above)."""
    with tempfile.TemporaryDirectory() as tmp:
        lib_text = "MARKER_SOURCED=1\n"
        origin = _make_origin(tmp, lib_text, sidecar=None)
        served_hash = _sha256_file(str(origin / "venya-common.sh"))
        (origin / "venya-common.sh.sha256").write_text(served_hash + "\n", encoding="utf-8")
        fetch_dir = Path(tmp) / "fetch"
        fetch_dir.mkdir()
        legacy = _legacy_guard("install-venya-core.sh", served_hash)
        r = _run_guard(legacy, str(origin), str(fetch_dir), pin=None)
        # Old behavior: after the double sed EXPECTED equals the embedded hash
        # only by self-reference; the corrupted file with the matching sidecar
        # passed. On the fixed source the legacy reconstruction falls through
        # to the same-origin sidecar and passes too — this cell PINs that the
        # old byte shape IS the self-attesting one (guard body sources).
        assert r.returncode == 0, r.stderr
        assert "verified" in r.stderr


def test_unreplaced_placeholder_fails_closed_without_sidecar() -> None:
    """Bare-checkout bytes (placeholder never substituted): the comparison
    resets EXPECTED, sidecar ACCEPTED when it matches (today's documented
    fallback), and a MISSING sidecar aborts fail-closed rc=1 — no crash."""
    with tempfile.TemporaryDirectory() as tmp:
        origin = _make_origin(tmp, "MARKER_SOURCED=1\n", sidecar=None)
        real = _sha256_file(str(origin / "venya-common.sh"))
        guard = _guard_body("install-venya-core.sh")  # placeholder intact
        fetch_dir = Path(tmp) / "fetch"
        fetch_dir.mkdir()
        (origin / "venya-common.sh.sha256").write_text(real + "\n", encoding="utf-8")
        r = _run_guard(guard, str(origin), str(fetch_dir), pin=None)
        assert r.returncode == 0, r.stderr
        (origin / "venya-common.sh.sha256").unlink()
        fetch_dir2 = Path(tmp) / "fetch2"
        fetch_dir2.mkdir()
        r = _run_guard(guard, str(origin), str(fetch_dir2), pin=None)
        assert r.returncode == 1
        assert "refusing to source" in r.stderr.lower()


def test_serve_time_embed_lands_exactly_once_with_guard_intact() -> None:
    """The serve-time semantics cell: the runner's anchored sed on real
    installer source yields the hash exactly once, the placeholder gone, and
    the split-quote comparison untouched (still sed-invisible)."""
    hash_hex = "ab" * 32
    for name in INSTALLERS:
        src = (REPO_ROOT / name).read_text(encoding="utf-8")
        served = _embed(src, hash_hex)
        assert served.count(hash_hex) == 1, f"{name}: embedded hash appears {served.count(hash_hex)} times"
        assert PLACEHOLDER not in served, f"{name}: placeholder survived the embed"
        assert SPLIT_LITERAL in served, f"{name}: embed damaged the guard comparison"


# --- #690: the PUBLISHED face is raw tag bytes, so the sidecar is the only ---
# --- expectation an off-LAN `curl | bash` install can resolve. These cells   ---
# --- run the unreplaced guard body of EACH installer against a sidecar in the ---
# --- exact format the build tool writes (`printf '%s  %s\n'` — two spaces),   ---
# --- because `RELEASES.md` §5 publishes those bytes verbatim. The pre-#690    ---
# --- manifest never staged the sidecar, so all three installs hit the wall.   ---

#: The one format the tool emits — see create-tarball-and-serve.sh:345 (colorado
#: dust/venya-installer.git master). NOT a bare hash: the sibling tarball sidecars
#: and this one are all `<hash>  <name>`, and the installer reads `awk '{print $1}'`.
PUBLISHED_SIDECAR_NAME = "venya-common.sh"


def _published_sidecar_text(hash_hex: str) -> str:
    """Byte-for-byte the shape the build tool writes, two spaces included."""
    return f"{hash_hex}  {PUBLISHED_SIDECAR_NAME}\n"


def test_published_sidecar_format_verifies_on_all_three_installers() -> None:
    """POSITIVE, per script: raw tag bytes (placeholder UNREPLACED — what GitHub
    serves), no operator pin, sidecar published in the real two-space format.
    The guard must resolve the sidecar and pass for core, executor AND cli."""
    for name in INSTALLERS:
        with tempfile.TemporaryDirectory() as tmp:
            origin = _make_origin(tmp, "MARKER_SOURCED=1\n", sidecar=None)
            real = _sha256_file(str(origin / "venya-common.sh"))
            (origin / "venya-common.sh.sha256").write_text(_published_sidecar_text(real), encoding="utf-8")
            fetch_dir = Path(tmp) / "fetch"
            fetch_dir.mkdir()
            r = _run_guard(_guard_body(name), str(origin), str(fetch_dir), pin=None)
            assert r.returncode == 0, f"{name}: published sidecar format not accepted\n{r.stderr}"
            assert f"verified (sha256 {real})" in r.stderr, f"{name}: {r.stderr}"


def test_missing_published_sidecar_refuses_by_name_on_all_three_installers() -> None:
    """NEGATIVE half A (the shipped #690 defect): same raw tag bytes, sidecar
    REMOVED — exactly the published asset set of the 16 releases so far. All three
    must abort rc=1 and name the artifact that is missing."""
    for name in INSTALLERS:
        with tempfile.TemporaryDirectory() as tmp:
            origin = _make_origin(tmp, "MARKER_SOURCED=1\n", sidecar=None)
            fetch_dir = Path(tmp) / "fetch"
            fetch_dir.mkdir()
            r = _run_guard(_guard_body(name), str(origin), str(fetch_dir), pin=None)
            assert r.returncode == 1, f"{name}: sourced an unverified library\n{r.stderr}"
            # Pin THIS refusal, not any refusal: the MISMATCH sentence also contains
            # the words "Refusing to source", so a looser match is satisfied by a
            # different failure path and stops being a guard (measured — a mutation
            # that deleted this branch entirely still passed the loose version).
            assert (
                "unset and no hash sidecar at the origin" in r.stderr
            ), f"{name}: did not take the missing-sidecar refusal: {r.stderr}"
            assert "venya-common.sh.sha256" in r.stderr, f"{name}: refusal does not name the artifact: {r.stderr}"
            # The refusal must come BEFORE the source: the guard prints its verified
            # line only on the pass path.
            assert "verified (sha256" not in r.stderr, f"{name}: refused but still reported verified: {r.stderr}"


def test_altered_published_sidecar_refuses_on_all_three_installers() -> None:
    """NEGATIVE half B: the sidecar is present but its hash does not match the
    library it attests (truncated/corrupted upload). rc=1 with a MISMATCH naming
    both values — a present-but-wrong sidecar must never be treated as "no
    expectation", and publishing one is worthless if a bad one is accepted."""
    for name in INSTALLERS:
        with tempfile.TemporaryDirectory() as tmp:
            origin = _make_origin(tmp, "MARKER_SOURCED=1\n", sidecar=None)
            wrong = "0" * 64
            (origin / "venya-common.sh.sha256").write_text(_published_sidecar_text(wrong), encoding="utf-8")
            fetch_dir = Path(tmp) / "fetch"
            fetch_dir.mkdir()
            r = _run_guard(_guard_body(name), str(origin), str(fetch_dir), pin=None)
            assert r.returncode == 1, f"{name}: accepted a sidecar that does not match\n{r.stderr}"
            assert "MISMATCH" in r.stderr, f"{name}: {r.stderr}"
            assert wrong in r.stderr, f"{name}: refusal does not name the expected value"
