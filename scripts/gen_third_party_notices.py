# Copyright (c) 2026 Tabith LLC.
# Use of this source code is governed by the Business Source License 1.1
# included in the LICENSE file at the root of this repository. As of the
# Change Date listed there, the work is available under MPL 2.0.
# SPDX-License-Identifier: BUSL-1.1

"""Generator for the dependency-version inventory in THIRD-PARTY-NOTICES.md (refs leg 369).

**Owner order 2026-10-22, verbatim:** *"add to our release mechanism: we need to re-determine every
dependency version being used and update documentation properly!"*

**The defect this closes.** `docker-sbx` was declared `0.38.0` in the shipped notices page, a string
hand-typed at `ff262be9` (2026-09-15) and never re-checked, while the executor installer pulls the
package from Docker's FLOATING apt repository and enforces only a floor (`install-venya-executor.sh`,
`SBX_MIN_VERSION`). A typed number cannot see a move forward, so ten minor versions of drift shipped
in a customer-facing disclosure. The fix is not a corrected number — it is a number nobody has to
correct.

Three classes, and the split is the whole point:

* **locked** — Python deps resolved from `uv.lock`, Rust crates from `packages/executor/Cargo.lock`,
  the interpreter from `uv.lock`'s `requires-python`. These are the bytes a release ships.
* **floored** — vendor packages no lock carries (`docker-sbx`). The only version claim that can be
  made at build time is the floor the installer itself enforces, read out of that installer, plus the
  plain statement that the installed version is whatever the vendor repo serves.
* **install-time** — apt/distro components (`nginx`, `PostgreSQL`, `docker-ce` family, `uv`, the Rust
  toolchain). No version is knowable at build time; the doc says so and names the command that reads
  it on a machine.

**A live system probe exists and is deliberately NOT written into the doc.** `--probe` prints what
`dpkg-query` reports on the machine running the generator, labelled as machine state. Committing that
column would make the generated block machine-dependent and the interlock would read red on the next
host, so the shipped bytes come from the tree only. `shortcut: the probe is report-only; it becomes a
shipped column only when the release path can pin a machine to build on.`

Usage:
  python3 scripts/gen_third_party_notices.py            # print the resolved table
  python3 scripts/gen_third_party_notices.py --probe    # same, plus this machine's dpkg face
  python3 scripts/gen_third_party_notices.py --check    # exit 1 on drift or an unbacked version
  python3 scripts/gen_third_party_notices.py --write    # rewrite the generated block
"""

from __future__ import annotations

import argparse
import re
import shutil
import subprocess
import sys
import tomllib
from dataclasses import dataclass
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
DOC = REPO_ROOT / "THIRD-PARTY-NOTICES.md"
UV_LOCK = REPO_ROOT / "uv.lock"
CARGO_LOCK = REPO_ROOT / "packages" / "executor" / "Cargo.lock"
CARGO_TOML = REPO_ROOT / "packages" / "executor" / "Cargo.toml"
EXECUTOR_INSTALLER = REPO_ROOT / "install-venya-executor.sh"
CORE_INSTALLER = REPO_ROOT / "install-venya-core.sh"

BEGIN = "<!-- BEGIN GENERATED DEPENDENCY INVENTORY (scripts/gen_third_party_notices.py) -->"
END = "<!-- END GENERATED DEPENDENCY INVENTORY -->"

#: Vendor packages with no lock entry. `floor` is the installer constant they are governed by;
#: `apt` is the package name a machine can be asked about. Read from the installer text, never typed
#: as a version here — typing one is the defect.
VENDOR = (
    ("docker-sbx", "SBX_MIN_VERSION", ("docker-sbx",)),
    ("docker-ce", None, ("docker-ce", "docker-ce-cli", "containerd.io", "docker-buildx-plugin")),
    ("nginx", None, ("nginx",)),
    ("postgresql", None, ("postgresql",)),
)

#: Names the unbacked-version scan maps onto a component the tree resolves. The component NAMES from
#: `resolve()` are added to this map at scan time; these are the prose spellings that differ from the
#: lock key (`PostgreSQL 16` must reach the `postgresql` row, `Rust toolchain` the `rust-toolchain row`).
_ALIASES = {
    "docker ce": "docker-ce",
    "containerd": "docker-ce",
    "postgres": "postgresql",
    "rust": "rust-toolchain",
    "python": "python",
}


@dataclass(frozen=True)
class Row:
    """One component, the version a release ships, and the command that proves it."""

    name: str
    version: str
    kind: str  # locked | floored | install-time
    command: str

    @property
    def claim(self) -> str:
        """What the doc is allowed to assert about this component's version."""
        if self.kind == "locked":
            return f"`{self.version}`"
        if self.kind == "floored":
            return f"floor `{self.version}`, version installed is whatever the vendor repo serves"
        return "not knowable at build time — read it on the machine"


def _face_token(version: str) -> str:
    """The bare numeric face a prose claim is compared against: `==3.14.*` -> `3.14`, `0.10` -> `0.10`.

    A locked row can be a range specifier rather than a point version (the interpreter line is
    `requires-python`), and a floor is a major/minor pair, so the comparison is prefix-shaped in BOTH
    directions rather than string equality.
    """
    m = re.search(r"\d+(?:\.\d+)*", version)
    return m.group(0) if m else version


def _paths(root: Path) -> dict[str, Path]:
    """The six files a resolution reads, from whichever root is under analysis.

    A test that plants a version must move a source file, not the doc, so `resolve()` takes a root and
    every path is derived from it. The module-level constants are the real tree's defaults only.
    """
    return {
        "uv_lock": root / "uv.lock",
        "cargo_lock": root / "packages" / "executor" / "Cargo.lock",
        "cargo_toml": root / "packages" / "executor" / "Cargo.toml",
        "executor_installer": root / "install-venya-executor.sh",
        "packages": root / "packages",
    }


def _lock_toml(path: Path) -> dict[str, str]:
    """`[[package]]` name -> version from a lock file, whatever the ecosystem."""
    data = tomllib.loads(path.read_text(encoding="utf-8"))
    return {p["name"]: str(p.get("version", "")) for p in data.get("package", []) if p.get("name")}


def _direct_python_deps(packages: Path) -> list[str]:
    """Dependency NAMES declared by the workspace members, minus the members themselves.

    The notices page lists direct dependencies, so the set comes from the member manifests, not from
    the whole lock (102 entries, most of them transitive). Sorted and de-duplicated so the generated
    block is stable across machines.
    """
    members = set()
    for manifest in sorted(packages.glob("*/pyproject.toml")):
        with manifest.open("rb") as fh:
            members.add(tomllib.load(fh)["project"]["name"].lower().replace("-", "_"))

    names: set[str] = set()
    for manifest in sorted(packages.glob("*/pyproject.toml")):
        with manifest.open("rb") as fh:
            deps = tomllib.load(fh)["project"].get("dependencies") or []
        for spec in deps:
            name = re.split(r"[\[<>=!; ]", spec.strip(), maxsplit=1)[0].strip()
            if name and name.lower().replace("-", "_") not in members:
                names.add(name)
    return sorted(names)


def _direct_rust_crates(cargo_toml: Path) -> list[str]:
    """Crate names in `[dependencies]` — the one section, nothing after it.

    The scan STOPS at the next section header. Reading past it picked up `[profile.release]` keys
    (`lto`, `codegen-units`, `strip`) as if they were crates, which is the bare-directory-pathspec
    class in miniature: a parser that keeps going past its boundary reports confident rows about
    things that do not exist.
    """
    text = cargo_toml.read_text(encoding="utf-8")
    block = text.split("[dependencies]", 1)
    if len(block) != 2:
        return []
    names = []
    for line in block[1].split("\n"):
        if line.strip().startswith("["):
            break
        m = re.match(r"\s*([A-Za-z0-9_-]+)\s*=", line)
        if m:
            names.append(m.group(1))
    return sorted(names)


def _installer_floor(executor_installer: Path, var: str) -> str:
    """The floor value an installer enforces, read from the installer text.

    Returns "" when the constant is gone, and the caller turns that into an unresolvable row rather
    than a guessed one — a floor silently dropped from the installer must not keep shipping a number.
    """
    m = re.search(rf'^\s*{re.escape(var)}="([^"]+)"', executor_installer.read_text(encoding="utf-8"), re.MULTILINE)
    return m.group(1) if m else ""


def resolve(root: Path = REPO_ROOT) -> list[Row]:
    """Every version a release can state from the tree alone."""
    f = _paths(root)
    rows: list[Row] = []

    lock = _lock_toml(f["uv_lock"])
    for name in _direct_python_deps(f["packages"]):
        version = lock.get(name, "")
        if version:
            rows.append(
                Row(
                    name,
                    version,
                    "locked",
                    f"grep -A1 '^name = \"{name}\"$' uv.lock",
                )
            )
        else:
            rows.append(
                Row(name, "", "install-time", "python3 -c \"import tomllib;print(tomllib.load(open('uv.lock','rb')))\"")
            )

    cargo = _lock_toml(f["cargo_lock"])
    for crate in _direct_rust_crates(f["cargo_toml"]):
        version = cargo.get(crate, "")
        rows.append(
            Row(
                crate,
                version,
                "locked" if version else "install-time",
                f"grep -A1 '^name = \"{crate}\"$' packages/executor/Cargo.lock",
            )
        )
    rows.append(
        Row(
            "venya-filter",
            cargo.get("venya-filter", ""),
            "locked",
            "grep '^version' packages/executor/Cargo.toml",
        )
    )

    py = re.search(r'^requires-python = "([^"]+)"', f["uv_lock"].read_text(encoding="utf-8"), re.MULTILINE)
    rows.append(Row("python", py.group(1) if py else "", "locked", "grep '^requires-python' uv.lock"))

    rust_floor = re.search(r'^rust-version = "([^"]+)"', f["cargo_toml"].read_text(encoding="utf-8"), re.MULTILINE)
    rows.append(
        Row(
            "rust-toolchain",
            rust_floor.group(1) if rust_floor else "",
            "floored",
            "grep '^rust-version' packages/executor/Cargo.toml",
        )
    )

    for name, floor_var, apt_names in VENDOR:
        floor = _installer_floor(f["executor_installer"], floor_var) if floor_var else ""
        probe = " + ".join(f"dpkg-query -W -f='${{Version}}' {p}" for p in apt_names)
        rows.append(Row(name, floor, "floored" if floor else "install-time", probe))

    rows.append(Row("uv", "", "install-time", "uv --version"))
    return rows


def render_block(rows: list[Row]) -> str:
    """The generated section, between the sentinels. Deterministic: tree inputs only."""
    by_kind: dict[str, list[Row]] = {"locked": [], "floored": [], "install-time": []}
    for r in rows:
        by_kind[r.kind].append(r)

    out = [BEGIN, ""]
    out += [
        "## Dependency versions this release ships (generated)",
        "",
        "This block is written by `scripts/gen_third_party_notices.py`. Do not edit a number here;",
        "edit the source the row names and regenerate. A version in this file that is not in this",
        "block and not backed by a command below is a defect the release gate refuses to tag.",
        "",
        "### Locked — resolved from the lock files in this tree",
        "",
        "| Component | Version | How to re-derive |",
        "|-----------|---------|------------------|",
    ]
    for r in sorted(by_kind["locked"], key=lambda x: x.name.lower()):
        out.append(f"| {r.name} | `{r.version}` | `{r.command}` |")
    out += [
        "",
        "### Floored — the vendor package is fetched from a floating repository",
        "",
        "For these the release ships a MINIMUM, not a number. The installed version is whatever the",
        "vendor's repository serves on the day of the install.",
        "",
        "| Component | Floor enforced | How to read the installed version |",
        "|-----------|----------------|-----------------------------------|",
    ]
    for r in sorted(by_kind["floored"], key=lambda x: x.name.lower()):
        floor = f"`{r.version}`" if r.version else "none"
        out.append(f"| {r.name} | {floor} | `{r.command}` |")
    out += [
        "",
        "### Install-time only — no version is knowable at build time",
        "",
        "| Component | Why | How to read it on a machine |",
        "|-----------|-----|-----------------------------|",
    ]
    for r in sorted(by_kind["install-time"], key=lambda x: x.name.lower()):
        out.append(f"| {r.name} | distro/vendor package, not locked by Venya | `{r.command}` |")
    out += [
        "",
        "**The boundary that produced the defect this block replaces:** `docker-sbx` is not in",
        "`uv.lock` and is not in any lock file. It is a Docker apt package pulled from",
        "`get.docker.com`'s floating repository, so a dependency inventory that reads only the Python",
        "lock cannot see it move. Its row above is the floor the installer enforces, read from that",
        "installer, not a version anybody typed.",
        "",
        END,
    ]
    return "\n".join(out)


NOTICES_PAGE = "THIRD-PARTY-NOTICES.md"

#: The page the block is REQUIRED on. One name, used only to refuse a deleted block — the SCAN of
#: pages is a glob (see the cli test's use of `root_docs()`), so this is not the name-list defect #640
#: was filed over: a new root page is covered whether or not anyone knows its name.
REQUIRED_BLOCK_PAGE = "THIRD-PARTY-NOTICES.md"


def splice(doc_text: str, block: str) -> str:
    """Replace the region between the sentinels. Refuses loudly if only one is there."""
    if (BEGIN in doc_text) != (END in doc_text):
        raise ValueError(
            f"{doc_text[:40]}... has ONE sentinel of a generated block — both must be present, or "
            "the block cannot be re-derived"
        )
    start = doc_text.index(BEGIN)
    stop = doc_text.index(END, start) + len(END)
    return doc_text[:start] + block + doc_text[stop:]


def unbacked_versions(doc_text: str, rows: list[Row], label: str = "THIRD-PARTY-NOTICES.md") -> list[str]:
    """Version numbers attached to a component name OUTSIDE the generated block.

    This is the half that catches a hand-typed claim. Two shapes, deliberately differently scoped:

    * **dotted** (`0.38.0`) — a version wherever it appears beside a component name. `mcp 1.29.1` in a
      prose footer is a claim about the shipped face.
    * **bare major** (`PostgreSQL 16`) — checked ONLY inside a markdown table cell, and ONLY when the
      cell is exactly `Component N`. A bare integer in prose is routinely not a version at all: the
      first pass over `CHANGELOG.md` flagged `nginx 330` (seconds) and `mcp 36` (a test count), which
      is a false alarm that would have gotten this gate switched off. A table's first column has no
      such ambiguity — that is where a component's version is asserted.
    """
    outside = doc_text
    if BEGIN in outside and END in outside:
        start = outside.index(BEGIN)
        stop = outside.index(END) + len(END)
        outside = outside[:start] + outside[stop:]

    face = {r.name: _face_token(r.version) for r in rows if r.version}
    unresolvable = {r.name for r in rows if not r.version}
    # Every component the tree resolves is a name a prose claim can be checked against, plus the
    # spellings above that differ from the lock key. Built from the rows, not a fixed list, so a new
    # dependency is covered without anyone editing the scanner.
    aliases = {r.name.lower(): r.name for r in rows}
    aliases.update(_ALIASES)
    problems: list[str] = []
    seen: set[tuple[int, str]] = set()

    def _report(lineno: int, token: str, text: str, component: str) -> None:
        key = (lineno, text)
        if key in seen:
            return
        seen.add(key)
        truth = face.get(component)
        if truth is None and component in unresolvable:
            problems.append(
                f"{label}:{lineno}: `{text}` states a version for a component this tree cannot "
                "resolve — state the floor, not a number"
            )
        elif truth and not (truth.startswith(token) or token.startswith(truth)):
            problems.append(f"{label}:{lineno}: `{text}` does not match the resolved face `{truth}`")

    for lineno, line in enumerate(outside.split("\n"), 1):
        for alias, component in sorted(aliases.items()):
            for m in re.finditer(rf"\b{re.escape(alias)}\s+v?(\d+(?:\.\d+)+)", line, re.IGNORECASE):
                _report(lineno, m.group(1), m.group(0), component)
            if line.lstrip().startswith("|"):
                for cell in line.split("|"):
                    m = re.fullmatch(
                        rf"\s*{re.escape(alias)}\s+v?(\d+)\s*", cell, re.IGNORECASE
                    )  # a whole cell: `PostgreSQL 16`, nothing else in it
                    if m:
                        _report(lineno, m.group(1), m.group(0).strip(), component)
    return problems


def probe() -> list[str]:
    """This machine's dpkg face. Printed, never written into the doc."""
    lines = []
    if shutil.which("dpkg-query") is None:
        return ["dpkg-query: absent on this machine — vendor versions unresolvable here"]
    for _name, _floor, apt_names in VENDOR:
        for pkg in apt_names:
            r = subprocess.run(
                ["dpkg-query", "-W", "-f=${Version}", pkg],
                capture_output=True,
                text=True,
                check=False,
            )
            lines.append(f"{pkg}: {r.stdout.strip() or 'NOT INSTALLED'}")
    for tool in ("nginx", "psql", "uv", "cargo"):
        path = shutil.which(tool)
        if path is None:
            lines.append(f"{tool}: absent")
            continue
        r = subprocess.run([path, "--version"], capture_output=True, text=True, check=False)
        lines.append(f"{tool}: {(r.stdout or r.stderr).splitlines()[0] if r.stdout or r.stderr else '?'}")
    return lines


def check(doc_text: str, rows: list[Row], label: str = NOTICES_PAGE) -> list[str]:
    """Everything that should stop a tag: a stale block, a missing block, an unbacked version claim.

    Three shapes, because "no problem" has three different lies behind it:
      * sentinels present, block stale            -> regenerate
      * sentinels absent on the page that owns it -> the block was DELETED to quiet the gate. Red.
      * any page claiming a version off-face      -> the claim moves or the doc says it cannot know.
    """
    problems: list[str] = []
    has_block = BEGIN in doc_text and END in doc_text
    if not has_block:
        if label == REQUIRED_BLOCK_PAGE:
            problems.append(
                f"{label}: no generated block (both sentinels required). Deleting the version list "
                "does not satisfy this gate — regenerate with "
                "python3 scripts/gen_third_party_notices.py --write"
            )
    else:
        try:
            spliced = splice(doc_text, render_block(rows))
        except ValueError as e:
            return [str(e)]
        if spliced != doc_text:
            problems.append(
                f"{label}: the generated block does not match this tree — regenerate: "
                "python3 scripts/gen_third_party_notices.py --write"
            )
    problems += unbacked_versions(doc_text, rows, label)
    return problems


def main(argv: list[str] | None = None) -> int:
    rows = resolve()
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--check", action="store_true", help="exit 1 on drift or an unbacked version claim")
    ap.add_argument("--write", action="store_true", help="rewrite the generated block in the doc")
    ap.add_argument("--probe", action="store_true", help="also print this machine's dpkg face (never shipped)")
    args = ap.parse_args(argv)

    if args.probe:
        print("\n".join(probe()))

    if args.check:
        problems = check(DOC.read_text(encoding="utf-8"), rows)
        for p in problems:
            print(p, file=sys.stderr)
        if problems:
            return 1
        print(f"{len(rows)} components resolved; shipped block matches the tree")
        return 0

    if args.write:
        text = DOC.read_text(encoding="utf-8")
        DOC.write_text(splice(text, render_block(rows)), encoding="utf-8")
        print(f"wrote the generated block ({len(rows)} components)")
        return 0

    for r in rows:
        print(f"{r.kind:12s} {r.name:20s} {r.version or '-':16s} {r.command}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
