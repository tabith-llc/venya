# Copyright (c) 2026 Tabith LLC.
# Use of this source code is governed by the Business Source License 1.1
# included in the LICENSE file at the root of this repository. As of the
# Change Date listed there, the work is available under MPL 2.0.
# SPDX-License-Identifier: BUSL-1.1

"""Leg 369 interlock — a version in the shipped docs must be derivable, or the suite is RED.

**Owner order 2026-10-22, verbatim:** *"add to our release mechanism: we need to re-determine every
dependency version being used and update documentation properly!"*

The defect: `THIRD-PARTY-NOTICES.md` declared `docker-sbx 0.38.0`, typed in September and never
re-checked, while the executor installer pulls that package from Docker's floating apt repo and
enforces only a floor. Ten minor versions of drift shipped in a customer-facing disclosure. Nothing
in the suite could see it, because no check compared the doc to anything.

So this file compares it to everything, in the house shape of `test_bandit_suppressions_doc.py` and
`test_beta_terms_cite_interlock.py`: regenerate and demand byte equality, then demand the same of
every version CLAIM the prose makes. It is loaded off `test_root_docs_version_claim_640.py`'s own
`root_docs()` rather than a new filename list — #640 exists because doc gates that list names miss
the page nobody thought to add, and a version-drift gate that hardcoded `THIRD-PARTY-NOTICES.md`
would repeat that exact mistake on the next root page.

Three things this must not do, and each has a cell:

* **pass by scanning nothing** — `TestNotVacuous` proves the fixture scan sees files and rows.
* **be satisfied by deleting the claim** — the guard is that a version must MATCH a derived face, not
  that it be absent; weakening it to "no versions in docs" would satisfy the letter of the order while
  destroying the disclosure.
* **lie about which half is the control** — AC3 needs a red as well as a green, so the planted-defect
  cells run against a COPY of the tree with the source (not the doc) moved.
"""

import importlib.util
import shutil
from pathlib import Path

import pytest

TESTS_DIR = Path(__file__).resolve().parent
REPO_ROOT = TESTS_DIR.parents[2]


def _load(name: str, path: Path):
    """Load a module by path. Same idiom as `test_httpx2_upper_bound_447.py:45`."""
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None and spec.loader is not None, f"{path} must exist to be interlocked"
    module = importlib.util.module_from_spec(spec)
    # dataclasses resolves annotations through sys.modules, so a module loaded by path must be
    # registered before exec or `@dataclass` raises AttributeError on None.__dict__ (hit at authoring).
    module.__package__ = None
    sys_modules_names = {name}
    import sys

    for n in sys_modules_names:
        sys.modules.setdefault(n, module)
    spec.loader.exec_module(module)
    return module


gen = _load("gen_third_party_notices", REPO_ROOT / "scripts" / "gen_third_party_notices.py")
# The #640 gate is the widening: it enumerates root pages by SHAPE. Reuse its scan, do not restate it.
root_docs_gate = _load("test_root_docs_version_claim_640", TESTS_DIR / "test_root_docs_version_claim_640.py")

DOC = REPO_ROOT / "THIRD-PARTY-NOTICES.md"

#: Files a resolution reads. A planted defect moves one of THESE, so the doc cannot be faked green by
#: editing the doc.
SOURCES = (
    "uv.lock",
    "packages/executor/Cargo.lock",
    "packages/executor/Cargo.toml",
    "install-venya-executor.sh",
    "install-venya-core.sh",
)


def _fixture(tmp_path: Path) -> Path:
    """A tree holding the real sources and the real root pages, under a throwaway root.

    Copied, not symlinked: `resolve()` reads files relative to its root, so the fixture has to be a
    directory shape, and the member manifests have to come along or the dependency set is empty and
    every cell below would pass on an empty scan.
    """
    for rel in SOURCES:
        dst = tmp_path / rel
        dst.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy(REPO_ROOT / rel, dst)
    for manifest in sorted((REPO_ROOT / "packages").glob("*/pyproject.toml")):
        dst = tmp_path / "packages" / manifest.parent.name / "pyproject.toml"
        dst.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy(manifest, dst)
    shutil.copy(REPO_ROOT / "pyproject.toml", tmp_path / "pyproject.toml")
    for page in root_docs_gate.root_docs(REPO_ROOT):
        shutil.copy(page, tmp_path / page.name)
    return tmp_path


def _scan(root: Path) -> list[str]:
    """Every problem the gate can see in `root`, across ALL its root pages."""
    rows = gen.resolve(root)
    problems: list[str] = []
    for page in root_docs_gate.root_docs(root):
        problems += gen.check(page.read_text(encoding="utf-8"), rows, page.name)
    return problems


class TestShippedTree:
    """The gate over the real venue. Green here means it LOOKED and agreed, not that it skipped."""

    def test_generated_block_matches_this_tree(self):
        rows = gen.resolve()
        assert rows, "resolve() returned nothing — the interlock would be checking an empty table"
        assert gen.check(DOC.read_text(encoding="utf-8"), rows) == [], (
            "THIRD-PARTY-NOTICES.md is stale against the lock files — regenerate with "
            "python3 scripts/gen_third_party_notices.py --write"
        )

    def test_root_pages_carry_no_unbacked_version_claim(self):
        """All root pages, by shape. A version beside a component name must equal the derived face."""
        pages = root_docs_gate.root_docs(REPO_ROOT)
        assert len(pages) >= 5, f"suspiciously small root scan: {sorted(p.name for p in pages)}"
        problems = []
        rows = gen.resolve()
        for page in pages:
            problems += gen.unbacked_versions(page.read_text(encoding="utf-8"), rows, page.name)
        assert problems == [], problems

    def test_the_stale_docker_sbx_string_is_gone(self):
        """The named symptom. Pinned separately because 'the block regenerates' does not by itself
        prove the OLD claim was removed rather than merely duplicated beside the new one."""
        text = DOC.read_text(encoding="utf-8")
        assert "docker-sbx 0.38.0" not in text
        assert "0.38.0" not in text, "a bare 0.38.0 survives somewhere on the page"


class TestPlantedDefect:
    """AC3's red half. Each cell moves a SOURCE and expects the doc — unchanged — to disagree."""

    def test_a_lock_move_makes_the_shipped_page_stale(self, tmp_path: Path):
        """Bump one locked version in the fixture's `uv.lock` and leave the doc alone: RED.

        This is the control for the whole leg. A gate that only ever gets seen green is untested, and
        the way this one could silently stop working is a `resolve()` that returns the doc's numbers
        rather than the lock's — which would read green forever.
        """
        root = _fixture(tmp_path)
        lock = root / "uv.lock"
        text = lock.read_text(encoding="utf-8")
        truth = next(r.version for r in gen.resolve(root) if r.name == "httpx2")
        moved = _bump(truth)
        patched = _move_lock_package(text, "httpx2", moved)
        assert patched != text, f"fixture edit did nothing (httpx2 {truth} -> {moved})"
        lock.write_text(patched, encoding="utf-8")

        rows = gen.resolve(root)
        face = next(r.version for r in rows if r.name == "httpx2")
        assert face == moved, "resolve() is not reading uv.lock — it would never see a version move"
        problems = gen.check((root / "THIRD-PARTY-NOTICES.md").read_text(encoding="utf-8"), rows)
        assert problems, f"a moved lock left the shipped page green: {face}"
        assert any("generated block" in p for p in problems), problems

    def test_a_stale_claim_typed_into_a_root_page_is_red(self, tmp_path: Path):
        """The exact original defect, planted: a hand-typed vendor version that is not the derived face."""
        root = _fixture(tmp_path)
        page = root / "THIRD-PARTY-NOTICES.md"
        rows = gen.resolve(root)
        assert (
            gen.unbacked_versions(page.read_text(encoding="utf-8"), rows) == []
        ), "the fixture doc is not clean, so this cell cannot prove the plant is what went red"
        stale = _stale_face(rows)
        page.write_text(
            page.read_text(encoding="utf-8") + f"\n\nVerified against installed metadata: docker-sbx {stale}.\n",
            encoding="utf-8",
        )
        problems = gen.unbacked_versions(page.read_text(encoding="utf-8"), gen.resolve(root))
        assert problems, f"a planted vendor version ({stale}) walked past the gate"
        assert any("docker-sbx" in p for p in problems), problems

    def test_a_new_root_page_is_covered_without_editing_the_gate(self, tmp_path: Path):
        """#640's rule, applied here: coverage is a property of the scan, not of a name list."""
        root = _fixture(tmp_path)
        rows = gen.resolve(root)
        stale = _stale_face(rows)
        (root / "WARRANTY.md").write_text(f"# Warranty\n\nShips with httpx2 {stale}.\n", encoding="utf-8")
        assert _scan(root), "a brand-new root page carrying a wrong version read clean"

    def test_dropping_the_generated_block_is_red_not_green(self, tmp_path: Path):
        """The fail-loudly bar: deleting the version list is NOT how this gate is satisfied.

        Stripping the sentinels would make every prose claim vanish along with the truth, and a check
        that reads "no versions, no problem" would reward that. It refuses instead.
        """
        root = _fixture(tmp_path)
        page = root / "THIRD-PARTY-NOTICES.md"
        text = page.read_text(encoding="utf-8")
        start, stop = text.index(gen.BEGIN), text.index(gen.END) + len(gen.END)
        page.write_text(text[:start] + text[stop:], encoding="utf-8")
        problems = gen.check(page.read_text(encoding="utf-8"), gen.resolve(root))
        assert problems and any("no generated block" in p for p in problems), problems

    def test_a_dropped_installer_floor_is_reported_not_guessed(self, tmp_path: Path):
        """The `docker-sbx` row's floor is READ from the installer. If the installer stops enforcing
        one, the row must say so — it must not keep a number it can no longer point at."""
        root = _fixture(tmp_path)
        installer = root / "install-venya-executor.sh"
        text = installer.read_text(encoding="utf-8")
        assert 'SBX_MIN_VERSION="' in text, "fixture moved: the floor line is not where the gate looks"
        installer.write_text(
            text.replace('SBX_MIN_VERSION="', 'SBX_MIN_VERSION_MOVED="'),
            encoding="utf-8",
        )
        rows = gen.resolve(root)
        sbx = next(r for r in rows if r.name == "docker-sbx")
        assert sbx.version == "", f"a floor nobody enforces is still being reported: {sbx.version!r}"
        assert sbx.kind == "install-time"


class TestNotVacuous:
    def test_resolution_reads_both_locks(self):
        rows = gen.resolve()
        names = {r.name for r in rows}
        kinds = {r.name: r.kind for r in rows}
        assert "cryptography" in names and kinds["cryptography"] == "locked", "uv.lock side unread"
        assert "pyo3" in names and kinds["pyo3"] == "locked", "Cargo.lock side unread"
        assert len([r for r in rows if r.kind == "locked"]) >= 20, "suspiciously few locked rows"

    def test_the_vendor_class_is_named_and_not_empty(self):
        """The blind spot that produced the defect is part of the OUTPUT, not a comment."""
        rows = gen.resolve()
        vendor = [r for r in rows if r.name in ("docker-sbx", "docker-ce", "nginx", "postgresql")]
        assert len(vendor) == 4, f"vendor rows missing: {[r.name for r in vendor]}"
        block = gen.render_block(rows)
        assert "not in any lock file" in block, "the block stopped naming the boundary"

    def test_the_probe_is_never_written_into_the_doc(self):
        """Machine state cannot ship, or the interlock reddens on the next host.

        Asserted against the live page rather than the renderer: the guard is on the artifact.
        """
        text = DOC.read_text(encoding="utf-8")
        assert "dpkg-query" in text, "expected the probe COMMANDS to ship (how to read it yourself)"
        for marker in ("NOT INSTALLED", "unknown-linux"):
            assert marker not in text, f"this machine's dpkg face leaked into the shipped doc: {marker}"

    def test_fixture_scan_is_not_empty(self, tmp_path: Path):
        """A positive control on the harness itself: the copy must be scannable, or every RED above
        would be red for the wrong reason."""
        root = _fixture(tmp_path)
        assert gen.resolve(root), "fixture has no resolvable components"
        assert root_docs_gate.root_docs(root), "fixture has no root pages to scan"
        assert _scan(root) == []


def _bump(version: str) -> str:
    """A different version of the same shape, derived from the real one (never a literal plate)."""
    parts = version.split(".")
    last = parts[-1]
    digits = "".join(c for c in last if c.isdigit())
    if not digits:
        return version + ".1"
    new_last = last.replace(digits, str(int(digits) + 7))
    parts[-1] = new_last
    out = ".".join(parts)
    assert out != version
    return out


def _stale_face(rows) -> str:
    """A `docker-sbx`-shaped version that is NOT the resolved one."""
    truth = next((r.version for r in rows if r.name == "docker-sbx"), "0.39.0")
    return _bump(truth)


def _move_lock_package(lock_text: str, package: str, new_version: str) -> str:
    """Rewrite ONE package's version line in a lock file, anchored on its own `name = "<pkg>"`.

    Anchoring matters: `version = "2.12.0"` is not unique in `uv.lock`, and a first-match replace on
    the bare version line moved a DIFFERENT package (found by running it — `resolve()` still reported
    the real httpx2 face and the cell went red for the wrong reason). A fixture that plants a defect
    somewhere other than the place named is worse than no fixture, because the RED it produces looks
    like a caught bug.
    """
    lines = lock_text.split("\n")
    for i, line in enumerate(lines):
        if line == f'name = "{package}"' and i + 1 < len(lines) and lines[i + 1].startswith("version = "):
            lines[i + 1] = f'version = "{new_version}"'
            return "\n".join(lines)
    raise AssertionError(f"{package} not found in the lock text the way the gate reads it")


@pytest.mark.parametrize("bad_page", ["THIRD-PARTY-NOTICES.md"])
def test_gate_names_the_page_it_flags(bad_page: str, tmp_path: Path):
    """A violation must say WHERE it is. A bare 'something is stale' is not actionable at the cut."""
    root = _fixture(tmp_path)
    page = root / bad_page
    rows = gen.resolve(root)
    stale = _stale_face(rows)
    page.write_text(
        page.read_text(encoding="utf-8") + f"\n\nRuns on docker-sbx {stale}.\n",
        encoding="utf-8",
    )
    problems = _scan(root)
    assert problems, "no problem reported"
    assert all(p.startswith(f"{bad_page}:") for p in problems), problems
