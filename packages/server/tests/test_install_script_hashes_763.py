# Copyright (c) 2026 Tabith LLC.
# Use of this source code is governed by the Business Source License 1.1
# included in the LICENSE file at the root of this repository. As of the
# Change Date listed there, the work is available under MPL 2.0.
# SPDX-License-Identifier: BUSL-1.1

"""Currency of install-script-hashes.MANIFEST (#763, owner words O970 + O971).

The repo half of the fingerprint fix is only worth having if a script edit CANNOT land without its
fingerprint moving in the same diff. That is this file's job: rehash the working-tree bytes of every
tracked script and fail on drift. The SERVED half (sidecars emitted by `create-tarball-and-serve.sh`
after its substitutions) lives in the installer repo and is deliberately not asserted here — served
bytes differ from repo bytes by construction, which is the whole reason the manifest exists beside
the scripts rather than as committed per-file sidecars a customer could never check.

Paired negatives, each proven RED by construction rather than argued: a script edited under a stale
manifest, a script added with no row, a row left behind for a removed path, and a hash/role column
rewritten by hand. Synthetic fixture trees, so no cell mutates the repo.
"""

from __future__ import annotations

import hashlib
import importlib.util
import subprocess  # nosec B404 — fixed argv, own scratch git in fixture cells
from pathlib import Path

_HERE = Path(__file__).resolve().parent
_GEN = _HERE.parent / "scripts" / "gen_install_script_hashes.py"
_spec = importlib.util.spec_from_file_location("gen_install_script_hashes", _GEN)
ggen = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(ggen)  # house import form (test_beta_terms_cite_interlock.py:68)

build_manifest = ggen.build_manifest
check = ggen.check
parse_manifest = ggen.parse_manifest
tracked_scripts = ggen.tracked_scripts
MANIFEST = ggen.MANIFEST

REPO_ROOT = Path(__file__).resolve().parents[3]  # packages/server/tests -> repo root


def _sha(text: str) -> str:
    return hashlib.sha256(text.encode()).hexdigest()


class TestRealManifestIsCurrent:
    def test_manifest_covers_every_tracked_script_and_agrees(self):
        """The currency claim over THIS checkout: drift here fails the suite."""
        problems = check(Path(REPO_ROOT))
        assert problems == [], "\n".join(problems)

    def test_discovery_actually_finds_the_scripts(self):
        """The positive control for the negative test below: if `git ls-files '*.sh' '*.ps1'` ever
        returned nothing, every drift cell would be vacuously green."""
        found = tracked_scripts(Path(REPO_ROOT))
        assert "install-venya-core.sh" in found
        assert "venya-common.sh" in found
        assert len(found) >= 9


class TestDriftGoesRed:
    """Each of these builds a throwaway repo, so `check()` can be pointed at bytes no cell is
    allowed to write into the real tree."""

    @staticmethod
    def _fixture(tmp_path: Path, scripts: dict[str, str]) -> Path:
        for rel, body in scripts.items():
            p = tmp_path / rel
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_text(body, encoding="utf-8")
        git = ["git", "-C", str(tmp_path)]
        subprocess.run(git + ["init", "-q"], check=True, capture_output=True)  # nosec B603
        subprocess.run(git + ["add", "-A"], check=True, capture_output=True)  # nosec B603
        # ls-files reads the INDEX, so `git add` alone makes a path "tracked" for discovery —
        # no commit and no identity needed for a throwaway fixture.
        manifest = tmp_path / "install-script-hashes.MANIFEST"
        manifest.write_text(build_manifest(tmp_path), encoding="utf-8")
        return tmp_path

    def test_stale_row_for_edited_script_is_red(self, tmp_path):
        repo = self._fixture(tmp_path, {"install-venya-core.sh": "# v1\n", "venya-common.sh": "# lib\n"})
        (repo / "install-venya-core.sh").write_text("# v2 — edited, manifest NOT regenerated\n", encoding="utf-8")
        problems = check(repo)
        assert len(problems) == 1 and "drift: install-venya-core.sh" in problems[0]

    def test_added_script_without_a_row_is_red(self, tmp_path):
        repo = self._fixture(tmp_path, {"install-venya-core.sh": "# v1\n"})
        (repo / "install-venya-new.sh").write_text("# new\n", encoding="utf-8")
        subprocess.run(  # nosec B603
            ["git", "-C", str(repo), "add", "install-venya-new.sh"], check=True, capture_output=True
        )
        problems = check(repo)
        assert problems and "no manifest row for tracked script: install-venya-new.sh" in problems[0]

    def test_row_for_an_untracked_path_is_red(self, tmp_path):
        repo = self._fixture(tmp_path, {"install-venya-core.sh": "# v1\n", "gone-venya-old.sh": "# x\n"})
        (repo / "gone-venya-old.sh").unlink()
        subprocess.run(  # nosec B603
            ["git", "-C", str(repo), "rm", "-q", "--cached", "gone-venya-old.sh"], check=True, capture_output=True
        )
        problems = check(repo)
        assert problems and any("no longer tracks" in p for p in problems)

    def test_hand_edited_column_swap_is_red(self, tmp_path):
        """A gate you can defeat by editing the gate's data is no gate: swapping hash and path in a
        row must not read as currency."""
        repo = self._fixture(tmp_path, {"install-venya-core.sh": "# v1\n"})
        manifest = repo / "install-script-hashes.MANIFEST"
        rows = [ln for ln in manifest.read_text(encoding="utf-8").splitlines() if ln and not ln.startswith("#")]
        digest, rest = rows[0].split("  ", 1)
        path, _, role = rest.partition("  ")
        manifest.write_text("# header\n" + f"{path}  {digest}  {role}\n", encoding="utf-8")
        problems = check(repo)
        assert problems, "a swapped-column row must not pass the currency check"


class TestFormatContract:
    def test_every_row_has_three_fields_and_a_64_hex_digest(self):
        text = MANIFEST.read_text(encoding="utf-8")
        entries = parse_manifest(text)
        assert len(entries) >= 9
        for path, (digest, role) in entries.items():
            assert len(digest) == 64 and all(c in "0123456789abcdef" for c in digest), path
            assert role.strip(), f"row for {path} carries no role"

    def test_venya_common_digest_is_the_published_one(self):
        """Interlock with the #360 embed: the library hash in the manifest is the hash the build
        embeds; if they ever disagree, the committed bytes and the served bytes diverged silently."""
        entries = parse_manifest(MANIFEST.read_text(encoding="utf-8"))
        assert entries["venya-common.sh"][0] == _sha(Path(REPO_ROOT / "venya-common.sh").read_text(encoding="utf-8"))
