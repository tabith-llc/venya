# Copyright (c) 2026 Tabith LLC.
# Use of this source code is governed by the Business Source License 1.1
# included in the LICENSE file at the root of this repository. As of the
# Change Date listed there, the work is available under MPL 2.0.
# SPDX-License-Identifier: BUSL-1.1

"""One canonical version rendering across the layers (ticket version-reporting, leg 1196).

The defect: seven plates declare ``0.1.0beta3`` and two build backends write that
declaration differently — hatchling copies it verbatim, setuptools (the executor, for
its Rust extension) normalizes it to PEP 440 canonical form — so one tree answered
``0.1.0beta3`` on three surfaces and ``0.1.0b3`` on the executor's.

The truth these cells read is the **declaration**, taken from each plate's own
``pyproject.toml`` — not ``importlib.metadata``, which is the thing that drifted.
"""

from __future__ import annotations

import subprocess
import sys
import tomllib
from pathlib import Path
from typing import ClassVar

import pytest
from core.version import UNKNOWN, build_identity, canonical_release, dist_version, release_version

_ROOT = Path(__file__).resolve().parents[3]

#: dist name -> the plate that declares it. The root plate is included because the
#: release record's nameplate guard reads that one.
_PLATES = {
    "root": _ROOT / "pyproject.toml",
    "core": _ROOT / "packages/core/pyproject.toml",
    "server": _ROOT / "packages/server/pyproject.toml",
    "executor": _ROOT / "packages/executor/pyproject.toml",
    "venya-cli": _ROOT / "packages/cli/pyproject.toml",
    "venya-mcp": _ROOT / "packages/mcp/pyproject.toml",
    "venya-contract": _ROOT / "packages/venya-contract/pyproject.toml",
}


def _declared(path: Path) -> str:
    return tomllib.loads(path.read_text(encoding="utf-8"))["project"]["version"]


class TestCanonicalRendering:
    @pytest.mark.parametrize(
        "raw,expected",
        [
            ("0.1.0b3", "0.1.0beta3"),
            ("0.1.0beta3", "0.1.0beta3"),
            ("0.1.0a16", "0.1.0alpha16"),
            ("0.1.0alpha16", "0.1.0alpha16"),
            ("0.1.0rc1", "0.1.0rc1"),
            ("0.1.0c1", "0.1.0rc1"),
            ("1.2.3", "1.2.3"),
            ("10.20.30b4", "10.20.30beta4"),
        ],
    )
    def test_one_rule_one_answer(self, raw, expected):
        assert canonical_release(raw) == expected

    def test_nothing_is_mapped_twice(self):
        """The spelled form is a fixed point: rendering an already-canonical answer is inert."""
        once = canonical_release("0.1.0b3")
        assert canonical_release(once) == once == "0.1.0beta3"

    def test_the_honest_signal_survives_rendering(self):
        """``unknown`` is not a version and must never be rendered into one."""
        assert canonical_release(UNKNOWN) == UNKNOWN
        assert release_version("no-such-distribution-here-1196") == UNKNOWN

    def test_an_empty_value_is_not_invented(self):
        assert canonical_release("") == ""


class TestDeclarationAgreement:
    """Every plate declares one string, and every layer answers with that string."""

    def test_all_plates_declare_the_same_version(self):
        found = {name: _declared(path) for name, path in _PLATES.items()}
        assert len(set(found.values())) == 1, f"the plates disagree: {found}"

    @pytest.mark.parametrize("dist", ["core", "server", "executor", "venya-cli", "venya-mcp"])
    def test_each_layer_answers_with_its_declared_spelling(self, dist):
        declared = _declared(_PLATES[dist])
        assert release_version(dist) == declared, (
            f"{dist} declares {declared!r} but its metadata reads {dist_version(dist)!r} — "
            "the surfaces and the release record would disagree"
        )

    def test_the_executor_case_that_motivated_this(self):
        """The executor is the setuptools-built layer. Its metadata may read the
        normalized form; what a layer ANSWERS must still be the declaration."""
        declared = _declared(_PLATES["executor"])
        assert canonical_release(dist_version("executor")) == declared


class TestBinariesAnswerIdentically:
    """The regression guard the fix is judged by: run each binary's ``--version``
    and require the same canonical string, from the console scripts themselves —
    the path an operator actually takes, not the function under test.
    """

    _BINARIES: ClassVar[dict[str, str]] = {
        "venya-server": "server",
        "venya-executor": "executor",
        "venya-mcp": "venya-mcp",
        "venya": "venya-cli",
    }

    def test_a_stamped_face_prints_identically_on_every_binary(self):
        """R-2876, the whole set in one run: when the release states a face, every
        binary answers the same two facts — the declared release, then that face —
        and no layer restates the rule to do it.

        The statement is passed to each subprocess rather than set in this process,
        so what is compared is four printed lines, not four calls to one function.
        """
        import os

        env = {**os.environ, "VENYA_BUILD_COMMIT": "cafe1234"}
        for binary, dist in sorted(self._BINARIES.items()):
            script = Path(sys.executable).parent / binary
            out = subprocess.run(
                [str(script), "--version"], capture_output=True, text=True, timeout=60, check=False, env=env
            )
            assert out.returncode == 0, f"{binary} --version exited {out.returncode}: {out.stderr}"
            assert (
                out.stdout.strip() == f"{_declared(_PLATES[dist])} (build cafe1234)"
            ), f"{binary} printed {out.stdout.strip()!r}"

    @pytest.mark.parametrize("binary,dist", sorted(_BINARIES.items()))
    def test_version_flag_prints_the_declaration_and_exits_zero(self, binary, dist):
        script = Path(sys.executable).parent / binary
        if not script.is_file():
            pytest.fail(f"{binary} is not installed in this venue — {script} — so the surface is unproven")
        out = subprocess.run([str(script), "--version"], capture_output=True, text=True, timeout=60, check=False)
        assert out.returncode == 0, f"{binary} --version exited {out.returncode}: {out.stderr}"
        assert "Traceback" not in out.stderr, f"{binary} --version printed a traceback: {out.stderr}"
        printed = out.stdout.strip().split()[0]
        assert printed == _declared(_PLATES[dist]), f"{binary} printed {out.stdout.strip()!r}"
        assert "Traceback" not in out.stdout

    @pytest.mark.parametrize("binary,dist", sorted(_BINARIES.items()))
    def test_every_binary_answer_also_names_a_face(self, binary, dist):
        """Item 3, now for the whole set (R-2876): a commit or build identifier is
        reachable from a running install, on every binary and not just the server.

        The line is version-then-face, and the face is whatever ``build_identity``
        can prove. This venue is a git checkout, so it must be a sha prefix — and if
        the tree is dirty it must say so rather than look clean.
        """
        script = Path(sys.executable).parent / binary
        assert script.is_file(), f"{binary} is not installed in this venue — {script}"
        out = subprocess.run([str(script), "--version"], capture_output=True, text=True, timeout=60, check=False)
        assert out.returncode == 0, f"{binary} --version exited {out.returncode}: {out.stderr}"
        line = out.stdout.strip()
        assert "(build " in line, f"{binary} printed no face: {line!r}"
        face = line.split("(build ", 1)[1].rstrip(")")
        declared = _declared(_PLATES[dist])
        assert line.startswith(f"{declared} (build "), f"{binary} printed {line!r}"
        token = face.removesuffix("+dirty")
        assert token == UNKNOWN or (
            len(token) >= 7 and all(c in "0123456789abcdef" for c in token)
        ), f"the face field is neither a sha prefix nor the honest signal: {face!r}"
        if "+dirty" in face:
            assert subprocess.run(
                ["git", "status", "--porcelain"], cwd=_ROOT, capture_output=True, text=True, check=False
            ).stdout.strip(), "a +dirty answer with a clean tree is a lie in the other direction"


class TestBuildIdentityIsHonest:
    def test_environment_statement_wins_and_is_printed_verbatim(self, monkeypatch):
        monkeypatch.setenv("VENYA_BUILD_COMMIT", "deadbeef1")
        assert build_identity() == "deadbeef1"

    def test_blank_environment_is_not_an_answer(self, monkeypatch):
        """A set-but-empty variable must not print an empty face."""
        monkeypatch.setenv("VENYA_BUILD_COMMIT", "   ")
        assert build_identity() != ""

    def test_no_route_yields_the_honest_signal(self, monkeypatch):
        """Not a checkout, no stamp, no variable: say ``unknown``, never a clean-looking sha.

        This venue IS a checkout, so the two other routes are taken away deliberately:
        the git probe answers None (no repository) and the stamp filename is pointed at a
        name that cannot exist. The assertion is that the function degrades to the signal
        rather than to a value.
        """
        import core.version as core_version

        monkeypatch.delenv("VENYA_BUILD_COMMIT", raising=False)
        monkeypatch.setattr(core_version, "_git", lambda cwd, *args: None)
        monkeypatch.setattr(core_version, "BUILD_COMMIT_FILENAME", "no-such-stamp-1196")
        assert core_version.build_identity() == UNKNOWN

    def test_the_stamp_file_route_is_read_and_the_first_token_is_the_answer(self, monkeypatch, tmp_path):
        """An install that carries a stamp is believed — that is the artifact-only path."""
        import core.version as core_version

        monkeypatch.delenv("VENYA_BUILD_COMMIT", raising=False)
        (tmp_path / "BUILD_COMMIT").write_text("cafe123 built by the release recipe\n", encoding="utf-8")
        monkeypatch.setattr(core_version, "_git", lambda cwd, *args: None)
        monkeypatch.setattr(
            core_version,
            "_stamp_path",
            lambda: tmp_path / core_version.BUILD_COMMIT_FILENAME,
        )
        assert core_version.build_identity() == "cafe123"

    def test_the_surface_says_unknown_when_no_route_exists(self, monkeypatch):
        """The paired negative for R-2876, at the printed line rather than the helper.

        With no variable, no stamp and no repository, ``venya-server --version`` must
        print the honest signal — a surface that always looks like a release is worse
        than one that admits it cannot tell.
        """
        import core.version as core_version

        monkeypatch.delenv("VENYA_BUILD_COMMIT", raising=False)
        monkeypatch.setattr(core_version, "_git", lambda cwd, *args: None)
        monkeypatch.setattr(core_version, "BUILD_COMMIT_FILENAME", "no-such-stamp-1225")
        assert core_version.version_line("core").endswith(f"(build {UNKNOWN})")
