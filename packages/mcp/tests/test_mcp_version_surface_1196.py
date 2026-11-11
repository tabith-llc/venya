# Copyright (c) 2026 Tabith LLC.
# Use of this source code is governed by the Business Source License 1.1
# included in the LICENSE file at the root of this repository. As of the
# Change Date listed there, the work is available under MPL 2.0.
# SPDX-License-Identifier: BUSL-1.1

"""The ``venya-mcp`` argument surface, and the rendering pin (leg 1196).

Two things live here because both are about the MCP layer's one version answer:

1. ``run()`` now reads argv. Before, nothing did: ``--version`` fell into the config
   load and ``--help`` started a stdio server.
2. ``core.version`` owns the canonical rendering and this wheel does not depend on
   ``core``, so the rule is not copied here — the *agreement* is asserted instead, and it
   fails loudly the day this layer's metadata stops matching the plate it declares.
"""

from __future__ import annotations

import subprocess
import sys
import tomllib
from pathlib import Path

import pytest
from core.version import canonical_release
from venya_mcp.server import release_version, run, version_surface

_ROOT = Path(__file__).resolve().parents[3]
_DECLARED = tomllib.loads((_ROOT / "packages/mcp/pyproject.toml").read_text(encoding="utf-8"))["project"]["version"]


def _config_was_read(monkeypatch) -> list:
    """Record any attempt to build the MCP config, so the refusal is measured."""
    calls: list[str] = []
    import venya_mcp.server as mcp_server

    real = mcp_server.MCPConfig

    def spy(*args, **kwargs):
        calls.append("MCPConfig")
        return real(*args, **kwargs)

    monkeypatch.setattr(mcp_server, "MCPConfig", spy)
    return calls


class TestMcpArgSurface:
    def test_version_prints_the_declared_release_and_exits_zero(self, capsys):
        """Leg 1196's contract, widened by R-2876: the release name stays the FIRST
        token, and the face the build came from rides beside it."""
        with pytest.raises(SystemExit) as exc:
            run(["--version"])
        assert exc.value.code == 0
        printed = capsys.readouterr().out.strip()
        assert printed.split()[0] == _DECLARED, printed
        assert "(build " in printed, f"no build face on the MCP surface: {printed!r}"

    def test_help_answers_without_starting_the_stdio_server(self, monkeypatch, capsys):
        started = _config_was_read(monkeypatch)
        with pytest.raises(SystemExit) as exc:
            run(["--help"])
        assert exc.value.code == 0
        captured = capsys.readouterr()
        assert "usage: venya-mcp" in captured.out
        assert not started, "--help read the config — it must answer and leave"

    def test_unknown_flag_is_refused_before_the_config_load(self, monkeypatch, capsys):
        """The silent half: an unrecognized flag used to fall straight into the boot path."""
        started = _config_was_read(monkeypatch)
        with pytest.raises(SystemExit) as exc:
            run(["--transport", "sse"])
        assert exc.value.code == 2
        captured = capsys.readouterr()
        assert "usage: venya-mcp" in captured.err
        assert "unrecognized arguments" in captured.err
        assert "Traceback" not in captured.err
        assert not started

    def test_missing_config_refusal_is_untouched(self, tmp_path, monkeypatch, capsys):
        """Paired negative for #41's clean-exit behavior: an empty flag list still reaches it.

        If the new parse step had swallowed the boot path, this would exit 2 with usage
        instead of the documented actionable message with exit 1.
        """
        monkeypatch.setenv("VENYA_CONFIG", str(tmp_path / "absent.json"))
        with pytest.raises(SystemExit) as exc:
            run([])
        assert exc.value.code == 1
        assert "No Venya session token found" in capsys.readouterr().err


class TestTheAnswerIsCanonical:
    """The MCP layer carries no copy of the rendering rule, so the *agreement* is the check.

    ``core.version`` owns the rule and this wheel does not depend on ``core``. These two
    cells are what make that safe: the second one goes red the day a build backend starts
    writing a normalized spelling into this layer's metadata, which is the moment someone
    must either render it here or give the wheel the dependency. Silence is not an option
    the suite leaves open.
    """

    def test_the_live_answer_is_the_declaration(self):
        assert release_version() == _DECLARED

    def test_the_answer_is_already_in_canonical_form(self):
        """Idempotence as a drift alarm: a normalized value would NOT equal its own render."""
        answer = release_version()
        assert canonical_release(answer) == answer, (
            f"venya-mcp answers {answer!r}, which core.version would render as "
            f"{canonical_release(answer)!r} — this layer is now disagreeing with the plates"
        )


class TestTheFaceIsHonest:
    """The face is read from the two places a release states it, never restated here,
    and never invented (R-2876). These are the paired negatives the leg is gated on."""

    def test_a_stated_release_is_printed_verbatim(self, monkeypatch):
        monkeypatch.setenv("VENYA_BUILD_COMMIT", "beef12345 built by the release recipe")
        assert version_surface() == f"{_DECLARED} (build beef12345)"

    def test_the_stamp_beside_core_is_read_without_importing_core(self, monkeypatch, tmp_path):
        """A stand-in package dir holding only ``BUILD_COMMIT`` is found on the path and
        read; ``core`` is not loaded to do it — this wheel declares no dependency on it."""
        import venya_mcp.server as mcp_server

        (tmp_path / "core").mkdir()
        (tmp_path / "core" / "__init__.py").write_text("", encoding="utf-8")
        (tmp_path / "core" / "BUILD_COMMIT").write_text("beef12345 stamped at the cut\n", encoding="utf-8")
        monkeypatch.delenv("VENYA_BUILD_COMMIT", raising=False)
        monkeypatch.syspath_prepend(str(tmp_path))
        monkeypatch.delitem(sys.modules, "core", raising=False)
        assert mcp_server.build_face() == "beef12345"
        assert "core" not in sys.modules, "reading the stamp imported core"

    def test_no_statement_and_no_stamp_names_no_sha(self, monkeypatch):
        """A surface that always looks like a release is worse than one that admits it
        cannot tell: with neither route present the answer is ``unknown``."""
        import venya_mcp.server as mcp_server

        monkeypatch.delenv("VENYA_BUILD_COMMIT", raising=False)
        monkeypatch.setattr(mcp_server, "BUILD_COMMIT_FILENAME", "no-such-stamp-1225")
        assert mcp_server.version_surface() == f"{_DECLARED} (build unknown)"

    def test_the_printed_line_keeps_the_version_first(self, capsys):
        with pytest.raises(SystemExit) as exc:
            run(["--version"])
        assert exc.value.code == 0
        printed = capsys.readouterr().out.strip()
        assert printed.split()[0] == _DECLARED, printed
        assert printed.endswith(")") and " (build " in printed, printed


class TestBinaryOnThePath:
    def test_mcp_binary_refuses_an_unknown_flag(self):
        script = str(Path(sys.executable).parent / "venya-mcp")
        out = subprocess.run([script, "--versionn"], capture_output=True, text=True, timeout=60, check=False)
        assert out.returncode == 2, (out.returncode, out.stdout, out.stderr)
        assert "usage: venya-mcp" in out.stderr
        assert "Traceback" not in out.stderr
