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
from venya_mcp.server import release_version, run

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
        with pytest.raises(SystemExit) as exc:
            run(["--version"])
        assert exc.value.code == 0
        assert capsys.readouterr().out.strip() == _DECLARED

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


class TestBinaryOnThePath:
    def test_mcp_binary_refuses_an_unknown_flag(self):
        script = str(Path(sys.executable).parent / "venya-mcp")
        out = subprocess.run([script, "--versionn"], capture_output=True, text=True, timeout=60, check=False)
        assert out.returncode == 2, (out.returncode, out.stdout, out.stderr)
        assert "usage: venya-mcp" in out.stderr
        assert "Traceback" not in out.stderr
