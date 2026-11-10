# Copyright (c) 2026 Tabith LLC.
# Use of this source code is governed by the Business Source License 1.1
# included in the LICENSE file at the root of this repository. As of the
# Change Date listed there, the work is available under MPL 2.0.
# SPDX-License-Identifier: BUSL-1.1

"""The ``venya-server`` argument surface (ticket version-reporting, leg 1196).

Before this, ``app.py main()`` never read argv: ``--version`` died inside the config
load with a traceback, and any other flag was **silently discarded** — the binary
ignored it and booted the serve path. These cells drive the real entry point, not a
copy of its logic.

The mandatory paired negative is here too, and it is the load-bearing half:
``argv`` handling was added in front of ``ServerConfig()``, so an operator's bad
admin-mtls configuration must still be refused exactly as it was.
"""

from __future__ import annotations

import subprocess
import sys
import tomllib
from pathlib import Path

import pytest
import server.app as server_app
from core.version import canonical_release, release_version

_ROOT = Path(__file__).resolve().parents[3]
_DECLARED = tomllib.loads((_ROOT / "packages/server/pyproject.toml").read_text(encoding="utf-8"))["project"]["version"]


def _clean_server_env(monkeypatch):
    """Take every VENYA_* out of the picture so a cell states its own config.

    Without this, an operator's own environment (or another suite's leftover) decides
    whether the config is valid, and a cell that is meant to prove a refusal could
    pass for the wrong reason.
    """
    for name in [k for k in list(__import__("os").environ) if k.startswith("VENYA_")]:
        monkeypatch.delenv(name, raising=False)


def _config_was_loaded(monkeypatch) -> list:
    """Record every ServerConfig construction, so "argv before config" is measured."""
    calls: list[str] = []
    real = server_app.ServerConfig

    def spy(*args, **kwargs):
        calls.append("ServerConfig")
        return real(*args, **kwargs)

    monkeypatch.setattr(server_app, "ServerConfig", spy)
    return calls


class TestVersionAndHelpAnswer:
    def test_version_prints_the_declared_release_and_exits_zero(self, monkeypatch, capsys):
        _clean_server_env(monkeypatch)
        loaded = _config_was_loaded(monkeypatch)
        with pytest.raises(SystemExit) as exc:
            server_app.main(["--version"])
        assert exc.value.code == 0
        out = capsys.readouterr().out
        assert out.strip().split()[0] == _DECLARED, out
        assert canonical_release("0.1.0b3") in out, "the rendering must be the declared spelling, not a backend's"
        assert "(build " in out, f"--version must also name the face: {out!r}"
        assert not loaded, "ServerConfig was constructed — a flag answer still loads the config it cannot read"

    def test_help_answers_instead_of_starting_the_service(self, monkeypatch, capsys):
        _clean_server_env(monkeypatch)
        loaded = _config_was_loaded(monkeypatch)
        with pytest.raises(SystemExit) as exc:
            server_app.main(["--help"])
        assert exc.value.code == 0
        captured = capsys.readouterr()
        assert "usage: venya-server" in captured.out, captured.out
        assert "--version" in captured.out, "the surface must document itself"
        assert not loaded, "the usage answer read the config it is meant to avoid"

    def test_version_answer_matches_the_metadata_of_its_own_layer(self):
        """Single-source rule (``feature/version-surfaces`` condition 1) survives the render."""
        assert release_version("server") == _DECLARED


class TestUnknownFlagIsRefused:
    """The silent failure this fix exists for: a mistyped flag used to boot the server."""

    def test_unknown_flag_exits_two_with_usage_and_no_traceback(self, monkeypatch, capsys):
        _clean_server_env(monkeypatch)
        loaded = _config_was_loaded(monkeypatch)
        with pytest.raises(SystemExit) as exc:
            server_app.main(["--serve"])
        assert exc.value.code == 2
        captured = capsys.readouterr()
        assert "usage: venya-server" in captured.err, captured.err
        assert "unrecognized arguments: --serve" in captured.err, captured.err
        assert "Traceback" not in captured.err, captured.err
        assert not loaded, "an unknown flag reached the config load — the boot path is still reachable"

    def test_a_mistyped_flag_cannot_reach_the_boot_path_at_all(self, monkeypatch):
        """The negative that matters, driven with a config that WOULD boot.

        A valid-enough config is supplied (loopback, pepper set, admin-mtls off) and
        the two calls that start the service are replaced with recorders. With a bad
        flag the recorders must stay empty; that is the proof the flag was refused
        before the serve path, not merely printed over.
        """
        _clean_server_env(monkeypatch)
        monkeypatch.setenv("VENYA_HOST", "127.0.0.1")
        monkeypatch.setenv("VENYA_RECOVERY_CODE_PEPPER", "cell-pepper")
        booted: list[str] = []
        monkeypatch.setattr(server_app, "create_app", lambda *a, **k: booted.append("create_app"))
        import uvicorn

        monkeypatch.setattr(uvicorn, "run", lambda *a, **k: booted.append("uvicorn.run"))

        with pytest.raises(SystemExit) as exc:
            server_app.main(["--verion"])  # the realistic typo
        assert exc.value.code == 2
        assert booted == [], f"the serve path ran for a flag nobody declared: {booted}"
        # The recorder is proven live by ``test_the_same_path_boots_when_the_config_is_valid``:
        # the same call form, with a valid config and no bad flag, reaches both.


class TestAdminMtlsRefusalIsIntact:
    """Paired negative: the argv reordering must not weaken the serve path's own checks."""

    def test_enabled_admin_mtls_on_a_public_bind_is_still_refused(self, monkeypatch, capsys):
        _clean_server_env(monkeypatch)
        monkeypatch.setenv("VENYA_HOST", "0.0.0.0")
        monkeypatch.setenv("VENYA_RECOVERY_CODE_PEPPER", "cell-pepper")
        monkeypatch.setenv("VENYA_ADMIN_MTLS__ENABLED", "true")
        monkeypatch.setenv("VENYA_ADMIN_CA_KEY_PASSPHRASE", "some-passphrase")

        with pytest.raises(RuntimeError, match="loopback bind address"):
            server_app.main([])
        assert "Traceback" not in capsys.readouterr().err

    def test_enabled_admin_mtls_without_its_passphrase_is_still_refused(self, monkeypatch):
        _clean_server_env(monkeypatch)
        monkeypatch.setenv("VENYA_HOST", "127.0.0.1")
        monkeypatch.setenv("VENYA_RECOVERY_CODE_PEPPER", "cell-pepper")
        monkeypatch.setenv("VENYA_ADMIN_MTLS__ENABLED", "true")
        monkeypatch.delenv("VENYA_ADMIN_CA_KEY_PASSPHRASE", raising=False)

        with pytest.raises(RuntimeError, match="VENYA_ADMIN_CA_KEY_PASSPHRASE"):
            server_app.main([])

    def test_the_same_path_boots_when_the_config_is_valid(self, monkeypatch):
        """Positive control: these refusals are the config, not ``main()`` always raising.

        Loopback bind, pepper set, admin-mtls enabled *with* its passphrase: the two
        boot calls are reached. Nothing here asserts on the service itself — the point
        is that the gate opened when the operator did what the message asks.
        """
        _clean_server_env(monkeypatch)
        monkeypatch.setenv("VENYA_HOST", "127.0.0.1")
        monkeypatch.setenv("VENYA_RECOVERY_CODE_PEPPER", "cell-pepper")
        monkeypatch.setenv("VENYA_ADMIN_MTLS__ENABLED", "true")
        monkeypatch.setenv("VENYA_ADMIN_CA_KEY_PASSPHRASE", "some-passphrase")

        booted: list[str] = []
        monkeypatch.setattr(server_app, "create_app", lambda *a, **k: booted.append("create_app"))
        import uvicorn

        monkeypatch.setattr(uvicorn, "run", lambda *a, **k: booted.append("uvicorn.run"))
        server_app.main([])
        assert booted == ["create_app", "uvicorn.run"], booted

    def test_a_missing_required_setting_is_still_demanded(self, monkeypatch):
        """No flag, no config: the old traceback path is preserved for a real misconfiguration."""
        _clean_server_env(monkeypatch)
        with pytest.raises(Exception) as exc:
            server_app.main([])
        assert type(exc.value).__name__ == "ValidationError"
        assert "recovery_code_pepper" in str(exc.value)


class TestBinaryOnThePath:
    """The same four claims through the installed console script, in a child process."""

    def _run(self, *args):
        script = str(Path(sys.executable).parent / "venya-server")
        return subprocess.run([script, *args], capture_output=True, text=True, timeout=60, check=False)

    def test_binary_refuses_an_unknown_flag(self):
        out = self._run("--nope")
        assert out.returncode == 2, (out.returncode, out.stdout, out.stderr)
        assert "usage: venya-server" in out.stderr
        assert "Traceback" not in out.stderr

    def test_binary_answers_version(self):
        out = self._run("--version")
        assert out.returncode == 0, (out.returncode, out.stderr)
        assert out.stdout.strip().startswith(_DECLARED)
