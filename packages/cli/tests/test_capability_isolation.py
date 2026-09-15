"""Capability isolation checks for the venya-cli package.

The CLI runs on untrusted workstations/jump hosts and must never use
mlock (CAP_IPC_LOCK) or import core.engine.secure_memory. These checks
moved here from packages/core/tests/test_capability_isolation.py when the
CLI was carved out into venya-cli; they are equal-or-stronger: the source
scan covers every module in the package, not just two named files.
"""

import sys
from pathlib import Path

_SECURE_SYMBOLS = {"secure_memory", "secure_mlock", "secure_munlock", "secure_zero", "SecureBuffer"}

_SRC_DIR = Path(__file__).resolve().parent.parent / "src" / "venya_cli"


class TestCliCapabilityIsolation:
    def test_no_core_imports_in_source(self):
        """venya_cli must be standalone: no `core.*` imports, top-level or
        function-level. Regression tripwire for the carve-out (mypy cannot
        catch this: ignore_missing_imports=true)."""
        sources = sorted(_SRC_DIR.glob("*.py"))
        assert sources, f"no sources found at {_SRC_DIR}"
        for path in sources:
            for lineno, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
                stripped = line.strip()
                assert not stripped.startswith(
                    ("from core.", "import core.")
                ), f"{path.name}:{lineno} imports from core — venya_cli must stay standalone"

    def test_no_secure_memory_symbols_in_source(self):
        """No venya_cli module may reference secure_memory symbols."""
        sources = sorted(_SRC_DIR.glob("*.py"))
        assert sources, f"no sources found at {_SRC_DIR}"
        for path in sources:
            content = path.read_text(encoding="utf-8")
            for sym in _SECURE_SYMBOLS:
                assert sym not in content, f"secure_memory symbol '{sym}' found in {path.name}"

    def test_importing_cli_does_not_pull_secure_memory(self):
        """Importing every venya_cli module must not load secure_memory."""
        import venya_cli.api_client
        import venya_cli.cli
        import venya_cli.commands
        import venya_cli.fido2_client
        import venya_cli.webauthn  # noqa: F401

        loaded = [name for name in sys.modules if "secure_memory" in name]
        assert not loaded, f"secure_memory modules loaded by CLI imports: {loaded}"

    def test_secure_memory_not_in_cli_module_exports(self):
        """secure_memory symbols must not be accessible from CLI modules."""
        from venya_cli import api_client, cli, commands

        for mod in (cli, commands, api_client):
            for sym in ("secure_mlock", "SecureBuffer"):
                assert not hasattr(mod, sym), f"{sym} should not be accessible from {mod.__name__}"
