# Copyright (c) 2026 Tabith LLC.
# Use of this source code is governed by the Business Source License 1.1
# included in the LICENSE file at the root of this repository. As of the
# Change Date listed there, the work is available under MPL 2.0.
# SPDX-License-Identifier: BUSL-1.1

"""Capability isolation checks for the venya-cli package.

WHAT THESE CHECKS ENFORCE, stated to match the checks and not exceed them
(#538, lead ruling 2026-10-09; prose correction only — every assertion in this
file is unchanged, and the invariant below is the one they actually test):

* the CLI must never IMPORT the core package's protected-memory module, and must
  never NAME its symbols — `test_no_core_imports_in_source`,
  `test_no_secure_memory_symbols_in_source`, `test_secure_memory_not_in_cli_module_exports`,
  and the clean-interpreter import probe;
* the CLI holds no standing resident key — the protected buffer is a scoped,
  single-use holder that erases its own copy on release;
* the CLI must never RELY on pinning. A short-lived pin is ATTEMPTED and
  REPORTED, never depended on: `venya_cli/secret_holder.py` asks the kernel to
  keep its one buffer resident and tolerates a refusal as the ordinary case,
  because an operator workstation has no CAP_IPC_LOCK to ask with. Measured (the
  #538 design note, reproduced in the implementation leg): `RLIMIT_MEMLOCK` 8 MiB
  soft/hard, `CapEff` all zeros, and `mlock` on a 241-byte buffer — the product's
  own SECP256R1 PEM size — fails errno 12 in 200 of 200 trials. That is why #538's claim is "erased on release,
  not pinned", and why nothing here treats a pin attempt as a violation.

Earlier prose in this docstring said the CLI "must never use mlock
(CAP_IPC_LOCK)". That sentence out-ran these checks — no assertion here bans the
`mlock` syscall itself, only the import and the naming of the core module — and
under #538's ruling an ATTEMPTED, non-depended-on pin is sanctioned, so the
sentence was false as written. Narrowing prose to match a check is the honest
half of the pair; making a check match its prose is a separate defect and is
filed as one (a guard whose comment claims more than it enforces lets a later
lane pass while doing something the team believes is banned).

These checks moved here from packages/core/tests/test_capability_isolation.py when
the CLI was carved out into venya-cli; they are equal-or-stronger: the source
scan covers every module in the package, not just two named files. The semantics
of record for the protected-buffer contract on both planes are
``docs/design-secure-memory-kek.md``.
"""

import json
import subprocess
import sys
from pathlib import Path

_SECURE_SYMBOLS = {"secure_memory", "secure_mlock", "secure_munlock", "secure_zero", "SecureBuffer"}

_SRC_DIR = Path(__file__).resolve().parent.parent / "src" / "venya_cli"

# The import surface the isolation guarantee covers: every CLI module that can
# reach the network or hold key material.
_CLI_MODULES = (
    "venya_cli.api_client",
    "venya_cli.cli",
    "venya_cli.commands",
    "venya_cli.fido2_client",
    "venya_cli.webauthn",
)

# Runs in a clean interpreter. Reports which of the requested modules it loaded,
# and every loaded module whose name contains "secure_memory" — the same
# predicate the check used when it inspected the pytest process.
_PROBE_SOURCE = """
import json
import sys

mods = json.loads(sys.argv[1])
for name in mods:
    __import__(name)
report = {
    "loaded": [name for name in mods if name in sys.modules],
    "secure_memory": [name for name in sys.modules if "secure_memory" in name],
}
print(json.dumps(report))
"""


def _run_import_probe(modules, cwd=None):
    """Import ``modules`` in a FRESH interpreter and return its report.

    A fresh interpreter is the point: the pytest process is not a clean room.
    Other CLI tests import server modules for response-shape coverage (see
    test_cli_response_key_drift_482.py), and since #472 CP2 the core engine's
    ``backend`` module owns the KEK cache and imports ``secure_memory`` at
    module level — so ``sys.modules`` of the test process reports
    ``core.engine.secure_memory`` no matter what the CLI does. That measured
    the process, not the CLI (#472 CP6).
    """
    proc = subprocess.run(
        [sys.executable, "-c", _PROBE_SOURCE, json.dumps(list(modules))],
        capture_output=True,
        text=True,
        timeout=180,
        check=False,
        cwd=str(cwd) if cwd is not None else None,
    )
    assert proc.returncode == 0, f"import probe failed (rc={proc.returncode}):\n{proc.stderr}"
    return json.loads(proc.stdout.strip().splitlines()[-1])


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
        """Importing every venya_cli module must not load secure_memory.

        Measured in a clean interpreter (see ``_run_import_probe``), so the
        verdict is about the CLI's own import graph and not about whatever the
        pytest process happened to load first.
        """
        report = _run_import_probe(_CLI_MODULES)

        assert report["loaded"] == list(_CLI_MODULES), f"probe did not import the whole CLI surface: {report['loaded']}"
        assert not report["secure_memory"], f"secure_memory modules loaded by CLI imports: {report['secure_memory']}"

    def test_import_probe_is_failable(self, tmp_path):
        """Negative half: a planted module that DOES pull secure_memory is caught.

        Without this cell the assertion above could pass vacuously — a probe
        that imported nothing, or a finder whose predicate stopped matching,
        would both report an empty list. This is the paired rejection the
        truth-table rule requires (#472 CP6).
        """
        (tmp_path / "_cp6_planted_puller.py").write_text(
            "from core.engine.secure_memory import SecureBuffer\n", encoding="utf-8"
        )

        report = _run_import_probe(("_cp6_planted_puller",), cwd=tmp_path)

        assert report["loaded"] == ["_cp6_planted_puller"], "planted module did not import"
        assert report["secure_memory"], "planted secure_memory importer was NOT detected — the finder is broken"

    def test_secure_memory_not_in_cli_module_exports(self):
        """secure_memory symbols must not be accessible from CLI modules."""
        from venya_cli import api_client, cli, commands

        for mod in (cli, commands, api_client):
            for sym in ("secure_mlock", "SecureBuffer"):
                assert not hasattr(mod, sym), f"{sym} should not be accessible from {mod.__name__}"
