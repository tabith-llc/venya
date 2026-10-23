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

import ast
import json
import subprocess
import sys
from pathlib import Path

_SECURE_SYMBOLS = {"secure_memory", "secure_mlock", "secure_munlock", "secure_zero", "SecureBuffer"}

#: The pin syscalls, tracked by CALL SHAPE (#555, ruling R13). A separate set
#: from ``_SECURE_SYMBOLS`` on purpose: the interlock in
#: ``test_secret_holder_538.py`` reads that set and bans its names as substrings
#: across every CLI source file, and ``secret_holder.py`` legally contains
#: ``mlock`` — the #538 pin-with-fallback contract. Folding the syscall names
#: into the symbol set would red-gate the ruled code.
_PIN_SYSCALLS = frozenset({"mlock", "munlock"})

#: The one module that owns the pin-and-fallback contract (#538), and therefore
#: the only place a pin call shape may appear in this package (R13).
_PIN_HOME = "secret_holder.py"

#: Reported instead of cleared when a module cannot be parsed — a file the
#: finder cannot read is a file the finder must not pass.
UNPARSEABLE_MODULE = "<unparseable>"

#: The sibling guard in the core package, read by the parity cell below. The CLI
#: must not import core (that is the guard above), so the two finders are two
#: copies — this file path is how they are kept honest with each other.
_CORE_ISOLATION_TEST = Path(__file__).resolve().parents[2] / "core" / "tests" / "test_capability_isolation.py"


def _pin_call_shapes(source: str) -> list[str]:
    """Every pin-syscall shape used in one module's source, as CODE.

    A shape is a call (``libc.mlock(buf)``), a reference (``PIN = mlock``), or a
    string handed to a dynamic lookup (``getattr(libc, "mlock")``). A name that
    appears only in a comment or a docstring is not a shape, and neither is one
    buried inside a longer identifier. This is an AST walk and not a text search
    for the reason #555 records: a direct ``ctypes`` pin names no Python symbol,
    so a scan for identifier strings passes the file while the promise about it
    is broken.

    Mirrors ``_protected_memory_shapes`` in the core guard; the parity cell below
    keeps the tracked names from drifting apart.
    """
    try:
        tree = ast.parse(source)
    except SyntaxError:
        return [UNPARSEABLE_MODULE]
    found: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Name) and node.id in _PIN_SYSCALLS:
            found.add(node.id)
        elif isinstance(node, ast.Attribute) and node.attr in _PIN_SYSCALLS:
            found.add(node.attr)
        elif isinstance(node, ast.alias) and node.name in _PIN_SYSCALLS:
            found.add(node.name)
        elif isinstance(node, ast.Constant) and isinstance(node.value, str) and node.value in _PIN_SYSCALLS:
            found.add(node.value)
    return sorted(found)


def _pin_sites(directory: Path, home: str = _PIN_HOME) -> list[tuple[str, str]]:
    """Every (file, pin shape) pair in *.py under ``directory`` outside ``home``.

    Shared by the shipped location guard and by the cells that plant a synthetic
    second pin site, so the proof that the guard fires is a proof about the guard
    that ships.
    """
    sites: list[tuple[str, str]] = []
    for path in sorted(directory.glob("*.py")):
        if path.name.startswith("_") or path.name == home:
            continue
        for shape in _pin_call_shapes(path.read_text(encoding="utf-8")):
            sites.append((path.name, shape))
    return sites


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


class TestCliPinLocation:
    """R13/#555 — the CLI location guard: pin calls live in ONE file, and the
    guard that says so looks at the CALL, not at a name.

    Two rules, each with its paired rejection (the project's truth-table law):

    1. ``secret_holder.py`` is the only module in ``venya_cli`` that makes a
       kernel pin or unpin call. That is where the #538 contract lives: attempt
       the pin, report the outcome, never depend on it.
    2. The check is a syscall-shape check, so a direct ``ctypes`` pin in some
       other module is refused even though it names no Python symbol at all —
       which is exactly the case the name-scanning version of this guard passed
       (#555).

    Scope is this package only. The core package owns its own protected-memory
    guard, with its own two-file allowlist (``secure_memory.py``, ``backend.py``)
    for the ruled server-side primitive; a repo-wide "``secret_holder.py`` only"
    assertion would red-gate that ruled code, so it is not what this guard does.
    """

    #: A pin taken straight through `ctypes`, naming no Python primitive — the
    #: shape #555 was filed for. Shared by the cells below so the planted file
    #: and the shipped finder are talking about the same bytes.
    _DIRECT_CTYPES_PIN = (
        "import ctypes\n"
        "\n"
        '_LIB = ctypes.CDLL("libc.so.6")\n'
        "\n"
        "\n"
        "def pin(buf, size):\n"
        "    return _LIB.mlock(ctypes.addressof(buf), size)\n"
    )

    def test_only_the_holder_file_holds_a_pin_call(self):
        """The shipped location guard, run on the real package: no offenders."""
        sources = sorted(_SRC_DIR.glob("*.py"))
        assert sources, f"no sources found at {_SRC_DIR}"
        offenders = _pin_sites(_SRC_DIR)
        assert not offenders, (
            f"pin syscall shapes found in venya_cli outside the one home {_PIN_HOME!r}: {offenders} "
            "— move the call into secret_holder.py, or make it a reviewed change to this guard"
        )

    def test_the_home_really_does_hold_the_pin_so_the_guard_is_not_vacuous(self):
        """Non-vacuity on the sanctioned side.

        If `secret_holder.py` made no pin call, the cell above would be green
        because nothing in the package pins memory rather than because one file
        owns the pin. So the guard's own premise is asserted here.
        """
        home_source = (_SRC_DIR / _PIN_HOME).read_text(encoding="utf-8")
        shapes = _pin_call_shapes(home_source)
        assert "mlock" in shapes, shapes
        assert "munlock" in shapes, shapes

    def test_guard_fires_on_a_planted_second_pin_site(self, tmp_path):
        """The paired negative, and the #555 regression in one cell.

        First the premise: the planted file names none of ``_SECURE_SYMBOLS``, so
        the name-scanning version of this guard had nothing to look for and let
        it through. Then the verdict: the shipped guard reports it.
        """
        assert not any(
            name in self._DIRECT_CTYPES_PIN for name in _SECURE_SYMBOLS
        ), "the planted file names a guarded symbol — it no longer reproduces #555"
        (tmp_path / "sneaky_store.py").write_text(self._DIRECT_CTYPES_PIN, encoding="utf-8")
        assert _pin_sites(tmp_path) == [("sneaky_store.py", "mlock")]

    def test_the_same_pin_under_the_allowed_name_is_not_an_offender(self, tmp_path):
        """Rejection of the rejection: the exemption is real, not a dead branch.

        Identical bytes in the file that owns the contract must pass, otherwise
        the guard above would be a scan that never agrees with anything.
        """
        (tmp_path / _PIN_HOME).write_text(self._DIRECT_CTYPES_PIN, encoding="utf-8")
        assert _pin_sites(tmp_path) == []

    def test_indirection_is_a_call_shape_too(self, tmp_path):
        """`getattr(libc, "mlock")` is a pin site, so resolving the name later
        does not put it past the guard."""
        (tmp_path / "late_bind.py").write_text(
            'import ctypes\nPIN = getattr(ctypes.CDLL("libc.so.6"), "mlock")\n', encoding="utf-8"
        )
        assert _pin_sites(tmp_path) == [("late_bind.py", "mlock")]

    def test_prose_about_the_pin_is_not_a_pin_site(self, tmp_path):
        """The honesty half: documentation is not code.

        A module that only talks about `mlock` — in a docstring, in a comment, in
        a longer identifier — is not reported. A guard that flagged prose would
        be a text search wearing a shape check's clothes, which is the other way
        #555 describes the same defect.
        """
        (tmp_path / "notes.py").write_text(
            '"""Explains the mlock pin to the reader."""\n\n# mlock and munlock are attempted, never fatal\n'
            'MEMLOCK_NOTE = "munlock is reported too"\n'
            "VALUE = 1\n",
            encoding="utf-8",
        )
        assert _pin_sites(tmp_path) == []

    def test_a_module_that_does_not_parse_is_not_cleared(self, tmp_path):
        """A file the finder cannot read is a file the finder must not pass."""
        (tmp_path / "broken.py").write_text("def (:\n", encoding="utf-8")
        assert _pin_sites(tmp_path) == [("broken.py", UNPARSEABLE_MODULE)]

    def test_the_two_packages_track_the_same_pin_syscalls(self):
        """The per-package guards stay per-package, and stay in step.

        The CLI cannot import core (the guard above is the point), so the syscall
        names are two literals in two files. Read the core one the way
        `test_secret_holder_538.py` reads the symbol sets — from the shipped
        source, never hardcoded here — so a widening on one side shows up as a
        red cell instead of as two guards with different teeth.
        """
        assert _CORE_ISOLATION_TEST.is_file(), f"the core guard file is missing: {_CORE_ISOLATION_TEST}"
        core_names: set[str] = set()
        tree = ast.parse(_CORE_ISOLATION_TEST.read_text(encoding="utf-8"), filename=str(_CORE_ISOLATION_TEST))
        for node in ast.walk(tree):
            if not isinstance(node, (ast.Assign, ast.AnnAssign)):
                continue
            targets = [node.target] if isinstance(node, ast.AnnAssign) else node.targets
            if not any(isinstance(t, ast.Name) and t.id == "PROTECTED_MEMORY_SYSCALLS" for t in targets):
                continue
            assert node.value is not None
            for literal in ast.walk(node.value):
                if isinstance(literal, ast.Constant) and isinstance(literal.value, str):
                    core_names.add(literal.value)
        assert core_names, "no pin syscalls parsed out of the core guard — the finder is broken"
        assert core_names == set(_PIN_SYSCALLS), f"the two location guards diverged: core={sorted(core_names)}"
