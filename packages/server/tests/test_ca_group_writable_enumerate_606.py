# Copyright (c) 2026 Tabith LLC.
# Use of this file is governed by the Business Source License 1.1
# included in the LICENSE file at the root of this repository. As of the
# Change Date listed there, the work is available under MPL 2.0.
# SPDX-License-Identifier: BUSL-1.1

"""#606 AC6 — the enumerate-negative for group-writable CA directories.

docs/BACKUPS.md "Delivered modes, per CA-material surface" promises every directory holding CA
material under the two CA roots is owner-only. ``install -d -m`` RE-APPLIES its mode on every
installer invocation, so one group bit in one of those pins is not a first-install accident — it is
the steady state every re-run leaves behind (the #606 mechanism, and #610's sibling of it). The
row's acceptance text names the shipped instrument:

    find /var/lib/venya /etc/venya -type d -perm -0020

which must print nothing on a served host. ``-perm -0020`` selects entries carrying the group-write
bit, so this is a set-emptiness claim, and it is NOT satisfied by the positive pin test in
``test_installer_ca_dir_mode_606.py`` — that one asserts a digit, this one asserts nothing matches.

Cells, and every cell that could pass green forever has a control beside it:

* three **text guards** — every shipped mode applied to a path under a CA root carries no
  group-write bit, read from ``install -d -m`` pins, from bare ``chmod`` pins, and from the
  embedded-Python / library ``os.chmod`` calls. Each guard asserts a minimum hit count, so a regex
  that quietly matches nothing cannot read as a clean tree;
* **functional negative** — replay the shipped ``install -d`` pins into a fixture tree and run the
  predicate: the group-writable set is EMPTY, and the cell also proves the tree was actually built;
* **functional positive control** — plant one ``0770`` directory in that same tree and prove the
  predicate returns exactly it. Without this half, an inert predicate passes the negative forever —
  the exact defect class this gate exists to catch;
* **instrument cross-check** — where GNU ``find`` exists, the shipped ``-perm -0020`` form and the
  in-process predicate must agree on the same tree, so a re-implementation bug is caught rather
  than trusted;
* **doc fidelity** (AC3) — the per-surface mode table must state ``0700`` for each secret leaf, must
  name the ``VENYA_ADMIN_MTLS_ENABLED=false`` scoping, and must NOT mention ``0770``: loosening the
  prose to bless a wider incumbent mode is loosening a check, not passing it.

Scope is narrow on purpose. The two roots are ``/var/lib/venya`` and ``/etc/venya`` — what the row
names. The installers DO ship group-writable directories elsewhere:
``install -d -m 0770 -o venya -g venya "$INSTALL_DIR/.local/share/uv/python"`` (``venya-common.sh``,
``venya_install_python314``) and the executor's ``/home/venya/.local/share/sandboxes``. Those are a
toolchain cache and a sandbox spool, not CA material, and no cell here allowlists them because no
cell enumerates outside the CA roots — widening this row's scope must be a decision, not a side
effect of this file.

Everything runs in-process against a ``tmp_path`` fixture plus the git-tracked installer text: no
guest, no root, and the real ``/var/lib/venya`` is never a target. The identity flags (``-o`` /
``-g venya``) are dropped in the replay because the test runs unprivileged — the mode digit is the
whole mechanism under test, exactly as in ``test_installer_ca_dir_mode_606.py``.
"""

import re
import shutil
import stat
import subprocess
from pathlib import Path

import pytest

_ROOT = Path(__file__).resolve().parents[3]
_CORE_INSTALLER = _ROOT / "install-venya-core.sh"
_EXECUTOR_INSTALLER = _ROOT / "install-venya-executor.sh"
_COMMON = _ROOT / "venya-common.sh"
_CA_LIB = _ROOT / "packages" / "server" / "src" / "server" / "ca.py"

# The two roots the row enumerates. Anything resolving outside them is out of this class's scope
# (see the module docstring) and is never silently absorbed here.
_CA_ROOTS = ("/var/lib/venya", "/etc/venya")

# Every directory surface the shipped installers create with an explicit `install -d -m` pin under
# those roots. The first guard asserts the parser finds exactly this set: that is the anti-vacuity
# half, not a store of expected modes.
_EXPECTED_DIR_SURFACES = {
    "/var/lib/venya",
    "/var/lib/venya/ca",
    "/var/lib/venya/ca/admin-ca",
    "/var/lib/venya/executor",
    "/etc/venya",
    "/etc/venya/admin",
}

# Variables that cannot be resolved to a literal path are skipped only when the file proves their
# assignment never names a CA root — see `_assignment_mentions_ca_root`. Nothing here is a bare
# name-list exemption: an unresolvable operand whose assignment DOES mention a CA root fails loudly.

# Any file-scope `VAR="..."` assignment, resolved where the value is an absolute-path literal.
# Resolution is best-effort BY DESIGN, and the safety is `_assignment_mentions_ca_root`: an operand
# whose variable cannot be resolved is skipped ONLY after this file proves the assignment text never
# names a CA root. So `$BACKUP_FILE` (built from `/root/...`) can be skipped honestly, while an
# unresolvable `chmod 770 "$SOMETHING"` whose assignment does mention `/etc/venya` fails loudly
# instead of dropping out of the enumeration unnoticed.
_ASSIGN = re.compile(r'^\s*([A-Z][A-Z0-9_]*)="([^"]*)"$', re.MULTILINE)
_CHMOD_LINE = re.compile(r"^\s*chmod\s+([0-7]{3,4})\s+(\S.*)$", re.MULTILINE)
_GROUP_WRITE = stat.S_IWGRP  # 0o020 — the bit `-perm -0020` selects
_FLAG_WITH_VALUE = {"-m", "-o", "-g"}


def _under_ca_root(path: str) -> bool:
    return any(path == root or path.startswith(root + "/") for root in _CA_ROOTS)


def _dir_assigns(text: str) -> dict[str, str]:
    """Variable name -> absolute path, for every `VAR="/abs/path"` assignment in `text`."""
    return {m.group(1): m.group(2) for m in _ASSIGN.finditer(text) if m.group(2).startswith("/")}


def _assignment_mentions_ca_root(raw: dict[str, str], var: str, seen: set[str]) -> bool:
    """True if `var`'s assignment text, or any variable it interpolates, names a CA root.

    This is the anti-"silently dropped an in-scope pin" test. It follows one level of $VAR
    interpolation because `$BACKUP_DIR` is assigned from `$BACKUP_FILE`-style chains in the real
    scripts, and a two-level chain that still reaches a CA root is rare enough that hitting it is
    itself a reason to look at this file.
    """
    if var in seen:
        return False
    seen.add(var)
    value = raw.get(var, "")
    if any(root in value for root in _CA_ROOTS):
        return True
    for inner in re.findall(r"\$\{?([A-Z][A-Z0-9_]*)", value):
        if _assignment_mentions_ca_root(raw, inner, seen):
            return True
    return False


def _resolves(token: str, assigns: dict[str, str], raw: dict[str, str], script: Path) -> str | None:
    """Expand a ``$VAR`` / ``"${VAR}"`` operand (optionally with a path suffix) to an absolute path.

    Returns None for an operand this file has PROVED cannot land under a CA root (so the caller
    skips it without losing coverage); raises for any operand that is neither resolvable nor proved
    out of scope, because that is the case where an in-scope pin would go unenumerated.
    """
    token = token.strip('"')
    if not token.startswith("$"):
        return token
    # `$INSTALL_DIR/.local` and `${ADMIN_CA_DIR}` both carry a leading variable name that may be
    # followed by a path suffix — read the name up to the first `/` or `}`.
    ref = token[1:].lstrip("{")
    var = re.split(r"[}/]", ref, maxsplit=1)[0]
    suffix = ref[len(var) :].lstrip("}")
    if var in assigns:
        return assigns[var] + suffix
    if not _assignment_mentions_ca_root(raw, var, set()):
        return None
    raise AssertionError(
        f"{script.name}: pin target {token!r} names a CA root in its assignment but does not resolve "
        "to a literal path — the enumeration would miss an in-scope pin (extend _dir_assigns, do not "
        "skip it)"
    )


def _dir_pins(scripts: tuple[Path, ...]) -> dict[str, str]:
    """Target path -> mode digit for every non-comment ``install -d -m`` operand under a CA root.

    Comment lines are skipped on purpose: line 484 of the core installer is prose reading
    ``# "install -d -m 0755 /etc/venya" (#317 status-quo pin) re-pins that``, and matching it would
    let a sentence masquerade as a shipped pin. Multi-operand lines are handled by taking EVERY
    trailing operand, not just the last — ``venya-common.sh`` lists four ``$INSTALL_DIR`` paths on
    one line.
    """
    pins: dict[str, str] = {}
    for script in scripts:
        text = script.read_text()
        assigns, raw = _dir_assigns(text), {m.group(1): m.group(2) for m in _ASSIGN.finditer(text)}
        for line in text.splitlines():
            stripped = line.strip()
            if stripped.startswith("#"):
                continue
            tokens = stripped.split()
            if tokens[:2] != ["install", "-d"] or "-m" not in tokens:
                continue
            mode = tokens[tokens.index("-m") + 1]
            i = 2
            while i < len(tokens):
                tok = tokens[i]
                if tok in _FLAG_WITH_VALUE:
                    i += 2
                    continue
                target = _resolves(tok, assigns, raw, script)
                if target is not None and _under_ca_root(target):
                    pins[target] = mode
                i += 1
    return pins


def _chmod_pins(scripts: tuple[Path, ...]) -> dict[str, str]:
    """Target path -> mode digit for every bare ``chmod <mode> <path>`` line under a CA root.

    These cover the directory pins ``install -d`` does not make (``chmod 700 /var/lib/venya/ca`` in
    ``venya_create_directories``, ``chmod 700 /etc/venya/executor`` in the executor installer) and
    the key/cert files inside the leaves. Files are included deliberately: 0600/0640/0644 carry no
    group-write bit either, so the same negative governs them.
    """
    pins: dict[str, str] = {}
    for script in scripts:
        text = script.read_text()
        assigns, raw = _dir_assigns(text), {m.group(1): m.group(2) for m in _ASSIGN.finditer(text)}
        for m in _CHMOD_LINE.finditer(text):
            mode, operand = m.group(1), m.group(2).strip()
            for token in operand.split():
                target = _resolves(token, assigns, raw, script)
                if target is not None and _under_ca_root(target):
                    pins[target] = mode
    return pins


def _library_chmod_modes(text: str) -> list[str]:
    """Every ``os.chmod(str(<expr>), 0o<mode>)`` digit in `text`, in source order."""
    return re.findall(r"os\.chmod\(str\([^)]*\),\s*0o([0-7]{3,4})\)", text)


def _replay_shipped_pins(tree: Path) -> dict[str, str]:
    """Rebuild the CA directory tree under `tree` by running the shipped mode digits.

    Real paths are remapped onto the fixture (``/var/lib/venya`` -> ``tree/var/lib/venya``) and
    replayed in the order the installer lists them, so a later re-pin wins exactly as it does on a
    host (``/etc/venya`` is pinned 0750 in the admin-mTLS block and re-pinned 0755 further down).
    """
    pins = _dir_pins((_CORE_INSTALLER, _EXECUTOR_INSTALLER, _COMMON))
    for target, mode in pins.items():
        dest = tree / target.lstrip("/")
        # Scaffolding above the enumerated roots (tree/var, tree/var/lib, tree/etc) gets the
        # installer's own entry posture — `umask 077`, install-venya-core.sh:16 — rather than the
        # test host's umask, so this cell cannot pass or fail on an inherited-create accident.
        parent = dest.parent
        made = []
        while not parent.exists() and parent != tree:
            made.append(parent)
            parent = parent.parent
        parent.mkdir(parents=True, exist_ok=True)
        for new_dir in reversed(made):
            new_dir.mkdir(exist_ok=True)
            new_dir.chmod(0o700)
        subprocess.run(["install", "-d", "-m", mode, str(dest)], check=True)
    return pins


def _group_writable_dirs(roots: list[Path]) -> list[str]:
    """The in-process form of ``find <root> -type d -perm -0020``, reporting paths."""
    hits: set[str] = set()
    for root in roots:
        if not root.exists():
            continue
        candidates = [root, *root.rglob("*")]
        for path in candidates:
            if path.is_dir() and (path.stat().st_mode & _GROUP_WRITE):
                hits.add(str(path))
    return sorted(hits)


def _find_binary() -> str | None:
    return shutil.which("find")


class TestCaGroupWritableTextGuards606:
    def test_shipped_directory_pins_carry_no_group_write_bit(self):
        """Every `install -d -m` pin under a CA root is group-write free, and all are found."""
        pins = _dir_pins((_CORE_INSTALLER, _EXECUTOR_INSTALLER, _COMMON))
        assert set(pins) == _EXPECTED_DIR_SURFACES, (
            f"the CA-root install -d enumeration found {sorted(pins)}, expected "
            f"{sorted(_EXPECTED_DIR_SURFACES)} — a missing or extra surface means a parser or "
            "installer-shape change, not a clean tree"
        )
        wide = {t: m for t, m in pins.items() if int(m, 8) & _GROUP_WRITE}
        assert not wide, (
            f"directory pins carrying the group-write bit under a CA root: {wide} — install -d "
            "re-applies that mode on EVERY run, so a group bit here IS the #606 class "
            "(docs/BACKUPS.md 'Delivered modes, per CA-material surface' promises 0700 leaves)"
        )

    def test_shipped_chmod_pins_under_the_ca_roots_carry_no_group_write_bit(self):
        """Same negative for the bare `chmod` pins, including the root-CA directory re-pin."""
        pins = _chmod_pins((_CORE_INSTALLER, _EXECUTOR_INSTALLER, _COMMON))
        assert len(pins) >= 4, f"only {len(pins)} chmod pins resolved under the CA roots: {pins}"
        assert (
            "/var/lib/venya/ca" in pins and "/etc/venya/executor" in pins
        ), f"the directory chmod re-pins dropped out of the enumeration: {sorted(pins)}"
        wide = {t: m for t, m in pins.items() if int(m, 8) & _GROUP_WRITE}
        assert not wide, (
            f"chmod pins carrying the group-write bit under a CA root: {wide} — the shipped "
            "posture is owner-only for CA material (0700 dirs, 0600/0640 files)"
        )

    def test_embedded_python_and_library_ca_chmods_carry_no_group_write_bit(self):
        """The `os.chmod` pins are guarded too — the installer's CA step is embedded Python.

        The core installer's CA generation re-asserts the root CA directory mode from inside a
        `python -c` heredoc, and `server/ca.py` does the same for both CA managers. A digit there
        with a group bit would be invisible to a shell-pin grep.
        """
        core_modes = _library_chmod_modes(_CORE_INSTALLER.read_text())
        lib_modes = _library_chmod_modes(_CA_LIB.read_text())
        assert (
            "700" in core_modes
        ), f"the core installer's embedded CA step no longer chmods 0o700 (modes seen: {core_modes})"
        assert "700" in lib_modes, f"server/ca.py no longer chmods a CA dir 0o700 (modes seen: {lib_modes})"
        combined = core_modes + lib_modes
        wide = sorted({m for m in combined if int(m, 8) & _GROUP_WRITE})
        assert not wide, (
            f"os.chmod modes carrying the group-write bit in the CA path: {wide} — these run inside "
            "the CA managers, so no install -d pin would catch them"
        )


class TestCaGroupWritableEnumerate606:
    def test_fixture_replay_of_the_shipped_pins_enumerates_empty(self, tmp_path):
        """Functional negative: replaying the shipped pins leaves NO group-writable CA directory."""
        pins = _replay_shipped_pins(tmp_path)
        assert pins, "the replay landed nothing — this cell proved nothing"
        roots = [tmp_path / target.lstrip("/") for target in _CA_ROOTS]
        hits = _group_writable_dirs(roots)
        assert not hits, (
            f"group-writable directories under the CA roots after replaying the shipped pins: {hits} "
            f"(pins replayed: {pins})"
        )
        # Say plainly the tree really was built, or "empty" would just be an empty-tree artifact.
        landed = {str(p.relative_to(tmp_path)) for p in tmp_path.rglob("*") if p.is_dir()}
        assert {"var/lib/venya/ca/admin-ca", "etc/venya/admin"} <= landed, landed

    def test_predicate_catches_a_planted_group_writable_directory(self, tmp_path):
        """Positive control for the cell above: the predicate is not inert.

        A negative that only ever asserts "empty" also passes when the check itself is broken, so
        the same predicate must return the one directory this cell widens by hand.
        """
        _replay_shipped_pins(tmp_path)
        planted = tmp_path / "var/lib/venya/ca/group-writable-incumbent"
        planted.mkdir()
        planted.chmod(0o770)
        roots = [tmp_path / target.lstrip("/") for target in _CA_ROOTS]
        hits = _group_writable_dirs(roots)
        assert hits == [str(planted)], (
            f"planted a 0770 directory and the predicate returned {hits!r} — expected exactly the "
            "planted path; if this is empty the enumerate-negative is decoration, not a check"
        )

    @pytest.mark.skipif(_find_binary() is None, reason="GNU find absent on this host")
    def test_the_shipped_find_form_agrees_with_the_in_process_predicate(self, tmp_path):
        """Cross-check the instrument: ``find ... -type d -perm -0020`` must agree with the cell.

        The predicate is re-implemented rather than shelled out so the suite runs where ``findutils``
        is absent; that re-implementation is only trustworthy while it matches the form the row
        ships, and this cell is what keeps it honest — clean tree and widened tree alike.
        """
        find = _find_binary()
        assert find is not None
        _replay_shipped_pins(tmp_path)
        roots = [tmp_path / target.lstrip("/") for target in _CA_ROOTS]
        planted = tmp_path / "var/lib/venya/ca/admin-ca/widened"
        planted.mkdir()
        planted.chmod(0o770)

        out = subprocess.run(
            [find, *(str(r) for r in roots), "-type", "d", "-perm", "-0020"],
            check=True,
            capture_output=True,
            text=True,
        ).stdout
        shell_hits = sorted(p for p in out.splitlines() if p.strip())
        assert shell_hits == _group_writable_dirs(roots), (
            f"GNU find reported {shell_hits} but the in-process predicate reported "
            f"{_group_writable_dirs(roots)} — the predicate has drifted from the shipped form"
        )
        assert shell_hits == [str(planted)], shell_hits

    def test_backups_doc_states_a_delivered_mode_per_ca_surface(self):
        """AC3 fidelity: the doc must state a mode for each surface, not one figure for the tree.

        The row is open because row 4 of the must-back-up table gave the root CA its mode and left
        ``admin-ca/`` with none, while ``/etc/venya/admin`` was not listed anywhere at all. That
        shape is now a per-surface table, and this cell keeps it per-surface: each of the three 0700
        secret leaves must appear on a line that also states ``0700``.
        """
        doc = (_ROOT / "docs" / "BACKUPS.md").read_text()
        parts = doc.split("### Delivered modes, per CA-material surface", 1)
        assert len(parts) == 2, (
            "docs/BACKUPS.md lost the 'Delivered modes, per CA-material surface' section — the "
            "per-surface promise this row's AC3 asks for is no longer in the document"
        )
        body = parts[1].split("\n**Regenerable", 1)[0]
        for surface in ("`/var/lib/venya/ca/`", "`/var/lib/venya/ca/admin-ca/`", "`/etc/venya/admin/`"):
            lines = [ln for ln in body.splitlines() if surface in ln]
            assert lines, f"{surface} is not stated in the Delivered modes section at all"
            assert any(
                "**`0700`**" in ln for ln in lines
            ), f"{surface} appears without a stated `0700` delivered mode: {lines}"
        # The scoping sentence is part of the promise: "every run" without the admin-mTLS condition
        # is a claim a customer falsifies in one VENYA_ADMIN_MTLS_ENABLED=false install.
        assert "VENYA_ADMIN_MTLS_ENABLED=false" in body, (
            "the Delivered modes section no longer states the ADMIN_MTLS_ENABLED scoping, so the "
            "0700 rows read as an unconditional claim about every install"
        )
        # And the prose must NOT bless a wider incumbent mode. 0700 is the target.
        assert "0770" not in body, (
            "the Delivered modes section now mentions 0770 — the doc promise is 0700, and editing "
            "the prose to accept a wider mode is loosening a check, not passing it"
        )
