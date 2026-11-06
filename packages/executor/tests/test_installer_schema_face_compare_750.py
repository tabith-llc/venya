# Copyright (c) 2026 Tabith LLC.
# Use of this source code is governed by the Business Source License 1.1
# included in the LICENSE file at the root of this repository. As of the
# Change Date listed here, the work is available under MPL 2.0.
# SPDX-License-Identifier: BUSL-1.1

"""#750 — the core installer compares the schema FACE, not the version LABEL, and the restore
point follows the schema.

``install-venya-core.sh`` asked whether two version STRINGS were equal and treated "equal" as
safety: ``elif [ "$INSTALLED_VERSION" = "$INCOMING_VERSION" ]; then info "… (same-version re-run)"``.
Two different source trees can carry the same release name, so a same-version face swap walked
through that arm and into forward-only migrations — and walked past the pre-upgrade backup as well,
because the backup keyed on ``INSTALLED_VERSION != INCOMING_VERSION``. The state that matters is the
alembic position, which the installer can read: the head the incoming tarball ships (``revision`` /
``down_revision`` lines, unextracted) and the stamp the live database stores
(``select version_num from alembic_version``). Both are printed on every path that decides; the run
refuses when the stored stamp is neither the incoming head nor one of its ancestors, overridable only
by ``VENYA_ALLOW_AHEAD_SCHEMA``.

Why a separate knob: ``VENYA_ALLOW_DOWNGRADE`` already answers the version-string question. Folding
the schema question into it would let an operator who meant "install the older label anyway" move a
database stamp without ever reading the two numbers, which is the pair this row exists to make
visible.

The string arm is NOT deleted and the backup body is NOT rewritten: #750 adds one read of the table
that writer populates, and moves the existing backup body into a function so the refusal path can
take the restore point before it stops. That is the paired negative in the second sense — the check
that this leg must not weaken is the same check the old ticket pinned
(``test_installer_upgrade_support.py``), and it still passes.

Method: the house shape from ``test_installer_dial_contract_order_745.py`` and
``test_installer_pg_cluster_resolve_496.py`` — the REAL region lifted out of the installer by its two
anchors and run against PATH stubs in a tmpdir. No VM, no sudo, no install, nothing written outside
``tmp_path``. The tarballs are real ``tar.gz`` files built by ``tarfile``; the alembic read is the
shipped ``tar -xzOf`` line, not a stand-in.
"""

import io
import subprocess
import tarfile
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[3]
INSTALLER = REPO_ROOT / "install-venya-core.sh"

COMPARE_HEADER = "# --- Schema-face compare BEFORE any mutation (ticket installer-version-guard-face-compare-750)"
BACKUP_FN_HEADER = "venya_preupgrade_backup() {"
EXTRACT_CALL = "\nvenya_extract_tarball"

# The strings the previous ticket pinned in the backup body. They must survive the move, so a
# refactor that "simplified" them away fails here rather than in a customer's upgrade.
BACKUP_BODY_MARKS = (
    'BACKUP_DIR="/var/backups/venya"',
    "sudo -u postgres pg_dump -d venya",
    "no backup, no upgrade",
    "tail -n +4",
)

# Real ids from the shipped chain, so the cells are reading the tree the installer will meet —
# note 011's id is a NAME, not a number: the parser must not assume digits.
REAL_CHAIN = Path(REPO_ROOT / "packages/core/alembic/versions")


def _source() -> str:
    return INSTALLER.read_text(encoding="utf-8")


def _region(text: str, start: str, end: str) -> str:
    """Lift a real region out of the installer between two anchors, refusing ambiguity."""
    assert text.count(start) == 1, f"start anchor not unique in install-venya-core.sh: {start!r}"
    assert end in text[text.index(start) :], f"end anchor not found after the start: {end!r}"
    i = text.index(start)
    j = text.index(end, i) + len(end)
    return text[i:j]


def _compare_block() -> str:
    """The shipped compare block, extraction call included (the harnesses stub it)."""
    return _region(_source(), COMPARE_HEADER, EXTRACT_CALL)


def _backup_fn() -> str:
    """The moved backup function, through its closing brace."""
    text = _source()
    assert text.count(BACKUP_FN_HEADER) == 1
    i = text.index(BACKUP_FN_HEADER)
    j = text.index("\n}\n", i) + 3
    return text[i:j]


def _migrations_from_repo() -> list[str]:
    return sorted(p.read_text(encoding="utf-8") for p in REAL_CHAIN.glob("*.py"))


def _chain(revisions: list[tuple[str, str | None]]) -> list[str]:
    """Synthetic migration files: (revision, down_revision) pairs, in alembic's two spellings."""
    out = []
    for rev, down in revisions:
        body = "def upgrade() -> None:\n    pass\n"
        if down is None:
            out.append(f'"""x"""\nrevision: str = "{rev}"\ndown_revision: str | None = None\n{body}')
        else:
            out.append(f'"""x"""\nrevision: str = "{rev}"\ndown_revision: str | None = "{down}"\n{body}')
    return out


def _tarball(tmp_path: Path, migrations: list[str], version: str = "0.1.0beta3", name: str = "core.tgz") -> Path:
    """A real tarball in the shipped layout: <root>/packages/core/{pyproject.toml,alembic/versions/*}."""
    path = tmp_path / name
    with tarfile.open(path, "w:gz") as tf:
        for i, text in enumerate(migrations):
            info = tarfile.TarInfo(f"core-{version}/packages/core/alembic/versions/m{i:03d}.py")
            data = text.encode()
            info.size = len(data)
            tf.addfile(info, io.BytesIO(data))
        py = f'[project]\nname = "core"\nversion = "{version}"\n'.encode()
        info = tarfile.TarInfo(f"core-{version}/packages/core/pyproject.toml")
        info.size = len(py)
        tf.addfile(info, io.BytesIO(py))
    return path


def _stub_dir(tmp_path: Path, *, stamp: str | None, psql_rc: int = 0) -> Path:
    """PATH bin dir: `sudo` drops -u <user> and execs; `psql` answers the stored stamp."""
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir(exist_ok=True)
    sudo = bin_dir / "sudo"
    sudo.write_text('#!/bin/bash\n[ "$1" = "-u" ] && shift 2\nexec "$@"\n', encoding="utf-8")
    sudo.chmod(0o755)
    psql = bin_dir / "psql"
    psql.write_text(
        f'#!/bin/bash\nprintf \'%s\\n\' "{stamp if stamp is not None else ""}"\nexit {psql_rc}\n',
        encoding="utf-8",
    )
    psql.chmod(0o755)
    return bin_dir


def _run(tmp_path: Path, block: str, *, stub_bin: Path, env: dict[str, str]) -> subprocess.CompletedProcess:
    """Run the lifted block with the harness the shipped lines expect, and nothing else on PATH
    except the stubs plus coreutils."""
    script = (
        "set -uo pipefail\n"
        'info()  { echo "[INFO] $*"; }\n'
        'warn()  { echo "[WARN] $*"; }\n'
        'error() { echo "[ERROR] $*"; }\n'
        'venya_extract_tarball() { echo "EXTRACTED=1"; }\n'
        'venya_preupgrade_backup() { echo "BACKUP_TAKEN=1"; }\n'
        'TARBALL_FILE="$TEST_TARBALL"\n'
        'INSTALLED_VERSION="${TEST_INSTALLED-0.1.0beta3}"\n'
        'INCOMING_VERSION="${TEST_INCOMING-0.1.0beta3}"\n'
        "BACKUP_REQUIRED=no\n"
        f"{block}\n"
        'echo "REACHED_END=1 BACKUP_REQUIRED=$BACKUP_REQUIRED"\n'
    )
    path = tmp_path / "run.sh"
    path.write_text(script, encoding="utf-8")
    full = {"PATH": f"{stub_bin}:/usr/bin:/bin", "HOME": str(tmp_path)}
    full.update(env)
    return subprocess.run(
        ["/bin/bash", str(path)],
        cwd=str(tmp_path),
        env=full,
        capture_output=True,
        text=True,
        check=False,
        timeout=120,
    )


@pytest.fixture
def real_tarball(tmp_path):
    return _tarball(tmp_path, _migrations_from_repo())


class TestTheFacesAreReadAndPrinted:
    """AC1: read both positions, print both, and key the decision on the position."""

    def test_equal_head_admits_and_names_both_faces(self, tmp_path, real_tarball):
        """The healthy same-version re-run: stored stamp IS the incoming head. This is the case the
        string arm called safe by accident, and the compare proves it on purpose."""
        head = "043"  # the shipped chain's head at this face — see test_the_head_is_the_shipped_one
        proc = _run(
            tmp_path,
            _compare_block(),
            stub_bin=_stub_dir(tmp_path, stamp=head),
            env={"TEST_TARBALL": str(real_tarball)},
        )
        assert proc.returncode == 0, proc.stdout + proc.stderr
        assert f"incoming head: {head}; stored stamp: {head}; verdict: equal" in proc.stdout, proc.stdout
        assert "BACKUP_REQUIRED=no" in proc.stdout, proc.stdout
        assert "EXTRACTED=1" in proc.stdout, "an equal face must still extract — the run is a re-run"

    def test_the_head_is_the_shipped_one_and_the_parser_takes_named_ids(self, tmp_path, real_tarball):
        """Control for the instrument itself: the shipped chain has ONE head and its ids include a
        NAME (011_admin_cert_revocations), so a digits-only parser would have read nothing.

        Without this cell every verdict below could be a reading of an empty index."""
        out = subprocess.run(
            ["tar", "-xzOf", str(real_tarball), "--wildcards", "*/packages/core/alembic/versions/*.py"],
            capture_output=True,
            text=True,
            check=False,
        )
        assert out.returncode == 0, out.stderr
        index = [ln for ln in out.stdout.splitlines() if ln.startswith(("revision", "down_revision"))]
        assert len(index) == 2 * len(list(REAL_CHAIN.glob("*.py")))
        assert 'revision: str = "011_admin_cert_revocations"' in out.stdout
        assert 'revision = "043"' in out.stdout

    def test_ancestor_stamp_admits_but_moves_the_backup_gate(self, tmp_path, real_tarball):
        """AC2, the silent half: stored 042 with an INCOMING == INSTALLED label. The strings say
        "nothing to do"; the stamp says migrations will run, so the restore point is required."""
        proc = _run(
            tmp_path,
            _compare_block(),
            stub_bin=_stub_dir(tmp_path, stamp="042"),
            env={"TEST_TARBALL": str(real_tarball)},
        )
        assert proc.returncode == 0, proc.stdout + proc.stderr
        assert "verdict: ancestor" in proc.stdout, proc.stdout
        assert "Schema moves this run: stored 042 -> incoming 043" in proc.stdout, proc.stdout
        assert "BACKUP_REQUIRED=yes" in proc.stdout, proc.stdout
        assert "EXTRACTED=1" in proc.stdout


class TestTheAheadFaceRefusesAndStillBacksUp:
    """AC3 + the paired negative: refuse, but never without the restore point."""

    def test_same_label_with_ahead_stamp_refuses_after_taking_the_backup(self, tmp_path, real_tarball):
        """THE paired negative. Same version string both sides, stored head ahead of the incoming
        head: the run must refuse AND must still take its backup — rc 1, backup taken, and no
        extraction at all."""
        proc = _run(
            tmp_path,
            _compare_block(),
            stub_bin=_stub_dir(tmp_path, stamp="044"),
            env={"TEST_TARBALL": str(real_tarball)},
        )
        assert proc.returncode == 1, f"the ahead face did not refuse: {proc.stdout}{proc.stderr}"
        assert "verdict: ahead" in proc.stdout, proc.stdout
        assert "BACKUP_TAKEN=1" in proc.stdout, "refused with no restore point — the loss this row is about"
        assert "EXTRACTED=1" not in proc.stdout, "the refusal extracted anyway — mutation after the stop"
        assert "REACHED_END=1" not in proc.stdout
        assert "VENYA_ALLOW_AHEAD_SCHEMA=yes" in proc.stdout, proc.stdout

    def test_a_stamp_the_incoming_tree_has_never_heard_of_refuses_too(self, tmp_path, real_tarball):
        """Not merely "one past the head": any stored position the incoming chain cannot reach is
        ahead-of-unknown and refuses. A face swap off a branch or a hotfix build lands here."""
        proc = _run(
            tmp_path,
            _compare_block(),
            stub_bin=_stub_dir(tmp_path, stamp="099_hotfix_from_a_different_face"),
            env={"TEST_TARBALL": str(real_tarball)},
        )
        assert proc.returncode == 1, proc.stdout + proc.stderr
        assert "verdict: ahead" in proc.stdout, proc.stdout
        assert "BACKUP_TAKEN=1" in proc.stdout

    def test_distinct_opt_in_proceeds_where_the_downgrade_knob_does_not(self, tmp_path, real_tarball):
        """The escape is its own knob. VENYA_ALLOW_DOWNGRADE=yes must NOT open the schema gate —
        it answers the label, and conflating them is how an operator moves a stamp they never read."""
        opted = _run(
            tmp_path,
            _compare_block(),
            stub_bin=_stub_dir(tmp_path, stamp="044"),
            env={"TEST_TARBALL": str(real_tarball), "VENYA_ALLOW_AHEAD_SCHEMA": "yes"},
        )
        assert opted.returncode == 0, opted.stdout + opted.stderr
        assert "VENYA_ALLOW_AHEAD_SCHEMA=yes proceeds" in opted.stdout, opted.stdout
        assert "BACKUP_REQUIRED=yes" in opted.stdout, "opted through a schema step with no restore point"

        old_knob = _run(
            tmp_path,
            _compare_block(),
            stub_bin=_stub_dir(tmp_path, stamp="044"),
            env={"TEST_TARBALL": str(real_tarball), "VENYA_ALLOW_DOWNGRADE": "yes"},
        )
        assert old_knob.returncode == 1, f"the label knob opened the schema gate:\n{old_knob.stdout}"

    def test_the_new_knob_is_not_the_downgrade_knob_in_the_source(self):
        src = _source()
        assert "VENYA_ALLOW_AHEAD_SCHEMA" in src
        assert src.count('VENYA_ALLOW_DOWNGRADE:-}" = "yes"') == 1, "the two knobs were merged into one test"


class TestTheQuietCasesAreNotRefusals:
    """A guard that refuses a healthy install is the other wrong answer (root AGENTS.md §2)."""

    def test_fresh_install_with_no_incumbent_completes(self, tmp_path, real_tarball):
        """Named its own cell because it is the regression a face compare can create: the same
        version re-run on a FRESH box must still complete, with no DB to read and nothing to refuse."""
        proc = _run(
            tmp_path,
            _compare_block(),
            stub_bin=_stub_dir(tmp_path, stamp=None, psql_rc=3),
            env={"TEST_TARBALL": str(real_tarball), "TEST_INSTALLED": ""},
        )
        assert proc.returncode == 0, proc.stdout + proc.stderr
        assert "no incumbent install — fresh install, nothing to compare and no refusal" in proc.stdout
        assert "EXTRACTED=1" in proc.stdout
        assert "verdict" not in proc.stdout, "the compare ran on a fresh box it should have skipped"

    def test_empty_database_stores_no_stamp_and_is_not_refused(self, tmp_path, real_tarball):
        """A venv exists but the DB has no alembic_version yet (a mid-failed earlier install). There
        is no stored position to compare, so the honest answer is a warning plus a restore point."""
        proc = _run(
            tmp_path,
            _compare_block(),
            stub_bin=_stub_dir(tmp_path, stamp=""),
            env={"TEST_TARBALL": str(real_tarball)},
        )
        assert proc.returncode == 0, proc.stdout + proc.stderr
        assert "verdict: nostored" in proc.stdout, proc.stdout
        assert "stored: <none>" in proc.stdout, proc.stdout
        assert "BACKUP_REQUIRED=yes" in proc.stdout

    def test_tarball_without_readable_revisions_warns_and_does_not_refuse(self, tmp_path):
        """The read can fail (layout change, a tarball built without the alembic dir). Silence is the
        weakening class, and refusal would break every install on that layout — so: warn, and take
        the restore point."""
        ball = _tarball(tmp_path, [], version="0.1.0beta9")
        proc = _run(
            tmp_path,
            _compare_block(),
            stub_bin=_stub_dir(tmp_path, stamp="042"),
            env={"TEST_TARBALL": str(ball)},
        )
        assert proc.returncode == 0, proc.stdout + proc.stderr
        assert "no alembic revisions readable in the tarball" in proc.stdout, proc.stdout
        assert "BACKUP_REQUIRED=yes" in proc.stdout

    def test_branched_chain_reads_unreadable_rather_than_refusing(self, tmp_path):
        """The stated limit: a merge revision gives two heads, and two heads is NOT evidence of an
        ahead face. It warns and takes a restore point. If a later leg ships a branched set, this is
        the cell that must change deliberately, not by accident."""
        ball = _tarball(
            tmp_path,
            _chain([("A", None), ("B", "A"), ("C", "A")]),
            version="0.1.0beta9",
        )
        proc = _run(
            tmp_path,
            _compare_block(),
            stub_bin=_stub_dir(tmp_path, stamp="A"),
            env={"TEST_TARBALL": str(ball)},
        )
        assert proc.returncode == 0, proc.stdout + proc.stderr
        assert "verdict: unreadable" in proc.stdout, proc.stdout
        assert "could not name both faces" in proc.stdout, proc.stdout
        assert "BACKUP_REQUIRED=yes" in proc.stdout

    def test_named_ids_walk_as_ancestors(self, tmp_path):
        """The chain's ids are not digits (011's is a name). Ancestor-walking on strings, executed."""
        ball = _tarball(
            tmp_path,
            _chain(
                [("001_base", None), ("011_admin_cert_revocations", "001_base"), ("043", "011_admin_cert_revocations")]
            ),
            version="0.1.0beta9",
        )
        proc = _run(
            tmp_path,
            _compare_block(),
            stub_bin=_stub_dir(tmp_path, stamp="011_admin_cert_revocations"),
            env={"TEST_TARBALL": str(ball)},
        )
        assert proc.returncode == 0, proc.stdout + proc.stderr
        assert (
            "incoming head: 043; stored stamp: 011_admin_cert_revocations; verdict: ancestor" in proc.stdout
        ), proc.stdout


class TestTheStringArmAndTheBackupBodyAreIntact:
    """The checks this leg could have quietly weakened, pinned instead."""

    def test_the_equal_string_arm_is_still_there(self):
        """Deleting or muting the string comparison to keep installs quiet is the weakening class.
        It stays for what it already proves; the new read sits beside it, not in its place."""
        src = _source()
        assert 'info "Version: $INSTALLED_VERSION (same-version re-run)"' in src
        assert "Refusing to downgrade" in src
        assert 'VENYA_ALLOW_DOWNGRADE:-}" = "yes"' in src
        # …and the compare is the thing AFTER it, so the label arm still runs first.
        assert src.index("same-version re-run") < src.index(COMPARE_HEADER)

    def test_backup_body_moved_once_and_not_duplicated(self):
        """The function holds the shipped body; the old inline copy is gone. Two bodies would mean
        two retention rules drifting apart, and zero would mean the restore point was deleted."""
        fn = _backup_fn()
        for mark in BACKUP_BODY_MARKS:
            assert mark in fn, f"the moved backup body no longer carries {mark!r}"
        src = _source()
        for mark in BACKUP_BODY_MARKS:
            # The prose above the call site also says "no backup, no upgrade", so the count that
            # matters is the CODE's: each executable mark appears in exactly one place.
            expected = 1 if mark != "no backup, no upgrade" else 2
            assert src.count(mark) == expected, f"{mark!r} count {src.count(mark)}, expected {expected}"
        assert src.count("venya_preupgrade_backup") == 3, "definition + two call sites expected"

    def test_backup_still_strictly_before_migrations_and_compare_before_every_mutation(self):
        src = _source()
        assert src.index("pg_dump") < src.index("_run_migrations"), "#750 moved the backup after migrations"
        i = src.index(COMPARE_HEADER)
        assert i < src.index("\nvenya_create_venv"), "the compare no longer precedes the venv rebuild"
        assert i < src.index("_run_migrations"), "the compare no longer precedes the migration step"
        # The extraction the refusal must precede is located AFTER the block, not by first mention:
        # the name `venya_extract_tarball` also appears in prose near the top of the file, and an
        # index() on it returns 7658 and would make this cell pass on a block that moved anywhere.
        assert src.index(EXTRACT_CALL, i) > i
        assert src.count(EXTRACT_CALL + "\n") == 1, "a second extraction call appeared"

    def test_the_compare_reads_only_and_writes_nothing(self):
        """Schema position is READ, never written: no alembic invocation, no INSERT/UPDATE on
        alembic_version, no migration added. This is the boundary the row was given with."""
        block = _compare_block()
        for forbidden in ("alembic upgrade", "alembic downgrade", "alembic stamp", "INSERT INTO", "UPDATE "):
            assert forbidden not in block, f"the compare block contains a write: {forbidden!r}"
        assert block.count("select version_num from alembic_version limit 1") == 1
        src = _source()
        # One touch in the whole installer, and it is the comment plus this read: no other code path
        # discovered alembic_version, so there is no second writer to audit.
        assert src.count("alembic_version") == block.count("alembic_version")

    def test_the_pip_failure_rescue_is_present_on_both_reads(self):
        """`set -euo pipefail` would abort the installer on a psql that answers nothing (a fresh box
        with no database), turning a read that cannot conclude into a crash. Both substitutions carry
        their own rescue, and neither pipes a secret."""
        block = _compare_block()
        assert block.count('|| MIG_INDEX=""') == 1
        assert block.count('|| STORED_STAMP=""') == 1
        assert "VENYA_DB_PASSWORD" not in block, "the stamp read must not need the app password"
