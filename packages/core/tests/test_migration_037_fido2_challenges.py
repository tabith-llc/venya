# Copyright (c) 2026 Tabith LLC.
# Use of this source code is governed by the Business Source License 1.1
# included in the LICENSE file at the root of this repository. As of the
# Change Date listed there, the work is available under MPL 2.0.
# SPDX-License-Identifier: BUSL-1.1

"""Migration 037 — fido2_challenges table (#534).

Same tested shape as 034/035/036: the real upgrade()/downgrade() run
through alembic Operations on a live SQLite connection (a fresh database,
no prior table — this migration CREATES), plus the model interlock (ORM
INSERT/FLUSH/READ against the MIGRATED schema: a column in the model but
not in the migration surfaces here as UndefinedColumn) and the
server_default pin: state lands 'created' without the ORM saying so, so a
raw-SQL insert that omits it stays correct.

AC5 also wants the chain VERIFIED LINEAR onto the head at implementation
time, so the whole versions directory is walked here: exactly one head,
every revision referenced by at most one child, no cycles. A fork (two
migrations sharing a down_revision) or a second head fails this cell —
which is the point: the merge that introduces a fork reddens the suite.
"""

import importlib.util
import re
from datetime import UTC, datetime, timedelta
from pathlib import Path

from alembic.migration import MigrationContext
from alembic.operations import Operations
from core.iam.models import Fido2Challenge
from sqlalchemy import create_engine, inspect
from sqlalchemy.orm import Session as OrmSession

_VERSIONS_DIR = Path(__file__).resolve().parents[1] / "alembic" / "versions"
_MIGRATION_PATH = _VERSIONS_DIR / "037_fido2_challenges.py"


def _load_migration():
    spec = importlib.util.spec_from_file_location("migration_037", _MIGRATION_PATH)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def _run(engine, fn) -> None:
    mod = _load_migration()
    with engine.begin() as conn:
        ctx = MigrationContext.configure(conn)
        mod.op = Operations(ctx)
        fn(mod)


def _bare_engine(tmp_path):
    return create_engine(f"sqlite:///{tmp_path / 'mig.db'}")


def _chain():
    """(revision -> down_revision) for every file in versions/, read from
    source text (no alembic env/DB needed)."""
    pairs = {}
    pattern_rev = re.compile(r'^revision(?::\s*str)?\s*=\s*["\']([^"\']+)["\']', re.MULTILINE)
    pattern_down = re.compile(r'^down_revision(?::[^=]+)?\s*=\s*(?:["\']([^"\']+)["\']|None)', re.MULTILINE)
    for path in sorted(_VERSIONS_DIR.glob("*.py")):
        text = path.read_text()
        rev = pattern_rev.search(text)
        down = pattern_down.search(text)
        assert rev is not None, f"{path.name} declares no revision id"
        assert down is not None, f"{path.name} declares no down_revision (use None for the root)"
        # An alembic tuple/branch form is a fork by construction; refuse to
        # read it as a single parent and let it pass as "linear".
        assert (
            "(" not in text.split("down_revision", 1)[1].split("\n")[0]
        ), f"{path.name} uses a multi-parent down_revision"
        pairs[rev.group(1)] = (down.group(1), path.name)
    return pairs


def test_revision_chain():
    mod = _load_migration()
    assert mod.revision == "037"
    assert mod.down_revision == "036"


def test_chain_is_linear_with_one_head():
    """AC5 (037-era invariant; head ADVANCES deliberately as migrations land —
    038 moved it in the attestation-store leg, 039 in the #591 cascade-parity
    leg): the chain has no fork, exactly
    one head, and every revision in the graph is reachable from it. 037 hangs
    off 036 and nothing else hangs off 036."""
    chain = _chain()
    assert "037" in chain

    children: dict[str, list[str]] = {}
    for rev, (down, _name) in chain.items():
        if down is not None:
            assert down in chain, f"{rev} points at a missing parent {down}"
            children.setdefault(down, []).append(rev)

    forks = {parent: kids for parent, kids in children.items() if len(kids) > 1}
    assert not forks, f"migration chain has a fork: {forks}"

    heads = [rev for rev in chain if rev not in children]
    # pin the CURRENT head deliberately: adding a migration must make a seat
    # advance this line on purpose — the invariant (one head, no forks) is
    # what the cell guards, the identifier is the acknowledgement.
    # head history: 037 -> 038 (attestation store) -> 039 (#591 cascade parity)
    # -> 040 (#597 core relay credential registry) -> 041 (#684 admin credential registry).
    assert heads == ["041"], f"expected exactly one head (041), got {heads}"

    # walk back from the head: everything reachable, no cycle
    seen = set()
    node = heads[0]
    while node is not None:
        assert node not in seen, f"cycle at {node}"
        seen.add(node)
        node = chain[node][0]
    assert seen == set(chain), "orphaned revision(s): " + str(set(chain) - seen)


def test_upgrade_creates_table_and_indexes(tmp_path):
    engine = _bare_engine(tmp_path)
    _run(engine, lambda mod: mod.upgrade())
    insp = inspect(engine)
    assert "fido2_challenges" in insp.get_table_names()
    cols = {c["name"]: c for c in insp.get_columns("fido2_challenges")}
    for name in ("challenge_id", "user_id", "payload", "state", "created_at", "expires_at"):
        assert name in cols
    assert cols["user_id"]["nullable"] is False
    assert cols["payload"]["nullable"] is False
    idx = {i["name"] for i in insp.get_indexes("fido2_challenges")}
    assert {
        "ix_fido2_challenges_challenge_id",
        "ix_fido2_challenges_user_id",
        "ix_fido2_challenges_expires_at",
    } <= idx


def test_state_has_created_server_default(tmp_path):
    engine = _bare_engine(tmp_path)
    _run(engine, lambda mod: mod.upgrade())
    with engine.begin() as conn:
        conn.exec_driver_sql(
            "INSERT INTO fido2_challenges (challenge_id, user_id, payload, created_at, expires_at) "
            "VALUES ('c1', 'u1', '{}', '2026-10-08 00:00:00', '2026-10-08 00:05:00')"
        )
        state = conn.exec_driver_sql("SELECT state FROM fido2_challenges WHERE challenge_id='c1'").scalar()
    assert state == "created"


def test_downgrade_drops_the_table(tmp_path):
    engine = _bare_engine(tmp_path)
    _run(engine, lambda mod: mod.upgrade())
    _run(engine, lambda mod: mod.downgrade())
    assert "fido2_challenges" not in inspect(engine).get_table_names()


def test_migrated_schema_round_trips_through_the_orm(tmp_path):
    engine = _bare_engine(tmp_path)
    _run(engine, lambda mod: mod.upgrade())
    now = datetime.now(UTC)
    with OrmSession(engine) as s:
        s.add(
            Fido2Challenge(
                challenge_id="c2",
                user_id="u2",
                payload='{"raw_challenge": {"__b64__": "AAEC"}}',
                state="created",
                created_at=now,
                expires_at=now + timedelta(seconds=300),
            )
        )
        s.flush()  # UndefinedColumn class guard: fails if the migration lacks a model column
        row = s.query(Fido2Challenge).filter_by(challenge_id="c2").one()
        assert row.state == "created"
        assert row.payload.startswith("{")


def test_model_matches_the_migration_columns():
    """Drift pin: model and migration 037 describe the same fields."""
    table = Fido2Challenge.__table__
    assert {c.name for c in table.columns} == {
        "id",
        "challenge_id",
        "user_id",
        "payload",
        "state",
        "created_at",
        "expires_at",
    }
    assert table.c.challenge_id.unique is True
    # The deliberate divergence from elevation_challenges: no FK on user_id.
    assert list(table.c.user_id.foreign_keys) == []
