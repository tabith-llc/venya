# Copyright (c) 2026 Tabith LLC.
# Use of this source code is governed by the Business Source License 1.1
# included in the LICENSE file at the root of this repository. As of the
# Change Date listed there, the work is available under MPL 2.0.
# SPDX-License-Identifier: BUSL-1.1

"""#597 tier 1 — a raw-SQL canary proves the DEFENSE against incomplete enumeration.

**The scope line, and it is the whole point of this file.** This proves the defense
against incomplete enumeration, **not** that enumeration is complete. #597's carrier
admits "raw SQL or out-of-band revocations were not exhaustively searched." Nothing
here narrows that admission: a canary that reaches the snapshot says the publisher
reads TABLE state, so a revocation nobody enumerated is still honored. It says
nothing about revocations landing somewhere the publisher is not bound to.

**Why raw SQL is the instrument.** Every writer in the product goes through the ORM,
so an ORM-only test can only ever prove the paths the code already names. Inserting
the row with a bare ``INSERT`` is a write no enumeration question could have covered —
which is exactly the class the carrier could not search.

**Publisher seam chosen (located, not inherited):** ``server/revocation_snapshot.py``,
``revocation_populations`` (:276) — an unfiltered ``db.query(ExecutorCertRevocation).all()``
— reached through the real publisher entry ``publish_once`` (:446), which is what
``revocation_snapshot_loop`` calls each tick. ``revocation_read.py`` is the request-path
reader the spec guessed at; it is NOT the publisher, and the snapshot module's own
contract says so (it stores a population, never a verdict).

**Both halves, because a positive-only cell here cannot fail:**
+-------------------------------------------+----------------------------------------+
| shape                                     | expected                               |
+-------------------------------------------+----------------------------------------+
| raw-SQL canary, publisher bound to that DB| next snapshot carries it, ONE cycle    |
| raw-SQL canary, BEFORE any re-publish     | absent — the publish is what moved it  |
| canary in a DB the publisher is NOT bound | NEVER appears, after any number of     |
| to (second engine, second file)           | publishes — this is the negative half  |
| same serial inserted twice                | IntegrityError from the table's own    |
|                                         | UNIQUE, and ONE entry in the snapshot  |
| serial bytes                              | generated per run, never a real serial |
+-------------------------------------------+----------------------------------------+

Real SQLite, no PostgreSQL door: the population under test is table state, and that is
the house precedent (``test_revocation_snapshot_603.py`` runs real SQLite for the same
reason — "a mock DB would pin the mock instead of the semantics"). No scratch database
was created for these cells.
"""

import os
import re
from datetime import UTC, datetime

import pytest
from core.iam.models import Base
from server import revocation_snapshot as rs
from sqlalchemy import create_engine, text
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import sessionmaker

#: Every serial in this file is generated. No live or historically real serial is
#: written into this source, in any form — including as a "never be this" constant.
#: The pre-commit detect-secrets hook flagged exactly that mistake here (a real
#: estate serial pasted in from a dispatch), and suppressing it with an allowlist
#: pragma would have weakened a check that was telling the truth. The generator
#: below is proven synthetic by shape and by randomness, not by comparison to one
#: known-real value.
_SERIAL_SHAPE = re.compile(r"^[0-9A-F]{16}$")

_RAW_INSERT = text(
    "INSERT INTO executor_cert_revocations (serial_number, executor_id, revoked_at, reason)"
    " VALUES (:serial, :executor_id, :revoked_at, :reason)"
)


def _synthetic_serial() -> str:
    """Random uppercase-hex bytes, 16 wide — the SHAPE of a real serial, never a real one."""
    serial = os.urandom(8).hex().upper()
    assert _SERIAL_SHAPE.match(serial), f"generator emitted a non-canonical serial: {serial}"
    return serial


def test_generated_serials_are_random_and_never_a_fixed_literal() -> None:
    """The canary is synthetic BY CONSTRUCTION, and that is a checked claim.

    If the generator ever regressed to a constant, every cell in this file would
    still pass while the suite quietly carried a fixed serial into tracked source.
    """
    batch = {_synthetic_serial() for _ in range(200)}
    assert len(batch) == 200, "serial generator produced a repeat — it is not random"
    assert len({s for s in batch if _SERIAL_SHAPE.match(s)}) == 200


def _raw_insert(SessionLocal, serial: str, executor_id: str = "exec-canary") -> None:
    """One bare INSERT. No ORM object, no service call, no enumerated code path."""
    s = SessionLocal()
    try:
        s.execute(
            _RAW_INSERT,
            {"serial": serial, "executor_id": executor_id, "revoked_at": datetime.now(UTC), "reason": "raw-sql-canary"},
        )
        s.commit()
    finally:
        s.close()


def _read_serials(SessionLocal) -> list[str]:
    """Direct read of ONE database by raw SQL — proves an insert actually landed.

    This exists to kill the vacuous-negative class the lead named tonight: if the
    unbound INSERT had silently failed, the "publisher cannot see it" assertion would
    have been true for the wrong reason, and the cell would have passed doing nothing.
    """
    s = SessionLocal()
    try:
        return [row[0] for row in s.execute(text("SELECT serial_number FROM executor_cert_revocations"))]
    finally:
        s.close()


def _make_session(tmp_path, name: str):
    engine = create_engine(f"sqlite:///{tmp_path / name}")
    Base.metadata.create_all(engine)
    return engine, sessionmaker(bind=engine)


@pytest.fixture(autouse=True)
def _clean_snapshot_state():
    """Module state is process-global; no cell may inherit another's snapshot."""
    rs.reset_snapshot_state()
    yield
    rs.reset_snapshot_state()


@pytest.fixture()
def publisher_db(tmp_path):
    """The database the publisher IS bound to."""
    engine, SessionLocal = _make_session(tmp_path, "publisher.db")
    yield SessionLocal
    engine.dispose()


@pytest.fixture()
def unbound_db(tmp_path):
    """A second, real database the publisher is NOT bound to — the negative half."""
    engine, SessionLocal = _make_session(tmp_path, "other-cluster.db")
    yield SessionLocal
    engine.dispose()


class TestCanaryReachesTheSnapshot:
    """Positive half: an un-enumerated write still lands in the published population."""

    def test_raw_sql_canary_appears_in_the_next_snapshot(self, publisher_db) -> None:
        serial = _synthetic_serial()
        first = rs.publish_once(publisher_db)
        assert first is not None and first.serials == (), "baseline must start empty"

        _raw_insert(publisher_db, serial)

        second = rs.publish_once(publisher_db)
        assert second is not None
        assert serial in second.serials
        assert serial in rs.current_snapshot().serials, "the swap must be the published object"

    def test_the_canary_is_absent_until_a_publish_moves_it(self, publisher_db) -> None:
        """The publish cycle is what carried the row — not the insert, and not luck.

        Without this cell the positive half would pass against a snapshot that had
        already been refreshed by something else in-process.
        """
        serial = _synthetic_serial()
        rs.publish_once(publisher_db)
        _raw_insert(publisher_db, serial)

        assert rs.current_snapshot() is not None
        assert serial not in rs.current_snapshot().serials, "no publish has run since the insert"

        rs.publish_once(publisher_db)
        assert serial in rs.current_snapshot().serials

    def test_the_canary_carries_no_orm_write_and_no_identity_revocation(self, publisher_db) -> None:
        """The row is invisible to every product writer: only the table read finds it."""
        serial = _synthetic_serial()
        _raw_insert(publisher_db, serial, executor_id="exec-canary")
        snapshot = rs.publish_once(publisher_db)

        assert snapshot is not None
        assert serial in snapshot.serials
        assert (
            "exec-canary" not in snapshot.identities
        ), "a serial row is not an identity revocation; the two lists are not interchangeable"


class TestCanaryThePublisherCannotSee:
    """★ Negative half — the cell that earns the name. A blind canary stays blind."""

    def test_a_canary_in_an_unbound_database_never_appears(self, publisher_db, unbound_db) -> None:
        serial = _synthetic_serial()
        _raw_insert(unbound_db, serial)
        # The row is REALLY there — otherwise this negative proves nothing at all.
        assert serial in _read_serials(unbound_db), "the unbound INSERT silently failed"
        assert serial not in _read_serials(publisher_db), "the two engines are not separate databases"

        for _ in range(3):
            rs.publish_once(publisher_db)
            assert (
                serial not in rs.current_snapshot().serials
            ), "the publisher read a row from a database it is not bound to"

        # Prove the instrument works, not just that this serial is missing: the same
        # helper, written where the publisher IS bound, shows up on the next tick.
        _raw_insert(publisher_db, serial)
        rs.publish_once(publisher_db)
        assert (
            serial in rs.current_snapshot().serials
        ), "the negative half is only meaningful if the positive path still fires"

    def test_the_unbound_canary_does_not_disturb_the_bound_population(self, publisher_db, unbound_db) -> None:
        bound = _synthetic_serial()
        unbound = _synthetic_serial()
        _raw_insert(publisher_db, bound)
        _raw_insert(unbound_db, unbound)
        assert unbound in _read_serials(unbound_db), "the unbound INSERT silently failed"

        snapshot = rs.publish_once(publisher_db)
        assert snapshot is not None
        assert unbound not in snapshot.serials
        assert snapshot.serials == tuple(
            sorted([bound])
        ), "the read is not the bound table exactly — the unbound row, or something else, leaked in"


class TestTheTablesOwnConstraint:
    """The UNIQUE the migration declares is real, and it is what makes a serial one entry."""

    def test_a_duplicate_serial_is_refused_by_the_unique_constraint(self, publisher_db) -> None:
        serial = _synthetic_serial()
        _raw_insert(publisher_db, serial)

        with pytest.raises(IntegrityError):
            _raw_insert(publisher_db, serial)

        snapshot = rs.publish_once(publisher_db)
        assert snapshot is not None
        assert list(snapshot.serials).count(serial) == 1, "a retried insert must not double the population"

    def test_the_unique_semantic_on_serial_number_is_in_the_ddl(self, publisher_db) -> None:
        """The constraint the migration declares is really on the table.

        Asserted by SEMANTIC, not by the constraint's name: ``002_executor_cert_revocations.py``
        names it ``uq_executor_cert_revocations_serial_number``, but SQLite renders an inline
        unique as an anonymous ``UNIQUE (serial_number)`` and only PostgreSQL keeps the name in
        the DDL. These cells run on SQLite, so pinning the name would fail on a correct table —
        the behavioral proof that the constraint binds is the duplicate-serial cell above, which
        holds on any backend.
        """
        s = publisher_db()
        try:
            ddl = s.execute(
                text("SELECT sql FROM sqlite_master WHERE type='table' AND name='executor_cert_revocations'")
            ).scalar_one()
        finally:
            s.close()
        assert "serial_number" in ddl
        assert "UNIQUE (serial_number)" in ddl, f"no unique on serial_number in the shipped DDL: {ddl}"
        assert "serial_number VARCHAR(64) NOT NULL" in ddl
