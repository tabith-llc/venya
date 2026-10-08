# Copyright (c) 2026 Tabith LLC.
# Use of this source code is governed by the Business License 1.1
# included in the LICENSE file at the root of this repository. As of the
# Change Date listed there, the work is available under MPL 2.0.
# SPDX-License-Identifier: BUSL-1.1

"""#463 — deterministic tiebreakers on the three partial-order sites.

Three queries ordered on NON-UNIQUE keys with no tiebreaker, so the result SET
was decided by the engine's tie order rather than by the data:

1. ``routes/audit.py`` paged review — ``timestamp DESC`` then OFFSET/LIMIT.
   Same-timestamp rows could be SKIPPED on one page and DUPLICATED on the next,
   and ``total`` (same filtered count) hides it.
2. ``ca.py`` ``CAManager.generate_crl`` fallback — ``revoked_at DESC`` then
   ``limit(max_entries)``.
3. ``ca.py`` ``AdminCAManager.generate_crl`` — same shape, admin family.

At the cap boundary a ``revoked_at`` tie decides WHICH SERIAL IS SIGNED INTO
THE DER — two cores minting "the same" CRL can list different revocations.

Fix shape is drift-to-precedent, not design: the tree already carries the
correct form at ``routes/executors.py:1109``
(``desc(revoked_at), asc(serial_number)``). Secondary keys here are the PK /
serial to match it.

Cells run against REAL SQLite (not mock chains) because the defect IS the query
planner's tie order — a mock ``order_by`` cannot exhibit it. Two assertions this
file deliberately does NOT make, each for a stated reason:

* ``der1 == der2`` on raw CRL bytes is UNACHIEVABLE: ECDSA signing is
  randomized, so identical content yields different signatures. The
  determinism claim is about the revoked-serial SET (the signed content), so
  that is what the cells assert.
* A naive "call it twice, compare" audit cell passes VACUOUSLY on SQLite, which
  happens to break ties in rowid order. The RED half therefore asserts the
  ruled total order against an insertion order chosen to DISAGREE with it.
"""

import json
from datetime import UTC, datetime
from types import SimpleNamespace
from unittest.mock import patch

import pytest
from fastapi import FastAPI
from server.ca import AdminCAManager, CAManager
from server.dependencies import get_current_user
from server.routes import audit as audit_routes
from starlette.testclient import TestClient

_TIE_TS = datetime(2026, 10, 8, 12, 0, 0, tzinfo=UTC)

# The real gate helper, restored per-test so the _is_admin stub used by these
# cells cannot leak into a later module (the leak class recorded at the top of
# test_audit.py).
_ORIGINAL_IS_ADMIN = audit_routes._is_admin

# Started patchers, stopped per-test for the same reason.
_STARTED = []


@pytest.fixture(autouse=True)
def _cleanup():
    yield
    while _STARTED:
        _STARTED.pop().stop()
    audit_routes._is_admin = _ORIGINAL_IS_ADMIN


def _sqlite_engine(tables):
    from sqlalchemy import create_engine
    from sqlalchemy.orm import sessionmaker
    from sqlalchemy.pool import StaticPool

    engine = create_engine("sqlite://", poolclass=StaticPool, connect_args={"check_same_thread": False})
    for table in tables:
        table.create(engine)
    return engine, sessionmaker(bind=engine)


# ---------------------------------------------------------------------------
# AC2 — paged audit review


def _audit_app(session_factory):
    """Real audit router over real SQLite; the auditor gate patched away."""
    from core.iam.role_manager import RoleManager

    backend = SimpleNamespace(get_session=session_factory)
    app = FastAPI()
    app.state.backend = backend
    app.include_router(audit_routes.router, prefix="/api/v1")
    app.dependency_overrides[get_current_user] = lambda: {"user_id": "admin", "roles": [42]}
    audit_routes._is_admin = lambda db, uid: True
    _p = patch.object(RoleManager, "get_user_permissions", return_value={1: "read-write"})
    _p.start()
    _STARTED.append(_p)
    return app


def _page(client, limit, offset):
    resp = client.get("/api/v1/audit", params={"limit": limit, "offset": offset})
    assert resp.status_code == 200, resp.text
    body = resp.json()
    return [e["id"] for e in body["events"]], body["total"]


class TestAuditPagingTiebreaker:
    def _seed(self, sm):
        from core.iam.models import AuditEvent

        s = sm()
        # SIX same-timestamp rows, ids inserted OUT OF ORDER so the engine's
        # natural tie order (rowid) disagrees with the ruled total order.
        for row_id in (503, 501, 502, 506, 504, 505):
            s.add(
                AuditEvent(
                    id=row_id,
                    event_type="command_executed",
                    user_id="admin",
                    fields=json.dumps({"i": row_id}),
                    timestamp=_TIE_TS,
                )
            )
        s.commit()
        s.close()

    def test_all_tied_rows_appear_exactly_once_across_pages(self):
        """AC2 outcome half — a REGRESSION GUARD, and stated honestly: this
        cell also PASSES at base on SQLite, because an ``id`` PK is the rowid
        and SQLite's tie order therefore coincides with the ruled order. It
        pins the contract (every row exactly once, in the ruled order) so a
        future change that drops the tiebreaker and re-orders rows cannot slip
        through on a backend that does not coincide. The half that is RED at
        base on any engine is ``test_paging_statement_carries_the_tiebreaker_in_
        the_emitted_sql``.

        Three pages of two over six same-timestamp rows — every row appears
        EXACTLY ONCE and the sequence is timestamp DESC, id ASC."""
        from core.iam.models import AuditEvent

        _engine, sm = _sqlite_engine([AuditEvent.__table__])
        self._seed(sm)
        client = TestClient(_audit_app(sm), raise_server_exceptions=False)

        seen = []
        for offset in (0, 2, 4):
            ids, total = _page(client, 2, offset)
            assert total == 6, total
            seen.extend(ids)

        assert sorted(seen) == [501, 502, 503, 504, 505, 506]
        assert len(seen) == len(set(seen)), f"page-boundary duplication: {seen}"
        assert seen == [501, 502, 503, 504, 505, 506], seen

    def test_tied_rows_never_drop_across_a_misaligned_page_walk(self):
        """AC2 paired half — same guard status as the cell above (green at base
        on SQLite, for the same rowid-coincidence reason). Walks the SAME six
        rows with pages of size 1 and 3; both walks must land the identical
        complete set — a skipped row shows as a set difference, which is exactly
        the silent-loss class #463."""
        from core.iam.models import AuditEvent

        _engine, sm = _sqlite_engine([AuditEvent.__table__])
        self._seed(sm)
        client = TestClient(_audit_app(sm), raise_server_exceptions=False)

        by_one = []
        for offset in range(6):
            ids, _total = _page(client, 1, offset)
            by_one.extend(ids)
        by_three = []
        for offset in (0, 3):
            ids, _total = _page(client, 3, offset)
            by_three.extend(ids)

        assert set(by_one) == set(by_three) == {501, 502, 503, 504, 505, 506}
        assert by_one == by_three

    def test_paging_statement_carries_the_tiebreaker_in_the_emitted_sql(self):
        """AC2 mechanism half: on SQLite an ``id`` PK is the rowid, so the
        engine's own tie order happens to coincide with the ruled order — a
        data-only assertion therefore passes at base too (measured: base returns
        ids [503, 501, 502, 506, 504, 505] in rowid terms identical to the fixed
        order). So this cell asserts the SQL the route ACTUALLY RUNS, which is
        engine-independent: the paged SELECT must order on timestamp DESC then
        id ASC. RED at base (the ORDER BY is partial there) on any backend.

        This is the half that proves the fix rather than the environment: on
        PostgreSQL the base form has NO defined tie order at all, so the row SET
        across OFFSET/LIMIT pages is not determined by the data."""
        from core.iam.models import AuditEvent
        from sqlalchemy import event

        engine, sm = _sqlite_engine([AuditEvent.__table__])
        self._seed(sm)

        captured = []

        @event.listens_for(engine, "before_cursor_execute")
        def _record(conn, cursor, statement, params, context, executemany):
            captured.append(statement)

        try:
            client = TestClient(_audit_app(sm), raise_server_exceptions=False)
            ids, total = _page(client, 2, 2)
        finally:
            event.remove(engine, "before_cursor_execute", _record)

        paged = [s for s in captured if "LIMIT" in s.upper() and "audit_events" in s]
        assert paged, f"no paged audit SELECT captured: {captured}"
        order_clause = paged[0].split("ORDER BY")[1]
        assert "timestamp DESC" in order_clause, order_clause
        assert "id ASC" in order_clause, f"partial ORDER BY (no tiebreaker): {order_clause}"
        assert ids == [503, 504], ids
        assert total == 6

    def test_ac4_negative_single_and_under_cap_pages_unchanged(self):
        """AC4 (audit half): the no-tie cases stay exactly as they were —
        newest-first on timestamp, and a single row is a single row."""
        from core.iam.models import AuditEvent

        _engine, sm = _sqlite_engine([AuditEvent.__table__])
        s = sm()
        s.add(AuditEvent(id=1, event_type="a", user_id="admin", fields=None, timestamp=_TIE_TS))
        s.add(AuditEvent(id=2, event_type="b", user_id="admin", fields=None, timestamp=_TIE_TS.replace(hour=23)))
        s.commit()
        s.close()
        client = TestClient(_audit_app(sm), raise_server_exceptions=False)

        ids, total = _page(client, 10, 0)
        assert total == 2
        assert ids == [2, 1], ids  # distinct timestamps: primary key alone decides

        one, _ = _page(client, 1, 0)
        assert one == [2]


# ---------------------------------------------------------------------------
# AC3 — CRL population at the cap boundary (both families)
#
# The ruled total order is: revoked_at DESC, then serial_number ASC. So among a
# tied block the LOWEST serials are the ones kept when the cap cuts through the
# block. Each cell states that rule and asserts it, so a rowid-ordered engine
# cannot pass by luck.


def _loaded(crl_der, serials):
    from cryptography import x509

    crl = x509.load_der_x509_crl(crl_der)
    return [ser for ser in serials if crl.get_revoked_certificate_by_serial_number(int(ser, 16)) is not None]


class TestExecutorCrlTiebreaker:
    """Site 2 — ``CAManager.generate_crl`` self-queried fallback."""

    @pytest.fixture
    def ca_manager(self, tmp_path, monkeypatch):
        monkeypatch.setenv("VENYA_CA_KEY_PASSPHRASE", "test_passphrase_463_exec")
        manager = CAManager(str(tmp_path / "ca"))
        manager.initialize()
        return manager

    def _seed(self, sm, serials):
        from core.iam.models import ExecutorCertRevocation

        s = sm()
        for ser in serials:  # insertion order == the order given
            s.add(ExecutorCertRevocation(serial_number=ser, executor_id="exec-1", revoked_at=_TIE_TS, reason="r"))
        s.commit()
        s.close()

    def test_tie_at_cap_lists_the_ruled_serials_and_is_stable(self, ca_manager):
        """AC3 (executor family): three rows share ONE revoked_at, cap is 2, and
        they are INSERTED in an order that disagrees with serial ASC — the
        single-key order follows the engine (rowid), the ruled order follows the
        serial. Asserts the listed set equals the RULED set on two consecutive
        generations."""
        from core.iam.models import ExecutorCertRevocation

        _engine, sm = _sqlite_engine([ExecutorCertRevocation.__table__])
        serials = ["00AA0003", "00AA0001", "00AA0002"]
        self._seed(sm, serials)

        ruled = sorted(serials)[:2]  # revoked_at DESC tie -> serial ASC wins
        gen1 = ca_manager.generate_crl(sm(), max_entries=2)
        gen2 = ca_manager.generate_crl(sm(), max_entries=2)

        listed1 = _loaded(gen1, serials)
        listed2 = _loaded(gen2, serials)
        assert listed1 == ruled, f"listed {listed1}, ruled total order says {ruled}"
        assert listed2 == ruled
        assert listed1 == listed2, "CRL population flipped between generations"

    def test_ac4_negative_under_cap_lists_every_serial(self, ca_manager):
        """AC4 (executor half): with the cap ABOVE the population the tie
        cannot exclude anything — all serials listed, unchanged behaviour."""
        from core.iam.models import ExecutorCertRevocation

        _engine, sm = _sqlite_engine([ExecutorCertRevocation.__table__])
        serials = ["00BB0003", "00BB0001", "00BB0002"]
        self._seed(sm, serials)

        listed = _loaded(ca_manager.generate_crl(sm(), max_entries=10), serials)
        assert sorted(listed) == sorted(serials)


class TestAdminCrlTiebreaker:
    """Site 3 — ``AdminCAManager.generate_crl``, the admin family."""

    @pytest.fixture
    def admin_ca(self, tmp_path, monkeypatch):
        monkeypatch.setenv("VENYA_ADMIN_CA_KEY_PASSPHRASE", "test_passphrase_463_admin")
        manager = AdminCAManager(tmp_path / "admin-ca")
        manager.initialize()
        return manager

    def _seed(self, sm, serials):
        from core.iam.models import AdminCertRevocation

        s = sm()
        for ser in serials:
            s.add(AdminCertRevocation(serial_number=ser, revoked_at=_TIE_TS, reason="r"))
        s.commit()
        s.close()

    def test_tie_at_cap_lists_the_ruled_serials_and_is_stable(self, admin_ca):
        """AC3 (admin family): same shape as the executor cell against the
        admin table — tie at the cap, ruled order decides who is signed in."""
        from core.iam.models import AdminCertRevocation

        _engine, sm = _sqlite_engine([AdminCertRevocation.__table__])
        serials = ["00CC0003", "00CC0001", "00CC0002"]
        self._seed(sm, serials)

        ruled = sorted(serials)[:2]
        gen1 = admin_ca.generate_crl(sm(), max_entries=2)
        gen2 = admin_ca.generate_crl(sm(), max_entries=2)

        listed1 = _loaded(gen1, serials)
        listed2 = _loaded(gen2, serials)
        assert listed1 == ruled, f"listed {listed1}, ruled total order says {ruled}"
        assert listed2 == ruled
        assert listed1 == listed2

    def test_ac4_negative_under_cap_lists_every_serial(self, admin_ca):
        """AC4 (admin half): under cap, nothing is excluded by the tie."""
        from core.iam.models import AdminCertRevocation

        _engine, sm = _sqlite_engine([AdminCertRevocation.__table__])
        serials = ["00DD0003", "00DD0001", "00DD0002"]
        self._seed(sm, serials)

        listed = _loaded(admin_ca.generate_crl(sm(), max_entries=10), serials)
        assert sorted(listed) == sorted(serials)
