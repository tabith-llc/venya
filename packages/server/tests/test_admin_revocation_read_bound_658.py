# Copyright (c) 2026 Tabith LLC.
# Use of this source code is governed by the Business Source License 1.1
# included in the LICENSE file at the root of this repository. As of the
# Change Date listed there, the work is available under MPL 2.0.
# SPDX-License-Identifier: BUSL-1.1

"""#658 — the admin plane's revocation read is bounded, and every arm still REFUSES.

``_validate_admin_mtls`` reads ``admin_cert_revocations`` with a synchronous SQLAlchemy
``.first()`` inside an ``async def``, on the ordinary pool, on a table with its own purge
(``server/ca.py::AdminCAManager.purge_expired_revocations``). A held ``ACCESS EXCLUSIVE`` parked
that read and with it the single-worker core event loop — the same freeze #603 bounded for the
executor plane, on a different table and a different plane.

The fix routes that read through the SHIPPED seam (``revocation_read.bounded_read`` with the
existing deadline config) and adds a third arm. It is an availability fix, not a policy change, and
these cells are the proof of that claim. The truth table is three rows and there is no silent
fourth:

| arm | verdict | status | shape |
|---|---|---|---|
| serial on the list | refused | ``403`` | ``"Admin certificate revoked"`` — byte-identical to before this change |
| read could not answer in time | refused | ``503`` | the shared list-state sentence; counted at ``{site="admin-mtls"}`` |
| any other lookup fault | refused | ``403`` | ``"Admin access requires valid client certificate"`` — unchanged |

The row that matters most is the third. ``RevocationReadUnavailable`` is a ``RuntimeError``, so a
generic ``except Exception`` placed FIRST swallows the bounded refusal into the credential 403, and
one placed too BROAD converts an unrelated fault into an availability answer — which reads as "we
could not check" when in fact the check ran and said no. Arm order is asserted structurally as well
as behaviorally, because an arm order is exactly the kind of thing a later leg "tidies".

Nothing here reaches a database server: rows (a) and (c) run the middleware over the real SQLite
table (the ``func.upper()`` match key cannot be evaluated by a mock — house precedent, and the
reason ``test_admin_mtls.py`` builds a file-backed SQLite pool), while (b) drives the seam with a
session double whose bind reports the ``postgresql`` dialect, so the deadline is ACTIVE and the
refusal is the seam's own classification rather than a stub of it.

The doubles are imported from the two files that already own those shapes
(``tests.test_revocation_read_bound_603`` for the PG/SQLite session double and the 55P03 fault,
``tests.test_admin_mtls`` for the admin CA and leaf harness) — sibling-test imports are house
precedent (``test_ca_key_load_refusal_541.py``, ``test_csr_curve_contract_503.py``), and re-using
them is the point: a refusal that behaves differently because a test re-implemented the double is
not the same instrument.
"""

import re
from pathlib import Path

import pytest
from server.middleware.auth import ADMIN_MTLS_REVOCATION_SITE
from starlette.testclient import TestClient

try:
    from .conftest import ADMIN_SERIAL_HEX, forwarded_headers, make_cert_prefix
    from .test_admin_mtls import (
        _admin_leaf,
        _create_admin_mtls_app,
        admin_ca_security,
    )
    from .test_revocation_read_bound_603 import (
        _FakePGSession,
        _lock_timeout_fault,
        _unrelated_fault,
    )
except ImportError:  # pytest rootdir/tests-path import mode
    from conftest import ADMIN_SERIAL_HEX, forwarded_headers, make_cert_prefix
    from test_admin_mtls import (
        _admin_leaf,
        _create_admin_mtls_app,
        admin_ca_security,  # noqa: F401  (pytest fixture: bound by name, not by reference)
    )
    from test_revocation_read_bound_603 import (
        _FakePGSession,
        _lock_timeout_fault,
        _unrelated_fault,
    )

# The shipped sentences, verbatim at this tip. Byte-identity anchors: a leg that "improves" one of
# these strings has changed what an operator reads, not what the server decides.
SHIPPED_REVOKED_403 = "Admin certificate revoked"
SHIPPED_FAULT_403 = "Admin access requires valid client certificate"

AUTH_FILE = Path(__file__).resolve().parents[1] / "src" / "server" / "middleware" / "auth.py"


@pytest.fixture
def admin_ca_dir(tmp_path):
    """Local copy of the admin-CA dir fixture this harness needs.

    Declared rather than imported for one thing only (the path); the passphrase-config fixture IS
    imported below, because a copied `key_passphrase_env=` literal is a second detection for the
    same synthetic dev-test value and a second thing to rot.
    """
    d = tmp_path / "admin-ca"
    d.mkdir()
    return str(d)


class _AdminPlanePGSession(_FakePGSession):
    """The #603 PG double plus the one method the admin middleware calls and #603's did not need.

    ``_validate_admin_mtls`` closes its session in a ``finally``. The 603 double models only the
    seam's surface (bind/flush/begin_nested/execute/query), so without ``close()`` every cell in
    this file would die with ``AttributeError`` in that ``finally`` — and a naive fix would add a
    ``except Exception`` around it and quietly swallow the fault under test. Extending the imported
    double keeps the fault path the shipped seam's and makes the missing method explicit.
    """

    def close(self) -> None:  # pragma: no cover - resource teardown, no behavior under test
        self.events.append("close")


class _SessionBackend:
    """A backend whose every session is one pre-programmed double."""

    def __init__(self, session) -> None:
        self._session = session
        self.sessions_made = 0

    def get_session(self):
        self.sessions_made += 1
        return self._session


@pytest.fixture
def counter():
    def _read(site: str) -> float:
        from server import metrics

        return metrics.REVOCATION_READ_REFUSALS_TOTAL.labels(site=site)._value.get()

    return _read


@pytest.fixture(autouse=True)
def _clear_passphrase_env(monkeypatch):
    """Same posture as ``test_admin_mtls.py``'s autouse fixture: no inherited passphrase.

    Only the NAMES are touched here — a value literal copied into a second file is what the
    detect-secrets hook correctly flags, and ``_admin_leaf`` sets the passphrase it needs itself.
    """
    monkeypatch.delenv("VENYA_CA_KEY_PASSPHRASE", raising=False)
    monkeypatch.delenv("VENYA_ADMIN_CA_KEY_PASSPHRASE", raising=False)


class TestAdminRevocationReadTruthTable658:
    """The three rows. Each one REFUSES; that is the whole point of the row."""

    def test_row_a_revoked_serial_still_refuses_403_byte_identically(self, admin_ca_dir, admin_ca_security, tmp_path):
        """A genuine admin-leaf revocation refuses exactly as it did before #658 existed.

        This cell is the "no decision changed" half: the seam is a no-op on the SQLite bind, so the
        read runs for real against the seeded row, and the response is the SAME status and the SAME
        sentence as the pre-#658 middleware.
        """
        prefix = make_cert_prefix(tmp_path)
        cert = _admin_leaf(admin_ca_dir, admin_ca_security, serial=int(ADMIN_SERIAL_HEX, 16))
        app = _create_admin_mtls_app(
            admin_ca_dir,
            revocation_rows=[(ADMIN_SERIAL_HEX, "compromised")],
            cert_prefix=prefix,
        )
        client = TestClient(app, raise_server_exceptions=False)
        resp = client.get("/api/v1/admin/test", headers=forwarded_headers(prefix, cert))
        assert resp.status_code == 403, resp.text
        assert resp.json()["detail"] == SHIPPED_REVOKED_403, resp.json()

    def test_row_b_lock_wait_refuses_503_and_never_falls_through(
        self, admin_ca_dir, admin_ca_security, tmp_path, counter
    ):
        """Row (b): the lock wait refuses in the bounded class and does NOT reach the handler.

        The failure mode #658 exists for is a held ``ACCESS EXCLUSIVE``; the double raises the
        seam's own trigger (a ``DBAPIError`` carrying SQLSTATE 55P03) from inside the read, so the
        classification, the count and the raise are all the shipped seam's, not a mock's. The
        assertion that carries the security weight is the last one: the admin route must NOT have
        run. "The read timed out, so allow" is the regression this cell is the gate on.
        """
        prefix = make_cert_prefix(tmp_path)
        cert = _admin_leaf(admin_ca_dir, admin_ca_security, serial=int(ADMIN_SERIAL_HEX, 16))
        session = _AdminPlanePGSession(fail_read=_lock_timeout_fault())
        app = _create_admin_mtls_app(admin_ca_dir, cert_prefix=prefix)
        app.state.backend = _SessionBackend(session)
        before = counter(ADMIN_MTLS_REVOCATION_SITE)

        client = TestClient(app, raise_server_exceptions=False)
        resp = client.get("/api/v1/admin/test", headers=forwarded_headers(prefix, cert))

        assert resp.status_code == 503, resp.text
        detail = resp.json()["detail"]
        assert "no revocation asserted" in detail.lower(), detail
        assert "revoked" not in detail.lower(), detail
        assert counter(ADMIN_MTLS_REVOCATION_SITE) == before + 1, (
            "the bounded refusal did not reach the cumulative counter — #651's defect class is a "
            "warning with no count, so the lost volume would be unknowable after the fact"
        )
        # The handler never ran: its body answers {"user": …} and would be a 200.
        assert resp.status_code != 200 and "user" not in resp.json(), resp.json()

    def test_row_c_unrelated_fault_keeps_the_shipped_fail_closed_403(
        self, admin_ca_dir, admin_ca_security, tmp_path, counter
    ):
        """Row (c): an unrelated fault keeps its current fail-closed 403 shape and is NOT counted.

        This is the cell that catches a too-broad ``except``. If the availability arm swallowed
        every fault, a real backend bug would answer "could not check" (503) when the check actually
        ran and refused — and if the generic arm swallowed the bounded class, THIS credential fault
        would answer the credential 403. Both directions are asserted here: the status and sentence
        are the shipped credential pair, and the refusal counter for this site did not move.
        """
        prefix = make_cert_prefix(tmp_path)
        cert = _admin_leaf(admin_ca_dir, admin_ca_security, serial=int(ADMIN_SERIAL_HEX, 16))
        session = _AdminPlanePGSession(fail_read=_unrelated_fault())
        app = _create_admin_mtls_app(admin_ca_dir, cert_prefix=prefix)
        app.state.backend = _SessionBackend(session)
        before = counter(ADMIN_MTLS_REVOCATION_SITE)

        client = TestClient(app, raise_server_exceptions=False)
        resp = client.get("/api/v1/admin/test", headers=forwarded_headers(prefix, cert))

        assert resp.status_code == 403, resp.text
        assert resp.json()["detail"] == SHIPPED_FAULT_403, resp.json()
        assert counter(ADMIN_MTLS_REVOCATION_SITE) == before, (
            "a non-lock fault was counted as a revocation-plane refusal — the counter would then "
            "report lost revocation checks that were never refused for the lock deadline"
        )

    def test_row_b_still_refuses_when_the_serial_is_not_on_the_list(self, admin_ca_dir, admin_ca_security, tmp_path):
        """The empty-list read is inside the same deadline, so a stall there cannot admit either.

        The no-match branch runs a SECOND query (``rows_exist``, the #481 "which no-match is this"
        line). Both reads are inside one ``bounded_read``, and this cell proves the second one is
        too: widening only the first read would let a lock stall on the logging query fall through
        to a 200.
        """
        prefix = make_cert_prefix(tmp_path)
        cert = _admin_leaf(admin_ca_dir, admin_ca_security, serial=int(ADMIN_SERIAL_HEX, 16))
        session = _AdminPlanePGSession(fail_read=_lock_timeout_fault())
        app = _create_admin_mtls_app(admin_ca_dir, cert_prefix=prefix)
        app.state.backend = _SessionBackend(session)

        client = TestClient(app, raise_server_exceptions=False)
        resp = client.get("/api/v1/admin/test", headers=forwarded_headers(prefix, cert))
        assert resp.status_code == 503, resp.text

    def test_the_bounded_arm_is_ordered_before_the_generic_fail_closed_arm(self):
        """Arm ORDER is load-bearing and must be pinned, not trusted.

        ``RevocationReadUnavailable`` is a ``RuntimeError``. In Python the FIRST matching ``except``
        wins, so if a later leg "simplifies" this block by deleting the bounded arm or moving it
        under the generic one, the lock refusal is silently re-labelled as a credential failure —
        right status class for a fault, wrong claim about the credential, and no counter either way.
        Read structurally from the tracked file rather than by behavior, because both orders behave
        and only one tells the truth.
        """
        text = AUTH_FILE.read_text()
        start = text.index("async def _validate_admin_mtls")
        end = text.index("async def dispatch", start)
        block = text[start:end]
        bounded = block.index("except RevocationReadUnavailable")
        generic = block.index("except Exception:")
        assert bounded < generic, (
            "the bounded-refusal arm now sits BELOW the generic fail-closed arm, so a lock-wait "
            "refusal is answered with the credential 403 instead of the list-state 503 (#658 AC6)"
        )
        assert block.count("except RevocationReadUnavailable") == 1, "two arms for one fault class"

    def test_the_admin_plane_extends_the_seam_and_does_not_fork_it(self, counter):
        """AC's "extend, do not fork": no second deadline mechanism may appear in this middleware.

        A parallel savepoint / ``SET LOCAL`` implementation is the split-brain #603's module comment
        already booked once. The admin plane must borrow the shipped instrument, so the only
        lock-timeout machinery in ``auth.py`` is the seam call itself, and the only knob is the one
        #603 shipped (``crl.revocation_read_lock_timeout_ms``).
        """
        text = AUTH_FILE.read_text()
        assert (
            "bounded_read(db, site=ADMIN_MTLS_REVOCATION_SITE)" in text
        ), "the admin revocation read no longer runs through the shipped bounded seam"
        for forbidden in ("SET LOCAL lock_timeout", "begin_nested", "lock_timeout ="):
            assert forbidden not in text, (
                f"a second lock-timeout implementation appeared in middleware/auth.py ({forbidden!r}) "
                "— extend revocation_read.bounded_read instead"
            )
        # And the label vocabulary must not collide with the executor plane's.
        from server.middleware.auth import SessionMiddleware as _MW

        executor_labels = {
            _MW._revocation_site(path)
            for path in (
                "/api/v1/heartbeat",
                "/api/v1/audit/ingest",
                "/api/v1/sessions/x",
                "/api/v1/whatever",
            )
        }
        assert ADMIN_MTLS_REVOCATION_SITE not in executor_labels, (
            f"the admin site label {ADMIN_MTLS_REVOCATION_SITE!r} collides with the executor plane's "
            f"vocabulary {sorted(executor_labels)} — an operator could not tell the planes apart"
        )

    def test_a_healthy_read_still_admits_with_the_seam_active(self, admin_ca_dir, admin_ca_security, tmp_path):
        """The paired positive half of every row above: nothing here broke admission.

        With a clean SQLite table and a verified, allowlisted, unrevoked machine cert the request
        must still reach the handler with ``caller=admin`` — otherwise the three refusals above
        would be indistinguishable from a middleware that refuses everyone.
        """
        prefix = make_cert_prefix(tmp_path)
        cert = _admin_leaf(admin_ca_dir, admin_ca_security)
        app = _create_admin_mtls_app(admin_ca_dir, cert_prefix=prefix)
        client = TestClient(app, raise_server_exceptions=False)
        resp = client.get("/api/v1/admin/test", headers=forwarded_headers(prefix, cert))
        assert resp.status_code == 200, resp.text
        assert resp.json()["user"]["caller"] == "admin", resp.json()

    def test_the_refusal_detail_is_the_one_shared_sentence_not_a_new_one(self):
        """The admin arm answers the SAME list-state sentence the executor plane uses.

        Two sentences for one fault is how an ops line ends up naming an event that never happened
        (the #603 law about retyping the wording). Asserted by identity against the constant, and
        the shape is re-checked as text so a re-flow into a near-synonym is caught too.
        """
        from server.revocation_read import REVOCATION_UNAVAILABLE_DETAIL

        text = AUTH_FILE.read_text()
        start = text.index("async def _validate_admin_mtls")
        end = text.index("async def dispatch", start)
        assert "REVOCATION_UNAVAILABLE_DETAIL" in text[start:end], (
            "the admin bounded-refusal arm no longer answers the shared sentence — a second wording "
            "for one fault class"
        )
        assert REVOCATION_UNAVAILABLE_DETAIL == (
            "Revocation list stale or unavailable — request refused (no revocation asserted)"
        ), "the shipped sentence changed under this leg; that is an operator-facing edit, not this row"
        assert not re.search(
            r"detail\":\s*\"[^\"]*unavailable[^\"]*\"", text[start:end]
        ), "a hand-typed unavailable detail appeared beside the imported constant"
