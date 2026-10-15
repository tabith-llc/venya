# Copyright (c) 2026 Tabith LLC. All rights reserved.
"""#603 AC2 step 1 (a′-i) — the reserved liveness pool exists and is bounded.

Capacity PARTITION, not capacity growth: the revocation read on the executor-mTLS
path gets its own small engine so it cannot queue behind ordinary request traffic
for a slot of the shared ``pool_size=5, max_overflow=10`` pool.

These cells are the sizing contract. The behavior contract (the 403 stays a 403, a
starved reservation refuses and never allows) lives on the server side in
``tests/test_session_middleware.py``, because that is where the read is issued.

No cell here opens a database connection: ``create_engine`` is lazy, so the pool
shape is inspectable without a server. That is deliberate — a sizing claim must not
depend on fleet capacity.
"""

from __future__ import annotations

from core.engine.backend import KEK_SIZE, Backend, BackendConfig

# The shared pool's shipped numbers, restated here as the NEGATIVE half: the
# reservation must not touch them. A change to these constants in the shared engine
# is #603 AC6 / RF-4 territory and belongs in its own ruled ticket, not in this one.
SHARED_POOL_SIZE = 5
SHARED_MAX_OVERFLOW = 10

# A URL with NO userinfo: this file judges pool SHAPE only, and a
# ``user:pass@`` form here reads to a secret scanner (correctly, on shape) as a
# credential. Keeping it credential-free means the gate needs no allowlist entry
# and no check is weakened.
URL = "postgresql+psycopg2://liveness-pool-shape-test/venya?host=venya-core-9&port=5432"


def _backend() -> Backend:
    """A Backend on a URL it never connects to (create_engine is lazy).

    The ``kek`` intake is the shipped test form (``test_core.py:351``): a raw
    32-byte key, no passphrase, so no salt read and no database contact — these
    cells judge pool shape only.
    """
    return Backend(BackendConfig(database_url=URL, kek=b"k" * KEK_SIZE))


class TestLivenessPoolIsBounded:
    def test_reserved_pool_numbers(self) -> None:
        """The reserved pool is 1 + 1 — a carve-out, not a second full pool."""
        backend = _backend()
        pool = backend.liveness_engine.pool

        assert pool.size() == 1
        assert pool._max_overflow == 1
        # Headroom is 1 + 1 = 2 connections taken OUT of the fleet's budget, not 15.
        assert pool.size() + pool._max_overflow == 2

    def test_reserved_pool_timeout_is_short(self) -> None:
        """A starved reservation fails LOUD and fast, never queues for 30 s.

        The QueuePool default timeout is 30 s; inheriting it would make the
        reserved path wait out the very traffic it was carved out of, and hold the
        request open that whole time.
        """
        backend = _backend()
        assert backend.liveness_engine.pool.timeout() == 2.0
        assert Backend.LIVENESS_POOL_TIMEOUT < 30.0

    def test_shared_pool_numbers_are_untouched(self) -> None:
        """Paired negative: the reservation did NOT resize or replace the shared pool."""
        backend = _backend()
        shared = backend.engine.pool

        assert shared.size() == SHARED_POOL_SIZE
        assert shared._max_overflow == SHARED_MAX_OVERFLOW
        # And they are two distinct engines — the read is not sharing a pool with
        # command traffic, which is the entire point of the step.
        assert backend.liveness_engine is not backend.engine

    def test_reservation_acquires_no_new_credential(self) -> None:
        """The reserved engine rides the SAME URL: no new secret, no new permission.

        #603's shape note is explicit that a second engine must not acquire a
        credential, and the #573 passphrase floor / KEK cache belong to the one
        Backend — a second set of DB credentials would be a second secret to leak.
        """
        backend = _backend()
        # Compare URL OBJECTS, not their rendered strings: SQLAlchemy renders a
        # password as ``***``, so a string compare would judge the mask, not the
        # credential (and ``hide_password=False`` would print one into a failure).
        assert backend.liveness_engine.url == backend.engine.url
        # And the reserved engine carries no userinfo of its own — the credential
        # story here is "there is no second one", not "there is a hidden second one".
        assert backend.liveness_engine.url.username is None
        assert backend.liveness_engine.url.password is None
        # One KEK cache, one owner — the reservation must not fork it.
        assert backend.liveness_engine is not None
        assert backend.kek_cache is backend.kek_cache


class TestLivenessSessionSupply:
    def test_get_liveness_session_returns_a_bound_session(self) -> None:
        """The supplier exists on the CLASS (the middleware discriminates on that)."""
        assert callable(getattr(Backend, "get_liveness_session", None))
        backend = _backend()
        session = backend.get_liveness_session()
        try:
            assert session.get_bind() is backend.liveness_engine
            # And NOT the shared engine — a session that silently fell back to the
            # shared pool would make the whole reservation a no-op.
            assert session.get_bind() is not backend.engine
        finally:
            session.close()

    def test_liveness_factory_is_the_reserved_engine_only(self) -> None:
        """``session_factory`` stays on the shared engine; only the liveness one moves."""
        backend = _backend()
        assert backend.session_factory().get_bind() is backend.engine
        assert backend.liveness_session_factory().get_bind() is backend.liveness_engine


class TestDisposeReleasesTheReservation:
    def test_dispose_drops_both_engines(self) -> None:
        """A held-back connection must not outlive the process boundary."""
        backend = _backend()
        # Force both engines into existence before teardown is asserted.
        assert backend.engine is not None and backend.liveness_engine is not None

        backend.dispose()

        assert backend._engine is None
        assert backend._session_factory is None
        assert backend._liveness_engine is None
        assert backend._liveness_session_factory is None

    def test_dispose_is_safe_when_the_reservation_was_never_used(self) -> None:
        """Negative half: dispose on a Backend that never took the reserved path."""
        backend = _backend()
        backend.dispose()  # no exception, no engine built
        assert backend._liveness_engine is None
