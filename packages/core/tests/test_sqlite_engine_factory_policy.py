# Copyright (c) 2026 Tabith LLC.
# Use of this source code is governed by the Business Source License 1.1
# included in the LICENSE file at the root of this repository. As of the
# Change Date listed there, the work is available under MPL 2.0.
# SPDX-License-Identifier: BUSL-1.1

"""Characterization: what the PRODUCT engine factory actually yields for a sqlite URL.

Why this file exists. The #634 measurement found that the suite's sqlite engines are never built by
the product: a cell that wants a sqlite backend calls ``create_engine`` itself and then writes the
result into the private attribute — ``backend._engine = engine`` (`test_core.py:350-352` is the
pattern, repeated across the suite). That route skips ``Backend._create_engine`` entirely, so every
policy the shipped factory installs on a connection is untested on sqlite — and the factory's own
behavior is invisible, because nothing asks it.

What this file asserts is the ANSWER AS MEASURED at the commit it was written against
(``dev`` ``b73cef8``), not a hope. Measured: **the factory cannot produce a usable sqlite engine at
all.** ``_create_engine`` installs a ``"connect"`` listener that speaks PostgreSQL on every connection
(``SET statement_timeout = '300s'``), so the first connect of a sqlite URL raises
``sqlite3.OperationalError: near "SET": syntax error`` — which also means the question "does the
shipped policy enforce foreign keys on sqlite?" is never answered, because no sqlite connection ever
survives long enough to be asked.

So the cell is the second form the leg was offered: it proves the factory-boundary refusal. Its paired
negative is the injection route, which answers the same question with a silent ``0``.

EXPECT THIS FILE TO GO RED WHEN THE ROW LANDS. ``test_factory_sqlite_engine_refuses_at_the_first_connect``
and ``test_the_factory_never_answers_the_foreign_keys_question`` pin today's refusal; a fix that makes
the listeners dialect-aware turns both red, and the replacement is named here rather than left to
guesswork: assert ``PRAGMA foreign_keys`` reads ``1`` on a factory-built sqlite connection, and that the
orphan insert below is refused instead of accepted. ``test_the_injection_route_bypasses_the_factory…``
stays true either way and is the one that keeps the bypass honest.

No new dependency, no conftest change, no other test file edited, and no product behavior touched: this
file only ever asks the shipped code what it does.
"""

from __future__ import annotations

import inspect
from pathlib import Path

import pytest
from core.engine.backend import Backend, BackendConfig
from core.engine.encryption import KEK_SIZE
from core.iam.models import Base
from sqlalchemy import create_engine, event
from sqlalchemy.exc import IntegrityError, OperationalError
from sqlalchemy.orm import sessionmaker

#: The FK pair the negative half exercises: role_members.role_id -> roles.id, and
#: role_members.user_id -> users.user_id. Both are among the 16 model-level constraints.
FK_TABLES = ("users", "roles", "role_members")

#: The statement that cannot be satisfied under enforcement: a role_members row whose parents do not exist.
ORPHAN_INSERT = "INSERT INTO role_members (role_id, user_id) VALUES (999999, 'no-such-user')"

#: The shipped listener's own failure signature. It names the PG-only statement, which is the point:
#: the refusal comes from the product's connect policy, not from the URL, sqlite, or SQLAlchemy.
PG_STATEMENT_ON_SQLITE = 'near "SET": syntax error'


@pytest.fixture
def sqlite_url(tmp_path: Path) -> str:
    """A file-backed sqlite URL, so two engines can look at the same database."""
    return f"sqlite:///{tmp_path / 'factory-policy.db'}"


@pytest.fixture
def factory_calls(monkeypatch: pytest.MonkeyPatch) -> list[str]:
    """Record every time the product factory is actually asked to build an engine.

    Wraps rather than replaces, so a cell can distinguish "the factory ran" from "the attribute was
    assigned around it" — which is the whole difference between the two routes this file compares.
    """
    seen: list[str] = []
    original = Backend._create_engine

    def spy(self: Backend) -> None:
        seen.append("_create_engine")
        original(self)

    monkeypatch.setattr(Backend, "_create_engine", spy)
    return seen


def _backend(sqlite_url: str) -> Backend:
    return Backend(BackendConfig(database_url=sqlite_url, kek=b"k" * KEK_SIZE))


def _fk_schema(engine) -> None:
    """Create the FK pair's tables on this engine, exactly as an injecting test would."""
    Base.metadata.create_all(engine, tables=[t for t in Base.metadata.sorted_tables if t.name in FK_TABLES])


# --------------------------------------------------------------------- the factory route


def test_factory_builds_the_engine_object_but_cannot_connect_it(sqlite_url: str, factory_calls: list[str]) -> None:
    """Construction is fine; the FIRST connect is what the shipped policy refuses.

    Named explicitly because it matters: the failure is not a config refusal at ``BackendConfig`` and
    not a URL parse error — ``Backend.engine`` returns a real Engine object with the sqlite URL on it,
    and only then does the connect listener fire.
    """
    backend = _backend(sqlite_url)
    engine = backend.engine

    assert str(engine.url).startswith("sqlite:///"), f"the factory built {engine.url!r}, not a sqlite engine"
    assert factory_calls == ["_create_engine"], (
        "the factory was expected to build this engine and did not — if the attribute was assigned "
        "around it, this cell is measuring the injection route, which is the other half of this file"
    )

    with pytest.raises(OperationalError) as refused:
        with engine.connect():
            pass  # pragma: no cover - unreachable under the shipped policy
    assert PG_STATEMENT_ON_SQLITE in str(refused.value), (
        f"the refusal did not name the shipped PostgreSQL statement ({PG_STATEMENT_ON_SQLITE!r}); "
        f"measured instead: {str(refused.value).splitlines()[0][:160]!r} — the connect policy changed "
        "shape and this characterization needs re-reading, not editing to match"
    )
    backend.dispose()


def test_the_factory_never_answers_the_foreign_keys_question(sqlite_url: str) -> None:
    """Through the factory, ``PRAGMA foreign_keys`` is not answered - it is unreachable.

    This is the cell's real subject. sqlite makes FK enforcement a per-connection switch that defaults
    to OFF, so "is it on?" is only meaningful once a connection exists. Under the shipped policy no
    sqlite connection exists long enough to ask, which is why 16 declared constraints can sit
    unenforced on that route without any test noticing.
    """
    backend = _backend(sqlite_url)
    with pytest.raises(OperationalError, match=PG_STATEMENT_ON_SQLITE):
        with backend.engine.begin() as conn:
            conn.exec_driver_sql("PRAGMA foreign_keys")
    backend.dispose()


# ------------------------------------------------------------------- the injection route


def test_the_injection_route_bypasses_the_factory_and_yields_a_blind_engine(
    sqlite_url: str, factory_calls: list[str]
) -> None:
    """PAIRED NEGATIVE: the route the suite uses answers 0, and the factory is never called.

    Same URL, same database, two differences that this cell pins together: the shipped ``_create_engine``
    does not run at all (the spy never fires), and the resulting engine accepts the orphan row the
    declared constraint forbids. A test that injects an engine therefore cannot see any part of the
    product's connect policy - not the timeout, not the pruning, not foreign keys.
    """
    engine = create_engine(sqlite_url)
    _fk_schema(engine)

    backend = _backend(sqlite_url)
    backend._engine = engine  # the pattern under test, verbatim from test_core.py:351
    backend._session_factory = sessionmaker(bind=engine)

    assert factory_calls == [], (
        "the injected engine did not bypass the factory - _create_engine ran, so the shipped "
        "connect policy is in play and this cell's premise (injection hides it) needs re-reading"
    )

    with engine.connect() as conn:
        enforced = conn.exec_driver_sql("PRAGMA foreign_keys").scalar()
    assert enforced == 0, (
        f"the injected sqlite engine reported PRAGMA foreign_keys = {enforced!r}, not 0 - something "
        "turned enforcement on behind the injection route, so #634's premise moved and this cell is "
        "the place that has to say so"
    )

    with engine.begin() as conn:
        conn.exec_driver_sql(ORPHAN_INSERT)
    with engine.connect() as conn:
        orphans = conn.exec_driver_sql("SELECT count(*) FROM role_members").scalar()
    assert orphans == 1, (
        f"the blind engine was expected to ACCEPT the orphan row (it declared role_members.role_id -> "
        f"roles.id and enforced nothing); measured {orphans} - the refusal came from somewhere the "
        "injection route does not control"
    )

    # And the refusal this cell contrasts with is the factory's, not the data's: the identical row on
    # an enforcing connection is refused, proved by asking sqlite directly rather than by asserting a
    # behavior the injected engine never had.
    enforced_engine = create_engine(sqlite_url)

    @event.listens_for(enforced_engine, "connect")
    def _fk_on(dbapi_connection, connection_record):
        cursor = dbapi_connection.cursor()
        try:
            cursor.execute("PRAGMA foreign_keys = ON")
        finally:
            cursor.close()

    with pytest.raises(IntegrityError):
        with enforced_engine.begin() as conn:
            conn.exec_driver_sql(ORPHAN_INSERT)
    enforced_engine.dispose()
    engine.dispose()
    backend.dispose()


def test_the_plain_url_is_not_the_problem_the_listener_is(sqlite_url: str) -> None:
    """Same URL, same file: a plain engine connects, the factory-built one cannot.

    This is what makes cell 1 a statement about the SHIPPED POLICY rather than about sqlite, the URL,
    or SQLAlchemy. The only difference between the two engines is the ``"connect"`` listener the factory
    installs, so the refusal is attributable to that body - which the assertion below then names from
    the shipped source text, repo convention for this kind of pin
    (`test_session_audit_logger_467.py:343` reads ``inspect.getsource`` the same way).
    """
    plain = create_engine(sqlite_url)
    with plain.connect() as conn:  # the URL is fine; the policy is not
        assert conn.exec_driver_sql("select 1").scalar() == 1
    plain.dispose()

    source = inspect.getsource(Backend._create_engine)
    assert "SET statement_timeout" in source, (
        "the shipped engine body no longer carries the PostgreSQL statement this file names as the "
        f"refusal cause; measured source: {source[:200]!r} — re-read the policy before editing these "
        "cells, and expect the refusal cells to change form rather than be deleted"
    )
    assert "foreign_keys" not in source, (
        "the factory's sqlite path now mentions foreign_keys, so the #634 product-side claim this cell "
        "pins has moved - and the two refusal cells above must be flipped to enforcement assertions "
        "(PRAGMA foreign_keys == 1, orphan insert refused), not left pinning a refusal nobody performs"
    )
