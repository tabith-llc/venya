# Copyright (c) 2026 Tabith LLC.
# Use of this source code is governed by the Business Source License 1.1
# included in the LICENSE file at the root of this repository. As of the
# Change Date listed there, the work is available under MPL 2.0.
# SPDX-License-Identifier: BUSL-1.1

"""#625 — the per-user ``session_timeout`` WRITE PATH is dead; the COLUMN stands, unread.

Shape (a) DELETE as ruled: ``--timeout`` (CLI), the request field, the ``user.session_timeout``
assignment and its ``changed_fields`` entry are gone. The ``users.session_timeout`` column is
deliberately RETAINED — ``001_initial_schema.py`` declares it ``NOT NULL`` with
``server_default="900"``, so it cannot express "unset" and an Alembic drop is the wrong cost for
dead text inside the beta window. AC1's "real or gone" is therefore answered as **the write path
gone, the column retained-as-unread**, and the cells below pin both halves of that sentence.

Harness: a REAL SQLite session and the REAL admin router (shape copied from
``test_admin_role_lockout_guards_443.py``). Every claim here is about what lands in the database
and in ``audit_events``; a MagicMock can neither answer a roster question nor refuse a key.

Cells:
  1. the dead key is refused 422 by ``extra=\"forbid\"`` (#357), never a silent no-op;
  2. the refusal writes no column and audits nothing;
  3. PAIRED: a live field still writes, and its audit row names only that field (AC3);
  4. the column is still there, NOT NULL, default 900, and no migration drops it;
  5. a source sweep: no shipped code assigns to a user row's ``session_timeout`` any more, and
     the one read left is the user-list display echo;
  6. AC2 paired negative — the GLOBAL session plane is untouched and still governs lifetime;
  7. AC5 — the status gate that reads the ``User`` row in ``create_session`` stands unchanged.
"""

import inspect
import json
import re
from pathlib import Path

import pytest
from core.iam.models import AuditEvent, Base, User
from core.iam.session_manager import SessionManager
from fastapi import FastAPI
from server.dependencies import get_current_user, get_db, require_admin
from server.routes import admin as admin_routes
from sqlalchemy import create_engine
from sqlalchemy import inspect as sa_inspect
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool
from starlette.testclient import TestClient

_SERVER_PKG = Path(__file__).resolve().parents[1]
_REPO_ROOT = _SERVER_PKG.parents[1]
_PACKAGES = _REPO_ROOT / "packages"

# `user.` / `u.` / `row.` — the user-row spellings in this codebase. Config objects are read as
# `config.`/`sc.`/`session.`/`self.config.` and are NOT what this row is about, so the sweep
# names the row, not the attribute.
_ROW_WRITE = re.compile(r"\b(?:user|row|u)\.session_timeout\s*=(?!=)")
_ROW_READ = re.compile(r"\b(?:user|row|u)\.session_timeout\b")
_DROP_COLUMN = re.compile(r"drop_column\s*\([^)]*session_timeout", re.DOTALL)

# The one read of the row attribute that remains, kept on purpose: the column still exists and
# `admin list --json` passes the payload through verbatim, so the API face did not change.
_DISPLAY_ECHO = '"session_timeout": u.session_timeout,'


@pytest.fixture()
def session():
    engine = create_engine(
        "sqlite://",
        poolclass=StaticPool,
        connect_args={"check_same_thread": False},
    )
    Base.metadata.create_all(engine)
    factory = sessionmaker(bind=engine)

    s = factory()
    s.add(User(user_id="admin1", status="active", display_name="Ops"))
    s.add(User(user_id="plainjane", status="active"))
    s.commit()
    yield s
    s.close()
    engine.dispose()


def _client(session, caller_id="admin1"):
    app = FastAPI()
    app.include_router(admin_routes.router, prefix="/api/v1")
    auth = {"user_id": caller_id}
    app.dependency_overrides[get_current_user] = lambda: auth
    app.dependency_overrides[require_admin] = lambda: auth
    app.dependency_overrides[get_db] = lambda: session
    return TestClient(app, raise_server_exceptions=False)


def _user(session, user_id="plainjane"):
    session.expire_all()
    return session.query(User).filter(User.user_id == user_id).one()


def _updated_rows(session):
    return session.query(AuditEvent).filter(AuditEvent.event_type == "user_updated").all()


def _fields(row):
    """AuditEvent.fields round-trips as JSON text off a real DB read."""
    return json.loads(row.fields) if isinstance(row.fields, str) else row.fields


def _source_files():
    for pkg in sorted(_PACKAGES.glob("*/src")):
        yield from sorted(pkg.rglob("*.py"))


def _matches(pattern):
    """(path, line-number, text) for every non-comment source line matching `pattern`."""
    hits = []
    for path in _source_files():
        text = path.read_text(encoding="utf-8")
        for n, line in enumerate(text.splitlines(), start=1):
            stripped = line.strip()
            if stripped.startswith("#"):
                continue
            if pattern.search(line):
                hits.append((path, n, stripped))
    return hits


class TestDeadKeyIsRefused:
    def test_put_with_session_timeout_is_a_422_not_a_silent_no_op(self, session):
        client = _client(session)

        resp = client.put("/api/v1/admin/users/plainjane", json={"session_timeout": 1800})

        assert resp.status_code == 422, resp.text
        assert "session_timeout" in resp.text, "the refusal must name the key it rejects"

    def test_refusal_writes_no_column_and_lands_no_audit_row(self, session):
        client = _client(session)

        client.put("/api/v1/admin/users/plainjane", json={"session_timeout": 1800})

        assert _user(session).session_timeout == 900, "the column default, untouched"
        assert _updated_rows(session) == [], "a refused write must not audit a change"


class TestLiveFieldStillWorks:
    """AC3 paired negative: the route is not disabled, only the dead key is gone."""

    def test_display_name_write_succeeds_and_the_audit_names_only_it(self, session):
        client = _client(session)

        resp = client.put("/api/v1/admin/users/plainjane", json={"display_name": "New Name"})

        assert resp.status_code == 200, resp.text
        assert resp.json()["configured"] is True
        assert _user(session).display_name == "New Name"
        rows = _updated_rows(session)
        assert len(rows) == 1
        changed = _fields(rows[0])["changed_fields"]
        assert changed == ["display_name"]
        assert "session_timeout" not in changed, "the audit surface stops lying (AC3)"

    def test_empty_body_is_still_accepted_by_the_route(self, session):
        """Deliberate boundary: the SERVER answers `{}` with a no-op success — the fix for that
        face is the CLI's local refusal (`test_cli_configure_user_625.py`), and this cell keeps
        the two halves from being confused for one another. What changed under #625 is only that
        `session_timeout` can no longer be part of a body at all."""
        client = _client(session)

        resp = client.put("/api/v1/admin/users/plainjane", json={})

        assert resp.status_code == 200, resp.text
        rows = _updated_rows(session)
        assert len(rows) == 1
        assert _fields(rows[0])["changed_fields"] == []


class TestColumnIsRetained:
    """Ruling part 2: no Alembic drop in a beta window — the column stays, and unread."""

    def test_users_table_still_carries_the_column(self, session):
        columns = {c["name"]: c for c in sa_inspect(session.get_bind()).get_columns("users")}

        assert "session_timeout" in columns, "the ruling keeps the column; a drop is not in scope"

    def test_the_shipped_migration_still_declares_it_not_null_default_900(self):
        """Why the column cannot express "unset", which is what the ruling priced against.

        A fresh SQLite table built by ``create_all`` follows the ORM model (nullable, Python-side
        default), so the nullability claim is read from the migration that ships to real installs
        — not from this fixture's DDL. The model/migration nullability difference itself is a
        separate row (the clerk-booked nullability-drift item), not adjudicated here.
        """
        migration = (_PACKAGES / "core" / "alembic" / "versions" / "001_initial_schema.py").read_text(encoding="utf-8")

        assert 'sa.Column("session_timeout", sa.Integer(), nullable=False, server_default="900")' in migration

    def test_a_row_created_without_the_value_still_reads_900(self, session):
        session.add(User(user_id="fresh", status="active"))
        session.commit()

        assert _user(session, "fresh").session_timeout == 900

    def test_no_migration_drops_the_column(self):
        versions = sorted((_REPO_ROOT / "packages" / "core" / "alembic" / "versions").glob("*.py"))
        assert versions, f"no alembic revisions under {_REPO_ROOT}"
        for path in versions:
            assert not _DROP_COLUMN.search(
                path.read_text(encoding="utf-8")
            ), f"{path.name} drops users.session_timeout — #625 ruled the column retained"


class TestSourceSweep:
    """The sweep `admin.py`'s comment points at: nothing writes the row field, and the only
    read of it left is the user-list display echo."""

    def test_positive_control_the_search_can_return_hits(self):
        """An empty result is only evidence once the method is shown to work: the display echo
        is a row READ, so a read sweep over the same tree must find it."""
        reads = _matches(_ROW_READ)
        assert reads, "read sweep found nothing at all — the sweep itself is broken"
        assert any(_DISPLAY_ECHO in text for _p, _n, text in reads), reads

    def test_no_shipped_code_writes_a_user_row_session_timeout(self):
        writes = _matches(_ROW_WRITE)
        assert writes == [], f"#625 dead writes came back: {[(str(p), n, t) for p, n, t in writes]}"

    def test_the_only_row_read_left_is_the_display_echo(self):
        reads = [(p, n, t) for p, n, t in _matches(_ROW_READ) if ".session_timeout" in t]
        assert [t for _p, _n, t in reads] == [_DISPLAY_ECHO], reads

    def test_the_cli_no_longer_reads_it_for_a_table_column(self):
        cli_commands = (_PACKAGES / "cli" / "src" / "venya_cli" / "commands.py").read_text(encoding="utf-8")
        assert 'u.get("session_timeout"' not in cli_commands
        assert '"SESSION_TIMEOUT"' not in cli_commands, "the admin list header must be gone"


class TestGlobalSessionPlaneUntouched:
    """AC2: the knob died, the mechanism it never reached stands and still binds."""

    def test_core_expiry_still_comes_from_the_global_config(self):
        src = (_PACKAGES / "core" / "src" / "core" / "iam" / "session_manager.py").read_text(encoding="utf-8")
        assert "expires_at = now + self.config.session_timeout" in src
        assert "session_timeout: timedelta = field(default_factory=lambda: timedelta(minutes=15))" in src
        assert "user.session_timeout" not in src

    def test_server_config_still_feeds_the_core_dataclass(self):
        src = (_PACKAGES / "server" / "src" / "server" / "session_gate_config.py").read_text(encoding="utf-8")
        assert "session_timeout=timedelta(seconds=session.session_timeout)" in src

    def test_the_admin_route_still_echoes_the_column_in_the_user_list(self):
        """The payload face did not change: an operator reading `admin list --json` still sees
        the stored value, and this row's ruling is that the value is unread, not unseen."""
        src = inspect.getsource(admin_routes.admin_list_users)
        assert _DISPLAY_ECHO in src

    def test_status_gate_that_loads_the_row_is_unchanged(self):
        """AC5's premise: `create_session` holds the User row and consults it for the status
        gate only — the same statement that used to be one attribute away from the dead write."""
        src = inspect.getsource(SessionManager.create_session)
        assert "user = self.db.query(User).filter(User.user_id == user_id).first()" in src
        assert "if not is_user_active(user):" in src
        assert "raise UserNotActiveError(" in src
