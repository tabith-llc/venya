# Copyright (c) 2026 Tabith LLC.
# Use of this source code is governed by the Business Source License 1.1
# included in the LICENSE file at the root of this repository. As of the
# Change Date listed there, the work is available under MPL 2.0.
# SPDX-License-Identifier: BUSL-1.1

"""#339: the enrollment-token cap takes a per-user advisory lock first.

Statement-construction cells (SQLite cannot run pg_advisory_xact_lock — these
assert the emitted SQL and bind params, matching the repo precedent of pinning
PG-specific SQL by construction, e.g. test_secret_metadata_type.py dialect
compiles). The cap check itself is exercised end-to-end server-side elsewhere;
here we only pin the lock's presence, text, keying, and ordering.
"""

from core.iam.enrollment_manager import EnrollmentManager


class _FakeQuery:
    def __init__(self, recorder, model):
        self._recorder = recorder
        self._model = model

    def filter(self, *args, **kwargs):
        return self

    def with_for_update(self):
        return self

    def all(self):
        self._recorder.append(("cap_query", self._model))
        return []


class _FakeDb:
    def __init__(self):
        self.calls = []

    def execute(self, statement, params=None):
        self.calls.append(("execute", str(statement), params))

    def query(self, model):
        self.calls.append(("query", model))
        return _FakeQuery(self.calls, model)

    def add(self, obj):
        self.calls.append(("add", obj))

    def flush(self):
        self.calls.append(("flush",))


def _manager():
    db = _FakeDb()
    return EnrollmentManager(db), db


def test_advisory_lock_statement_emitted_before_cap_query():
    manager, db = _manager()
    _record, plaintext = manager.create_enrollment_token("alice")
    assert plaintext
    kinds = [c[0] for c in db.calls]
    assert "execute" in kinds, f"no statement executed; calls={kinds}"
    exec_idx = kinds.index("execute")
    query_idx = kinds.index("query")
    assert exec_idx < query_idx, "advisory lock must precede the active-token cap query"
    stmt_text = db.calls[exec_idx][1]
    assert "pg_advisory_xact_lock" in stmt_text
    assert "hashtext" in stmt_text
    assert ":user_id" in stmt_text, "user_id must travel as a bind param, not interpolated"
    assert db.calls[exec_idx][2] == {"user_id": "alice"}
    assert "alice" not in stmt_text.split(":user_id")[0], "no string-interpolated user_id"


def test_lock_keyed_per_user_not_constant():
    manager, db = _manager()
    manager.create_enrollment_token("alice")
    manager.create_enrollment_token("bob")
    binds = [c[2] for c in db.calls if c[0] == "execute"]
    assert binds[0] == {"user_id": "alice"}
    assert binds[1] == {"user_id": "bob"}
    assert binds[0] != binds[1]


def test_full_create_mint_on_real_sqlite_session(tmp_path):
    """#366 regression cell — a REAL user-create + token-mint through the
    full path on the SQLite harness. The statement pins above never execute
    SQL (a fake db records it), so a runtime dialect landmine —
    pg_advisory_xact_lock/hashtext are PostgreSQL-only functions — slipped
    past them and 500'd every real SQLite mint. Guarded, this path must
    mint end to end; unguarded it dies with
    'no such function: hashtext' (RED at the #339 tip)."""
    import hashlib

    from core.iam.models import Base, EnrollmentToken, User
    from sqlalchemy import create_engine
    from sqlalchemy.orm import sessionmaker

    engine = create_engine(f"sqlite:///{tmp_path / 'mint.db'}")
    Base.metadata.create_all(engine)
    with sessionmaker(bind=engine)() as s:
        s.add(User(user_id="bob-1", status="pending_enrollment"))
        s.commit()
        token, plaintext = EnrollmentManager(s).create_enrollment_token("bob-1")
        s.commit()
        assert token.user_id == "bob-1"
        stored = s.query(EnrollmentToken).filter_by(user_id="bob-1").one()
        assert stored.state == "created"
        assert stored.token_hash == hashlib.sha256(plaintext.encode("utf-8")).hexdigest()
