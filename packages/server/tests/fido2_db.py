# Copyright (c) 2026 Tabith LLC.
# Use of this source code is governed by the Business Source License 1.1
# included in the LICENSE file at the root of this repository. As of the
# Change Date listed there, the work is available under MPL 2.0.
# SPDX-License-Identifier: BUSL-1.1

"""Shared SQLite wiring for DB-backed FIDO2 challenge tests (#534).

A pending ceremony challenge moved from the per-process Fido2Store dict to
the fido2_challenges table, so manager-level cells need a real store.
These helpers give a Fido2Manager a session_factory over a SQLite file
WITHOUT a backend: the credential-side active-state gate (and the
sign_count persist) stays skipped exactly as it was for the old
backend-less managers, so credential cells keep their meaning and only the
challenge plumbing changes.
"""

import json

from core.iam.models import Base, Fido2Challenge
from server.fido2.manager import Fido2Manager, _decode_payload
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker


def make_engine(db_path):
    engine = create_engine(f"sqlite:///{db_path}")
    Base.metadata.create_all(engine)
    return engine


def manager_with_db(tmp_path, filename="fido2.db", **manager_kwargs):
    """(manager, session_factory) over a fresh SQLite file.

    manager_kwargs pass through to Fido2Manager (rp_id, user_verification,
    ...). Pass ``backend=`` here only for cells that WANT the credential-side
    DB gate live — see test_fido2_manager
    TestFinishAuthenticationActiveGate.
    """
    engine = make_engine(tmp_path / filename)
    session_factory = sessionmaker(bind=engine)
    manager = Fido2Manager(session_factory=session_factory, **manager_kwargs)
    return manager, session_factory


def challenge_rows(session_factory):
    """Every challenge row as (challenge_id, state) — the DB stand-in for
    iterating the old dict, used by the TTL cells and the gone-pin."""
    db = session_factory()
    try:
        return sorted((r.challenge_id, r.state) for r in db.query(Fido2Challenge).all())
    finally:
        db.close()


def live_challenge_ids(session_factory):
    """Ids still in play (the sweep prunes expired rows, so a missing row is
    the honest reading of 'the store no longer holds it')."""
    return [cid for cid, state in challenge_rows(session_factory) if state == "created"]


def peek_challenge_data(session_factory, challenge_id):
    """Read a pending challenge's ceremony dict WITHOUT consuming it.

    The store itself is consume-only by design (single-consume claim, AC3),
    so a cell that has to build a real client response — which needs the
    raw_challenge before finish_registration pops the row — goes to the
    table directly. This is the honest stand-in for the old
    ``store._challenges[cid].data`` pokes.
    """
    db = session_factory()
    try:
        row = db.query(Fido2Challenge).filter(Fido2Challenge.challenge_id == challenge_id).one()
        return _decode_payload(json.loads(row.payload))
    finally:
        db.close()
