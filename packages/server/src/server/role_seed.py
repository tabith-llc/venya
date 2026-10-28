# Copyright (c) 2026 Tabith LLC.
# Use of this source code is governed by the Business Source License 1.1
# included in the LICENSE file at the root of this repository. As of the
# Change Date listed there, the work is available under MPL 2.0.
# SPDX-License-Identifier: BUSL-1.1

"""Boot-time idempotent re-apply of the two product roles (#718).

THE INVARIANT THIS MODULE HOLDS: an initialised core holds the `admin` and `user` roles.
Before this leg the only writer of those two rows was `init` step 1 (`routes/init.py`
`init_core`), which lives inside a ROUTE, and `deployment_is_initialized()` (same file)
returns True on an initialised core — so the route is gated away on exactly the cores
whose `roles` table was emptied after init. A core in that state had no shipped path that
recreated the rows, and three doors fail three different ways without naming the cause:
`400 Role '<name>' not found` (`routes/admin.py`), `403 Admin role not found`
(`dependencies.py`), and the break-glass `503` (`routes/recovery.py`) — the last-resort
door refuses, and names the missing row as its reason.

Placement is the lifespan, the shape #597 (`relay_registry`) and #684 (`admin_registry`)
already use for a boot-time identity write: an installer-only seed would cover only cores
installed afterwards, while a boot re-apply repairs cores already on the network on their
next start, with no operator step and no reinstall.

★ WHY THE AUDIT IS WRITTEN HERE. `ROLE_CREATED` had exactly one emission site before this
leg, inside `POST /roles` (`routes/roles.py`), and `core/iam/role_manager.py` contains no
audit call at all — that module's comments state the convention that the SERVER layer
writes the event. Hoisting the get-or-create without the event would therefore reproduce,
at fleet scale, a silent identity write: rows that exist and appear in no trail. Each role
this function creates emits the SAME event with the SAME field table as the admin route. A
re-apply that creates nothing writes nothing — a `role_created` row on every boot would
make a seed indistinguishable from an operator action, which is the asymmetry ticket #718
§6 describes and refuses to paper over.

Actor convention (ruled Q5, `audit_lifecycle`): the boot path has no principal — no
session, no certificate, nothing a route could have consulted — so the actor is NULL, the
established no-principal shape (`login_failed`). The bootstrap's naming trail stays
`admin_initialized`, which carries the role names in its field table and keeps its exact
shape here.

Idempotency is the SELECT-then-INSERT the init route already shipped, never a bare INSERT
wrapped in `except IntegrityError`: `uq_roles_name` (migration 001) remains a fact about
the schema, not control flow, and a re-run after a partial failure lands the way a first
run does.

Failure posture: non-fatal at boot, wrapped by its caller the way #597 wraps its own. A
core that cannot re-apply its roles still serves, and every role-consuming door still
refuses loudly with its own named error; that is a better outage than a startup aborting on
a transient DB fault. The refusal is logged, never swallowed.
"""

from __future__ import annotations

import logging
from typing import Any

from core.iam.models import Role
from sqlalchemy.orm import Session

from server.audit_lifecycle import ROLE_CREATED, audit_lifecycle

logger = logging.getLogger("venya.server")

#: The roles the product ships with, in creation order, as (name, permissions,
#: description). These are the exact values `init_core` wrote before this leg: a fresh
#: install and a re-applied install must not differ, so this table is the single source
#: both paths read.
SEED_ROLES: tuple[tuple[str, str, str], ...] = (
    ("admin", "read-write", "System administrator — full access"),
    ("user", "read", "Regular user — read-only access"),
)

SEED_ROLE_NAMES: tuple[str, ...] = tuple(name for name, _perm, _desc in SEED_ROLES)


def ensure_seed_roles(db: Session) -> tuple[dict[str, Role], list[str]]:
    """Get-or-create the seed roles in the CALLER's transaction. Adds and flushes; never
    commits — the site owns the transaction, so a role row and its audit row ride one
    commit (ruled Q4 posture, `audit_lifecycle`).

    Returns (roles by name, names this call created). The init bootstrap needs the `admin`
    row's id for the membership it writes in the same transaction; the boot site needs the
    created-names list for its log line, and writes its audit rows from it.
    """
    roles: dict[str, Role] = {role.name: role for role in db.query(Role).filter(Role.name.in_(SEED_ROLE_NAMES)).all()}
    created: list[str] = []
    for name, permissions, description in SEED_ROLES:
        if name in roles:
            continue
        role = Role(name=name, permissions=permissions, description=description)
        db.add(role)
        roles[name] = role
        created.append(name)
    db.flush()  # assigns ids; the audit field table needs them
    for name in created:
        role = roles[name]
        audit_lifecycle(
            db,
            ROLE_CREATED,
            None,
            {"role_id": role.id, "role_name": role.name, "permissions": role.permissions},
        )
    return roles, created


def ingest_seed_roles(backend: Any) -> list[str]:
    """Re-apply the seed roles on the backend's own session, at core startup.

    Opens its own session and closes it, because a boot site has no Request and no route
    dependency to reach — the `relay_registry.ingest_relay_credential` shape. Returns the
    names it created (empty when the table was already complete).

    A raise here is logged and swallowed on purpose (failure posture above): the seed
    repairs a state a core should never have reached, and the alternative — letting a
    transient DB fault abort startup — trades a loud, self-healing refusal at three doors
    for a core that does not boot at all. The swallow is not silent: it logs at WARNING
    with the traceback and names the doors that will refuse.
    """
    db = None
    try:
        db = backend.get_session()
        _roles, created = ensure_seed_roles(db)
        db.commit()
    except Exception:
        logger.warning(
            "Role re-apply at startup raised — this core may be missing the `admin`/`user` "
            "roles, which makes role grants, the admin gate, and break-glass recovery refuse "
            "until the next successful boot (#718).",
            exc_info=True,
        )
        if db is not None:
            db.rollback()
        return []
    finally:
        if db is not None:
            db.close()
    if created:
        logger.info("Re-applied missing product roles at startup: %s", ", ".join(created))
    return created
