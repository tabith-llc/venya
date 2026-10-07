# Copyright (c) 2026 Tabith LLC.
# Use of this source code is governed by the Business Source License 1.1
# included in the LICENSE file at the root of this repository. As of the
# Change Date listed there, the work is available under MPL 2.0.
# SPDX-License-Identifier: BUSL-1.1

"""The user-ID grammar, defined in ONE place (#517).

Promoted out of ``routes/admin.py`` (where it was ``USER_ID_PATTERN``) so every
surface that MINTS a ``users.user_id`` validates against the same allowlist the
surface that ADDRESSES one already requires. Before that promotion the break-glass
route could hand back an admin whose ID the admin routes answer 422 on — an
uppercase, underscore, edge-punctuation, or over-length ID passes an unpatterned
``str`` field here while ``AdminEnrollRequest``/``AdminRemoveRequest`` reject the
same string, and over-length additionally runs into the ``String(64)`` column.

Grammar, and why each clause is there:

* ``^[a-z0-9]`` / ``[a-z0-9]$`` — starts and ends alphanumeric, so no leading or
  trailing hyphen survives into a name the admin surface has to quote in a path.
* ``[a-z0-9-]{0,62}`` — lowercase letters, digits and interior hyphens only, and
  with the two anchor characters the whole ID is 2-64 characters, which is exactly
  the ``users.user_id`` column width.
* The same expression is the ``chk_user_id_format`` CHECK that alembic migration
  ``009_executor_id_constraints`` puts on ``users.user_id`` (executor IDs and human
  IDs share the grammar by design — a machine identity that logs in as a user is a
  user row), and ``server.utils.executor_id`` is its executor-side twin. Route-layer
  reject means a 422 BEFORE any write, never a value-too-long or CHECK violation
  dying inside the transaction (the #289/#334 lineage).

New writers of ``users.user_id`` import ``USER_ID_PATTERN`` from here rather than
pasting the expression again.
"""

USER_ID_PATTERN = r"^[a-z0-9][a-z0-9-]{0,62}[a-z0-9]$"

USER_ID_MIN_LENGTH = 2
USER_ID_MAX_LENGTH = 64
