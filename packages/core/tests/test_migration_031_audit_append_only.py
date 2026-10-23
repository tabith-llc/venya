# Copyright (c) 2026 Tabith LLC.
# Use of this source code is governed by the Business Source License 1.1
# included in the LICENSE file at the root of this repository. As of the
# Change Date listed there, the work is available under MPL 2.0.
# SPDX-License-Identifier: BUSL-1.1

"""Migration 031 — DB-enforced append-only audit trail (privilege interlock).

The 031 migration is PostgreSQL DCL, so it cannot execute against the SQLite
fixtures the rest of this suite uses. This interlock pins the grant STATEMENT
SURFACE instead — the same pattern as the generated-doc interlocks: any future
migration or edit that drops the role guard, removes a default-privileges line,
or reorders the REVOKE before the blanket grants red-gates the merge. The
BEHAVIORAL pin (UPDATE/DELETE physically refused for venya_audit, allowed for
the owner) is the post-deploy bench on venya-core-1; see
testing/security-guarantees-audit-2026-09-28.md (issue #66, G9).
"""

import importlib.util
import inspect
from pathlib import Path

_MIGRATION_PATH = Path(__file__).resolve().parents[1] / "alembic" / "versions" / "031_audit_append_only_grants.py"


def _load_migration():
    spec = importlib.util.spec_from_file_location("migration_031", _MIGRATION_PATH)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def test_migration_file_exists_and_is_chained():
    mod = _load_migration()
    assert mod.revision == "031"
    assert mod.down_revision == "030"


def test_role_guard_fails_loud_and_runs_first():
    mod = _load_migration()
    assert "RAISE EXCEPTION" in mod.ROLE_GUARD_SQL
    assert "venya_audit" in mod.ROLE_GUARD_SQL
    upgrade_src = inspect.getsource(mod.upgrade)
    assert upgrade_src.index("ROLE_GUARD_SQL") < upgrade_src.index(
        "GRANT_CONNECT_SQL"
    ), "role guard must run before any grant: a half-granted install is worse than an aborted one"


def test_runtime_role_is_passwordless_local_role():
    mod = _load_migration()
    assert mod.APP_ROLE == "venya_audit"
    assert mod.OWNER_ROLE == "venya"
    # REFERENCES is MANDATORY (FK-dense schema: INSERT into a referencing
    # table checks REFERENCES on the referenced table); TRUNCATE/CREATE must
    # never be granted to the runtime role.
    for stmt in (mod.GRANT_TABLES_SQL, mod.DEFAULT_PRIVS_TABLES_SQL):
        assert "REFERENCES" in stmt, "missing REFERENCES breaks ordinary FK INSERTs"
        for verb in ("TRUNCATE", "CREATE"):
            assert verb not in stmt, f"{verb} must not be granted to {mod.APP_ROLE}"


def test_default_privileges_cover_future_migrations():
    mod = _load_migration()
    for stmt in (mod.DEFAULT_PRIVS_TABLES_SQL, mod.DEFAULT_PRIVS_SEQUENCES_SQL):
        assert f"FOR ROLE {mod.OWNER_ROLE}" in stmt, (
            "default privileges must be set FOR the owner role — migrations run as the owner, "
            "so only owner-created objects are auto-granted"
        )
        assert f"TO {mod.APP_ROLE}" in stmt
    assert "ON TABLES" in mod.DEFAULT_PRIVS_TABLES_SQL
    assert "ON SEQUENCES" in mod.DEFAULT_PRIVS_SEQUENCES_SQL


def test_revoke_audit_runs_last_and_revokes_exactly_update_delete():
    mod = _load_migration()
    assert mod.REVOKE_AUDIT_SQL == "REVOKE UPDATE, DELETE ON audit_events FROM venya_audit"
    upgrade_src = inspect.getsource(mod.upgrade)
    revoke_idx = upgrade_src.index("REVOKE_AUDIT_SQL")
    for const in ("GRANT_TABLES_SQL", "GRANT_SEQUENCES_SQL", "DEFAULT_PRIVS_TABLES_SQL", "DEFAULT_PRIVS_SEQUENCES_SQL"):
        assert upgrade_src.index(const) < revoke_idx, (
            f"{const} must run BEFORE the audit REVOKE — the REVOKE narrows the blanket grant "
            "and only the final position wins"
        )
    # The REVOKE must not be broader (a REVOKE ALL here would break INSERT
    # logging) or narrower (INSERT/SELECT must survive).
    assert "REVOKE ALL" not in mod.REVOKE_AUDIT_SQL
    assert "INSERT" not in mod.REVOKE_AUDIT_SQL
    assert "SELECT" not in mod.REVOKE_AUDIT_SQL


def test_downgrade_reverses_everything_granted():
    mod = _load_migration()
    downgrade_src = inspect.getsource(mod.downgrade)
    for const in (
        "ALL TABLES IN SCHEMA public",
        "ALL SEQUENCES IN SCHEMA public",
        "USAGE ON SCHEMA public",
        "CONNECT ON DATABASE",
    ):
        assert const in downgrade_src
    # Default privileges are revoked too — otherwise a downgraded install
    # keeps silently granting future owner-created tables.
    assert downgrade_src.count("REVOKE") >= 6
    assert "ALTER DEFAULT PRIVILEGES" in downgrade_src
