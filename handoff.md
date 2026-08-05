# Venya Build Handoff

**Date:** 2025-08-04
**Branch:** init
**Last commit:** `725f83a` test(server): add executor daemon integration tests + fix empty secret filter bug

---

## What Was Being Done

Migrating Stage 1 output filter from C extension to Rust, then switching vault from SQLCipher SQLite to PostgreSQL.

## Current State

### Completed

#### Executor Package
- Rust source in `packages/executor/src/rust/` (filter.rs, hashes.rs, lib.rs)
- Build backend: setuptools + setuptools-rust (not maturin)
- `build.sh` automates cargo build + `pip install -e`
- 82/82 Python tests pass (37 filter + 25 daemon + 20 executor)
- 79/79 Rust tests pass

#### Vault Package
- Switched from SQLCipher SQLite to PostgreSQL via `psycopg2`
- `BackendConfig` uses `database_url` instead of `database_path`
- `vault.py` methods fully wired: get/put/delete/list with RBAC
- Alembic migrations updated for PostgreSQL
- 12 vault unit tests pass
- PostgreSQL integration tests pass (Docker container)
- `Backend.get_vault()` added for easy vault instantiation
- 15 ORM models (added `WebAuthnCredential` table)

#### Server Package — All Routes Implemented (119 tests)

**Secrets routes** (`routes/secrets.py`):
- `POST /secrets` — create with vault.put(), encryption, role scoping
- `GET /secrets/{key}` — retrieve with masking (human) or plaintext (executor)
- `GET /secrets/{key}/executor` — sentinel-wrapped plaintext + detection hashes
- `GET /secrets` — list with prefix filtering and role-based access
- `DELETE /secrets/{key}` — delete with ownership check
- `POST /sessions/{id}/secrets/revoke` — credential revocation with audit logging

**Roles routes** (`routes/roles.py`):
- `POST /roles` — create role via RoleManager
- `GET /roles` — list roles with member counts
- `GET /roles/{id}` — get role details
- `PUT /roles/{id}` — update role (name, permissions, description)
- `DELETE /roles/{id}` — delete role
- `GET /roles/{id}/members` — list role members
- `POST /roles/{id}/members` — add user to role
- `DELETE /roles/{id}/members/{user_id}` — remove user from role

**Admin routes** (`routes/admin.py`):
- `POST /admin/enroll` — create enrollment token
- `DELETE /admin/users/{user_id}` — remove user (cascades memberships/sessions)
- `GET /admin/users` — list all users
- `PUT /admin/users/{user_id}` — configure user settings
- `GET /admin/key-versions` — list key versions
- `POST /admin/key-versions/rotate` — start key rotation (creates job + per-secret tracking)
- `POST /admin/key-versions/rollback` — rollback rotation job
- `POST /admin/command-policy` — set executor command policy
- `POST /admin/recovery` — break-glass recovery (create new admin)
- `POST /admin/command-policy/allowed` — add command to allowlist
- `POST /admin/key-versions/{id}/deactivate` — deactivate key version
- `POST /admin/key-versions/{id}/revoke` — permanently remove key version
- `GET /admin/key-rotation/status` — show active rotation jobs
- `POST /admin/key-rotation/{job_id}/rollback` — rollback rotation job
- `POST /admin/executors/{executor_id}/revoke` — revoke executor certificate

**Enrollment routes** (`routes/enrollment.py`):
- `POST /enrollment/tokens` — create enrollment token via EnrollmentManager
- `GET /enrollment/tokens` — list active enrollment tokens
- `POST /enrollment/confirm` — consume token and create user

**Auth routes** (`routes/auth.py`):
- `POST /auth/registration/start` — start WebAuthn registration
- `POST /auth/registration/complete` — complete registration, store credential in DB
- `POST /auth/login/start` — start WebAuthn authentication
- `POST /auth/login/complete` — verify assertion, create session, issue token
- `POST /auth/refresh` — refresh access token

**Recovery routes** (`routes/recovery.py`):
- `POST /recovery` — break-glass recovery (short CLI path)

**Audit routes** (`routes/audit.py`):
- `GET /audit` — query audit log with filters (user, date range, days, hours, pagination)

**Health routes** (`routes/health.py`):
- `GET /health` — liveness probe
- `GET /ready` — readiness probe (checks DB connectivity)

**Filter routes** (`routes/filter.py`):
- `POST /sessions/{session_id}/filter` — filter secrets from executor output using hash matching
- Bug fix: empty secret values now skipped to prevent false positive masking

### Build Status
- `./build.sh` — builds executor package (Rust + Python)
- `uv sync` — installs all package dependencies into `.venv` (uses `uv` workspace)
- `uv run pytest` — runs all tests across workspace
- `docker run -d --name venya-postgres ...` — starts PostgreSQL container
- `VENYA_DB_URL=... alembic upgrade head` — runs migrations

### Remaining Issues

All server route stubs have been implemented. No remaining stub handlers.

**Bug fix (2025-08-04):** Empty secret values in `filter_output()` caused every output byte to be masked (since `b"" in output` is always `True`). Fixed by skipping empty secret values.

## Build Commands

> **All paths must stay within the project directory.** Do NOT reference `/home/dust/` or any external paths.

### Dependency Management
```bash
uv sync          # install all workspace dependencies into .venv
uv run pytest    # run tests across workspace
```

The project uses `uv` as a workspace package manager. Workspace members are in `packages/*`.
`uv.lock` locks all versions. Do NOT use `pip install -e` directly — always use `uv sync`.

### Build Executor
```bash
./build.sh
```

### Start PostgreSQL
```bash
docker run -d --name venya-postgres \
  -e POSTGRES_PASSWORD=venya \
  -e POSTGRES_USER=venya \
  -e POSTGRES_DB=venya \
  -p 5432:5432 \
  postgres:16
```

### Run Migrations
```bash
cd packages/vault
VENYA_DB_URL=postgresql://venya:venya@localhost:5432/venya \
  ../../.venv/bin/python -m alembic -c alembic.ini upgrade head
```

## Next Steps

1. ~~Server package TODOs~~ — RBAC middleware fixed (12 tests added); auth.py imports also fixed
2. ~~Secrets routes~~ — ✅ fully implemented with vault integration (18 tests)
3. ~~Roles routes~~ — ✅ fully implemented (20 tests pass) — PUT update added
4. ~~Admin routes~~ — ✅ fully implemented (30 tests pass) — enrollment, key rotation, user management
5. ~~Enrollment routes~~ — ✅ fully implemented (7 tests pass)
6. ~~Auth routes~~ — ✅ fully implemented (12 tests pass) — WebAuthn credential persistence added
7. ~~Recovery routes~~ — ✅ fully implemented (4 tests pass)
8. ~~Audit routes~~ — ✅ fully implemented (8 tests pass)
9. ~~Health routes~~ — ✅ fully implemented (4 tests pass) — DB connectivity check
10. ~~Filter routes~~ — ✅ fully implemented (4 tests pass) — session secret filtering
11. ~~Executor daemon integration testing~~ — ✅ fully implemented (25 integration tests pass); also fixed empty secret filter bug
12. CLI integration with server API

## Key Files

### Executor
- `packages/executor/Cargo.toml` — Rust build config
- `packages/executor/pyproject.toml` — setuptools + setuptools-rust
- `packages/executor/src/rust/lib.rs` — PyO3 bindings
- `packages/executor/src/rust/filter.rs` — Core filter logic (1297 lines, 80+ tests)
- `packages/executor/src/rust/hashes.rs` — SHA-256, FNV-1a, detection hashes
- `packages/executor/src/venya_executor/filter.py` — Python wrapper
- `packages/executor/tests/test_filter.py` — 37 Python tests

### Vault
- `packages/vault/src/venya/vault/vault.py` — Vault facade (get/put/delete/list)
- `packages/vault/src/venya/vault/backend.py` — PostgreSQL backend
- `packages/vault/src/venya/vault/encryption.py` — KEK/DEK encryption
- `packages/vault/src/venya/iam/models.py` — ORM models (15 tables)
- `packages/vault/src/venya/iam/role_manager.py` — RoleManager CRUD + membership
- `packages/vault/src/venya/iam/enrollment_manager.py` — Enrollment token management
- `packages/vault/src/venya/iam/session_manager.py` — Session + access token management
- `packages/vault/alembic/` — Migrations
- `packages/vault/tests/test_vault.py` — 12 unit tests

### Server
- `packages/server/src/venya_server/routes/` — All API endpoints (11 routes, 40+ endpoints)
- `packages/server/src/venya_server/middleware/` — Auth, RBAC, rate limiting
- `packages/server/src/venya_server/dependencies.py` — FastAPI dependency injection
- `packages/server/src/venya_server/app.py` — FastAPI app
- `packages/server/src/venya_server/ca.py` — CA manager for executor certificates
- `packages/server/src/venya_server/fido2/manager.py` — FIDO2/WebAuthn manager
- `packages/server/tests/` — 144 tests across 8 test files (including 25 executor integration tests)

### Docs
- `venya-docs/code/plan.md` — Project plan
