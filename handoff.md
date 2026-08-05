# Venya Build Handoff

**Date:** 2025-08-04
**Branch:** init
**Last commit:** `60a963b` fix(server): wire RBAC middleware to RoleManager DB queries

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

#### Server Package
- **Secrets routes fully implemented** (`routes/secrets.py`):
  - `POST /secrets` — create with vault.put(), encryption, role scoping
  - `GET /secrets/{key}` — retrieve with masking (human) or plaintext (executor)
  - `GET /secrets/{key}/executor` — sentinel-wrapped plaintext + detection hashes
  - `GET /secrets` — list with prefix filtering and role-based access
  - `DELETE /secrets/{key}` — delete with ownership check
  - `POST /sessions/{id}/secrets/revoke` — credential revocation with audit logging
- Vault wired into app lifespan (`app.state.vault`)
- Fixed `dependencies.py` init_db for PostgreSQL (reads `VENYA_DB_URL` env var)
- Fixed import path bug in revoke endpoint (`..iam.models` → `venya.iam.models`)
- 30/30 server tests pass (12 RBAC + 18 secrets)

### Build Status
- `./build.sh` — builds executor package (Rust + Python)
- `uv sync` — installs all package dependencies into `.venv` (uses `uv` workspace)
- `uv run pytest` — runs all tests across workspace
- `docker run -d --name venya-postgres ...` — starts PostgreSQL container
- `VENYA_DB_URL=... alembic upgrade head` — runs migrations

### Remaining Issues

- Server routes: ~32 stub handlers returning mock data
- `routes/roles.py`: 7 stubs → ✅ fully implemented (20 tests pass) — PUT update added
- `routes/admin.py`: 15 stubs → ✅ fully implemented (30 tests pass)
- `routes/enrollment.py`: 3 stubs — enrollment flow
- `routes/auth.py`: 1 stub — WebAuthn credential persistence
- `routes/recovery.py`: 1 stub — admin recovery
- `routes/audit.py`: 1 stub — audit log queries
- `routes/health.py`: 1 stub — DB connectivity check
- `routes/filter.py`: 1 stub — session secret filtering
- `middleware/rbac.py`: ✅ fixed (wired to `RoleManager`; also fixed broken `from ..iam` imports in auth.py)
- `routes/secrets.py`: ✅ fully implemented with vault integration

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
5. Executor daemon integration testing
6. CLI integration with server API

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
- `packages/vault/src/venya/iam/models.py` — ORM models (14 tables)
- `packages/vault/alembic/` — Migrations
- `packages/vault/tests/test_vault.py` — 12 unit tests

### Server
- `packages/server/src/venya_server/routes/` — API endpoints
- `packages/server/src/venya_server/middleware/` — Auth, RBAC, rate limiting
- `packages/server/src/venya_server/app.py` — FastAPI app
- `packages/server/tests/test_rbac.py` — 12 RBAC middleware tests

### Docs
- `venya-docs/code/plan.md` — Project plan
