# Venya Plan

## Status: In Progress

---

## Completed

### Executor Package
- Migrated Stage 1 output filter from C extension to Rust (`venya_filter`)
- Switched build backend from maturin to setuptools + setuptools-rust
- `pip install -e` works for mixed Rust+Python packages
- `build.sh` automates cargo build + package install
- 82/82 Python tests pass, 79/79 Rust tests pass

### Vault Package
- SQLAlchemy ORM models defined (14 tables)
- SQLCipher encryption layer (KEK/DEK model, ChaCha20-Poly1305)
- Vault facade with RBAC and rate limiting scaffolding
- Alembic migration setup

---

## In Progress

### Vault: Switch to PostgreSQL

**Status: Complete**

Vault facade methods wired to PostgreSQL backend:
- `get()` — retrieve secrets with RBAC, masked/plaintext based on caller
- `put()` — store secrets with role scoping
- `delete()` — remove secrets with ownership check
- `list()` — query secrets with prefix/role filtering
- 12 unit tests passing

**Tasks:**
1. ~~Create PostgreSQL migration (replaces SQLCipher SQLite)~~
2. ~~Update `Backend` to use PostgreSQL via `psycopg2`~~
3. ~~Wire `vault.py` methods to use the new backend~~
4. ~~Update `BackendConfig` for PostgreSQL connection string~~
5. ~~Add `psycopg2-binary` to vault dependencies~~
6. ~~Write integration tests against PostgreSQL~~
7. ~~Update `build.sh` to handle PostgreSQL setup~~
8. ~~Vault facade methods wired (get/put/delete/list)~~

**Migration approach:**
- Keep the same ORM models (they're DB-agnostic)
- Replace `sqlcipher3` with `psycopg2` in `backend.py`
- Move key derivation from DB-level (SQLCipher PRAGMA) to app-level (KEK/DEK already does this)
- Database encryption at rest handled by PostgreSQL's `pgcrypto` or disk encryption

---

## Pending

### Server Package
- Wire server routes to vault client
- Implement remaining TODOs (~47 TODOs across server/vault)
- RBAC middleware integration
- Rate limiting middleware
- FIDO2/WebAuthn enrollment flow
- Key rotation endpoints
- Admin endpoints
- Audit logging

### Executor Package
- Daemon integration testing
- mTLS certificate rotation
- Command validation against policies
- Stage 2 server-side filter integration

### CLI
- CLI integration with server API
- Secret management commands
- User enrollment flow

---

## Key Files

### Executor
- `packages/executor/src/rust/filter.rs` — Core filter logic
- `packages/executor/src/rust/hashes.rs` — SHA-256, FNV-1a, detection hashes
- `packages/executor/src/venya_executor/filter.py` — Python wrapper
- `packages/executor/pyproject.toml` — setuptools + setuptools-rust
- `packages/executor/tests/test_filter.py` — 37 Python tests

### Vault
- `packages/vault/src/venya/vault/vault.py` — Vault facade
- `packages/vault/src/venya/vault/backend.py` — Database backend
- `packages/vault/src/venya/vault/encryption.py` — KEK/DEK encryption
- `packages/vault/src/venya/iam/models.py` — ORM models (14 tables)
- `packages/vault/alembic/` — Migrations

### Server
- `packages/server/src/venya_server/routes/` — API endpoints
- `packages/server/src/venya_server/middleware/` — Auth, RBAC, rate limiting
- `packages/server/src/venya_server/app.py` — FastAPI app
