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
- PostgreSQL integration tests passing (via Docker container)

**Tasks:**
1. ~~Create PostgreSQL migration (replaces SQLCipher SQLite)~~
2. ~~Update `Backend` to use PostgreSQL via `psycopg2`~~
3. ~~Wire `vault.py` methods to use the new backend~~
4. ~~Update `BackendConfig` for PostgreSQL connection string~~
5. ~~Add `psycopg2-binary` to vault dependencies~~
6. ~~Write integration tests against PostgreSQL~~
7. ~~Update `build.sh` to handle PostgreSQL setup~~
8. ~~Vault facade methods wired (get/put/delete/list)~~
9. ~~PostgreSQL Docker container running for integration tests~~

**Migration approach:**
- Keep the same ORM models (they're DB-agnostic)
- Replace `sqlcipher3` with `psycopg2` in `backend.py`
- Move key derivation from DB-level (SQLCipher PRAGMA) to app-level (KEK/DEK already does this)
- Database encryption at rest handled by PostgreSQL's `pgcrypto` or disk encryption

---

## Pending

### Server Package — Unimplemented Endpoints
**Status: Route stubs exist but endpoints not wired**

The following endpoints have route definitions but no handler implementation:
- `POST /api/v1/executors/register` — executor mTLS certificate registration (CSR → signed cert)
- `POST /api/v1/executors/sessions` — create executor session with secret injection
- `POST /api/v1/executors/{id}/execute` — execute command via executor
- `POST /api/v1/executors/certs/revocation-list` — get revoked cert serials
- `POST /api/v1/init` — initial bootstrap (first admin enrollment)
- `GET /api/v1/admin/command-policy` — get current executor command policy
- `POST /api/v1/admin/key-rotation` — start key encryption key rotation
- `POST /api/v1/heartbeat` — executor heartbeat (cert fingerprint tracking)

**Tasks:**
1. Implement executor registration endpoint (CSR validation → CA signing → cert return)
2. Implement executor session creation (session DB record + secret bundle)
3. Implement executor command execution (command dispatch + Stage 2 filter)
4. Implement cert revocation list endpoint
5. Implement init/bootstrap endpoint
6. Implement get-command-policy endpoint
7. Implement key-rotation start endpoint
8. Implement heartbeat endpoint

### Executor Package — Daemon Implementation
**Status: Skeleton exists, server endpoints missing**

- `ExecutorDaemon.start()` — full lifecycle (register, heartbeat, rotation, revocation polling)
- `CertificateManager` — mTLS cert lifecycle (register, rotate, check revocation)
- `ReaperLoop` — orphaned resource cleanup
- Heartbeat protocol (POST /heartbeat with cert fingerprint)
- Certificate rotation (auto-rotate before expiry)
- Revocation polling (check revocation list periodically)

**Tasks:**
1. Wire daemon to server endpoints (registration, heartbeat, revocation)
2. Implement certificate rotation flow
3. Implement revocation check and graceful shutdown
4. Add daemon integration tests

### CLI — Completed
- ✅ `venya` — main CLI entry point
- ✅ `venya store/get/list/delete` — secret CRUD
- ✅ `venya role` — role management (create, list, get, delete, members)
- ✅ `venya admin` — admin operations (enroll, remove, configure, list, policy, key-version, revoke-executor)
- ✅ `venya audit` — audit log queries
- ✅ `venya recovery` — break-glass recovery
- ✅ `venya exec` — executor command execution with secret injection + Stage 2 filtering
- ✅ `venya config` — CLI config management (show, set-server, clear-token)
- ✅ httpx migration (api_client.py, fido2_client.py)
- ✅ Config file persistence (~/.config/venya/config.json)
- 28 CLI tests passing

### End-to-End Integration
**Status: Not yet implemented**

Full pipeline test covering:
1. Start PostgreSQL → run migrations → start server
2. Enroll first admin user via `venya init`
3. Authenticate via WebAuthn → get access token
4. Store a secret via `venya store`
5. Execute command via `venya exec` with secret injection
6. Verify output filtering (Stage 1 Rust + Stage 2 server)
7. Verify secret masking in both stdout and stderr

**Tasks:**
1. Create `tests/test_e2e.py` with fixture for PostgreSQL + server lifecycle
2. Implement enrollment flow test
3. Implement secret CRUD test
4. Implement executor pipeline test
5. Implement output filtering verification

---

## Key Files

### Executor
- `packages/executor/src/rust/filter.rs` — Core filter logic
- `packages/executor/src/rust/hashes.rs` — SHA-256, FNV-1a, detection hashes
- `packages/executor/src/rust/lib.rs` — PyO3 bindings
- `packages/executor/src/venya_executor/filter.py` — Python wrapper
- `packages/executor/src/venya_executor/executor.py` — Command execution pipeline
- `packages/executor/src/venya_executor/daemon.py` — Daemon lifecycle (cert mgmt, heartbeat, reaper)
- `packages/executor/src/venya_executor/injector.py` — Secret FD injection
- `packages/executor/pyproject.toml` — setuptools + setuptools-rust
- `packages/executor/tests/test_filter.py` — 79 Rust tests + 82 Python tests

### Vault
- `packages/vault/src/venya/vault/vault.py` — Vault facade
- `packages/vault/src/venya/vault/backend.py` — PostgreSQL backend
- `packages/vault/src/venya/vault/encryption.py` — KEK/DEK encryption
- `packages/vault/src/venya/iam/models.py` — ORM models (15 tables)
- `packages/vault/src/venya/iam/role_manager.py` — RoleManager CRUD + membership
- `packages/vault/src/venya/iam/enrollment_manager.py` — Enrollment token management
- `packages/vault/src/venya/iam/session_manager.py` — Session + access token management
- `packages/vault/src/venya/cli/cli.py` — CLI argument parser
- `packages/vault/src/venya/cli/api_client.py` — httpx-based API client with config persistence
- `packages/vault/src/venya/cli/fido2_client.py` — Headless WebAuthn client
- `packages/vault/src/venya/cli/commands.py` — CLI command implementations
- `packages/vault/alembic/` — Migrations
- `packages/vault/tests/test_vault.py` — 12 unit tests
- `packages/vault/tests/test_cli.py` — 28 CLI tests
- `packages/vault/tests/test_capability_isolation.py` — Capability isolation tests

### Server
- `packages/server/src/venya_server/routes/` — API endpoints (11 routes, 40+ endpoints)
- `packages/server/src/venya_server/middleware/` — Auth, RBAC, rate limiting
- `packages/server/src/venya_server/dependencies.py` — FastAPI dependency injection
- `packages/server/src/venya_server/app.py` — FastAPI app
- `packages/server/src/venya_server/ca.py` — CA manager for executor certificates
- `packages/server/src/venya_server/fido2/manager.py` — FIDO2/WebAuthn manager
- `packages/server/tests/` — 144 tests across 8 test files
- `packages/server/tests/test_executor_integration.py` — 25 executor filter integration tests
