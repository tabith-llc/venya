# Deployment Configuration Requirements

Critical configuration fields that must be set before deployment. Missing these values causes hard failure at startup.

---

## Required Fields

### `recovery_code_pepper`

**Config key:** `recovery_code_pepper` (top-level field; env `VENYA_RECOVERY_CODE_PEPPER`)

**Requirement:** MUST be set to a non-empty value. A wholly missing value fails with a Pydantic `ValidationError` when `ServerConfig()` is constructed in `create_app()`; an empty value fails unconditionally (not debug-gated) during `lifespan()` startup.

**Purpose:** Server-side secret used to hash break-glass recovery codes before storing them in the database. Without a pepper, recovery code hashes are vulnerable to rainbow table attacks — an attacker with database access can precompute hashes for common recovery codes and match them against stored values.

**Error on missing (empty value; verbatim from `app.py`):**
```
RuntimeError: Recovery code pepper must be configured. Set VENYA_RECOVERY_CODE_PEPPER
in /opt/venya/.env (installer input variable: VENYA_RECOVERY_PEPPER)
or config.recovery_code_pepper. Recovery codes without a server-side
pepper are vulnerable to rainbow table attacks.
```

**Generation:** Use a CSPRNG to generate at least 32 bytes of randomness, encoded as hex or base64:
```bash
python3 -c "import secrets; print(secrets.token_hex(32))"
```

**Key rotation limitation:** Currently only one pepper version is supported. If the pepper is rotated, old recovery codes hashed under the previous pepper will no longer verify. Future key rotation will require storing multiple peppers and trying them during recovery code verification.

---

### `db.passphrase` (production only)

**Config key:** `db.passphrase` (env `VENYA_DB__PASSPHRASE` — note the DOUBLE underscore: `db` is a nested config section)

**Requirement:** MUST be set in production. In debug mode startup proceeds WITHOUT a warning — but the system is not usable for secrets: every secret operation fails closed with `CoreError("KEK not configured")`. There is NO unencrypted-storage fallback path.

**Purpose:** Passphrase used to derive the Key Encryption Key (KEK) for encrypting secrets at rest (envelope encryption: KEK wraps a per-secret DEK via AES-256-KW; values are ChaCha20-Poly1305).

**Error on missing (production; verbatim from `app.py`):**
```
RuntimeError: VENYA_DB__PASSPHRASE is not set.
Core secrets cannot be encrypted without a passphrase.
Set VENYA_DB__PASSPHRASE in /opt/venya/.env and restart
(installer input variable: VENYA_DB_PASSPHRASE).
```

---

### `dns_resolver` (executor)

**Config key:** `dns_resolver` (top-level field on the EXECUTOR config; env `VENYA_EXECUTOR_DNS_RESOLVER`; toml key `dns_resolver` in `/etc/venya/executor.toml`)

**Requirement:** MUST be set to a valid IPv4 address. With no value the executor daemon **refuses to start** — the check runs in `ExecutorDaemon.start()` before registration, so the one-shot enrollment token is never consumed on a doomed boot. This is a named, loud failure by design (owner ruling D1 option (a): "Venya never guesses your network"); there is no built-in default.

**Purpose:** The DNS resolver IP that sandboxed commands may use; it is always admitted to the sandbox egress policy. Without it, hostname-based egress entries can never resolve inside the sandbox, so the egress policy cannot be built.

**Error on missing (named ERROR log then `exit 1`; verbatim from `daemon.py` `start()`):**
```
dns_resolver is not configured — refusing to start: the sandbox egress policy cannot be built and hostname targets could never resolve. Set `dns_resolver` in /etc/venya/executor.toml or VENYA_EXECUTOR_DNS_RESOLVER in the service environment (find your resolver: resolvectl status or grep nameserver /etc/resolv.conf).
```

**How to find the value:** `resolvectl status` or `grep nameserver /etc/resolv.conf`.

**Installer knob:** `VENYA_DNS_RESOLVER` (required on fresh installs; re-runs reuse the stored `/etc/venya/executor.toml` value).

---

## Configuration Loading

The server config is a pydantic-settings `BaseSettings` class (`packages/server/src/server/config.py`). There is NO TOML config file for the server (the inert `/etc/venya/server.toml` written by old installers is actively removed; the sole file source is the env file). Sources, in precedence order:

1. Process environment variables — format `VENYA_<SECTION>__<KEY>` (single underscore after the `VENYA` prefix, DOUBLE underscore between section and key; top-level fields use `VENYA_<KEY>`)
2. The env file `$VENYA_ENV_DIR/.env` (default `/opt/venya/.env`, written by the installer)
3. Field defaults (where defined)

Unknown `VENYA_*` names are silently ignored (`extra="ignore"`) — a misspelled var is a no-op, so verify names against `config.py`.

### Environment Variable Mapping (examples)

| Config field | Environment Variable |
|-----------|---------------------|
| `recovery_code_pepper` | `VENYA_RECOVERY_CODE_PEPPER` |
| `db.passphrase` | `VENYA_DB__PASSPHRASE` |
| `db.database_url` | `VENYA_DB__DATABASE_URL` |
| `session.session_timeout` | `VENYA_SESSION__SESSION_TIMEOUT` |
| `fido2.enrollment_token_ttl` (minutes) | `VENYA_FIDO2__ENROLLMENT_TOKEN_TTL` |
| `executor_enrollment.token_ttl_seconds` | `VENYA_EXECUTOR_ENROLLMENT__TOKEN_TTL_SECONDS` |
| `executor_enrollment.require_token` | `VENYA_EXECUTOR_ENROLLMENT__REQUIRE_TOKEN` |

`executor_enrollment.require_token` defaults to **true** (ticket
`executor-rotation-require-token-400`, 2026-09-20): `POST /api/v1/executors/register`
without a valid enrollment token is rejected 400. Setting it `false` restores open
enrollment — any host reaching the core can mint an executor identity (physically
proven); do not disable outside deliberately open test networks. Rotation interaction:
see `cert-rotation-runbook.md` §1 (tokenless `rotate()` is exempt for the verified
incumbent credential — clean revocation state plus serial == current record).
| `cors.origins` (JSON list) | `VENYA_CORS__ORIGINS` |

Installer-level input variables (e.g. `VENYA_DB_PASSWORD`, `VENYA_DB_PASSPHRASE`, `VENYA_RECOVERY_PEPPER`, `CORE_HOSTNAME`) are consumed by `install-venya-core.sh`, which writes the correctly-named server variables into `/opt/venya/.env`. Setting an installer var in the server's environment does nothing.

---

## Validation Timing

Two layers:

- **Construction time** (`ServerConfig()` inside `create_app()`): fields declared without defaults — `recovery_code_pepper` — raise a Pydantic `ValidationError` before the app exists.
- **`lifespan()` startup** (before the first request is served): empty-pepper and missing-passphrase checks raise `RuntimeError`.

Together these ensure:

- Developers learn about misconfiguration early (during local deployment)
- Production deployments never start with missing critical config
- Failed startups exit immediately with a clear error message (no partial initialization)

---

## Related

- `cli-reference.md` — complete CLI command/argument reference (generated from the parser)
- `cert-rotation-runbook.md` — Executor certificate rotation procedures
- `bandit-nosec-suppressions.md` — Security scanner suppression list
