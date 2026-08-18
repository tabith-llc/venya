# Deployment Configuration Requirements

Critical configuration fields that must be set before deployment. Missing these values causes hard failure at startup.

---

## Required Fields

### `recovery_code_pepper`

**Config key:** `recovery_code_pepper` (TOML: `[server].recovery_code_pepper` or env `VENYA_RECOVERY_PEPPER`)

**Requirement:** MUST be set to a non-empty value. Deployment fails unconditionally if empty.

**Purpose:** Server-side secret used to hash break-glass recovery codes before storing them in the database. Without a pepper, recovery code hashes are vulnerable to rainbow table attacks — an attacker with database access can precompute hashes for common recovery codes and match them against stored values.

**Error on missing:**
```
RuntimeError: Recovery code pepper must be configured. Set VENYA_RECOVERY_PEPPER
or config.recovery_code_pepper. Recovery codes without a server-side
pepper are vulnerable to rainbow table attacks.
```

**PEP 784 env var:** `VENYA_RECOVERY_PEPPER`

**Generation:** Use a CSPRNG to generate at least 32 bytes of randomness, encoded as hex or base64:
```bash
python3 -c "import secrets; print(secrets.token_hex(32))"
```

**Key rotation limitation:** Currently only one pepper version is supported. If the pepper is rotated, old recovery codes hashed under the previous pepper will no longer verify. Future key rotation will require storing multiple peppers and trying them during recovery code verification.

---

### `db.passphrase` (production only)

**Config key:** `db.passphrase` (TOML: `[db].passphrase` or env `VENYA_DB_PASSPHRASE`)

**Requirement:** MUST be set in production. In debug mode, a warning is logged but deployment proceeds.

**Purpose:** Passphrase used to derive the Key Encryption Key (KEK) for encrypting secrets at rest. Without a passphrase, secrets are stored unencrypted in the database.

**Error on missing (production):**
```
RuntimeError: VENYA_DB_PASSPHRASE is not set.
Core secrets cannot be encrypted without a passphrase.
Set the passphrase in your secrets manager and restart.
```

---

## Configuration Loading

Configuration is loaded from these sources (in order of precedence):

1. Environment variables (PEP 784 format: `VENYA__SECTION__FIELD`)
2. TOML config file (loaded via `ServerConfig.from_file()`)
3. Field defaults (where defined)

Fields without defaults (like `recovery_code_pepper`) will raise a Pydantic validation error during config loading if not set via env var or config file.

### PEP 784 Environment Variable Mapping

| TOML Path | Environment Variable |
|-----------|---------------------|
| `server.recovery_code_pepper` | `VENYA_RECOVERY_PEPPER` |
| `db.passphrase` | `VENYA_DB_PASSPHRASE` |
| `db.database_url` | `VENYA_DB_DATABASE_URL` |

---

## Validation Timing

All required field checks happen during `lifespan()` startup (before the first request is served). This ensures:

- Developers learn about misconfiguration early (during local deployment)
- Production deployments never start with missing critical config
- Failed startups exit immediately with a clear error message (no partial initialization)

---

## Related

- `cert-rotation-runbook.md` — Executor certificate rotation procedures
- `bandit-nosec-suppressions.md` — Security scanner suppression list
