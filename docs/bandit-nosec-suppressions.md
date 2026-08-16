# Bandit `# nosec` Suppressions

All entries below are intentional — false positives or deliberate design decisions.
Each line has a corresponding `# nosec` comment added to the source.

## B108 — Hardcoded tmp directory (tmpfs paths)

| File | Line | Reason |
|------|------|--------|
| `packages/executor/src/executor/daemon.py` | 500 | `/tmp/venya-secrets` is on tmpfs, not persistent disk |
| `packages/executor/src/executor/daemon.py` | 638 | `/tmp/venya-secrets` is on tmpfs, not persistent disk |
| `packages/executor/src/executor/injector.py` | 166 | `/tmp/venya-secrets` is on tmpfs, not persistent disk |
| `packages/executor/src/executor/strategies/sbx_strategy.py` | 30 | `/dev/shm/venya-secrets` is tmpfs, not persistent disk |

## B105 — Hardcoded password string (non-password strings)

| File | Line | Reason |
|------|------|--------|
| `packages/executor/src/executor/strategies/sbx_strategy.py` | 30 | Path string `/dev/shm/venya-secrets`, not a password |
| `packages/executor/src/executor/strategies/sbx_strategy.py` | 33 | Mount path `/run/venya/secrets`, not a password |
| `packages/server/src/server/ca.py` | 119 | Env var name `VENYA_CA_KEY_PASSPHRASE`, not a password |
| `packages/server/src/server/ca.py` | 581 | Env var name `VENYA_ADMIN_CA_KEY_PASSPHRASE`, not a password |
| `packages/server/src/server/middleware/auth.py` | 124 | Cookie name `venya_access_token`, not a password |

## B106 — Hardcoded password function argument (placeholders)

| File | Line | Reason |
|------|------|--------|
| `packages/executor/src/executor/injector.py` | 196 | `secret_id=""` and `sentinel_hash=""` are placeholders set by caller |
| `packages/executor/src/executor/injector.py` | 234 | `secret_id=""` and `sentinel_hash=""` are placeholders set by caller |
| `packages/executor/src/executor/injector.py` | 275 | `secret_id=""` and `sentinel_hash=""` are placeholders set by caller |

## B602 — subprocess call with shell=True

| File | Line | Reason |
|------|------|--------|
| `packages/executor/src/executor/executor.py` | 255 | Core executor design — runs user commands via shell |

## B404 — Import subprocess

| File | Line | Reason |
|------|------|--------|
| `packages/executor/src/executor/executor.py` | 19 | Executor requires subprocess to run commands |
| `packages/executor/src/executor/strategies/sbx_strategy.py` | 20 | Sandbox strategy requires subprocess for sbx commands |
| `packages/server/src/server/utils/disk_encryption.py` | 5 | Disk encryption check requires subprocess for system commands |

## B603 — subprocess call without shell=True

| File | Line | Reason |
|------|------|--------|
| `packages/executor/src/executor/strategies/sbx_strategy.py` | 152 | Intentional `sbx exec` system call |
| `packages/executor/src/executor/strategies/sbx_strategy.py` | 175 | Intentional `sbx exec mkdir` system call |
| `packages/executor/src/executor/strategies/sbx_strategy.py` | 184 | Intentional `sbx cp` system call |
| `packages/executor/src/executor/strategies/sbx_strategy.py` | 195 | Intentional `sbx exec chmod` system call |
| `packages/executor/src/executor/strategies/sbx_strategy.py` | 220 | Intentional `sbx policy allow` system call |
| `packages/executor/src/executor/strategies/sbx_strategy.py` | 243 | Intentional `sbx exec sh -c` system call |
| `packages/executor/src/executor/strategies/sbx_strategy.py` | 255 | Intentional `sbx rm` system call |
| `packages/executor/src/executor/strategies/sbx_strategy.py` | 277 | Intentional `sbx secret set` system call |
| `packages/server/src/server/utils/disk_encryption.py` | 109 | Intentional `findmnt` system call |
| `packages/server/src/server/utils/disk_encryption.py` | 130 | Intentional `lsblk` system call |
| `packages/server/src/server/utils/disk_encryption.py` | 155 | Intentional `dmsetup table` system call |

## B607 — Start process with partial path

| File | Line | Reason |
|------|------|--------|
| `packages/executor/src/executor/strategies/sbx_strategy.py` | 175 | `sbx` is on PATH, standard sandbox CLI |
| `packages/executor/src/executor/strategies/sbx_strategy.py` | 184 | `sbx` is on PATH, standard sandbox CLI |
| `packages/executor/src/executor/strategies/sbx_strategy.py` | 195 | `sbx` is on PATH, standard sandbox CLI |
| `packages/executor/src/executor/strategies/sbx_strategy.py` | 220 | `sbx` is on PATH, standard sandbox CLI |
| `packages/executor/src/executor/strategies/sbx_strategy.py` | 243 | `sbx` is on PATH, standard sandbox CLI |
| `packages/executor/src/executor/strategies/sbx_strategy.py` | 255 | `sbx` is on PATH, standard sandbox CLI |
| `packages/executor/src/executor/strategies/sbx_strategy.py` | 277 | `sbx` is on PATH, standard sandbox CLI |
| `packages/server/src/server/utils/disk_encryption.py` | 109 | `findmnt` is on PATH, standard Linux utility |
| `packages/server/src/server/utils/disk_encryption.py` | 130 | `lsblk` is on PATH, standard Linux utility |
| `packages/server/src/server/utils/disk_encryption.py` | 155 | `dmsetup` is on PATH, standard Linux utility |

## B110 — Try/except pass

| File | Line | Reason |
|------|------|--------|
| `packages/server/src/server/fido2/manager.py` | 115 | DB cleanup in finally block, outer scope handles error |
| `packages/server/src/server/rate_limit.py` | 93 | Best-effort JSON parse, None falls through |
| `packages/server/src/server/rate_limit.py` | 124 | Best-effort DB query, None falls through |
| `packages/server/src/server/routes/auth_browser.py` | 584 | Rollback best-effort before raising HTTPException |
| `packages/server/src/server/routes/credentials.py` | 265 | Rollback best-effort before raising HTTPException |
| `packages/server/src/server/routes/enroll.py` | 284 | Rollback best-effort before re-raising HTTPException |
| `packages/server/src/server/routes/enroll.py` | 290 | Rollback best-effort before raising HTTPException |
| `packages/server/src/server/routes/secrets.py` | 278 | Rollback best-effort before raising HTTPException |
| `packages/vault/src/vault/vault/secure_memory.py` | 216 | Best-effort unlock in `__del__`, no stack to unwind |

## B112 — Try/except continue

| File | Line | Reason |
|------|------|--------|
| `packages/server/src/server/middleware/auth.py` | 246 | Iterate over trusted CAs, continue on each cert failure |
