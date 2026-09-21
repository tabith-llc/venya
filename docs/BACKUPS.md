# Venya Backup & Restore

> **ALPHA DOCUMENTATION — UNTESTED.** This guide describes the venya alpha and has **not**
> been validated by a full backup→wipe→restore drill. The paths, commands, and crypto
> relationships below are derived from the alpha source tree (installer, `core` encryption
> engine, `docs/architecture.md`) and may change. **Never trust a backup you have not
> restored** — run the restore test at the end of this doc before you depend on any of it.
> Where this page and your live host disagree (`ls -l`, `sudo -u postgres psql`), the host
> wins.

Venya splits its critical state across **four** places, and they only work **together**. A
database backup alone is worthless: the secrets in it are ciphertext that cannot be
decrypted without the passphrase in `/opt/venya/.env`. Read "The pairings" before you back
up anything.

## What must be backed up (core server)

| # | What | Path / command | Replaceable? | Why it matters |
|---|------|----------------|--------------|----------------|
| 1 | **PostgreSQL `venya` database** | `sudo -u postgres pg_dump -Fc venya` | **No** | Secrets (ciphertext), the **KEK salt** (`venya_config`), users, WebAuthn credentials, roles, executors + cert records, enrollment tokens (hashed), execution sessions, audit log. |
| 2 | **Server env file** | `/opt/venya/.env` (mode `0600`, `venya:venya`) | **No** | Holds `VENYA_DB__PASSPHRASE` (the KEK input that decrypts every secret), `VENYA_RECOVERY_CODE_PEPPER`, and the DB URL+password. |
| 3 | **CA passphrase env file** | `/etc/venya/venya-core.env` (mode `0640`, `root:venya`) | **No** | Holds `VENYA_CA_KEY_PASSPHRASE` and `VENYA_ADMIN_CA_KEY_PASSPHRASE` — the only things that can decrypt the CA private keys. |
| 4 | **CA material** | `/var/lib/venya/ca/` (mode `0700`) — `ca.crt` + **encrypted** `ca.key`, and `admin-ca/` (`admin-ca.crt` + encrypted `admin-ca.key`) | **No** | The root CA signs server TLS certs, relay client certs, and every executor cert. The Admin CA signs admin mTLS certs. Lose the CA → every certificate is unverifiable and nothing can be re-issued. |

**Regenerable — do not rely on backing these up** (the installer re-derives them from the
CA): server TLS cert/key (`/etc/venya/tls/`), relay client cert (`/etc/venya/relay/`), the
nginx site config, the admin cert copy under `/etc/nginx/ssl/`. Backing them up is harmless
but they are not the crown jewels.

## The pairings — why a partial backup is a lost backup

- **Secrets** recover only with **#1 (DB: ciphertext + KEK salt) + #2 (`VENYA_DB__PASSPHRASE`)**.
  Envelope encryption: a random DEK per secret is wrapped by the KEK (AES-256-KW); the KEK
  is derived from the passphrase **and** a salt stored in the DB (`venya_config`). Missing
  either half → the server refuses to start with `KekSaltMissingError` and the secrets are
  **unrecoverable**. There is no plaintext fallback.
- **The CA** is usable only with **#4 (encrypted `ca.key`) + #3 (its passphrase)**. The key
  is encrypted at rest; the passphrase is the only thing that unlocks it.
- **Break-glass recovery codes** verify only with **#2 (`VENYA_RECOVERY_CODE_PEPPER`)**.
  Rotate the pepper and previously-issued recovery codes stop working.

Net: back up **#1 + #2 + #3 + #4 together, every time.** A DB dump without `.env` and
`venya-core.env` is encrypted noise.

## How to back up (core server)

Stop nothing — PostgreSQL dumps are consistent online. Run as root or via `sudo`.

```bash
# 1. Database (custom format; compresses, allows selective restore)
sudo -u postgres pg_dump -Fc venya > /root/venya-backup/venya-db-$(date -u +%Y%m%dT%H%M%SZ).dump

# 2-4. The secret material, preserving ownership + modes.
#      tar as root so the 0600/0640/0700 perms and owners survive.
sudo tar -czpf /root/venya-backup/venya-secrets-$(date -u +%Y%m%dT%H%M%SZ).tar.gz \
  -C / \
  opt/venya/.env \
  etc/venya/venya-core.env \
  var/lib/venya/ca
```

Verify the archive captured the CA key and both env files:

```bash
sudo tar -tzf /root/venya-backup/venya-secrets-*.tar.gz | grep -E '\.env$|ca\.key$|admin-ca\.key$'
```

### Alternative: portable CA-key custody (CLI)

For off-site / escrow custody of the CA key, the CLI has purpose-built break-glass commands
(they never write the plaintext key to disk or stdout):

- `venya admin export-ca-key --output <file>` — re-encrypts the CA key under a passphrase
  **you** provide (PBKDF2 + AES-256-CBC). Store `<file>` + that passphrase separately.
- `venya admin split-ca-key` — splits the CA key with Shamir's Secret Sharing; distribute
  the shares (e.g. to different custodians), recombine with a threshold.
- `venya admin restore-ca-key` — restores the CA key from shares or an encrypted export.

These cover the **CA key only**. The database and `.env` (KEK passphrase, pepper) still need
the file/DB backup above. See [cli-reference.md](cli-reference.md) for exact flags.

## Executor hosts

Executor state is **lower priority** — an executor identity is re-enrollable, not
irreplaceable. If you want to avoid re-enrollment after a host loss, back up:

- `/etc/venya/executor/` — the executor client cert + key (`0700`/`0600`) and the copied `ca.crt`.
- `/etc/venya/executor.toml` — `server_url`, `executor_id`, `relay_client_ids`, mtls paths.
- `/var/lib/venya/executor/bootstrap-token` — only if a deferred registration is still pending (single-use).

Otherwise, re-run `install-venya-executor.sh` with a fresh enrollment token (minted by an
admin) and the executor re-registers. Target hosts hold nothing — no backup needed.

## Restore (core server)

1. Reinstall the core (`install-venya-core.sh`) on the host, **or** restore onto a host that
   already has PostgreSQL + nginx. Let the installer create an empty `venya` DB.
2. Stop the service: `sudo systemctl stop venya-core`.
3. Restore the database:
   ```bash
   sudo -u postgres pg_restore --clean --if-exists -d venya /root/venya-backup/venya-db-<stamp>.dump
   ```
4. Restore the secret material **with ownership/modes intact**:
   ```bash
   sudo tar -xzpf /root/venya-backup/venya-secrets-<stamp>.tar.gz -C /
   # confirm perms: .env 0600 venya:venya, venya-core.env 0640 root:venya, ca/ 0700
   ```
   The restored `VENYA_DB__PASSPHRASE` **must** match the one the secrets were encrypted
   under — there is no silent KEK rotation. If you also use the CLI CA custody, restore the
   CA key with `venya admin restore-ca-key`.
5. Start + verify:
   ```bash
   sudo systemctl start venya-core
   curl -sk https://<core-host>/api/v1/health   # expect {"status":"ok",...}
   ```
6. Confirm secrets decrypt: a `venya run` / `run_command` that injects a stored secret and
   returns redacted output proves the KEK + salt + ciphertext all line up.

## Backup security — these files ARE the keys to everything

`/opt/venya/.env` + `/etc/venya/venya-core.env` + `/var/lib/venya/ca/` together are
**plaintext-equivalent to every secret in the vault**: the passphrases decrypt the CA keys
and the KEK, and the KEK decrypts the secrets. Treat the backup archive as **top secret**:

- **Encrypt backups at rest** (e.g. `age`/`gpg`/`restic`/`borg` with a strong key, or an
  encrypted volume). Never store them unencrypted, never in the same trust domain as the
  server, never in a world-readable path or a repo.
- **Restrict access** to the backup location to named custodians; log access.
- The DB dump alone (without the env files) is ciphertext — but still treat it as sensitive
  (it carries usernames, audit history, executor inventory, and hashed tokens).
- Keep the CA-key export passphrase / Shamir shares in **separate** custody from the
  encrypted CA key blob.

## Test your restore (do this, do not skip it)

An untested backup is a hypothesis. Periodically:

1. Restore the latest backup onto a **spare** host (or VM) per the steps above.
2. Confirm `health` returns `ok`, a stored secret can be injected and comes back redacted,
   and an admin mTLS cert from the restored Admin CA still authenticates.
3. Record the date + result. If the restore fails, your backup is broken — fix it now, not
   during an incident.

---

## Related

- [FIREWALL.md](FIREWALL.md) — the network posture this state sits behind
- [architecture.md](architecture.md) — trust/CA layout, envelope-encryption detail, data stores
- [deployment-config.md](deployment-config.md) — `VENYA_DB__PASSPHRASE`, `VENYA_RECOVERY_CODE_PEPPER`, env mapping
- [cert-rotation-runbook.md](cert-rotation-runbook.md) — CA + cert rotation procedures
- [cli-reference.md](cli-reference.md) — `venya admin export-ca-key` / `split-ca-key` / `restore-ca-key`
