# Venya Backup & Restore

> **Validated by physical restore drill, 2026-09-30.** A full backup→wipe→reinstall→restore
> drill ran core-1→core-2 and was repeated as a second core-3→core-2 pass, including a real
> break-glass recovery-code use. Record: **restore drill PASS 2026-09-30 on 0.1.0alpha16.** The
> commands below are the drill-corrected forms (several as-written commands failed in the
> drill and are marked). **Never trust a backup you have not restored** — run the restore
> test at the end of this doc before you depend on any of it. Where this page and your live
> host disagree (`ls -l`, `sudo -u postgres psql`), the host wins.

Venya splits its critical state across **four** places, and they only work **together**. A
database backup alone is worthless: the secrets in it are ciphertext that cannot be
decrypted without the passphrase in `/opt/venya/.env`. Read "The pairings" before you back
up anything. Per-surface file *modes* are stated in their own table — see "Delivered modes,
per CA-material surface", which also covers `/etc/venya/admin/`.

## What must be backed up (core server)

| # | What | Path / command | Replaceable? | Why it matters |
|---|------|----------------|--------------|----------------|
| 1 | **PostgreSQL `venya` database** | `sudo -u postgres pg_dump -Fc venya` | **No** | Secrets (ciphertext), the **KEK salt** (`venya_config`), users, WebAuthn credentials, roles, executors + cert records, the core relay credential registry (`core_relay_credentials`, #597 — revoking a stolen relay credential lives only here), enrollment tokens (hashed), execution sessions, audit log. |
| 2 | **Server env file** | `/opt/venya/.env` (mode `0600`, `venya:venya`) | **No** | Holds `VENYA_DB__PASSPHRASE` (the KEK input that decrypts every secret), `VENYA_RECOVERY_CODE_PEPPER`, and the DB URL+password. |
| 3 | **CA passphrase env file** | `/etc/venya/venya-core.env` (mode `0640`, `root:venya`) | **No** | Holds `VENYA_CA_KEY_PASSPHRASE` and `VENYA_ADMIN_CA_KEY_PASSPHRASE` — the only things that can decrypt the CA private keys. |
| 4 | **CA material** | `/var/lib/venya/ca/` (mode `0700`) — `ca.crt` (mode `0644`) + **encrypted** `ca.key` (mode `0600`), and `admin-ca/` (mode `0700`) — `admin-ca.crt` (mode `0644`) + **encrypted** `admin-ca.key` (mode `0600`) | **No** | The root CA signs server TLS certs, relay client certs, and every executor cert. The Admin CA signs admin mTLS certs. Lose the CA → every certificate is unverifiable and nothing can be re-issued. |

### Delivered modes, per CA-material surface

One figure for the tree is not a promise a customer can check, so every CA-material surface states
its own delivered mode below — including `/etc/venya/admin/`, the machine-plane admin-credential
directory, which this document did not previously list. Each row names the pin that writes it.

| Surface | Delivered mode | Owner | Pinned by | Re-asserted on a re-run? |
|---|---|---|---|---|
| `/var/lib/venya/ca/` | **`0700`** | `venya:venya` | `chmod 700 /var/lib/venya/ca` in `venya_create_directories` (`venya-common.sh`), plus `os.chmod(str(ca_dir), 0o700)` in the CA-generation step (`install-venya-core.sh`) | **yes, unconditionally** — neither pin is inside the admin-mTLS block |
| `/var/lib/venya/ca/admin-ca/` | **`0700`** | `venya:venya` | `install -d -m 0700 -o venya -g venya "$ADMIN_CA_DIR"` (`install-venya-core.sh`) | every admin-mTLS run — `install -d` re-applies the mode to an existing directory. Skipped when admin mTLS is off. |
| `/etc/venya/admin/` | **`0700`** | `venya:venya` | `install -d -m 0700 -o venya -g venya "$ADMIN_CERT_DIR"` (`install-venya-core.sh`); inside it the mint writes `admin.crt` `0644` and `admin.key` `0600` | every admin-mTLS run. Skipped when admin mTLS is off. |
| `/opt/venya/.env` | `0600` | `venya:venya` | item 2 above (`chmod 600`) | every run |
| `/etc/venya/venya-core.env` | `0640` | `root:venya` | item 3 above (`chmod 0640`) | every run |

**Two parent directories are deliberately wider, and they are not CA material.** `/var/lib/venya/`
is `0750` on a default install (`install -d -m 0750 -g venya /var/lib/venya`, inside the admin-mTLS
block) and `0700` when admin mTLS is off, where `venya_create_directories` creates it under the
installer's entry `umask 077`. `/etc/venya/` is `0755` on every install (`install -d -m 0755
/etc/venya`, which appears in both `install-venya-core.sh` and `venya-common.sh`). Both are
group-*readable* so the `venya` service account can traverse to the leaves; **neither is ever
group-writable**. The secret leaves are the `0700` rows above and the `0600` key files inside them.

No CA-material directory is group-writable. Prove it on your own host — this predicate prints
nothing when the posture holds, and prints the offending directory when it does not:

```bash
sudo find /var/lib/venya /etc/venya -type d -perm -0020
```

**Scoping, and it is load-bearing.** The `admin-ca/` and `/etc/venya/admin/` pins sit *inside* the
`if [ "$ADMIN_MTLS_ENABLED" = "true" ]` block of `install-venya-core.sh`, so an install run with
`VENYA_ADMIN_MTLS_ENABLED=false` neither creates nor re-asserts those two directories at all —
their `0700` describes a default (admin-mTLS **on**) install, not every install. The **root** CA
directory is not conditional: `venya_create_directories` (`mkdir -p /var/lib/venya/ca` then
`chmod 700 /var/lib/venya/ca`) and the CA-generation step's `os.chmod(str(ca_dir), 0o700)` both run
outside that block, so `/var/lib/venya/ca` is `0700` on every install either way. Where this page
and your live host disagree (`ls -ld`, the `find` above), the host wins.

**Regenerable — do not rely on backing these up** (the installer re-derives them from the
CA **at install time**): server TLS cert/key (`/etc/venya/tls/`), relay client cert
(`/etc/venya/relay/`), the nginx site config, the admin cert copy under `/etc/nginx/ssl/`,
and the served CA copy at `/var/www/.well-known/venya-ca.crt`. Backing them up is harmless
but they are not the crown jewels. **On a restore they are NOT self-healing**: the installer
signs them before your backup's CA material is put back, so after restoring the CA you must
re-issue them from the restored CAs — see step 5 of "Restore".

## The pairings — why a partial backup is a lost backup

- **Secrets** recover only with **#1 (DB: ciphertext + KEK salt) + #2 (`VENYA_DB__PASSPHRASE`)**.
  Envelope encryption: a random DEK per secret is wrapped by the KEK (AES-256-KW); the KEK
  is derived from the passphrase **and** a salt stored in the DB (`venya_config`). Missing
  the salt row → the server refuses to start with `KekSaltMissingError`; there is no
  plaintext fallback. A **mismatched passphrase does NOT fail at boot**: KEK derivation is
  lazy and the passphrase is never touched at startup — the drill proved a wrong
  `VENYA_DB__PASSPHRASE` boots active with a clean journal, and the failure only surfaces
  at the first decrypt (use-time) attempt. Proof of this pairing is a successful secret
  injection, not a green boot (see step 7 of "Restore").
- **The CA** is usable only with **#4 (encrypted `ca.key`) + #3 (its passphrase)**. The key
  is encrypted at rest; the passphrase is the only thing that unlocks it. "CA present" is
  not the bar — "CA usable" is: sign something with it (the re-issue in step 5 of
  "Restore" both completes the restore and proves this pairing; the drill did exactly
  that).
- **Break-glass recovery codes** verify only with **#2 (`VENYA_RECOVERY_CODE_PEPPER`)** —
  and only if you still **have the code**. The server stores just a hash: nothing in the
  four artifacts contains the printed code itself, so **the printed code belongs IN the
  off-site backup set** alongside artifacts 1–4. Codes are **single-use**: a successful use clears
  the stored hash in the same commit (drill-proven — first use created the new admin, the
  replay was rejected `Invalid recovery code` with a CRITICAL journal entry and zero rows
  written). Codes are minted at `venya init`, and re-issue exists:
  `venya admin reissue-recovery-code` (takes no arguments; needs session bearer +
  elevation touch + admin mTLS; the new code prints ONCE and the old one dies
  immediately — see [cli-reference.md](cli-reference.md)). Rotate the pepper and
  previously-issued recovery codes stop working.

Net: back up **#1 + #2 + #3 + #4 together, every time.** A DB dump without `.env` and
`venya-core.env` is encrypted noise. `/etc/venya/admin/` is deliberately **not** a fifth artifact:
the installer re-mints that pair on every admin-mTLS run (see "Delivered modes" above), so a
reinstall replaces it and an off-site copy of it buys nothing.

## How to back up (core server)

Stop nothing — PostgreSQL dumps are consistent online. Run via `sudo bash -c` so file
writes happen as root (forms proven clean on the second drill pass, 2026-09-30):

```bash
# 0. The backup dir is not created by anything — make it first (drill finding D-2:
#    the as-written block died here on first run).
sudo mkdir -p /root/venya-backup

# 1. Database (custom format; compresses, allows selective restore).
#    The redirect must be INSIDE the root shell: `sudo -u postgres pg_dump ... > /root/...`
#    runs the redirect as the invoking operator and dies "Permission denied"
#    (drill finding D-1). Dump as postgres via su, redirect as root:
sudo bash -c "su -s /bin/bash postgres -c 'pg_dump -Fc venya' > /root/venya-backup/venya-db-$(date -u +%Y%m%dT%H%M%SZ).dump"

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

> **CUSTODY STATUS (defect `ca-key-export-blind-to-at-rest`) — was broken, fix merged,
> live verification pending.** The 2026-09-30 drill PROVED the export/restore commands
> **failed on installs where the CA key is encrypted at rest** — which is every install
> since the at-rest fixes (drill-confirmed, deterministic). Export wrapped the raw on-disk
> bytes (a `BEGIN ENCRYPTED PRIVATE KEY` blob) and restore's validator parsed them with no
> password, so even the **correct** passphrase was rejected: `Error: restored data is not a
> valid PEM private key`. The wrong-passphrase arm failed distinctly
> (`GCM authentication failed`), so operators can tell corruption from defect. The same-day
> custody fix makes export/split/restore honor the at-rest envelope; **live-core
> verification of the round-trip is scheduled for the next fleet window**. Until that
> passes, treat this custody path as REHEARSE-BEFORE-YOU-NEED-IT — exercise it against a
> test CA before an incident; the tar backup above remains the drill-proven path.
> The shares path is NOT a separate suspect: `split-ca-key` reads the same at-rest
> envelope through the same helper (`cmd_admin_split_ca_key` and
> `cmd_admin_export_ca_key` both call `unwrap_at_rest` in
> `packages/cli/src/venya_cli/commands.py`, fix `066f4c8`, ticket #297), so what is
> unverified for one is unverified for the other — the code path is shared, the fleet
> round-trip is not yet run.

For off-site / escrow custody of the CA key, the CLI has purpose-built break-glass commands
(they never write the plaintext key to disk or stdout):

- `venya admin export-ca-key --output <file>` — re-encrypts the CA key under a passphrase
  **you** provide: PBKDF2-HMAC-SHA256 (600,000 iterations) + **AES-256-GCM**, an
  authenticated envelope (`VENYACA1`), so a wrong passphrase or a tampered/corrupted blob
  fails loudly at restore (`GCM authentication failed`) instead of yielding silently
  damaged key material. Store `<file>` + that passphrase separately. There is no external
  `openssl enc` decode for this blob — the instrument is `venya admin restore-ca-key`.
- **Which blob do you hold?** A current export starts with the 8 magic bytes `VENYACA1`
  (`head -c 8 <file>`). Older alpha.11-era exports (no magic header — PBKDF2 +
  AES-256-CBC) still restore through the same command: the reader is dual-format, CBC
  read-only with full PKCS7 validation. New exports are always GCM/`VENYACA1`.
- `venya admin split-ca-key` — splits the CA key with Shamir's Secret Sharing; distribute
  the shares (e.g. to different custodians), recombine with a threshold.
- `venya admin restore-ca-key` — restores the CA key from shares or an encrypted export
  (both blob formats above).

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
   already has PostgreSQL + nginx. Let the installer create an empty `venya` DB. If you are
   clearing an old host first, go in order: release the grants the database role owns
   INSIDE the old database, then drop the database, then drop the cluster-wide login role —
   dropping only the database leaves the role alive on its previous password, and the
   installer's pre-write authentication probe stops the install (with the remedy printed)
   until the supplied password matches the role or the password is rotated deliberately.
   Note the
   installer's CA behavior (drill-confirmed): it **preserves an existing on-disk CA** — if
   `/var/lib/venya/ca/ca.key` is present it prints "CA already exists - preserved" and
   mints nothing; it only generates a fresh CA when the key is absent. Either way, the
   install-time TLS material it signs belongs to whatever CA was on disk at install time,
   not to the CA you are about to restore — that is why step 5 exists.
2. Stop the service: `sudo systemctl stop venya-core`.
3. Restore the database. The as-written `sudo -u postgres pg_restore ... /root/...` form
   **fails**: the postgres user cannot read the root-owned dump under a `0700 /root`
   (drill finding D-3). Root opens the file and pipes it into postgres:
   ```bash
   sudo bash -c "cat /root/venya-backup/venya-db-<stamp>.dump | su -s /bin/bash postgres -c 'pg_restore --clean --if-exists -d venya'"
   ```
   `--clean --if-exists` over the installer's freshly-migrated empty schema was proven clean
   twice in the drill: restored census matched the dump exactly (23 tables; audit, secrets,
   users, roles, executor rows all equal), and the migration-`031` append-only audit
   enforcement (the `venya_audit` role + grants) survived — INSERT/SELECT work, UPDATE and
   DELETE stay `permission denied`.
4. Restore the secret material **with ownership/modes intact**:
   ```bash
   sudo tar -xzpf /root/venya-backup/venya-secrets-<stamp>.tar.gz -C /
   # confirm perms (drill-observed): .env 0600 venya:venya, venya-core.env 0640 root:venya,
   # ca/ 0700, ca keys 0600
   ```
   The restored `VENYA_DB__PASSPHRASE` **must** match the one the secrets were encrypted
   under — there is no silent KEK rotation. If you use the CLI CA-key custody path, restore
   the CA key with `venya admin restore-ca-key` — drill-proven broken on at-rest installs
   (defect `ca-key-export-blind-to-at-rest`), fix merged, live-core verification pending
   (see CUSTODY STATUS above); the tar in step 4 is the drill-proven path.
5. **Re-issue the install-time TLS material from the restored CAs — mandatory, the restore
   is not self-healing.** Nothing at boot re-signs the server leaf, the relay client cert,
   the nginx client-CA bundle, or the served CA copy against the restored CA; if you skip
   this step the served chain silently mismatches the restored CA (drill finding D-5; a
   `curl -k` health check masks exactly this). Run this block **as root**, mirroring the
   installer's own steps (`install-venya-core.sh`: leaf, relay, nginx bundle, served-CA
   sections). The passphrase is sourced from the restored env file and passed via the
   process environment (`-passin env:...`), never on argv:
   ```bash
   set -a; . /etc/venya/venya-core.env; set +a   # VENYA_CA_KEY_PASSPHRASE et al.
   CORE_HOSTNAME=$(hostname)

   # Server TLS leaf: fresh EC key, CSR, signed under the restored root CA (SAN DNS, 365d).
   openssl ecparam -genkey -name prime256v1 -noout -out /etc/venya/tls/server.key
   chown venya:venya /etc/venya/tls/server.key; chmod 600 /etc/venya/tls/server.key
   openssl req -new -key /etc/venya/tls/server.key -out /tmp/server.csr \
     -subj "/O=Venya/CN=$CORE_HOSTNAME"
   openssl x509 -req -in /tmp/server.csr \
     -CA /var/lib/venya/ca/ca.crt -CAkey /var/lib/venya/ca/ca.key \
     -passin env:VENYA_CA_KEY_PASSPHRASE \
     -CAcreateserial -out /etc/venya/tls/server.crt -days 365 \
     -extfile <(echo "subjectAltName=DNS:$CORE_HOSTNAME")
   chown venya:venya /etc/venya/tls/server.crt; chmod 644 /etc/venya/tls/server.crt
   rm -f /tmp/server.csr

   # Relay client cert: CN=<host>-relay, clientAuth EKU + SKI/AKI (Python 3.14 ssl
   # rejects a chain without an Authority Key Identifier — keep both extensions).
   openssl ecparam -genkey -name prime256v1 -noout -out /etc/venya/relay/relay-client.key
   chown venya:venya /etc/venya/relay/relay-client.key; chmod 600 /etc/venya/relay/relay-client.key
   openssl req -new -key /etc/venya/relay/relay-client.key -out /tmp/relay-client.csr \
     -subj "/O=Venya/CN=${CORE_HOSTNAME}-relay"
   openssl x509 -req -in /tmp/relay-client.csr \
     -CA /var/lib/venya/ca/ca.crt -CAkey /var/lib/venya/ca/ca.key \
     -passin env:VENYA_CA_KEY_PASSPHRASE \
     -CAcreateserial -out /etc/venya/relay/relay-client.crt -days 365 \
     -extfile <(printf 'extendedKeyUsage=clientAuth\nsubjectAltName=DNS:%s-relay\nsubjectKeyIdentifier=hash\nauthorityKeyIdentifier=keyid,issuer\n' "$CORE_HOSTNAME")
   chown venya:venya /etc/venya/relay/relay-client.crt; chmod 644 /etc/venya/relay/relay-client.crt
   rm -f /tmp/relay-client.csr

   # nginx client-CA files: rebuild from the restored Admin CA + root CA.
   cp /var/lib/venya/ca/admin-ca/admin-ca.crt /etc/nginx/ssl/client-ca.crt
   chmod 644 /etc/nginx/ssl/client-ca.crt
   cat /var/lib/venya/ca/ca.crt /etc/nginx/ssl/client-ca.crt > /etc/nginx/ssl/client-ca-bundle.crt
   chmod 644 /etc/nginx/ssl/client-ca-bundle.crt

   # Served CA copy: refresh it too — a stale copy misleads future installs/clients
   # (the first drill pass missed exactly this).
   cp /var/lib/venya/ca/ca.crt /var/www/.well-known/venya-ca.crt
   chmod 644 /var/www/.well-known/venya-ca.crt

   # Prove the restored CA actually signs (this is the CA-pairing check):
   openssl verify -CAfile /var/lib/venya/ca/ca.crt \
     /etc/venya/tls/server.crt /etc/venya/relay/relay-client.crt
   nginx -t && systemctl reload nginx
   ```
   The `.env` `VENYA_MTLS_CERT`/`VENYA_MTLS_KEY` paths are unchanged — the relay files were
   replaced in place.
6. Start + verify **strictly** (no `-k` — it masks step-5-class failures):
   ```bash
   sudo systemctl start venya-core
   curl --cacert /var/www/.well-known/venya-ca.crt https://<core-host>/api/v1/health
   # expect {"status":"ok",...} with rc=0 against the restored CA
   ```
7. Confirm the restored material with **use-time proofs, not boot-success**. A clean boot
   and a zero-ERROR journal prove nothing about the secret material: the KEK is lazy and a
   wrong passphrase starts active and silent (drill finding D-6 — the doc's old
   boot-fail-loud claim was falsified). What proves the pairings, each drill-verified:
   - **KEK + salt + ciphertext**: a `venya run` / `run_command` that injects a
     pre-existing stored secret → the value decrypts end-to-end and comes back redacted
     (`[REDACTED:<id>]`), exit 0. A wrong passphrase cannot produce this.
   - **Admin CA chain**: an admin mTLS request carrying the core's own machine-plane
     pair on that core (e.g. `venya admin list`) → 200 through nginx + the server.
     A person's ceremony-minted certificate is the other kind of administrator
     credential, and the server admits one once it is presented and the role check
     passes — but the CLI writes its key encrypted at rest with no passphrase read
     path yet (#565 Part B), so that pair is not the credential this drill step can
     be performed with.
   - **CA key + passphrase**: already proven if step 5's `openssl verify` passed.
   - **Recovery-code + pepper**: only verifiable by **using** a code — which burns it
     (single-use). Prefer not to spend one in a test; if you do, reissue immediately
     (`venya admin reissue-recovery-code`).

## Backup security — these files ARE the keys to everything

`/opt/venya/.env` + `/etc/venya/venya-core.env` + `/var/lib/venya/ca/` together are
**plaintext-equivalent to every secret in the store**: the passphrases decrypt the CA keys
and the KEK, and the KEK decrypts the secrets. Treat the backup archive as **top secret**:

- **Encrypt backups at rest** (e.g. `age`/`gpg`/`restic`/`borg` with a strong key, or an
  encrypted volume). Never store them unencrypted, never in the same trust domain as the
  server, never in a world-readable path or a repo.
- **Restrict access** to the backup location to named custodians; log access.
- The DB dump alone (without the env files) is ciphertext — but still treat it as sensitive
  (it carries usernames, audit history, executor inventory, and hashed tokens).
- Keep the CA-key export passphrase / Shamir shares in **separate** custody from the
  encrypted CA key blob.
- Keep the **printed recovery code** in the off-site backup set with these artifacts. It is
  not stored anywhere else (the server holds only a hash) and it is single-use — if it is
  ever spent, re-issue it immediately (`venya admin reissue-recovery-code`).

## Test your restore (do this, do not skip it)

An untested backup is a hypothesis. Periodically (the procedure below is what the
2026-09-30 drill ran — do the same):

1. Restore the latest backup onto a **spare** host (or VM) per the steps above, including
   the step-5 re-issue.
2. Confirm `health` returns `ok` **strictly** (no `-k`, against the restored CA), a stored
   secret can be injected and comes back redacted, an admin mTLS cert from the restored
   Admin CA still authenticates, and the audit table is still append-only for the
   `venya_audit` role (UPDATE/DELETE denied). Booting clean proves none of this.
3. Record the date + result. If the restore fails, your backup is broken — fix it now, not
   during an incident.

---

## Related

- [FIREWALL.md](FIREWALL.md) — the network posture this state sits behind
- [architecture.md](architecture.md) — trust/CA layout, envelope-encryption detail, data stores
- [deployment-config.md](deployment-config.md) — `VENYA_DB__PASSPHRASE`, `VENYA_RECOVERY_CODE_PEPPER`, env mapping
- [cert-rotation-runbook.md](cert-rotation-runbook.md) — CA + cert rotation procedures
- [cli-reference.md](cli-reference.md) — `venya admin export-ca-key` / `split-ca-key` / `restore-ca-key`
