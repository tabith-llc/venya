# Venya Certificate & Key Rotation Runbook

> **Provenance:** rewritten 2026-09-19 against the working tree at dev `28941fb`
> (full evidence register: venya-dev `testing/results-2026-09-19-1755.md`). The previous
> version of this document described a pre-nginx deployment (TLS on :8080, CA under
> `/etc/venya/ca`, users `venya-core`/`venya-executor`, a nonexistent
> `venya-executor generate-csr` command) and was largely unrunnable as written.
> Every path, command, and behavior below cites its source. Open defects that affect
> procedures are flagged with ⚠ and their ticket IDs.

## 0. Key material inventory — what rotates, and where it lives

| Material | Location | Validity / rotation | Notes |
|---|---|---|---|
| Root CA keypair | core: `/var/lib/venya/ca/ca.key` (0600), `ca.crt` | manual break-glass only (§5) | key is PLAINTEXT at rest — ⚠ ticket `root-ca-key-plaintext-at-rest`; encryption deferred |
| Admin CA keypair | core: `/var/lib/venya/ca/admin-ca/` | manual (§7) | key ENCRYPTED; passphrase in `/etc/venya/venya-core.env` (0640 root:venya) |
| Server TLS leaf | core: `/etc/venya/tls/server.crt|.key` | 365 days; re-signed on every installer run (`install-venya-core.sh:335-349`) | CN + SAN DNS = `CORE_HOSTNAME` |
| Relay client cert | core: `/etc/venya/relay/relay-client.crt|.key` | regenerated on installer run (`:355-400`) | CN `<core-hostname>-relay`; must appear in executors' `relay_client_ids` |
| Executor client cert | executor: `/etc/venya/executor/executor.crt|.key` (ca.crt alongside) | 30 days (`EXECUTOR_VALIDITY_DAYS = 30`, server `ca.py:44`); auto-rotation attempted 3 days before expiry (`rotate_before_days`, executor `config.py:34-37`) | ⚠ auto-rotation CANNOT persist on deployed systems — ticket `executor-cert-rotation-erofs`; use §2 manual renew |
| Admin client certs | workstations / core: `/etc/venya/admin/admin.crt|.key` | manual (§7) | re-issued on every core installer run |
| Secret-encryption KEK + key versions | core: database + server config | `venya admin rotate-key` (§6) | independent of the TLS CA hierarchy |

nginx terminates TLS on :443 and proxies to the plain-HTTP backend on 127.0.0.1:8080
(`install-venya-core.sh:458-480`). Nothing listens on `https://…:8080`; all verification
curls below go through `https://<core-host>/…`.

## 1. Executor certificate auto-rotation (design + deployment caveat)

Design (daemon `CertManager`, `packages/executor/src/executor/daemon.py:239-323`):

1. Every main-loop iteration (~30 s) checks `needs_rotation()`: cert expires within
   `rotate_before_days` (default 3), or is already expired.
2. `rotate()` generates a fresh ECDSA P-256 keypair + CSR and POSTs it to
   `/api/v1/executors/register` (same endpoint as enrollment; server replaces the cert
   record and returns `cert_pem` + `ca_cert_pem` + serial + expiry).
3. The daemon validates the new cert against the CA, then writes cert/key/ca to disk.

⚠ **Deployed reality (ticket `executor-cert-rotation-erofs`):** the systemd unit sets
`ReadOnlyPaths=/etc/venya` (`systemd/venya-executor.service`), so step 3 fails with
EROFS — AFTER the server has already replaced the cert, and the freshly generated
private key is lost. The failure is caught and logged (`Certificate rotation failed`),
and retried every loop. Consequence: without manual intervention (§2), a deployed
executor's identity dies no later than day 30. Watch for the log line:

```bash
sudo journalctl -u venya-executor | grep -i "rotation failed"
```

## 2. Manual executor cert operations (working path)

Run ON the executor host. The CLI is installed in the executor venv; writes need root
(the unit's read-only mount does not apply to manual shells):

```bash
sudo /opt/venya/.venv/bin/venya exec cert status                 # expiry + remaining days
sudo /opt/venya/.venv/bin/venya exec cert renew                  # CSR via existing mTLS identity, atomic write
sudo /opt/venya/.venv/bin/venya exec cert renew --cert-path /etc/venya/executor/executor.crt
```

`renew` authenticates with the CURRENT cert — run it while the cert is still valid
(the same 3-day window the daemon uses). If the cert already expired, re-register
instead (§3).

Revoke (admin action, from a workstation holding the admin mTLS cert, or on the core):

```bash
SSL_CERT_FILE=~/.config/venya-ca.crt \
VENYA_ADMIN_CERT=admin-cert/admin.crt VENYA_ADMIN_KEY=admin-cert/admin.key \
  venya admin revoke-executor <executor-id>
# or, targeting the executor's own cert from the executor host:
sudo /opt/venya/.venv/bin/venya exec cert revoke --executor-id <executor-id>
```

## 3. Re-registering an executor (lost/expired cert, or after CA rotation)

Runtime (daemon-side) registration cannot write `/etc/venya/executor` either
(`daemon.py:118-136` fails closed; empty-token installs crash-loop — ticket
`executor-ero-fs-crash-loop-on-empty-token`). The supported path is install-time
registration with a bootstrap token:

```bash
# 1. On the core (admin mTLS cert lives there) or a workstation holding it:
venya admin executor-enroll <executor-id> --output-dir /secure/enroll
#    (token TTL default 1800 s, single-use, stored hashed — server config.py:131-136)

# 2. Transfer /secure/enroll to the executor host, then re-run the executor installer:
curl -fsSL <origin>/install-venya-executor.sh | sudo \
  VENYA_SKIP_PROMPT=yes \
  VENYA_SERVER_URL=https://<core-host> \
  VENYA_EXECUTOR_ID=<executor-id> \
  VENYA_EXECUTOR_ENROLLMENT_TOKEN=<token> \
  bash -s
```

The installer fetches the current CA from `/.well-known/venya-ca.crt`, updates system
trust (`install-venya-executor.sh:361-376`), writes `/etc/venya/executor/`, and
registers at install time (`:416-474`). The SSH user on provisioned hosts is `bot`
(there are no `venya-executor`/`venya-core` user accounts; the service account is
`venya`, nologin).

## 4. Revocation behavior (what an executor does when revoked)

- `venya admin revoke-executor <id>` adds the current cert SERIAL to the revocation
  list (`server/routes/admin.py:985-1030`).
- Executors poll the public list every main-loop iteration (~30 s —
  `daemon.py:948,977`; the `revocation_poll_seconds` config field is dead, ticket
  `executor-dead-rotation-config`). Endpoint (no auth): 
  `curl -sk https://<core-host>/api/v1/executors/certs/revocation-list`
- On detection: the daemon logs, sets `revoked`, and performs an ORDERLY stop
  (`daemon.py:950-953,1004-1020`) — in-flight commands are NOT force-aborted and
  injected secrets are NOT immediately zeroed by this path; the tmpfs reaper (TTL,
  default 300 s) and the next daemon start's sweep clean up (`daemon.py:614-688,858-862`).
- Fail-loud: 3 consecutive unreachable-server revocation checks
  (`max_revocation_failures`, `config.py:42-45`) → the executor self-revokes and stops
  (`daemon.py:963-971`).

## 5. Root CA backup and restore (break-glass)

The CLI's `--ca-dir` defaults to `/var/lib/venya/ca` (matches the server; fixed 2026-09-19
under ticket `cli-ca-dir-default-mismatch` — pre-fix CLIs defaulted to a nonexistent
`/etc/venya/ca`, so on older workstations pass `--ca-dir /var/lib/venya/ca` explicitly).
The examples below pass it explicitly anyway — harmless and version-independent.

```bash
# Encrypted export of the CA key (prompts for a passphrase — ⚠ the prompt currently
# ECHOES input, ticket export-ca-key-echoed-passphrase; prefer a private terminal):
venya admin export-ca-key --output /secure/venya-ca.key.enc --ca-dir /var/lib/venya/ca

# Shamir K-of-N split (writes share-01..share-NN):
venya admin split-ca-key -t 2 -s 3 -d /secure/shares --ca-dir /var/lib/venya/ca

# Public cert export (what executors/workstations hold):
venya admin export-ca-cert --output /secure/venya-ca.crt --ca-dir /var/lib/venya/ca

# Restore — from shares:
venya admin restore-ca-key --mode shares --shares share-01 share-02 --ca-dir /var/lib/venya/ca
# Restore — from encrypted backup:
venya admin restore-ca-key --mode backup --backup-file /secure/venya-ca.key.enc --ca-dir /var/lib/venya/ca
```

⚠ **Threshold not enforced (ticket `shamir-combine-no-threshold-verification`):**
restoring with FEWER than `threshold` shares silently reconstructs a CORRUPT key.
After any shares-restore, verify before trusting it:

```bash
# restored ca.key must pair with the surviving ca.crt:
openssl pkey -in /var/lib/venya/ca/ca.key -pubout -out /tmp/k.pub
openssl x509 -in /var/lib/venya/ca/ca.crt -pubkey -noout -out /tmp/c.pub
diff /tmp/k.pub /tmp/c.pub && echo "PAIRING OK" || echo "CORRUPT RESTORE — do not proceed"
```

## 6. KEK / secret-encryption rotation (independent of the TLS CA)

```bash
venya admin rotate-key                      # server generates the new KEK
venya admin rotate-key --new-key /secure/kek.bin
venya admin key-version rotate-status       # rotation job progress
venya admin key-version rollback <job-id>   # roll back a FAILED rotation job
venya admin key-version list --json         # versions + active flag
venya admin key-version deactivate <id>
venya admin key-version revoke <id>
```

Fresh installs seed one active `v1` key version (migration
`027_bootstrap_active_key_version.py`), so `venya store` never needs `--key-version`.

## 7. Full root-CA rotation (compromise) — the honest procedure

There is NO in-place CA-rotation command. The supported mechanism is the installer's
create-if-absent behavior: the CA is generated only when `/var/lib/venya/ca/ca.key` is
absent (`install-venya-core.sh:289-331`), while the server TLS cert, relay cert, system
trust, well-known copy, and nginx client-CA bundle are rebuilt on EVERY run
(`:335-457`). Rotating the root CA therefore means: remove it, re-run the installer,
then re-enroll every executor.

**Impact:** ALL executor client certs signed by the old CA become unverifiable — every
executor must re-register (§3). The admin CA under `/var/lib/venya/ca/admin-ca/` can be
PRESERVED (installer re-creates it only if absent, `:166-168`) — preserving it keeps
existing admin client certs valid for mTLS, but note the installer still RE-ISSUES the
`/etc/venya/admin/admin.crt|.key` pair each run (`:172-192`), so workstation copies
should be refreshed from the core afterwards. The database (users, secrets, KEK,
sessions) is untouched — secret encryption does not depend on the TLS CA.

```bash
# --- 0. Prepare: one enrollment token per executor (§3 step 1). Note the env vars
#        used at the original install (CORE_HOSTNAME, DB password, passphrases).
#        Read the current admin CA passphrase — you will need it to keep the admin CA:
sudo cat /etc/venya/venya-core.env        # VENYA_ADMIN_CA_KEY_PASSPHRASE=...

# --- 1. Stop the core service (nginx may stay up):
sudo systemctl stop venya-core

# --- 2. Back up, then remove the root CA keypair (KEEP admin-ca/ to preserve admin identity):
sudo cp -a /var/lib/venya/ca /secure/ca-backup-$(date +%F)
sudo rm -f /var/lib/venya/ca/ca.key /var/lib/venya/ca/ca.crt

# --- 3. Re-run the core installer with the SAME env vars as the original install,
#        passing the EXISTING admin CA passphrase (an unattended run without it
#        generates a NEW one and rewrites /etc/venya/venya-core.env, :124-137 —
#        that would silently break the preserved admin CA key decryption):
curl -fsSL <origin>/install-venya-core.sh | sudo \
  VENYA_SKIP_PROMPT=yes \
  VENYA_DB_PASSWORD=<original> VENYA_DB_PASSPHRASE=<original> \
  CORE_HOSTNAME=<original> \
  VENYA_ADMIN_CA_PASSPHRASE=<value from venya-core.env> \
  bash -s
# New CA generated; server + relay certs re-signed; system trust, well-known copy,
# and nginx bundle (root + admin) rebuilt; admin cert pair re-issued.

# --- 4. Verify the core:
curl -sk https://<core-host>/api/v1/health
# expect: {"status":"ok","checks":{"ca":"ok","admin_ca":"ok"}}

# --- 5. Every executor: re-install with a fresh token (§3). Runtime re-registration
#        is not possible (read-only /etc/venya).

# --- 6. Every workstation: refresh CA + admin cert copies, then re-login:
curl -sk https://<core-host>/.well-known/venya-ca.crt -o ~/.config/venya-ca.crt
ssh <core-host> "sudo cat /etc/venya/admin/admin.crt" > admin-cert/admin.crt
ssh <core-host> "sudo cat /etc/venya/admin/admin.key" > admin-cert/admin.key
chmod 600 admin-cert/admin.key
SSL_CERT_FILE=~/.config/venya-ca.crt venya login <user-id>   # FIDO2 touch

# --- 7. Smoke-test end to end:
venya run --executor-id <executor-id> -- /usr/bin/true
```

If the old CA private key was compromised, treat all material it signed as compromised:
prefer wiping `admin-ca/` too (fresh admin CA + fresh admin certs everywhere) over
preserving it, and rotate the KEK (§6) if secret ciphertext exposure is in scope.

## 8. Verification quick table

| Check | Command | Expected |
|---|---|---|
| Core health | `curl -sk https://<core-host>/api/v1/health` | `{"status":"ok","checks":{"ca":"ok","admin_ca":"ok"}}` |
| Revocation list reachable | `curl -sk https://<core-host>/api/v1/executors/certs/revocation-list` | JSON list (public endpoint) |
| Executor cert expiry | `sudo /opt/venya/.venv/bin/venya exec cert status` (on executor) | remaining days > 3 |
| Executor registered/ONLINE | `venya admin list` / `venya exec status` | executor ONLINE |
| CA keypair pairing after restore | §5 openssl diff | `PAIRING OK` |
| Rotation not failing silently | `journalctl -u venya-executor \| grep -i "rotation failed"` | no hits (until `executor-cert-rotation-erofs` is fixed, hits are EXPECTED near expiry — renew manually) |

## 9. Known issues affecting this runbook (tickets)

- `executor-cert-rotation-erofs` (H) — auto-rotation cannot persist on deployed units (§1)
- `cli-ca-dir-default-mismatch` — FIXED 2026-09-19 (default now `/var/lib/venya/ca`; pre-fix CLIs need explicit `--ca-dir`, §5)
- `shamir-combine-no-threshold-verification` (M) — verify pairing after shares-restore (§5)
- `export-ca-key-echoed-passphrase` (M) — echoed passphrase prompt (§5)
- `executor-dead-rotation-config` (L) — `revocation_poll_seconds` / `rotation_days` are inert (§4)
- `root-ca-key-plaintext-at-rest` — root CA key unencrypted at rest (§0)
- `executor-ero-fs-crash-loop-on-empty-token` (H) — never deploy an executor without an install-time token (§3)
