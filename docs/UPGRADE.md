# Upgrading Venya

**Provenance:** every command and expected-output line below was observed in a
physical core-server upgrade drill (v0.1.0alpha15 → v0.1.0alpha16, 2026-09-29)
unless the section is marked **not drill-exercised**. The drill evidence:
version capture + upgrade summary, pre-migration `pg_dump` ordered *before*
migrations, alembic head flip, health flip, operator `.env` key preservation
with secret continuity, unattended no-password re-run, wrong-password abort
state-intact, downgrade refusal (zero mutation) and knob honor (schema stays),
backup retention ≤ 3 with a pruning pass observed.

## Scope & model

An upgrade is **re-running the installer over the existing install** —
in-place, same host, same paths. Data, stored secrets, and the CA stack are
preserved.

One credential is not preserved: every run of the core installer mints a **new**
machine-plane admin credential at `/etc/venya/admin/` on that core. That pair is
the core's own and it is not copied to workstations, so nothing on a workstation
has to be refreshed after an upgrade — a person's administrator certificate comes
from the security-key ceremony instead
([installation.md](installation.md) §2), and the date the older hand-off copies
finally expire on is computed in
[cert-rotation-runbook.md](cert-rotation-runbook.md) §0.1.

Guaranteed by a version-changing re-run:

- **Stored-reuse, fail-loud.** The stored DB password, server passphrase, and
  recovery pepper are reused from `/opt/venya/.env`; an explicitly-passed
  value that does not match the stored one aborts the run before any change.
  A re-run whose stored file is gone is still fail-loud: the installer
  authenticates the existing PostgreSQL role before its first DB write and
  aborts with the remedy printed, rather than rotating the password silently.
- **A pre-upgrade backup before migrations.** Any version-changing re-run
  (up or down) takes a compressed `pg_dump` to `/var/backups/venya/` before
  migrations run. Same-version re-runs and fresh installs take none.
- **Operator config survives.** Keys you added to `/opt/venya/.env` are
  preserved across the regeneration (see "Operator .env keys").
- **Downgrades are refused** unless explicitly allowed (see "Downgrades").
- **The service is stopped for the migration window and proven on the new
  bytes before the run claims success.** The re-run halts
  `venya-core.service` before migrations (announced by a `NOTICE` — the schema
  must not move under a process still running the previous build, #587), then
  restarts it on the deployed bytes. The guard is a running unit, not a version
  change, so a same-version re-run pauses too; a first install never stops.
  No manual `systemctl restart` is needed. The run closes with a
  `PROOF-OF-FRESH-BYTES` line attesting the probes hit the new process; that
  proof is a gate — an unattested run says so in the transcript instead of
  printing `Installation verified successfully`. Plan a seconds-long
  interruption, not an outage. The full wording of both halves is in
  [installation.md](installation.md) §1.

NOT guaranteed: **the database schema never downgrades.** Alembic migrations
are forward-only; an allowed version downgrade leaves the schema at the newer
head (see "Downgrades" and "Rollback").

## Prerequisites

- **Disk:** a version-changing re-run writes a gzipped `pg_dump` of the full
  database and rebuilds the Python venv before migrations complete. Have at
  least (current DB dump size + one venv) free beyond normal headroom.
- **Version guard:** the installer reads the installed version and the
  incoming tarball's version and compares them. A downgrade without the knob
  exits 1 **before the tarball is even extracted** — zero mutation.
- **Backups:** `/var/backups/venya/` (dir `0700`, root-owned), files
  `pre-upgrade-<from>-to-<to>-<UTC-stamp>.sql.gz` (mode `0600`, root-owned).
  The **3 newest are kept**; the 4th backup prunes the oldest (pruning
  observed in the drill).
- **Integrity:** the tarball is always SHA-256-verified (`SHA-256 verified.`).
  Set `VENYA_TARBALL_SHA256` to supply the expected hash; unset, the installer
  fail-closed fetches the release's `.sha256` sidecar from the same origin.

## Core upgrade procedure

Run on the core host, as root (via sudo), with the script AND tarball pinned
to the same release tag:

```bash
TAG=v0.1.0alpha16   # the tag you are upgrading to
curl -fsSL "https://github.com/tabith-llc/venya/releases/download/${TAG}/install-venya-core.sh" \
  | sudo VENYA_SKIP_PROMPT=yes \
      VENYA_TARBALL="https://github.com/tabith-llc/venya/releases/download/${TAG}/venya-core-install.tar.gz" \
      bash -s
```

**Pin both, same tag.** The script and the tarball are separate release
assets, and a tag-published script still defaults to pulling its tarball from
`releases/latest/download` — without the `VENYA_TARBALL` pin, script version
and package version can silently disagree. The tag's directory serves the
tag-exact tarball, `venya-common.sh`, and the checksum sidecar.

An upgrade re-run needs **no secrets** — the stored DB password, passphrase,
and pepper are reused from `/opt/venya/.env` (a fresh install needs
`VENYA_DB_PASSWORD`/`VENYA_DB_PASSPHRASE`; see
[installation.md](installation.md) §1). The one exception is the passphrase
floor: a re-run whose STORED `VENYA_DB__PASSPHRASE` is under 15 Unicode code
points refuses at the installer's pre-mutation gate, because carrying it forward
would boot on a KEK the core now rejects. That is a deliberate reinstall (or a
deliberate rotation), never a silent pass.

Drill-observed key output, in this order (order is the guarantee):

```
[INFO]  Installed version: 0.1.0alpha15
[INFO]  Upgrade: 0.1.0alpha15 -> 0.1.0alpha16
[INFO]  SHA-256 verified.
[INFO]  Preserved 1 operator-added .env key(s) across regeneration.   (only when operator keys exist)
[INFO]  Backing up database before migrations -> /var/backups/venya/pre-upgrade-0.1.0alpha15-to-0.1.0alpha16-<UTC-stamp>.sql.gz
[INFO]  Backup complete: 8.0K
[INFO]  Running database migrations...
Database migrations complete.
```

The backup lines appear **before** the migration lines — no backup, no
upgrade. The transcript above was captured in the 2026-09-29 drill, which
predates #587: a re-run on a current build prints two `NOTICE` lines about the
deliberate service stop immediately **before** `Running database migrations...`,
and a `PROOF-OF-FRESH-BYTES` line further down. Both are recorded in
[installation.md](installation.md) §1; nothing was re-observed in a drill on a
post-#587 build at the time of writing. Verify afterwards:

```bash
curl -sk https://<core-host>/api/v1/health
# {"status":"ok","version":"0.1.0alpha16","checks":{"ca":"ok","admin_ca":"ok"}}

sudo -u postgres psql -d venya -t -c "SELECT version_num FROM alembic_version;"
# the migration head shipped with the release (drill: 029 -> 030)
```

A `502` for the first seconds after the flip is the known settle window —
re-probe (Troubleshooting below).

## Unattended re-runs

- **No `VENYA_DB_PASSWORD` needed.** The stored value is reused like the
  other stored secrets. Drill-observed line:
  `Existing install: reusing stored PostgreSQL password from /opt/venya/.env (VENYA_DB_URL).`
  A same-version re-run also reports `Version: <v> (same-version re-run)` and
  takes **no** backup (nothing can change schema).
- **An explicit value must match.** Passing a wrong `VENYA_DB_PASSWORD` aborts
  with `VENYA_DB_PASSWORD does not match the password stored in /opt/venya/.env
  (VENYA_DB_URL).` … `Aborting — no changes made.` and exit 1. Drill-verified
  state-intact: health and backup inventory unchanged after the abort.
- **Stored `.env` gone (for example, after a partial wipe).** The installer
  proves that any existing database role authenticates with the supplied
  password BEFORE the first DB write; a stale role aborts with
  `The PostgreSQL role 'venya' exists but does not authenticate with the
  password this install will use.` … `Aborting — no changes made.` Re-run with
  the role's actual password, or rotate deliberately with `ALTER USER` and
  re-run carrying the new one — rotation is always a manual, deliberate act.
- The server passphrase and recovery pepper follow the same
  reuse-or-must-match rule (their own messages).

## Operator .env keys

`/opt/venya/.env` is regenerated on every re-run, but **only the 13 managed
keys are owned by the installer template**: `VENYA_HOST`, `VENYA_DB_URL`,
`VENYA_DB__DATABASE_URL`, `VENYA_DB__PASSPHRASE`, `VENYA_FIDO2__RP_ID`,
`VENYA_FIDO2__RP_NAME`, `VENYA_CORS__ORIGINS`, `VENYA_RECOVERY_CODE_PEPPER`,
`VENYA_ADMIN_MTLS__ENABLED`, `VENYA_ADMIN_MTLS__CA_CERT`,
`VENYA_ADMIN_MTLS__KNOWN_ADMIN_IDS`, `VENYA_MTLS_CERT`, `VENYA_MTLS_KEY`.

Every other line starting at column 0 with `VENYA_` (e.g.
`VENYA_SESSION__ACCESS_TOKEN_TTL=28800`) is captured before regeneration and
re-appended after it under the marker:

```
# --- operator-added keys preserved across re-run (installer) ---
```

with the info line `Preserved N operator-added .env key(s) across
regeneration.` In the drill the probe key survived every re-run (upgrades, a
knob downgrade, same-version re-runs), each template key appeared exactly once
after every regeneration, and the stored secret values stayed byte-identical
(verified by hashing, never by displaying).

Notes:

- **Managed-key overrides do not survive** a re-run — the template rewrites
  them. Use non-managed keys for tuning.
- Precedence is dotenv last-wins within the file: the preserved block sits at
  the end, so a duplicate line there wins over a template line above it —
  until the next re-run drops it if it duplicates a managed key.

## Downgrades

Refused by default, exit 1, **before extraction** (drill-verified zero
mutation — health, backups, and `.env` all unchanged afterwards):

```
[ERROR] Refusing to downgrade: installed 0.1.0alpha16, tarball 0.1.0alpha15.
[ERROR] Alembic migrations never run in reverse automatically — old code on a newer
[ERROR] schema is undefined behavior. If this is deliberate: VENYA_ALLOW_DOWNGRADE=yes.
```

Reason: alembic migrations are forward-only; old code on a newer schema is
undefined behavior.

With `VENYA_ALLOW_DOWNGRADE=yes` the run proceeds after two loud warnings
(verbatim):

```
[WARN]  DOWNGRADE 0.1.0alpha16 -> 0.1.0alpha15 allowed by VENYA_ALLOW_DOWNGRADE=yes.
[WARN]  The database schema is NOT downgraded; old code on a new schema is unsupported.
```

Drill-observed knob behavior: a pre-upgrade backup IS taken, the run completes
healthy on the older version, and `alembic_version` is UNCHANGED — the schema
stays at the newer head. That is the documented honest behavior, not a bug.

**Hazard — never downgrade by running the OLD installer.** Pre-alpha16
installers carry no version guard, no pre-upgrade backup, and no `.env`
preservation. In the drill, running the alpha15 installer over a newer install
reinstalled old code, overwrote `/opt/venya/.env` (operator keys lost),
regenerated CA material, and exited 0 even with PostgreSQL down. Always
downgrade with the **current** installer script + `VENYA_TARBALL` pinned to
the older tarball + the knob.

## Rollback

Migrations are forward-only, so the honest rollback is: **restore the
pre-upgrade database, reinstall the older version.**

1. Restore the `pre-upgrade-…sql.gz` dump from `/var/backups/venya/` into the
   `venya` database. The dump is plain `pg_dump | gzip`. What a database dump
   is and is not (it is half of a paired secret set) is covered by
   [BACKUPS.md](BACKUPS.md) — read its "pairings" section before restoring;
   its restore procedure carries that document's own honest caveat: it is
   alpha-documented and not yet validated by a full restore drill.
2. Reinstall the older version with the **current** installer: pin `TAG` and
   `VENYA_TARBALL` to the older tag and pass `VENYA_ALLOW_DOWNGRADE=yes`
   (schema-stays warning applies — your restored dump carries the old schema,
   which is exactly why step 1 must come first).

The drill verified the dumps themselves (`gzip -t` OK, pg_dump header read on
each) but did not run a restore drill.

**What a failed upgrade can leave.** The version-guard refusal happens before
extraction — that path is zero-mutation (proven). Failures AFTER that point
(database unstartable, migrations erroring, `/var/backups/venya` not
creatable) can leave the incoming tarball's code already extracted and the
venv rebuilt on disk while the database is unchanged; one completing run in
either direction restores consistency (observed in the drill). The
`Pre-upgrade pg_dump FAILED — aborting BEFORE migrations (no backup, no
upgrade).` abort is **unit-tested only**: the drill could not realize it on a
stock installer without fault injection, because the installer itself starts
PostgreSQL before the backup step and the dump runs as the `postgres` system
user (peer auth — a wrong app password cannot break it). If the backup
directory itself is unwritable, the installer exits on the shell error at
directory setup, before printing that documented message. In every
failure variant the drill observed, migrations never ran against a broken or
absent database.

## Executor upgrade (not drill-exercised)

The drill was core-only. The executor upgrade surface is a re-run of
`install-venya-executor.sh` with the same script+tarball tag-pin pattern: the
executor installer is idempotent, reuses the `dns_resolver` from the existing
`/etc/venya/executor.toml`, and existing registration/certificates survive the
re-run. Executor re-run idempotency was proven in the alpha14 fleet session —
**not** by this drill; treat it as documented, not drill-proven.

## CLI / MCP upgrade (not drill-exercised)

Re-run `install-venya-cli.sh` on the workstation (non-root, no sudo): it
re-installs both `venya` and `venya-mcp` with `uv tool install --force`,
swapping the `~/.local/bin` shims to the new versions in place. Not exercised
by this drill.

## Troubleshooting

- **`502` right after the health flip:** the known post-install settle window;
  re-probe `api/v1/health` (see [installation.md](installation.md)
  Troubleshooting).
- **Health still reports the OLD version after a re-run:** look for the
  restart NOTICE and the `PROOF-OF-FRESH-BYTES` line in the installer output —
  the re-run contract restarts the service when the process predates the new
  bytes ([installation.md](installation.md) §1). A `VERIFICATION NOT CLAIMED`
  line means that proof did not land and the run said so rather than claiming
  a verification it could not stand behind; re-run the installer (it is
  idempotent) after checking the unit.
- **First sandbox command after an executor re-install:** seconds-scale (the
  installer warms the sbx template); cold-start guidance in
  [installation.md](installation.md) Troubleshooting.

## Related

- [installation.md](installation.md) — fresh install, env variables, re-run contract
- [BACKUPS.md](BACKUPS.md) — what the pre-upgrade dump is paired with
- [deployment-config.md](deployment-config.md) — `.env` key meanings
