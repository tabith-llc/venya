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
| Root CA keypair | core: `/var/lib/venya/ca/ca.key` (0600), `ca.crt` | manual break-glass only (§5) | key ENCRYPTED at rest since fix `4218ec1` (ticket `root-ca-key-plaintext-at-rest`, CLOSED 2026-09-20); passphrase `VENYA_CA_KEY_PASSPHRASE` in `/etc/venya/venya-core.env` (0640 root:venya), reused on re-run — an explicit wrong value fails loudly at decrypt |
| Admin CA keypair | core: `/var/lib/venya/ca/admin-ca/` | manual (§7) | key ENCRYPTED; passphrase in `/etc/venya/venya-core.env` (0640 root:venya) |
| Server TLS leaf | core: `/etc/venya/tls/server.crt|.key` | 365 days; re-signed on every installer run (`install-venya-core.sh`, the `Server TLS certificate signed with Venya CA` block) | CN + SAN DNS = `CORE_HOSTNAME` |
| Relay client cert | core: `/etc/venya/relay/relay-client.crt|.key` | regenerated on installer run (the `Relay client certificate signed and verified` block) | CN `<core-hostname>-relay`; must appear in executors' `relay_client_ids`. Registered in `core_relay_credentials` at core boot and revocable — see § Revoking the core's relay client credential (#597) |
| Executor client cert | executor: `/etc/venya/executor/executor.crt|.key` (ca.crt alongside) | 30 days (`EXECUTOR_VALIDITY_DAYS = 30`, server `ca.py`); auto-rotation attempted 3 days before expiry (`rotate_before_days`, executor `config.py`) | Auto-rotation persistence FIXED 2026-09-19 (ticket `executor-cert-rotation-erofs`, §1); pre-fix hosts need the unit refresh; manual path: §2 |
| Admin client certs | core (machine plane): `/etc/venya/admin/admin.crt|.key` · person (human plane): a workstation path you choose | core pair: 90 days (`ADMIN_CERT_VALIDITY_DAYS`, `server/ca.py`), re-minted every installer run · person's certificate: 60 minutes, minted by ceremony (note below) | manual rotation: §7; the two credentials are different things and rotate differently |
| Secret-encryption KEK + key versions | core: database + server config | `venya admin rotate-key` (§6) | independent of the TLS CA hierarchy |

**Admin client certificates also have a renewal path of their own.** The row
above covers the installer-driven re-issue; routine expiry is minted on the
workstation with `venya admin cert renew`, which generates a fresh keypair
locally and writes the new certificate and its private key to the configured
pair. The mint rides a login session plus one security-key ceremony and never
presents the old certificate, so an expired leaf does not block the request.
One limit is stated here because operator text should carry it rather than hide
it: the private key is written encrypted at rest, and the CLI cannot yet load an
encrypted admin key for admin mTLS, so the renewed pair does not serve
certificate-authenticated admin commands until that read-side work lands
(#565, Part B). Exact flags: `cli-reference.md` (generated). What an interactive
desktop ceremony requires, including on Windows, is covered in `faq.md` and
`installation.md` and is deliberately not restated here.

### 0.1 The age-out date for a certificate an installer used to hand to a workstation

**Published date: 2027-01-10.** It is computed, not chosen, and the inputs are these:

| Input | Value | Where it was read |
|---|---|---|
| Lifetime of the pair the installer mints | 90 days | `ADMIN_CERT_VALIDITY_DAYS = 90`, `packages/server/src/server/ca.py` (Admin CA constants block; consumed by `AdminCAManager.sign_admin_cert`) |
| Cut-over — the run of the installer that stopped printing the copy instruction | 2026-10-12 | `2b70210` 11:35:25 -0600, merged into `dev` as `832c11c` 11:36:13 -0600 (RF-10) |
| Sum | **2027-01-10** | `date -u -d "2026-10-12 + 90 days"` → 2027-01-10 |

**Which number is enforced where**, because two of these lifetimes are one hour apart
in name only and a third number nearby is not a lifetime at all:

- **90 days** — `ADMIN_CERT_VALIDITY_DAYS = 90`, `packages/server/src/server/ca.py` (the Admin CA
  constants block), enforced in `AdminCAManager.sign_admin_cert` as
  `not_valid_after(now + timedelta(days=ADMIN_CERT_VALIDITY_DAYS))`. This is the machine-plane pair
  the installer mints, and it is the input to the date above.
- **60 minutes** — `ADMIN_SHORT_CERT_LIFETIME_SECONDS = 3600`, same block, enforced by the
  human-plane mint: `routes/admin_certs.py`, `admin_issue_cert` calls `sign_admin_csr` with
  `lifetime_seconds=ADMIN_SHORT_CERT_LIFETIME_SECONDS`. A person's certificate, not the core's.
- **Not a lifetime:** the `next_update(now + timedelta(hours=1))` stamps in `CAManager.generate_crl`
  and `AdminCAManager.generate_crl` are how often a **revocation list** goes stale. They read like
  an hour and mean something else entirely — never cite them as a credential lifetime.

The clock starts at the cut-over because the age-out is about the **handoff**: an
install made with an installer that still told you to copy the pair mints a
credential that lives 90 days from *that* install. So the published date is a floor,
not a guarantee, and one fact about the cut-over matters to it: the banner change
(`2b70210`, subject "installer: the admin banner points at the ceremony, not a copied
key") landed on the development branch — that branch has since been rewritten, so read
it by subject rather than trusting the number — and when this file was written the
newest published tag (`v0.1.0alpha16`, 2026-09-27) still printed the old copy
instruction. That alpha line is withdrawn by owner order (2026-10-18), so the sentence
above is a dated reading of a release being retired, and `v0.1.0beta1` is the first
release to be published that carries the new banner. Until an operator installs from a
release that carries it, an install still mints an old-shape pair,
and that install's own closure date is its install day plus 90 days — readable, not
guessable, on the core that holds it:

```bash
sudo openssl x509 -in /etc/venya/admin/admin.crt -noout -enddate
```

Re-anchor this section on the release that first ships the new banner.

- **What the date means:** up to it, a credential minted by a pre-cut-over installer
  — including one copied to a workstation — is still valid on its own schedule. Past
  it, nothing such an installer minted can still authenticate anywhere.
- **What it does NOT mean: this is not a revocation mechanism.** Under the two-plane
  ruling, lifetime stopped being the revocation mechanism and became purely the theft
  window. Removing a person's administrator role takes effect on their next request;
  revoking a certificate serial is what closes an exposure early, and it costs a
  lockout if you pick the wrong serial — the same serial may be the core's own
  machine-plane credential.
- **The honest limit:** nothing in the product knows where copies were made. A copy
  taken before the cut-over dies on the date above unless its serial is revoked; a
  copy made from an older build dies 90 days after that build's own mint.
- **The skew tail:** a certificate is admitted until `not_valid_after` plus the
  deployment's `VENYA_CLOCK_SKEW__CERT_TOLERANCE_SECONDS` (default 60 s,
  `ClockSkewConfig.cert_tolerance_seconds`, `packages/server/src/server/config.py`),
  so the last usable instant is the date above plus that tolerance — read the
  deployment's value rather than assuming the default.

nginx terminates TLS on :443 and proxies to the backend over the inner-mTLS
channel: uvicorn serves TLS on the loopback bind only and nginx presents the
relay client certificate (`install-venya-core.sh`, the nginx site config block
with `proxy_pass https://127.0.0.1:8080`). The port is unreachable from other
hosts; all verification curls below go through `https://<core-host>/…`.

## Revoking the core's relay client credential (#597)

The same relay client certificate is used in two places, and they are not the same
exposure: nginx presents it on the **loopback** inner-mTLS hop above, and the core
presents it when it **dials an executor's :8443** listener
(`routes/executors.py`, inside `execute_command_on_executor` — the dial URL is
`https://<executor-hostname>:8443/execute`). Losing the second one means a stolen
credential can keep relaying commands, so it now has a revocation path.

It did not used to. The credential is minted by `install-venya-core.sh` with `openssl`
and historically entered no table, so there was nothing to revoke it *in* — a
compromised core relay credential had no kill switch, and no list could name it at the
executor door.

1. **See what the deployment holds.** The registry is populated by the core itself at
   boot (`server/relay_registry.py`, the function `ingest_relay_credential`), which
   registers the certificate the process actually presents:

   ```
   venya admin core-relay-cert list
   ```

   The serial printed there is what you revoke. Do not copy a serial out of `openssl x509
   -serial` off a disk file and assume it is registered — if the core has not booted since
   the file changed, it will not be.

2. **Revoke it, by serial or straight off the file:**

   ```
   venya admin core-relay-cert revoke --serial <hex-serial> --reason "host decommissioned"
   venya admin core-relay-cert revoke --cert-file /etc/venya/relay/relay-client.crt
   ```

   The second form reads the serial off the certificate, which is the safer one when you
   are standing on the core.

3. **A serial the registry does not name is REFUSED**, with `REFUSE_UNREGISTERED` and the
   remedy in the message. This is deliberate: accepting a revocation for a credential the
   store cannot name would let "revoked" mean nothing, and an empty store must never act
   as an allowlist. Register it first (`venya admin core-relay-cert register --cert-file
   <path>`) or restart the core, then revoke.

4. **Propagation is not instantaneous.** The executor learns revoked peers from the
   revocation poll it already runs (~30 s, `REVOCATION_LIST_PATH` in `executor/daemon.py`),
   and the refusal lands on **new** connections only — a relay call already in flight is
   not terminated. That boundary is the owner's ruling and is not a knob.

5. **Revocation is terminal.** There is no un-revoke; the credential's row keeps its
   `revoked_at` across a reboot, and re-minting the file (a fresh installer run) creates a
   row for the NEW serial and leaves the revoked one revoked. Re-enrolment means a new
   credential, same law as an executor identity.

## 1. Executor certificate auto-rotation (design + deployment caveat)

Design (daemon `CertManager`, `packages/executor/src/executor/daemon.py:239-323`):

1. Every main-loop iteration (~30 s) checks `needs_rotation()`: cert expires within
   `rotate_before_days` (default 3), or is already expired.
2. `rotate()` generates a fresh ECDSA P-256 keypair + CSR and POSTs it to
   `/api/v1/executors/register` (same endpoint as enrollment; server replaces the cert
   record and returns `cert_pem` + `ca_cert_pem` + serial + expiry).
3. The daemon validates the new cert against the CA, then writes cert/key/ca to disk.

**Deployment caveat (FIXED 2026-09-19, ticket `executor-cert-rotation-erofs`):** units
installed BEFORE the fix set `ReadOnlyPaths=/etc/venya` without the identity dir in
`ReadWritePaths`, so step 3 died EROFS *after* the server had already replaced the cert
record — retries every ~30 s burned server state and lost each fresh keypair, and the
executor died unrecoverably at day 30 (an expired cert cannot even `renew` — the mTLS
handshake fails first; only §3 re-registration works). The fix: the unit now carries
`ReadWritePaths=... /etc/venya/executor`; `rotate()` refuses BEFORE contacting the server
when the cert dir is unwritable; and the in-memory serial adopts the new cert only after
all disk writes succeed. **Pre-fix deployed hosts** need the corrected unit: re-run the
executor installer (refreshes the unit) or add a drop-in:

```bash
sudo systemctl edit venya-executor   # add: [Service] / ReadWritePaths=/etc/venya/executor
sudo systemctl daemon-reload && sudo systemctl restart venya-executor
```

Watch for the historical failure signature on un-upgraded hosts:

```bash
sudo journalctl -u venya-executor | grep -i "rotation failed"
```

Residual structural note (ticket `executor-revocation-by-identity` — CLOSED by
the hybrid identity model): if a write fails between the register POST and
persistence (e.g. ENOSPC), the server record and the on-disk cert diverge.
Since the identity rulings (2026-09-20) this no longer defeats revocation:
replacing the record serial AUTO-REVOKES the predecessor in the same
transaction (the diverged daemon dies within one poll), identity-level
revocation matches regardless of which serial the daemon presents, and the
dial gates refuse a revoked identity/record-serial server-side. The pre-check
from the EROFS fix remains as the availability narrowing.

**require_token (default TRUE since ticket `executor-rotation-require-token-400`,
Phases 1+2, 2026-09-20):** the register endpoint rejects tokenless POSTs by default.
Since Phase 2, `rotate()` is EXEMPT: a tokenless rotation is accepted only if the caller
presents a verified mTLS client cert whose revocation state is clean (the shared
`executor_revocation_state` — identity flag first, then serial history) AND whose serial
equals the current `ExecutorCert` record serial for that executor_id (ruled order:
revocation check FIRST). New identities and bootstrap installs still require a token. A
rotation 400 under the exemption means the presented cert is not the record credential
(revoked, diverged, or replaced) — re-register with a fresh token per §3 before expiry.
**Trust boundary:** the exemption consumes the outer client certificate that nginx
forwards as HEADER CONTENT (`X-Client-Cert-PEM`, URL-encoded PEM via the stock
`$ssl_client_escaped_cert` variable, #314 — the former `X-Client-Verified` /
`X-Client-Subject` / `X-Client-Serial` header chain is retired); nginx verifies the
client chain against `/etc/nginx/ssl/client-ca-bundle.crt` (Root CA + Admin CA), and the
app percent-decodes the PEM and re-verifies it cryptographically — identity and serial
are read from the verified certificate object, no forwarded header is trusted as
identity, and with no client cert the exemption simply never applies. The CN match is a
discriminator, not the authorization: the authorization is the Root-CA-issued record
serial (random 64-bit at signing, no serial-chooser API exists), which an Admin-CA cert
— even one shaped with an executor CN — cannot carry. Both phases ship in the same
release (tag-cut gate); never run Phase-1-only bytes in production past a 30-day cert
lifetime. Do NOT set `VENYA_EXECUTOR_ENROLLMENT__REQUIRE_TOKEN=false` in production
(open enrollment — physically proven to mint executor identities from ANY host reaching
the core).

## 2. Manual executor cert operations (working path)

Run ON the executor host. The CLI is installed in the executor venv; writes need root
(the unit's read-only mount does not apply to manual shells):

```bash
sudo /opt/venya/.venv/bin/venya exec cert status                 # expiry + remaining days
sudo /opt/venya/.venv/bin/venya exec cert renew                  # CSR via existing mTLS identity, atomic write
sudo /opt/venya/.venv/bin/venya exec cert renew --cert-path /etc/venya/executor/executor.crt
```

**The executor key is encrypted at rest (#565), so both `renew` and `register` need
the passphrase.** `cert renew` reads the incumbent key to authenticate the renewal and
then writes the new one as an encrypted envelope, so the process must see
`VENYA_EXECUTOR_KEY_PASSPHRASE` — the same variable the `venya-executor` service reads
from the installer's root-only `EnvironmentFile`. Two shapes, both supported:

```bash
# reuse what the service already has (sudo strips the environment, so pass it in):
sudo VENYA_EXECUTOR_KEY_PASSPHRASE="$(sudo sed -n 's/^VENYA_EXECUTOR_KEY_PASSPHRASE=//p' /etc/venya/venya-executor.env)" \
  /opt/venya/.venv/bin/venya exec cert renew

# or run it interactively and answer the hidden prompt (the write-time ceremony)
sudo -E /opt/venya/.venv/bin/venya exec cert renew
```

Without either, the command refuses and writes NOTHING — no directory, no staged temp,
no half-renewed key, and no request sent (a renewal that POSTed first would replace the
server-side certificate record before discovering it cannot store the key). A key
written by an EARLIER release is plaintext on disk and still reads normally; the
requirement applies to the next write, so set the passphrase once and rotate.

This is disk protection by a file passphrase, **not** hardware-key custody: the
passphrase lives on the host, delivered through the service environment. The interim
exemption and its retirement trigger are written up in
`docs/design-fido2-keywrap-565.md` §6 (owner ruling R7-Q3).

`renew` authenticates with the CURRENT cert — run it while the cert is still valid
(the same 3-day window the daemon uses). If the cert already expired, re-register
instead (§3).

Revoke (admin action, on the core with its machine-plane pair — with admin mTLS
enabled, which is the default, an admin request that carries no client certificate is
refused 403, so a session alone is not a path here; the session arm applies only on an
install made with admin mTLS off):

```bash
VENYA_ADMIN_CERT=/etc/venya/admin/admin.crt VENYA_ADMIN_KEY=/etc/venya/admin/admin.key \
  venya admin revoke-executor <executor-id>
# or, targeting the executor's own cert from the executor host:
sudo /opt/venya/.venv/bin/venya exec cert revoke --executor-id <executor-id>
```

## 3. Re-registering an executor (lost/expired cert, or after CA rotation)

**Terminal identities:** if the executor was revoked with the IDENTITY form
(`revoke-executor <id>`, no `--serial`), it can NEVER re-register — even with a
valid fresh token (the 403 fires after token validation; the token's
consumption rolls back with the request, so it expires unused rather than
burning). Re-enroll under a NEW executor_id. Serial-form revocation does not
block re-registration (it kills one credential, not the identity).

Runtime (daemon-side) registration cannot write `/etc/venya/executor` either
(`daemon.py:118-136` fails closed), and since ticket
`executor-rotation-require-token-400` Phase 1 the server additionally rejects
tokenless registration by default (bootstrap/new identities — incumbent
rotation is exempt, §1) — an empty-token install now exits 1 at boot
with an actionable journal error naming `executor_enrollment.require_token`
(no crash-loop; the historical EROFS variant is ticket
`executor-ero-fs-crash-loop-on-empty-token`). The supported path is install-time
registration with a bootstrap token:

```bash
# 1. On the core (that is where the machine-plane admin pair lives — §0.1):
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
trust (the `Venya CA installed to system trust store` block of
`install-venya-executor.sh`), writes `/etc/venya/executor/`, and
registers at install time (the `Register mTLS certificate (if enrollment token provided)` block). The SSH user on provisioned hosts is `bot`
(there are no `venya-executor`/`venya-core` user accounts; the service account is
`venya`, nologin).

## 4. Revocation behavior (identity + serial, hybrid model)

Revocation state has ONE source (`server/revocation.py`,
`executor_revocation_state`): the IDENTITY flag (`Executor.revoked_at`) is
checked FIRST, then serial history (presented serial, else the current
`ExecutorCert` record serial).

**Two admin forms** (`venya admin revoke-executor <id> [--serial <hex>]`):

- **Identity form** (no `--serial`): sets `revoked_at` — **TERMINAL for alpha**
  (no un-revoke exists; re-enrollment requires a NEW executor_id, §3) — and
  CRLs the current record serial. Dial gates
  (`create_execution_session`/`execute`) refuse immediately with 403 — this is
  the control that stops an UNCOOPERATIVE daemon (command routing is
  core→executor push; nothing else can). The relay dial adds two operational
  refusals beside it (#586): no registered certificate, or an expired record, is a
  503, not a 403 — the credential is unusable, not killed. Registration under a
  revoked identity
  403s even with a valid fresh token (the token is NOT burned — the 403 rolls
  back its consumption; it expires unused).
- **Serial form** (`--serial <hex>`): CRLs ONE credential without touching the
  identity — the incident tool for orphaned/predecessor serials (e.g. a serial
  replaced by an admin-side re-register). A serial form on the CURRENT RECORD
  SERIAL also refuses dial (the shared state checks the record serial when none
  is presented); a serial form on a stale/off-record serial does not.

**Auto-revoke on replacement:** every re-registration/rotation CRLs the
REPLACED serial in the same transaction — normal operation no longer mints
off-record chain-valid orphans, and a daemon diverged onto a predecessor cert
dies within one poll.

**Executor-side detection:**
- Poll of the public list every main-loop iteration (~30 s): matches own
  serial (`revoked_serials`) OR own executor_id (`revoked_identities` —
  distinct TERMINAL warning naming the new-executor_id remedy). Endpoint (no
  auth): `curl -sk https://<core-host>/api/v1/executors/certs/revocation-list`
- Heartbeat response `revoked` flag is consumed too (fast stop between polls;
  advisory — the poll stays authoritative).
- On detection: the daemon logs, sets `revoked`, and performs an ORDERLY stop —
  in-flight commands are NOT force-aborted and injected secrets are NOT
  immediately zeroed by this path; the tmpfs reaper (TTL, default 300 s) and
  the next daemon start's sweep clean up.
- Fail-loud: 3 consecutive unreachable-server revocation checks
  (`max_revocation_failures`, `config.py`, `CertificateRotationConfig`, valid range 1-1000) → the executor STOPS as an
  operational fault. #603: this is not a self-revocation — the core asserted
  nothing about the credential, and the refusal it produces is the 503 class
  below, never `403 REVOKED`.

**Relay-listener accept gate (#586, owner-ruled option 3).** The listener on :8443
consults the ONE revocation answer this side holds (`DaemonState.revoked`, plus a
boot-scope "has the core answered?" flag) on every NEW connection, after the TLS
handshake and before a single request byte is read. It holds no copy of the
revocation list and does no serial matching of its own — `server/revocation.py` is
the one rulebook and a second implementation is the split-brain its contract comment
forbids. Three states, two of them refusals:

| State at accept | Outcome | Journal line (grep-able) |
|---|---|---|
| core answered, credential live | admitted, `/execute` runs as before | `Executor relay listener started …` |
| `revoked` (poll answer, or heartbeat flag — a server assertion ONLY) | connection closed, no HTTP response | `Relay :8443 refused a new connection from <ip>:<port> — 403 REVOKED …` |
| no answer yet this boot / fault-threshold stop / no state wired | connection closed, no HTTP response | `… — 503 OPERATIONAL FAULT — no revocation answer received …` |

**Read the two refusals apart.** `403 REVOKED` means an admin killed this
credential. `503 OPERATIONAL FAULT` means this daemon has not been able to ASK —
the remedy is core reachability, not re-enrollment. The bootstrap window is short by
construction: the relay binds and the FIRST revocation poll runs in the same
main-loop entry, so the refused window is one HTTP round trip, and a core that stays
unreachable ends the process at the failure threshold above anyway — as a fault, and
it is refused and journalled in the 503 class, not as a revocation (#603).

**What this does NOT claim.** Enforcement is post-handshake: a revoked peer
credential completes the TLS handshake and is refused at accept, so the honest
sentence is "a revoked credential is refused when the connection is admitted, before
any request is served" — not "refused at the handshake". Connection-layer CRL
consultation (at the proxy or in the TLS stack) is a different, unadopted option; and
no CRL Distribution Point is published by default (`crl_url` defaults to None and no
installer sets `VENYA_CRL__CRL_URL`), so nothing in this runbook should be read as
saying one exists.

**Lifecycle:** the identity flag dies only with the Executor row — never via
the CRL retention purge. The CRL table (`crl_retention_days`, default 90) is
append-only serial history + advisory broadcast; purge-dropped serial rows are
expected, not a bug (the identity flag is the enforcement truth).

**Admin client-cert revocation** (separate table, `admin_cert_revocations`):
the supported path is `venya admin revoke-admin-cert <serial>` (ORM — sets
`revoked_at` automatically). The table has NO server-side default for
`revoked_at` (Python-side lambda only): a raw-SQL INSERT omitting the column
violates NOT NULL — supply `revoked_at` explicitly (e.g. `now()`) in any
manual insert (ticket delta-b-run-low-bundle O6; ruled runbook-note, not
migration — raw SQL is not a supported revocation path).

## 5. Root CA backup and restore (break-glass)

The CLI's `--ca-dir` defaults to `/var/lib/venya/ca` (matches the server; fixed 2026-09-19
under ticket `cli-ca-dir-default-mismatch` — pre-fix CLIs defaulted to a nonexistent
`/etc/venya/ca`, so on older workstations pass `--ca-dir /var/lib/venya/ca` explicitly).
The examples below pass it explicitly anyway — harmless and version-independent.

```bash
# Encrypted export of the CA key (prompts for a passphrase, hidden input —
# fixed 2026-09-19 under ticket export-ca-key-echoed-passphrase; pre-fix CLIs
# ECHOED the prompt):
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

**Threshold + integrity enforcement (fixed 2026-09-19, ticket
`shamir-combine-no-threshold-verification`):** V2 share files carry the threshold K
and a checksum — restore with fewer than K shares, corrupt files, or files from
different splits now fails loudly instead of silently writing a corrupt key.
PRE-V2 share files (split before the fix) restore with the old unverified behavior
(the CLI warns) — for those, and as general practice after ANY shares-restore, verify
before trusting:

```bash
# restored ca.key must pair with the surviving ca.crt:
openssl pkey -in /var/lib/venya/ca/ca.key -pubout -out /tmp/k.pub
openssl x509 -in /var/lib/venya/ca/ca.crt -pubkey -noout -out /tmp/c.pub
diff /tmp/k.pub /tmp/c.pub && echo "PAIRING OK" || echo "CORRUPT RESTORE — do not proceed"
```

## 6. KEK / secret-encryption rotation (independent of the TLS CA)

```bash
venya admin rotate-key                      # server generates the new KEK
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
absent (`install-venya-core.sh`, the `if not ca_key_path.exists()` branch through the
`CA already exists - preserved` print), while the server TLS cert, relay cert, system
trust, well-known copy, and nginx client-CA bundle are rebuilt on EVERY run
(the server-TLS, relay/inner, trust-store, well-known, and bundle blocks that follow).
Rotating the root CA therefore means: remove it, re-run the installer,
then re-enroll every executor.

**Impact:** ALL executor client certs signed by the old CA become unverifiable — every
executor must re-register (§3). The admin CA under `/var/lib/venya/ca/admin-ca/` can be
PRESERVED (installer re-creates it only if absent — the `if not cm.has_ca` /
`Admin CA already exists - preserved` branch) — preserving it keeps
existing admin client certs valid for mTLS. Note what the installer does to the
core's own pair each run: it RE-ISSUES `/etc/venya/admin/admin.crt|.key` (the
machine-plane mint), and that pair is not copied anywhere — a person's certificate
comes from the workstation ceremony (`venya admin cert renew`), so there is no
workstation copy left to refresh after a re-run. The database (users, secrets, KEK,
sessions) is untouched — secret encryption does not depend on the TLS CA.

```bash
# --- 0. Prepare: one enrollment token per executor (§3 step 1). Note the env vars
#        used at the original install (CORE_HOSTNAME, DB password, passphrases).
#        The admin CA passphrase is auto-reused from the EnvironmentFile on re-run
#        (post-fix); read it anyway if you plan to wipe admin-ca/ too:
sudo cat /etc/venya/venya-core.env        # VENYA_ADMIN_CA_KEY_PASSPHRASE=...

# --- 1. Stop the core service (nginx may stay up):
sudo systemctl stop venya-core

# --- 2. Back up, then remove the root CA keypair (KEEP admin-ca/ to preserve admin identity):
sudo cp -a /var/lib/venya/ca /secure/ca-backup-$(date +%F)
sudo rm -f /var/lib/venya/ca/ca.key /var/lib/venya/ca/ca.crt

# --- 3. Re-run the core installer with the SAME env vars as the original install.
#        Since the installer-rerun-admin-ca-passphrase-mismatch fix (2026-09-19),
#        a re-run AUTOMATICALLY reuses the passphrase stored in
#        /etc/venya/venya-core.env when the admin CA is preserved — passing
#        VENYA_ADMIN_CA_PASSPHRASE explicitly still wins (and is REQUIRED if the
#        env file was lost, or if you also wipe admin-ca/ to rotate the admin CA):
curl -fsSL <origin>/install-venya-core.sh | sudo \
  VENYA_SKIP_PROMPT=yes \
  VENYA_DB_PASSWORD=<original> VENYA_DB_PASSPHRASE=<original> \
  CORE_HOSTNAME=<original> \
  VENYA_ADMIN_CA_PASSPHRASE=<value from venya-core.env — optional on pre-fix-free installs, see above> \
  bash -s
# New CA generated; server + relay certs re-signed; system trust, well-known copy,
# and nginx bundle (root + admin) rebuilt; the core's machine-plane admin pair is
# re-minted on that core (it is not copied to any workstation — §0.1).

# --- 4. Verify the core:
curl -sk https://<core-host>/api/v1/health
# expect: {"status":"ok","checks":{"ca":"ok","admin_ca":"ok"}}

# --- 5. Every executor: re-install with a fresh token (§3). Runtime re-registration
#        is not possible (read-only /etc/venya).

# --- 6. Every workstation: refresh the CA it dials, then re-establish a session:
venya setup <core-host>    # re-fetch the NEW CA (fingerprint printed for out-of-band verification)
venya login <user-id>   # FIDO2 touch
# Then, for administrator certificate work: `venya admin cert renew` mints this
# workstation's own short-lived certificate by ceremony. The core's
# `/etc/venya/admin/` pair is NOT copied to workstations (§0.1).

# --- 7. Smoke-test end to end:
venya run --executor-id <executor-id> -- /usr/bin/true
```

If the old CA private key was compromised, treat all material it signed as compromised:
prefer wiping `admin-ca/` too (fresh admin CA + fresh admin certs everywhere) over
preserving it, and rotate the KEK (§6) if secret ciphertext exposure is in scope.

## 8. Verification quick table

| Check | Command | Expected |
|---|---|---|
| Core health | `curl -sk https://<core-host>/api/v1/health` | `{"status":"ok","version":"<server-version>","checks":{"ca":"ok","admin_ca":"ok"}}` |
| Revocation list reachable | `curl -sk https://<core-host>/api/v1/executors/certs/revocation-list` | JSON list (public endpoint) |
| Executor cert expiry | `sudo /opt/venya/.venv/bin/venya exec cert status` (on executor) | remaining days > 3 |
| Executor registered/ONLINE | `venya admin list` / `venya exec status` | executor ONLINE |
| CA keypair pairing after restore | §5 openssl diff | `PAIRING OK` |
| Rotation not failing silently | `journalctl -u venya-executor \| grep -i "rotation failed"` | no hits (on pre-fix units, hits near expiry mean the RO-mount bug — upgrade the unit, §1) |

## 9. The credential-plane marker: what rotation re-issues and what it does not (#601)

Every administrator leaf the core mints carries a plane marker — an X.509
extension identifying it as machine-plane or human-plane. The middleware reads
that marker to decide which admin policy applies, and refuses a certificate
with no readable marker (fail-closed, `packages/server/src/server/middleware/auth.py`,
the `parse_plane_marker` step).

The marker's OID moved to **Tabith LLC's registered Private Enterprise Number
(`1.3.6.1.4.1.67159.1.1`)**, and that arc is now the only one the product
reads. The bounded transition window that also read an earlier arc — a
registration belonging to a different enterprise, recorded on ticket #601 and
deliberately not printed in this runbook — has been **closed and its read
branch removed**, on the owner's ruling that nothing alpha-era is supported.
`parse_plane_marker` consults the registered arc only, and new mints write it.
The constant is `VENYA_PLANE_MARKER_OID`, `packages/server/src/server/ca.py`; a
certificate whose marker sits anywhere else is refused at the marker leg with
the named re-issue text, exactly as a certificate with no marker is.

**What this means for an operator:** there is no window to be inside any more.
Rotation re-issues some copies onto the registered arc and never touches
others, so a copy that was minted before the move — above all a hand-copied
leaf — now fails closed rather than being admitted while you decide. Treat
retiring those copies as part of rotation, not as an optional follow-up.

| Copy | Rotation re-issues it onto the registered arc? | Mechanism, or why not |
|---|---|---|
| Core machine-plane pair `/etc/venya/admin/admin.crt\|.key` | **Yes** | every core installer run re-issues the pair (`sign_admin_cert`) |
| Workstation human-plane short certificate | **Yes, when it is minted next** | the CSR/login-ceremony signer (`sign_admin_csr`) mints it and the mint is an explicit act — `venya admin cert renew`; there is no automatic re-mint loop in the CLI, and the leaf lives about an hour (`ADMIN_SHORT_CERT_LIFETIME_SECONDS`, `packages/server/src/server/ca.py`), so the copy in hand keeps the arc it was minted on until it is renewed |
| Admin leaf an operator **copied by hand** off a core (the `admin-cert/admin.crt` pair the pre-RF-10 copy step used to write — that step is retired from both §7 step 6 here and [installation.md](installation.md) §2; the copies it left behind are what this row is about — a copy kept for a second host, a break-glass copy on removable media) | **No** | nothing re-writes a file that lives outside the product; with the window closed a copy minted before the move is **refused**, so retire it (see the paragraph after this table) |
| Admin leaf **cached by a peer** (a workstation's on-disk `admin.crt`) | **No**, not by the core | the core never writes to another host's copy; that file changes only when the workstation mints its own replacement (`venya admin cert renew`). `venya login` alone stores a session token, not a certificate |
| `/etc/nginx/ssl/client-ca-bundle.crt` (Root + Admin CA, §1 trust boundary) | **Not applicable** | a bundle of CA certificates, and CA certificates carry no plane marker; no arc migration is owed here |
| Revocation records (`AdminCertRevocation` serials) | **Not applicable** | serial-keyed and arc-independent; a revoked serial on any arc stays revoked |

**The window is closed — what that costs you.** The legacy read was a loan with
a named exit: it was to close once every plane-bearing credential path had been
re-minted per plane (machine = installer/bootstrap mint, human = CSR/login-
ceremony signer — separate proofs). The owner ruled instead that no alpha-era
credential is supported, so the read branch came out and the exit is now. A
hand-copied pre-#601 leaf **fails closed** with the named re-issue refusal, not
a silent plane default. If you hold such a copy, do not refresh it from the
core — retire it: mint your own short-lived certificate on the workstation
(`venya admin cert renew`, §0), and revoke the old serial if you cannot wait
for it to age out (§0.1). The per-plane re-mint census that the earlier
precondition asked for is recorded on #601; the refusal above is the behavior
either way.

## 10. Known issues affecting this runbook (tickets)

- `executor-cert-rotation-erofs` (H) — FIXED 2026-09-19 (unit RW path + rotate() ordering; pre-fix hosts need the unit refresh, §1); physical probe OPEN with trigger: lands with the next executor deployment or before any fleet is expected to live 30 days
- `executor-revocation-by-identity` (M) — serial-match revocation can miss a diverged identity after a failed persist (§1 residual note)
- `cli-ca-dir-default-mismatch` — FIXED 2026-09-19 (default now `/var/lib/venya/ca`; pre-fix CLIs need explicit `--ca-dir`, §5)
- `shamir-combine-no-threshold-verification` — FIXED 2026-09-19 (V2 shares carry K + checksum; below-threshold/corrupt/mixed sets fail loudly; pre-V2 files restore unverified with a CLI warning — still run the §5 pairing check)
- `export-ca-key-echoed-passphrase` — FIXED 2026-09-19 (all secret prompts now getpass; pre-fix CLIs echoed)
- `executor-dead-rotation-config` — FIXED 2026-09-19 (dead fields removed; legacy executor.toml keys still load, ignored)
- `root-ca-key-plaintext-at-rest` — FIXED (close confirmed against the shipped installer): root CA key is encrypted at rest (`4218ec1`; see §0)
- `executor-ero-fs-crash-loop-on-empty-token` (H) — never deploy an executor without an install-time token (§3)
