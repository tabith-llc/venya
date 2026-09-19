# Venya Full-Lifecycle Test Plan — Provision → Install → Identity → Secret → MCP Secret Use

> **REUSABLE PLAN — Do NOT record results here.**
> Record results in a separate file per run: `testing/results-YYYY-MM-DD-HH-MM.md`
> (template at the end of this document).
>
> This document is **fully self-contained**: every ceremony, failure mode, and
> verification query needed for the run is inline. No other document is required.

---

## Purpose

Exercise the complete lifecycle from a clean hypervisor to a proven
zero-knowledge secret use:

1. **Provision** — destroy all Venya VMs, recreate a minimal fleet (1 core + 1 executor + 1 target).
2. **Install** — core, executor, and workstation CLI from tarballs built from committed git state.
3. **Identity** — FIDO2 admin bootstrap (optionally a second, non-admin user).
4. **Secret** — create a secret via `venya store`.
5. **MCP** — drive an MCP `run_command` call that **injects the secret and uses it**,
   with output redaction proven.

**Endpoint criterion (the "use a secret" definition):**
An MCP `run_command` call that (a) injects a secret via `secret_keys`,
(b) runs a command that **consumes** the injected secret, and (c) returns output
where the secret value is **redacted** (`[REDACTED:<id>]`, `masked_count ≥ 1`).
A run that returns the plaintext secret value is a redaction failure — **STOP**.

**Source of truth** (verified against source 2026-09-17; line numbers rot — grep the symbol):

| Fact | Location (file → symbol) |
|------|--------------------------|
| MCP tools: `list_secrets`, `list_executors`, `run_command`, `get_audit` | `packages/mcp/src/venya_mcp/server.py` |
| `run_command` args: `executor_id`, `command`, `secret_keys` (all required) | same file → `run_command` |
| Secret mount path inside sandbox: `/run/secrets/venya/<pk>` | `packages/executor/src/executor/strategies/sbx_strategy.py` |
| `pk` = DB `secrets.id` (integer), normalized to `str` at the API boundary | `packages/executor/src/executor/executor.py` |
| Secret value wrapped with sentinel `[VENYA:xxxxxxxx]` for redaction | same file → sentinel wrap |
| Secret create CLI: `venya store <key> <value> --roles <r> [--key-version v] [--metadata k=v]` | `packages/cli/src/venya_cli/commands.py` → `cmd_store` |
| Canonical use-a-secret command shape | `packages/executor/tests/test_command_validator.py` |

---

## Parameters

Chosen at runtime. Do not hardcode personal paths, hostnames, or credentials in
run notes beyond what the operator needs.

| Variable | Description | Example |
|----------|-------------|---------|
| `HYPERVISOR` | Hypervisor host (libvirt/KVM) | `hv1.example.internal` |
| `HYPERVISOR_USER` | SSH user on the hypervisor (in the `libvirt` group) | `tester` |
| `HYPERVISOR_BIN` | Directory holding the provisioning scripts on the hypervisor | `/home/tester/bin` |
| `BUILD_HOST` | Workstation that builds tarballs and serves them over HTTP | `build1.example.internal` |
| `BUILD_HOST_IP` | Its IP as reachable from the VMs | `192.0.2.10` |
| `VENYA_SRC` | Venya source tree (committed git state) | `/srv/src/venya` |
| `ADMIN_WS` | Admin workstation directory (holds `.venv`, `config.json`) | `/srv/ws/venya-admin` |
| `USER_WS` | Regular-user workstation directory (full matrix only) | `/srv/ws/venya-user` |
| `ADMIN_USER` | Admin user ID (random per run) | `alice` |
| `USER_ID` | Regular user ID (random, full matrix only) | `jsmith` |
| `KEY_A` | Admin FIDO2 security key | any FIDO2 key |
| `KEY_B` | User FIDO2 security key (full matrix only) | a **different** key |
| `CORE_HOST` | Core server hostname (created by provisioning) | `venya-core-1` |
| `EXEC_HOST` | Executor hostname | `venya-exec-1` |
| `TARGET_HOST` | Target hostname (commands land here via ssh) | `venya-target-1` |
| `EXEC_ID` | Executor registration ID | `venya-exec-1` |
| `SECRET_KEY` | Secret key name (operator-chosen) | `bot_pw_target_1` |
| `SECRET_PK` | DB primary key of the secret (discovered in Phase D.3) | `1` |
| `TARGET_USER` / `TARGET_PW` | Credentials the secret carries | `bot` / (chosen at run time, never recorded in git) |
| `DB_PASSWORD` | PostgreSQL password for the install (dev run value; never commit) | (chosen at run time) |

The provisioning scripts create VMs named `venya-core-N` / `venya-exec-N` /
`venya-target-N` on a private network (`venya-net`, default `10.27.28.0/24`),
each with SSH user `bot` (passwordless sudo, key auth only). VM RAM/CPU/disk
sizes are constants in the provisioning script (default 5 GB / 2 vCPU / 10 GB).

**Provisioning tooling** (from the `venya-test-hypervisor` project, deployed to
`$HYPERVISOR_BIN` on the hypervisor; invoke with **absolute paths** —
non-interactive SSH does not load `~/bin` into `PATH`):

- `venya-provision-ubuntu.sh` — `create` / `destroy` VMs and networks
- `venya-power-ubuntu.sh` — `boot` / `halt` / `status`
- `remove_venya_known_hosts.sh` — clear stale SSH host keys after reprovision

**Tarball tooling** (from the installer project, run on `$BUILD_HOST`):

- `create-tarball-and-serve.sh` — builds core/executor/CLI tarballs from the
  current **committed git state**, prints SHA-256 hashes, writes `.sha256`
  sidecars, and serves everything over HTTP (default port 8080).

**Scope decision (make before starting):**
- **Minimal** — admin only (`KEY_A`). Reaches the use-a-secret endpoint. Phases
  marked *(full matrix only)* are skipped.
- **Full** — admin + regular user (`KEY_A` + `KEY_B`): adds the non-admin audit
  self-filter matrix (MCP criterion #5) and the FIDO2 security negatives
  (sign-count persistence, wrong-key rejection, challenge-replay rejection).

**Suite health gate (before any VM work):** from `$VENYA_SRC`, all five package
suites must be green — `cli`, `core`, `server`, `executor`, `mcp`
(`uv run -p 3.14 --directory packages/<pkg> pytest tests/`). Record the counts
in the run's results file; an unexplained delta versus the previous recorded
run — **including any shrinkage** — is a stop-condition to investigate before
provisioning. (Absolute reference counts deliberately do not live in this
plan: they rot with every merge and nothing enforces their sync; the
results-file lineage carries them.)

---

## Operational constraints (what bites if ignored)

- **Admin ops are workstation operations.** `init`, `login`, `enroll`, and every
  `admin …` subcommand need the venya CLI **and a physical FIDO2 key**. They
  cannot run on the headless core VM (no key → the browser-less ceremony dies
  with `Connection refused [Errno 111]`). The PIN prompt needs a TTY — a
  pipe/heredoc breaks it (`CliInteraction.request_pin` refuses non-TTY stdin).
- **Admin mTLS cert is per-core.** Every core install mints a fresh Admin CA +
  client cert pair. The workstation copy (`$ADMIN_WS/admin-cert/`) is stale
  after every core reinstall — re-sync (Phase C.1) or `admin …` commands 403.
- **`enrollment_tokens` (users) ≠ `executor_enrollment_tokens` (executors).**
  Executor tokens are stored hashed (HMAC-SHA256 + pepper), single-use, TTL
  ~30 min (default 1800 s). User enrollment tokens: 15-min TTL. Plaintext is
  shown once at mint and never stored.
- **Tokens print without a flag.** Admin commands that mint enrollment tokens
  print them directly (there is no redaction gate; the former
  `--show-sensitive` flag was removed — passing it is now an argparse error).
  Treat terminal scrollback and run logs accordingly: never paste tokens into
  committed files.
- **CA key at rest:** the admin CA key is encrypted at rest by default
  (passphrase delivered to the daemon via `/etc/venya/venya-core.env`). The
  root/executor CA key is still plaintext at rest (0600) — known limitation,
  fix deferred.
- **`venya store` key-version resolution.** Migration 027 seeds one active
  `v1` at install, so the automatic active-version lookup succeeds and
  `--key-version` is optional. On installs predating 027 the lookup 503s and
  `store` fails loudly with a hint — pass `--key-version v1` explicitly there.
  Labels are stored without validation and decryption never consults
  `key_versions`, so `v1` is safe.
- **Upsert on visible keys.** `venya store` on an existing key you can see
  (one of your roles in its scope OR you created it) **replaces that row in
  place** — id stable, `created_by` immutable, response `"replaced": true`,
  CLI prints "replaced existing". A key that exists but is scoped out for
  you inserts a **second row** (identical 201 shape — no existence leak, no
  cross-role clobber). There is no `--force`; the flag was removed as a
  no-op before upsert became real.
- **Static files serve from site-packages, not the source tree.** Any
  HTML/CSS/JS edit must be copied into
  `/opt/venya/.venv/lib/python3.14/site-packages/server/static/` on the core VM.
- **Python 3.14 only** (`requires-python = ">=3.14,<3.15"` in every package).
- **Session TTL / dead refresh path (known limitation):** default idle timeout
  is 900 s and a 401'd token can never refresh (`/auth/refresh` applies the
  same expiry check as the middleware). Any run pause > 15 min kills sessions
  mid-run. Dev accommodation in Phase D.1.
- **Deploys build from committed git state only** — never from a dirty working
  tree.

---

## Phase A — Provision (destroy + create)

> **DESTRUCTIVE.** `destroy` removes **all** Venya VMs **and both virtual
> networks** (`venya-net`, `physnet`). There is no per-VM destroy. Confirm
> before running.

### A.0 RAM guard

Each VM reserves ~5 GB. Before creating anything, confirm the hypervisor has
headroom for the whole fleet plus host services:

```bash
ssh $HYPERVISOR_USER@$HYPERVISOR 'free -g | grep Mem'
```

A 3-VM fleet needs ~15 GB available. If not — do not create.

### A.1 Destroy (wipes everything)

```bash
ssh $HYPERVISOR_USER@$HYPERVISOR $HYPERVISOR_BIN/venya-provision-ubuntu.sh destroy
```

### A.2 Create minimal fleet

```bash
# bare `create` = 1 core + 1 exec + 1 target
ssh $HYPERVISOR_USER@$HYPERVISOR $HYPERVISOR_BIN/venya-provision-ubuntu.sh create
```

Fleet: `venya-core-1`, `venya-exec-1`, `venya-target-1` (static leases on
`venya-net`). Max caps: 3 cores / 8 executors / 8 targets. Selective create:
`venya-provision-ubuntu.sh create <type> [range]`.

### A.3 Power on + wait for SSH

```bash
ssh $HYPERVISOR_USER@$HYPERVISOR $HYPERVISOR_BIN/venya-power-ubuntu.sh status
# if not running:
ssh $HYPERVISOR_USER@$HYPERVISOR $HYPERVISOR_BIN/venya-power-ubuntu.sh boot
```

Poll until `ssh bot@$CORE_HOST hostname` returns `$CORE_HOST` (same for
executor and target). First boot runs cloud-init; give it a minute.

### A.4 Stale host keys

Reprovisioned VMs have new SSH host keys. Clear stale `known_hosts` entries on
the workstation **and** the hypervisor:

```bash
remove_venya_known_hosts.sh                                              # workstation ($PATH)
ssh $HYPERVISOR_USER@$HYPERVISOR $HYPERVISOR_BIN/remove_venya_known_hosts.sh
```

**Gate A:** `ssh bot@$CORE_HOST hostname` = `$CORE_HOST`; executor + target
also reachable. (After the wipe, first connects must accept the new host keys —
interactive ssh prompts; automated/batch ssh needs
`-o StrictHostKeyChecking=accept-new`, which is TOFU and acceptable **only**
for freshly provisioned VMs.)

---

## Phase B — Install

All installs run from **committed git state**. Build + serve once, then install
each component. Installer URLs below assume the default serve port 8080 on
`$BUILD_HOST_IP`.

### B.1 Build tarballs + start the installer server (on `$BUILD_HOST`)

Build from the committed ref — never the working tree:

```bash
create-tarball-and-serve.sh --ref <tag-or-commit>
```

Every served byte comes from the git ref (tarballs via
`git archive --prefix=./ | gzip -n`; scripts/common/README via `git show`):
the working tree is never consulted, and the output is byte-reproducible from
any clone of the ref. The script runs a **fail-closed pre-publish extraction
check** (extract with the installer's exact `--strip-components=1` flags and
assert the requirements + packages layout) — the build aborts unless it
prints its PASS line; **never publish a build without seeing it**. It prints
SHA-256 hashes and writes `<tarball>.sha256` sidecars. Capture: `CORE_SHA`,
`EXEC_SHA`, `CLI_SHA`. To stop the server later: kill it **by PID** (a blind
`pkill -f` has self-matched and killed the operator's own shell — twice).

Installer env vars (all three installers): `VENYA_TARBALL_SHA256` is
**mandatory** — the installer hard-fails without it. `VENYA_SKIP_PROMPT=yes`
disables interactive prompts (required for piped installs).

> **`VENYA_TARBALL` must be set explicitly for dev-state installs.** The
> built-in default points at the **GitHub latest release** — without the
> override the installer downloads stale published bytes, not the tarballs
> just built (this has bitten real runs). Always pass
> `VENYA_TARBALL=http://$BUILD_HOST_IP:8080/<tarball>`. Belt-and-braces: with
> `VENYA_TARBALL_SHA256` set to the local sidecar hash, a GitHub artifact
> fails verification and aborts; the shared `venya-common.sh` library is
> self-fetched from the same origin as `VENYA_TARBALL`, so the override keeps
> that local too.

### B.2 Install core (independent)

```bash
ssh bot@$CORE_HOST
curl -fsSL http://$BUILD_HOST_IP:8080/install-venya-core.sh | \
  sudo VENYA_SKIP_PROMPT=yes VENYA_DB_PASSWORD=$DB_PASSWORD \
       VENYA_TARBALL=http://$BUILD_HOST_IP:8080/venya-core-install.tar.gz \
       VENYA_TARBALL_SHA256=$CORE_SHA bash -s
sudo systemctl start venya-core
curl -sk https://$CORE_HOST/api/v1/health
# Expected: {"status":"ok","checks":{"ca":"ok","admin_ca":"ok"}}
```

During the install, watch for `Downloading tarball from http://$BUILD_HOST_IP:8080/...`
+ `SHA-256 verified` in the output — that is the mechanism proving local
provenance. Any `github.com` in the download lines = STOP, the override did
not take effect.

Core env vars (beyond the common three): `VENYA_DB_PASSWORD` (PostgreSQL),
`VENYA_DB_PASSPHRASE` (server encryption passphrase; a dev-only default exists
in the script header — production must override), `CORE_HOSTNAME` (server name
+ TLS cert SAN; default `$(hostname)`), `VENYA_ADMIN_MTLS_ENABLED` /
`VENYA_ADMIN_IDENTITY` / `VENYA_ADMIN_CA_PASSPHRASE` (admin mTLS; enabled by
default, passphrase auto-generated unattended and delivered via
`/etc/venya/venya-core.env`).

**Gate B2:** health endpoint returns the `ok` JSON above.

### B.3 Install the workstation CLI (independent; non-root, no sudo)

Two equivalent routes into `$ADMIN_WS` (repeat for `$USER_WS`, full matrix):

```bash
# Route 1 — installer (shims in ~/.local/bin):
curl -fsSL http://$BUILD_HOST_IP:8080/install-venya-cli.sh | \
  VENYA_SKIP_PROMPT=yes \
  VENYA_TARBALL=http://$BUILD_HOST_IP:8080/venya-cli-install.tar.gz \
  VENYA_TARBALL_SHA256=$CLI_SHA bash

# Route 2 — editable venv (picks up current source; default for dev runs):
python3.14 -m venv $ADMIN_WS/.venv        # first time only
source $ADMIN_WS/.venv/bin/activate
uv pip install --force-reinstall -e $VENYA_SRC/packages/cli
uv pip install -e $VENYA_SRC/packages/mcp --no-deps   # provides venya-mcp
deactivate
```

**Gate B3:** `$ADMIN_WS/.venv/bin/venya --help` lists `init`, `login`,
`enroll`, `store`, `run`; `venya store --help` shows `--key-version` and does
**not** show `--force` or `--show-sensitive`.

### B.4 Install executor (needs the executor token — minted in Phase C.4)

Order matters: this runs **after** admin bootstrap + token mint.
`$EXEC_TOKEN` is **single-use, ~30 min TTL** — mint immediately before this step.

**Operator-run command (recommended — interactive).** Docker credentials are
typed at hidden prompts by the human operator: they never pass through an
automated runner, never sit in argv of a *remote interactive* shell, shell
history, or on disk. 

> **Paste-race warning (bit two live runs, 2026-09-17):** do NOT paste a
> multi-line block that *starts* with `ssh host` — the lines typed while ssh
> is still connecting are consumed by the local terminal buffer and silently
> lost; the remote session starts at an idle prompt with nothing executed.
> Either paste only after the remote prompt appears, or use the single-line
> forms below (each is one paste, one command).

Run from the workstation — **step 1 mints, steps 2-3 install in two
single-line commands**:

```bash
# 1) Mint the executor token (Phase C.4) from the admin workstation.
#    The token prints directly on the "Token:" line — copy it.
VENYA_CONFIG=$ADMIN_WS/config.json SSL_CERT_FILE=/tmp/venya-ca.crt \
  VENYA_ADMIN_CERT=$ADMIN_WS/admin-cert/admin.crt \
  VENYA_ADMIN_KEY=$ADMIN_WS/admin-cert/admin.key \
  $ADMIN_WS/.venv/bin/venya admin executor-enroll $EXEC_ID

# 2) Stage the installer on the executor (single line; hash-check the output):
ssh bot@$EXEC_HOST "curl -fsSLo /tmp/install-venya-executor.sh http://$BUILD_HOST_IP:8080/install-venya-executor.sh && sha256sum /tmp/install-venya-executor.sh"

# 3) One-line interactive install — `-t` forwards the TTY, so the Docker
#    prompts appear in YOUR terminal (single quotes; substitute <EXEC_TOKEN>):
ssh -t bot@$EXEC_HOST 'sudo VENYA_SKIP_PROMPT=yes VENYA_TARBALL=http://'"$BUILD_HOST_IP"':8080/venya-executor-install.tar.gz VENYA_TARBALL_SHA256='"$EXEC_SHA"' VENYA_SERVER_URL=https://'"$CORE_HOST"' VENYA_EXECUTOR_ID='"$EXEC_ID"' VENYA_EXECUTOR_ENROLLMENT_TOKEN=<EXEC_TOKEN> bash /tmp/install-venya-executor.sh'
# Prompts appear near the end of the install:
#   Docker username (sbx template pulls): <type username>
#   Docker API key / access token (input hidden): <type token — not echoed>

# 4) Cleanup (single line):
ssh bot@$EXEC_HOST 'rm -f /tmp/install-venya-executor.sh'
```

Mechanism (verified in installer source): the Docker prompt fires when stdin
is a TTY **and** `VENYA_DOCKER_USERNAME`/`VENYA_DOCKER_API_KEY` are unset —
`VENYA_SKIP_PROMPT=yes` does not suppress it. The key is read hidden and piped
to `sbx login --username <u> --password-stdin` (never argv, never written by
the installer; sbx keeps it in its own credential store under `/home/venya`).
A failed `sbx login` aborts the install with an explicit error.

- **Piped/automated variant:** `curl … | sudo … VENYA_DOCKER_USERNAME=…
  VENYA_DOCKER_API_KEY=… bash -s` also works (a pipe consumes stdin, so the
  prompt can never fire and the vars are mandatory) — but the credentials
  then appear in the remote process argv; acceptable only for throwaway dev
  credentials. An automated runner must **ask the human** for them, never look
  them up or store them.
- No credentials available? `VENYA_SKIP_DOCKER_LOGIN=yes` gives a degraded
  install (sandbox creates 503 until a manual `sudo -H -u venya sbx login`).
- The installer starts `venya-sandboxd.service` and runs
  `sbx policy init deny-all` — without both, every sandbox create 503s.

**Gate B4:** `systemctl status venya-executor` active; the core sees the
executor (Phase D criterion #3 shows it ONLINE).

**Executor pre-checks for Phase D** (the installer does NOT do these):

- `sshpass` present on the executor (`ssh bot@$EXEC_HOST 'command -v sshpass'`)
  — required for the `sshpass -f <secret-file> ssh …` command shape; the
  installer does not install it and the sandbox copy step silently no-ops when
  it is missing.
- Pre-warm the sandbox template (cold start measured ~1 m 04 s — exceeds the
  MCP client's 30 s HTTP timeout):

  ```bash
  ssh bot@$EXEC_HOST 'sudo -H -u venya sbx create --name warm shell /tmp && sudo -H -u venya sbx rm --force warm'
  ```

---

## Phase C — Identity bootstrap (FIDO2)

Every CLI command in this phase runs from the workstation with:
- `VENYA_CONFIG=<workstation>/config.json` (isolates workstations — the
  binaries are identical; an unannounced swap silently targets the wrong
  workstation, so **state which workstation each physical step uses**),
- `SSL_CERT_FILE=/tmp/venya-ca.crt` (the server's private CA),
- for `admin …` subcommands: `VENYA_ADMIN_CERT` / `VENYA_ADMIN_KEY` (mTLS).

Workstation layout:

```
$ADMIN_WS/
├── .venv/
├── config.json          # written by the CLI (VENYA_CONFIG)
└── admin-cert/          # admin.crt + admin.key (synced in C.1)
```

### C.0 Pre-flight (no keys attached)

```bash
curl -sk https://$CORE_HOST/api/v1/health                        # ok JSON
curl -sk https://$CORE_HOST/.well-known/venya-ca.crt -o /tmp/venya-ca.crt
VENYA_CONFIG=$ADMIN_WS/config.json $ADMIN_WS/.venv/bin/venya config set-server https://$CORE_HOST
# full matrix: repeat set-server for $USER_WS
```

Verify the fetched CA matches what the server presents (guards against a stale
local copy):

```bash
openssl x509 -in /tmp/venya-ca.crt -noout -ext subjectKeyIdentifier
echo | openssl s_client -connect $CORE_HOST:443 2>/dev/null | \
  openssl x509 -noout -ext authorityKeyIdentifier
# The CA's SubjectKeyIdentifier must equal the leaf's AuthorityKeyIdentifier.
```

### C.1 Sync the admin mTLS cert pair (**mandatory after any core reinstall**)

Each core install mints a **new** Admin CA and client pair; the workstation
copy is stale until re-synced — Phase C.3 mTLS fails (403) otherwise.

```bash
mkdir -p $ADMIN_WS/admin-cert
ssh bot@$CORE_HOST "sudo cat /etc/venya/admin/admin.crt" > $ADMIN_WS/admin-cert/admin.crt
ssh bot@$CORE_HOST "sudo cat /etc/venya/admin/admin.key" > $ADMIN_WS/admin-cert/admin.key
chmod 600 $ADMIN_WS/admin-cert/admin.key

# Verify hashes match the VM:
sha256sum $ADMIN_WS/admin-cert/admin.crt $ADMIN_WS/admin-cert/admin.key
ssh bot@$CORE_HOST "sudo sha256sum /etc/venya/admin/admin.crt /etc/venya/admin/admin.key"
```

Identical hashes required — else re-sync before continuing.

### C.2 Key maintenance (reset keys **before** any timed step)

All key resets happen here so they never consume an enrollment-token window.

FIDO2 key with `ykman` support (e.g. YubiKey):

```bash
# attach the key
lsusb | grep -i yubico
ykman fido reset
ykman fido access change-pin     # choose a PIN; never record it in git
# detach
```

Generic CTAP keys (`fido2-tools`):

```bash
fido2-token -L                   # list; note the /dev/hidrawN device
fido2-token -R /dev/hidrawN      # factory reset (wipes credentials + PIN)
fido2-token -S /dev/hidrawN      # set fresh PIN
```

If `-R` fails with `FIDO_ERR_NOT_ALLOWED`, use `-C` (change PIN; requires the
current PIN) instead.

> **The PIN step is not optional.** A key with no PIN cannot satisfy the
> CLI's user-verification requirement: `init`/`enroll`/`login` die with
> `ClientError code=3 (CONFIGURATION_UNSUPPORTED) — User verification not
> configured/supported`. A factory reset (`ykman fido reset` / `fido2-token
> -R`) **wipes the PIN** — always follow it with `change-pin` / `-S` before
> the ceremony.

**Windows variant (ruling 2026-09-18, ticket `windows-fido2-requires-elevation`):**
C.2 reset + PIN management are **the operator's/customer IT's responsibility,
performed with the vendor tool on a non-Windows host or via the vendor's
Windows utility** (e.g. YubiKey Manager). The venya CLI on Windows deliberately
does not own the authenticator lifecycle: the platform WebAuthn API exposes no
reset and no PIN set/change. Do not attempt `ykman`/`fido2-token` steps through
the venya CLI on Windows — Phase C.2 is executed as written on the key before
it is used from a Windows workstation, and the Windows phases that follow
assume a reset key with a PIN already set.

### C.3 Admin bootstrap `[FIDO2 — attach KEY_A]`

```bash
VENYA_CONFIG=$ADMIN_WS/config.json SSL_CERT_FILE=/tmp/venya-ca.crt VENYA_FIDO2_DEBUG=1 \
  $ADMIN_WS/.venv/bin/venya init $ADMIN_USER        # touch KEY_A when prompted; PIN needs a TTY
```

- Expected: `Initialization complete. User '<ADMIN_USER>' enrolled as admin.`
- A **recovery code is printed once** — record it in secure storage (not in
  committed files, and not by pasting it into chat/session transcripts —
  treat it like a password from the moment it prints).

Then log in and harvest the token:

```bash
VENYA_CONFIG=$ADMIN_WS/config.json SSL_CERT_FILE=/tmp/venya-ca.crt VENYA_FIDO2_DEBUG=1 \
  $ADMIN_WS/.venv/bin/venya login $ADMIN_USER       # touch KEY_A
# Expected: "Authenticated as <ADMIN_USER>." — token written to config.json

ADMIN_TOKEN=$(python3 -c "import json; print(json.load(open('$ADMIN_WS/config.json'))['access_token'])")
echo "Admin token: ${ADMIN_TOKEN:0:20}..."          # prefix only — never log the full token
```

**409 on retry:** if FIDO2 registration failed *after* the server committed a
pending user row (e.g. key not attached → `No FIDO2 devices found`), retrying
`init` returns **409**. The CLI prints only the raw HTTP error and hides the
actionable server `detail` (known limitation). Reset, then re-init:

```bash
VENYA_CONFIG=$ADMIN_WS/config.json SSL_CERT_FILE=/tmp/venya-ca.crt \
  $ADMIN_WS/.venv/bin/venya init $ADMIN_USER --installation-reset
```

(The reset is allowed only while no user is fully enrolled.) Confirm the stuck
state from the core if needed: `journalctl -u venya-core` or
`SELECT user_id, status FROM users;`.

**Windows workstation variant (ticket `windows-fido2-requires-elevation`):**
when C.3 — or any FIDO2 ceremony — runs from a Windows workstation, ceremonies
go through the Windows platform WebAuthn API: OS-drawn dialogs own the PIN and
touch prompts, and the terminal never asks for a PIN. Ceremonies require an
**interactive desktop session** (never SSH/WinRM — the platform API needs a
foreground window). Standard (non-admin) users are fully supported for
`init`/`login`/`enroll`/`credential add`; only the machine-wide installer
(`install-venya-cli.ps1`) is admin-run, once per machine. Per-user state lives
in `%APPDATA%\venya\`; CLI stderr is teed to `%APPDATA%\venya\venya.log` for
diagnostics. `venya credential add` elevates with an **already-registered** key
first, then registers the **new** key — have both keys at hand and follow the
dialog sequence (insert the enrolling key when the registration dialog opens).

### C.4 Mint the executor token → install the executor (Phase B.4) **now**

```bash
VENYA_CONFIG=$ADMIN_WS/config.json SSL_CERT_FILE=/tmp/venya-ca.crt \
  VENYA_ADMIN_CERT=$ADMIN_WS/admin-cert/admin.crt \
  VENYA_ADMIN_KEY=$ADMIN_WS/admin-cert/admin.key \
  $ADMIN_WS/.venv/bin/venya admin executor-enroll $EXEC_ID
```

Output (token prints directly — no flag needed):

```
Enrollment token for executor '<EXEC_ID>':
  Token: enrl_exec_...
  Expires in: 1800 seconds (30 minutes)
Deliver this token to the executor operator out-of-band.
```

Capture `EXEC_TOKEN` and run Phase B.4 immediately (single-use, ~30 min).

A 403 here means the admin mTLS client-cert presentation is broken (stale
cert pair — re-sync C.1). Record it as a failure; do **not** paper over it
with sudo-curl on the core.

### C.5 (Full matrix only) Create + enroll the regular user `[FIDO2 — KEY_B]`

```bash
# create user + mint user enrollment token (15-min TTL — proceed IMMEDIATELY)
VENYA_CONFIG=$ADMIN_WS/config.json SSL_CERT_FILE=/tmp/venya-ca.crt \
  VENYA_ADMIN_CERT=$ADMIN_WS/admin-cert/admin.crt \
  VENYA_ADMIN_KEY=$ADMIN_WS/admin-cert/admin.key \
  $ADMIN_WS/.venv/bin/venya admin create-user $USER_ID --roles user
# → "Enrollment Token: enrl_..." printed directly; capture as ENROLL_TOKEN

# detach KEY_A, attach KEY_B, then from the USER workstation:
VENYA_CONFIG=$USER_WS/config.json SSL_CERT_FILE=/tmp/venya-ca.crt VENYA_FIDO2_DEBUG=1 \
  $USER_WS/.venv/bin/venya enroll $ENROLL_TOKEN     # touch KEY_B
VENYA_CONFIG=$USER_WS/config.json SSL_CERT_FILE=/tmp/venya-ca.crt VENYA_FIDO2_DEBUG=1 \
  $USER_WS/.venv/bin/venya login $USER_ID           # touch KEY_B
```

### C.6 Verification (no keys needed except where marked)

**Config files:**

```bash
stat -c "%a" $ADMIN_WS/config.json && cat $ADMIN_WS/config.json
# Expected: mode 600; keys server_url + access_token present. (Full matrix: same for $USER_WS.)
```

**DB census:**

```bash
ssh bot@$CORE_HOST "sudo -u postgres psql -d venya -c \"
  SELECT u.user_id, u.status, u.enrolled_at, count(c.id) AS cred_count
  FROM users u LEFT JOIN webauthn_credentials c ON c.user_id = u.user_id
  GROUP BY u.user_id, u.status, u.enrolled_at ORDER BY u.enrolled_at;\""
```

Expected: one row per enrolled user, status `active`, 1 credential each,
`enrolled_at` ≈ now. (The `users` table has no `created_at` column.)

**Credential census (pass 1):** (`webauthn_credentials` fields: `credential_id`,
`public_key`, `sign_count`, `label`)

```bash
ssh bot@$CORE_HOST "sudo -u postgres psql -d venya -c \"
  SELECT user_id, length(credential_id) AS cred_id_bytes,
         length(public_key) AS pubkey_bytes, sign_count, label
  FROM webauthn_credentials ORDER BY created_at;\""
```

Expected: one row per user; `pubkey_bytes` nonzero (CBOR COSE key, ~60–80
bytes for P-256); `sign_count` ≥ 1 after the first logins. **Record the
`sign_count` values.** If `sign_count` is still 0 after two logins, the counter
persist path is broken despite a green suite — STOP and debug before anything
else piles on.

**Gate C:** census rows match the scope (minimal: 1 admin row; full: 2 rows),
all `active`, 1 credential each.

### C.7 (Full matrix only) FIDO2 security negatives `[FIDO2]`

**Second login round + sign-count increment.** Both users log in again (each
key attached in sequence, C.3/C.5 commands). Re-run the credential census:
`sign_count` must be **strictly greater** than pass 1 for both users. Equal or
0 → counter persist path broken → STOP.

**Wrong-key negative.** Present the **user's** key (KEY_B) for the **admin's**
login:

```bash
# KEY_B attached (NOT KEY_A), admin workstation:
VENYA_CONFIG=$ADMIN_WS/config.json SSL_CERT_FILE=/tmp/venya-ca.crt \
  $ADMIN_WS/.venv/bin/venya login $ADMIN_USER
```

Expected: rejection — the authenticator surfaces a CTAP error for no matching
credential (`0x2E NO_CREDENTIALS`; `0x27 OPERATION_DENIED` also possible — the
authenticator picks); `Authenticated as` is **not** printed. Record the exact
message. A successful login with the wrong key is a **security failure — STOP**.

**Replay negative.** One challenge must serve at most one assertion: the
identical `/auth/login/complete` body is POSTed twice (both endpoints are
pre-auth). Two constraints: the project uses `httpx2` (not `httpx`), and do
**not** run via `python - <<'EOF'` — a heredoc makes stdin a pipe and the PIN
prompt refuses non-TTY stdin. Write the script to a file, then run it:

```bash
cat > /tmp/replay_test.py <<'EOF'
import ssl, httpx2
from venya_cli.fido2_client import Fido2Auth

SERVER = "https://<CORE_HOST>"
USER   = "<USER_ID>"
ca     = ssl.create_default_context(cafile="/tmp/venya-ca.crt")

with httpx2.Client(verify=ca, timeout=30) as http:
    start = http.post(f"{SERVER}/api/v1/auth/login/start",
                      json={"user_id": USER}).json()

    fido2 = Fido2Auth(SERVER)
    assertion = fido2._get_assertion(fido2._build_request_options(start["options"]), timeout=60.0)
    body = {"challenge_id": start["challenge_id"],
            "response": fido2._format_assertion_response(assertion)}

    r1 = http.post(f"{SERVER}/api/v1/auth/login/complete", json=body)
    print("first :", r1.status_code)                    # expect 200

    r2 = http.post(f"{SERVER}/api/v1/auth/login/complete", json=body)
    print("replay:", r2.status_code, r2.json().get("detail"))
    # expect 401 "Challenge not found or expired"
EOF

$USER_WS/.venv/bin/python /tmp/replay_test.py           # KEY_B attached; touch at the prompt
```

First POST consumes the challenge (pop-on-read); the second must fail. If the
replay succeeds, replay protection is broken — **STOP, this is the security
claim**.

**Persist observability:**

```bash
ssh bot@$CORE_HOST "sudo journalctl -u venya-core --since '1 hour ago' --no-pager | grep 'sign_count persist'"
```

Expected: **silence** (counter updates persisted cleanly). Any hit = a persist
failure was logged (login still succeeded by design) — record it.

**Decision gate (full matrix):**

| Observed | Conclusion | Action |
|----------|-----------|--------|
| Census rows correct, nonzero `pubkey_bytes`, `sign_count` increments pass 1 → 2, both negatives reject | FIDO2 verification path closed | Proceed to Phase D |
| `sign_count` still 0 after two logins | Counter persist broken despite green suite | STOP — debug persist first |
| Login succeeded but DB row absent | Ghost factory | Inspect the enroll commit path |
| Wrong-key login authenticated | Security failure | STOP — allow-list enforcement broken |
| Replay second POST returned 200 | Security failure | STOP — challenge consumption broken |
| `create-user`/`executor-enroll` 403 | Admin mTLS client-cert path broken | Record failure; do not paper over with sudo-curl |

---

## Phase D — MCP "use a secret" (the endpoint)

### D.1 Prerequisites

- `venya-mcp` installed in the workstation venv (Phase B.3).
- **Timing accommodations for dev runs (set once, right after the core
  install).** Two knobs, both DEV-ONLY — they vanish on reinstall:

  1. *Session idle timeout* — default 900 s; the refresh path cannot revive a
     401'd token (known limitation), so any pause > 15 min kills sessions
     mid-run:

     ```bash
     ssh bot@$CORE_HOST "echo 'VENYA_SESSION__SESSION_TIMEOUT=28800' | sudo tee -a /opt/venya/.env && sudo systemctl restart venya-core"
     ```

  2. *Enrollment token TTLs* — defaults are 15 min (user enrollment) and
     30 min (executor enrollment, `VENYA_EXECUTOR_ENROLLMENT__TOKEN_TTL_SECONDS`,
     in **seconds**, allowed range 120–86400). For testing, raise the
     **executor** TTL to 4 hours so mint→install windows never rush a paste:

     ```bash
     ssh bot@$CORE_HOST "printf 'VENYA_FIDO2__ENROLLMENT_TOKEN_TTL=240\nVENYA_EXECUTOR_ENROLLMENT__TOKEN_TTL_SECONDS=14400\n' | sudo tee -a /opt/venya/.env && sudo systemctl restart venya-core"
     ```

     > **Knob status:** `VENYA_FIDO2__ENROLLMENT_TOKEN_TTL` is wired on
     > installs carrying the enrollment-manager fix (single construction
     > point; reported lifetimes derive from the config). Installs predating
     > it carry the dead knob (hardcoded 900 s) — treat the C.5 mint→enroll
     > window as **15 min** there. **Verify the wiring physically; do not
     > trust the unit suites** (unit-green-insufficient is on file three
     > times): mint a create-user token, then
     > `SELECT EXTRACT(EPOCH FROM (expires_at - created_at))::int FROM enrollment_tokens ORDER BY created_at DESC LIMIT 1;`
     > must read **14400** with the knob at 240. A 900 on a post-fix install
     > means the wiring claim is fiction — **stop and report**.

  **Verify pickup** before burning FIDO2 ceremonies: mint a throwaway executor
  token and check the DB — `SELECT EXTRACT(EPOCH FROM (expires_at -
  created_at))::int FROM executor_enrollment_tokens ORDER BY created_at DESC
  LIMIT 1;` must read 14400 (the core journal also logs `ttl=14400s` at mint).

  **Re-login after any TTL change or core restart.** Sessions carry the
  expiry issued at login time; raising the timeout does NOT extend existing
  sessions. Symptom if skipped (observed live 2026-09-17): bearer-only
  commands (`venya store`, `venya list`) 401 with "Invalid or expired token"
  while `admin …` commands keep working — they ride the mTLS client cert,
  which masks the dead bearer token. Re-run `venya login` (FIDO2 touch) for
  every workstation after the restart.
- Executor online (Gate B4); `sshpass` present; sandbox template pre-warmed
  (Phase B.4 pre-checks).
- *(Full matrix, criterion #5)* — the positive half needs a read-write
  **non-admin**: all event-creating endpoints require `read-write`, and the
  default `user` role has `read` (→ 403, zero own events). Grant it while
  keeping the user non-admin (so the self-filter negative stays valid):

  ```bash
  ssh bot@$CORE_HOST "sudo -u postgres psql -d venya -c \"UPDATE roles SET permissions='read-write' WHERE name='user';\""
  ```

### D.2 Create the secret (admin workstation)

The secret carries the target's login so `run_command` can ssh into the target.
The server seeds an active `v1` at install (migration 027), so no
`--key-version` flag is needed:

```bash
VENYA_CONFIG=$ADMIN_WS/config.json SSL_CERT_FILE=/tmp/venya-ca.crt \
  $ADMIN_WS/.venv/bin/venya store $SECRET_KEY "$TARGET_PW" \
    --roles admin \
    --metadata executor=$EXEC_ID --metadata purpose=ssh_login --metadata username=$TARGET_USER
# Expected: "Secret '$SECRET_KEY' stored successfully."
```

`--roles` is required. Metadata `executor`/`purpose`/`username` is what
`list_secrets` surfaces (values are never shown). On installs predating
migration 027, the active-version lookup answers 503 and `store` fails loudly
with a hint, writing nothing — pass `--key-version v1` explicitly there.

### D.3 Discover `SECRET_PK` (the sandbox path uses the DB primary key, not the key name)

`run_command`'s `secret_keys` takes the **key name**; the executor mounts each
injected secret at `/run/secrets/venya/<pk>` where `pk` = the integer DB
primary key (`secrets.id`). The command must reference that numeric path.

```bash
ssh bot@$CORE_HOST "sudo -u postgres psql -d venya -c \"SELECT id, key FROM secrets ORDER BY id;\""
# → SECRET_PK = the id on the $SECRET_KEY row
```

(Alternative: read the executor journal after session create.)

### D.4 Write the MCP config + start the session

```bash
mkdir -p $ADMIN_WS/mcp
ADMIN_MCP_TOKEN=$(python3 -c "import json; print(json.load(open('$ADMIN_WS/config.json'))['access_token'])")
printf '{"server_url":"https://%s","access_token":"%s"}' "$CORE_HOST" "$ADMIN_MCP_TOKEN" > $ADMIN_WS/mcp/config.json
chmod 600 $ADMIN_WS/mcp/config.json

VENYA_CONFIG=$ADMIN_WS/mcp/config.json VENYA_CA_CERT=/tmp/venya-ca.crt \
  $ADMIN_WS/.venv/bin/venya-mcp
```

`venya-mcp` is a stdio server — normally a subprocess of an LLM client. The
D.5 criteria must be driven as **MCP tool calls**, and the operator performs
them personally (the proof you see with your own actions is the point). Two
paths — do **Path 1** always; Path 2 additionally when an LLM client is
available:

**Path 1 — interactive MCP driver (operator-run, no LLM needed).** Spawns the
real `venya-mcp` exactly like a client would and hands you a menu:

```bash
$ADMIN_WS/.venv/bin/python testing/mcp_manual_drive.py \
    --mcp-bin $ADMIN_WS/.venv/bin/venya-mcp \
    --config  $ADMIN_WS/mcp/config.json \
    --ca      /tmp/venya-ca.crt
```

At the `mcp>` menu: `1` (list_secrets — criterion #2), `2` (list_executors —
#3), `3` (run_command — #4; enter the D.6 command and secret key when
prompted; the redacted output is your proof), `4` (get_audit — #5). Every
result prints raw, including `isError`.

**Path 2 — real LLM client (opencode example).** Do **not** register test
servers in the global client config. Create a throwaway project directory and
put the config there — project-scoped config loads only for sessions started
in that directory:

```bash
mkdir -p ~/tmp/venya-mcp-test
cat > ~/tmp/venya-mcp-test/opencode.json <<'EOF'
{
  "$schema": "https://opencode.ai/config.json",
  "mcp": {
    "venya": {
      "type": "local",
      "command": ["<ADMIN_WS>/.venv/bin/venya-mcp"],
      "enabled": true,
      "environment": {
        "VENYA_CONFIG": "<ADMIN_WS>/mcp/config.json",
        "VENYA_CA_CERT": "/tmp/venya-ca.crt"
      }
    }
  }
}
EOF
cd ~/tmp/venya-mcp-test && opencode     # config loads at startup — restart if edited
```

Then ask the agent: "list the venya secrets", "which venya executors are
online", and "on venya-exec-1 run `<D.6 command>` using the `<SECRET_KEY>`
secret" — and watch the redacted result come back through the LLM (approve
the tool-permission prompts). Any MCP client (Claude Code, Cursor, …) takes
the same stdio command + two env vars; prefer a scratch project config over
global settings there too.

*(Full matrix: build a second config from `$USER_WS/config.json` and repeat
for the user session — criterion #5's self-filter.)*

### D.5 Test criteria

| # | Criterion | Tool / how | Pass = |
|---|-----------|-----------|--------|
| 1 | MCP server starts | `venya-mcp` launches, reads config | no crash; tools listed |
| 2 | list_secrets | `list_secrets` | returns `$SECRET_KEY` + metadata, **no value** |
| 3 | list_executors | `list_executors` | `$EXEC_ID` **ONLINE** |
| 4 | **run_command uses a secret** | `run_command(executor_id=$EXEC_ID, command=<D.6>, secret_keys=[$SECRET_KEY])` | exit 0; command read the injected secret file; **raw value ABSENT from all returned output**. Minimal cat shape: stdout = `[REDACTED:<pk>]` + `masked_count ≥ 1`. Canonical ssh shape: `masked_count 0` expected (the value never traverses stdout) — proof = remote-identity output (hostname) + zero raw-value hits across payloads, journals, executor spool, and transcript |
| 5 | get_audit *(full matrix)* | admin makes ≥1 call; user calls `get_audit` | user sees own event (positive); admin event **absent** (negative = security claim) |
| 6 | Token refresh | 401 → refresh → retry | retry succeeds **or** documented known-limitation behavior (refresh path dead — see D.1) |
| 7 | Session expired | let the TTL lapse | actionable error message (not a crash) |

### D.6 The "use a secret" command (criterion #4)

**Structural-gate note (2026-09-18):** the executor rejects ANY shell
metacharacter (`| ; & $ ` + backtick + `( ) { } < > ! * ?`, newlines) ANYWHERE
in the WHOLE command string — quoted and remote portions included — before
dispatch (solution A, ticket executor-sbx-skips-shell-metachar-validation;
ruled accepted tradeoff, plan-9 Deviations row 6). The former shapes here
(`$(cat ...)` minimal, `'hostname && whoami && uptime'` canonical) physically
PASSed on pre-gate builds (run-2, results-2026-09-17-2353) and are now
rejected BY DESIGN. Shell features ⇒ script-file path. Commands must be a
SINGLE LINE (a newline is a metachar).

**Canonical shape** — ssh into the target using the injected secret as the
password, ONE remote command:

```
sshpass -f /run/secrets/venya/<SECRET_PK> ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null <TARGET_USER>@<TARGET_HOST> hostname
```

> The **remote** portion (after the first `ssh`) is exempt from the jump-host
> dangerous-pattern scan; a **local** `sudo` before `ssh` is still blocked.
> Remote chaining (`&&`, pipes, `$( )`) is blocked by the whole-string
> structural gate — for multi-command remote work, place a script on the
> target and invoke it: `... ssh <TARGET_USER>@<TARGET_HOST> /tmp/probe.sh`.
>
> **Target-auth precondition:** this shape needs the target to accept
> **password** auth for `$TARGET_USER`. Provisioned targets default to
> key-auth only — enable password auth on the target first, or use the minimal
> shape below.

**Minimal shape** (isolates injection + redaction from target connectivity):

```
cat /run/secrets/venya/<SECRET_PK>
```

Expected: stdout is the secret file's value **masked** —
`[REDACTED:<SECRET_PK>]`, `masked_count ≥ 1` (the command read the injected
file; the value never appears raw).

**Acceptance for criterion #4:** either shape — the command **reads the
injected secret file**, uses it, and the returned output has the value
**redacted**. Plaintext in the output = redaction failure = **STOP**.

---

## Failure modes & recovery

| Symptom | Cause | Recovery |
|---------|-------|----------|
| `venya init`/`enroll` 409 | partial pending row committed | `venya init <u> --installation-reset`, re-run (C.3) |
| Pasted block did nothing after the ssh banner | paste race: lines typed while ssh connects are consumed by the local terminal buffer (observed twice, 2026-09-17) | verify remote state before rerunning (`ls /tmp/...`, `ls /opt/venya`); use single-line commands or paste only after the remote prompt |
| `ClientError code=3 CONFIGURATION_UNSUPPORTED` on init/enroll/login | key has no PIN (UV impossible) | set the PIN (C.2), re-run; 409 afterwards → `--installation-reset` |
| CLI shows raw `409 Conflict`, no hint | CLI hides the server `detail` (known limitation) | confirm state via `journalctl -u venya-core` or the `users` table |
| `admin …` 403 | admin mTLS client cert stale/missing | re-sync C.1; do not sudo-curl around it |
| `venya store` fails: "No active key version configured" | pre-027 install with no active key version (503) — post-027 fresh installs seed `v1`; if seen there, check `alembic_version` | pass `--key-version v1` (pre-027 installs only) |
| `venya store` 422 `key_version_id Field required` | running a pre-fix CLI | update the workstation venv/install (B.3) |
| Executor offline after install | token single-use/expired, or mTLS | re-mint (C.4), reinstall executor |
| Every sandbox create 503 | `venya-sandboxd` down / `sbx policy init deny-all` missing / Docker login skipped | check service + policy + `sbx login` on the executor |
| First `run_command` times out (~30 s) | sandbox template cold start (~1 m) | pre-warm (B.4 pre-checks) |
| `sshpass` not found in sandbox cmd | not installed on executor | install it (`apt install sshpass` or local .deb) |
| Long run dies mid-run | 15-min session TTL; refresh path dead | set `VENYA_SESSION__SESSION_TIMEOUT` (D.1); re-login |
| TLS `CERTIFICATE_VERIFY_FAILED` from the CLI | stale/missing local CA copy | re-fetch C.0; verify SKI==AKI; never disable verification |
| Replay second POST returns 200 | challenge not consumed | **security failure — STOP** (C.7) |
| Wrong-key login succeeds | allow-list broken | **security failure — STOP** (C.7) |

**Stop-and-report (no mid-run improvisation):** if observed behavior
contradicts expectation during any step — STOP. Record verbatim: command, full
output, ranked hypotheses + evidence for each. Do not hotfix, retry with
changed parameters, or work around a blocker without explicit approval.
Distinguish **wiring** problems (sequence, environment) from **code bugs**
(correct deployment, wrong behavior) — code bugs always stop the run. Never
disable TLS verification or any security control to make a step pass; fix the
root cause or provision the missing material.

---

## Key attachment matrix

| Phase | KEY_A (admin) | KEY_B (user, full matrix only) |
|-------|:-------------:|:------------------------------:|
| A (provision) | — | — |
| B (install) | — | — |
| C.2 (key resets) | **ATTACHED** | **ATTACHED** (in sequence) |
| C.3 (admin bootstrap) | **ATTACHED** | — |
| C.5 (user enroll, full) | — | **ATTACHED** |
| C.7 (negatives, full) | **ATTACHED** (2nd login) | **ATTACHED** (2nd login, wrong-key, replay — in sequence) |
| D (MCP) | — | — |

Keys are attached only during their ceremony. Detach after. All resets happen
in C.2 **before** any timed step so they never consume an enrollment window.

---

## Results file template

Create per run: `testing/results-YYYY-MM-DD-HH-MM.md`

```markdown
# Test Run Results — YYYY-MM-DD HH:MM

## Parameters

| Variable | Value |
|----------|-------|
| Scope (minimal/full) | |
| ADMIN_USER / USER_ID | |
| KEY_A / KEY_B | |
| CORE_HOST / EXEC_HOST / TARGET_HOST | |
| ADMIN_WS / USER_WS | |
| git commit under test | |

## Phase A — Provision

| Step | Result |
|------|--------|
| A.0 RAM guard | |
| A.1 destroy | |
| A.2 create | |
| A.3 boot + SSH wait | |
| A.4 host keys cleared | |

## Phase B — Install

| Step | Result |
|------|--------|
| B.1 tarballs + hashes (CORE_SHA/EXEC_SHA/CLI_SHA) | |
| B.2 core install + health gate | |
| B.3 CLI install + help gate | |
| B.4 executor install + active gate | |
| B.4 pre-checks (sshpass, sandbox pre-warm) | |

## Phase C — Identity [FIDO2]

| Step | Result |
|------|--------|
| C.0 health + CA fetch (SKI==AKI) | |
| C.1 admin cert pair synced (hashes match) | |
| C.2 key resets + PINs set | |
| C.3 venya init (recovery code → secure storage) | |
| C.3 venya login + token harvested | |
| C.4 executor token minted (printed ungated) | |
| C.5 user create + enroll + login (full only) | |
| C.6 config perms / DB census / credential census pass 1 | |
| C.7 second login + sign_count increment (full only) | |
| C.7 wrong-key negative (full only) | |
| C.7 replay negative (full only) | |
| C.7 journal persist silence (full only) | |
| Decision gate | |

## Phase D — MCP use-a-secret

| Step | Result |
|------|--------|
| D.1 TTL accommodation + prerequisites | |
| D.2 secret stored (flag-free — 027 seed) | |
| D.3 SECRET_PK discovered | |
| D.5 #1 server starts | |
| D.5 #2 list_secrets (metadata, no value) | |
| D.5 #3 list_executors ONLINE | |
| D.5 #4 run_command uses secret (masked_count ≥ 1) | |
| D.5 #5 audit pos+neg (full only) | |
| D.5 #6 token refresh (or known-limitation behavior) | |
| D.5 #7 session-expired message | |

## Verdict

- Provision: PASS / FAIL
- Install: PASS / FAIL
- FIDO2: PASS / FAIL
- MCP use-a-secret: PASS / FAIL

## Issues

| # | Phase | Description | Resolution |
|---|-------|-------------|------------|
| | | | |

## Raw output (appendix)

Paste verbatim command output for any step that failed or was unexpected.
Never paste full tokens, PINs, passwords, or recovery codes.
```

---

## Known limitations

1. **FIDO2 keys must be physically attached to the workstation.** No remote
   ceremony exists; PIN prompts require a local TTY.
2. **Token windows are tight by default:** user enrollment 15 min — adjustable
   via `VENYA_FIDO2__ENROLLMENT_TOKEN_TTL` (minutes; wired at the manager —
   installs predating that fix have a dead knob and hardcode 900 s); executor
   enrollment ~30 min (dev runs raise it to 4 h — D.1); both single-use. Mint
   immediately before use, and remember TTL changes require re-login (D.1).
3. **Key-version bootstrap:** migration 027 seeds one active `v1` at install —
   `venya store` works without `--key-version` and `GET /key-versions/active`
   answers 200. Installs predating 027 have no active version: the lookup 503s
   and `store` fails loudly with a `--key-version v1` hint.
4. **The session refresh path cannot revive an expired token** — long runs need
   the D.1 timeout accommodation.
5. **Secret upsert is visibility-scoped** — re-storing a key replaces it iff you can see it (role in scope or creator); scoped-out callers create a second row.
