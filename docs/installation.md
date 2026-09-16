# Venya Installation Guide

Full deployment guide for the alpha. Venya runs on dedicated Linux VMs or
bare metal. All artifacts — installers, tarballs, SHA-256 sidecars — are
published on the GitHub releases page:
https://github.com/tabith-llc/venya/releases. The `releases/latest/download`
URLs used below always resolve to the current release; pin
`VENYA_TARBALL_SHA256` (hashes on the release page) for strict integrity.

## Topology

| Node | Role | Installer |
|---|---|---|
| Core server (1) | FastAPI vault + API behind nginx TLS, PostgreSQL, CA authority | `install-venya-core.sh` |
| Executor host (1..n) | Sandboxed command execution daemon, secret injection, redaction | `install-venya-executor.sh` |
| Operator workstation | `venya` CLI + `venya-mcp` (FIDO2 key attached here) | `install-venya-cli.sh` |
| Target hosts | The machines commands ultimately run on (via SSH from executors) | none |

Requirements: Ubuntu 24.04 LTS (tested target) on servers; PostgreSQL and
nginx are installed automatically by the core installer; Python 3.14 is
provisioned automatically via `uv`; a FIDO2 security key (YubiKey, TrustKey,
etc.) for every human operator.

## 1. Install the core server

On the core VM (root):

```bash
curl -fsSL https://github.com/tabith-llc/venya/releases/latest/download/install-venya-core.sh | sudo \
  VENYA_SKIP_PROMPT=yes \
  VENYA_DB_PASSWORD=<strong-db-password> \
  bash -s
```

The installer is SHA-256-gated and fail-closed: with `VENYA_TARBALL_SHA256`
set it verifies against that pin (strict integrity — recommended); unset, it
fetches the `.sha256` sidecar from the same origin as the tarball (corruption
guardrail). Any fetch failure or mismatch aborts the install.

What it creates: locked `venya` service account; nginx TLS termination
(internal CA-signed cert, admin mTLS enforcement); PostgreSQL role/database;
Python 3.14 venv with core+server+cli packages; runtime config at
`/opt/venya/.env` (the ONLY config source — no TOML files); the Venya root
CA (`/var/lib/venya/ca/`), an Admin CA with an encrypted key, and an admin
client certificate (`/etc/venya/admin/`); database migrations; and the
`venya-core.service` systemd unit.

Key environment variables (all optional except the SHA-256):

| Variable | Default | Purpose |
|---|---|---|
| `VENYA_TARBALL_SHA256` | (required) | integrity gate |
| `VENYA_DB_PASSWORD` | (prompt) | PostgreSQL password |
| `VENYA_DB_PASSPHRASE` | dev default | server encryption passphrase — set a strong one in any real deployment |
| `CORE_HOSTNAME` | `$(hostname)` | TLS cert SAN and relay CN base |
| `VENYA_ADMIN_MTLS_ENABLED` | `true` | admin client-cert enforcement |
| `VENYA_ADMIN_CA_PASSPHRASE` | auto-generated | stored in `/etc/venya/venya-core.env` (0640) |

Verify:

```bash
curl -sk https://<core-host>/api/v1/health
# {"status":"ok","checks":{"ca":"ok","admin_ca":"ok"}}
```

## 2. Bootstrap the first admin (workstation, FIDO2)

Install the workstation bundle first (section 4), then:

```bash
curl -sk https://<core-host>/.well-known/venya-ca.crt -o ~/.config/venya-ca.crt
venya config set-server https://<core-host>
SSL_CERT_FILE=~/.config/venya-ca.crt venya init <admin-user-id>
```

Touch the security key when prompted. A **recovery code is printed once** —
store it securely; it is the only way back if the key is lost. Migrations
already ran at install time; `venya init` never migrates.

Copy the admin mTLS certificate pair to the workstation (needed for
`venya admin ...` commands):

```bash
ssh <core-vm> "sudo cat /etc/venya/admin/admin.crt" > admin-cert/admin.crt
ssh <core-vm> "sudo cat /etc/venya/admin/admin.key" > admin-cert/admin.key
chmod 600 admin-cert/admin.key
```

## 3. Install executors

Executors need a single-use enrollment token minted by an admin from the
workstation (FIDO2 + admin mTLS cert; these operations cannot run on the
headless core):

```bash
SSL_CERT_FILE=~/.config/venya-ca.crt \
VENYA_ADMIN_CERT=admin-cert/admin.crt VENYA_ADMIN_KEY=admin-cert/admin.key \
venya admin executor-enroll <executor-id>
```

The token expires in ~30 minutes and is consumed on first use.
**`<executor-id>` is a contract**: it becomes the client-certificate SAN and
the hostname cores dial for relay calls — it must resolve from every core,
and must match the pattern `^[a-z0-9][a-z0-9-]{0,62}[a-z0-9]$`.

Then on the executor VM (root):

```bash
curl -fsSL https://github.com/tabith-llc/venya/releases/latest/download/install-venya-executor.sh | sudo \
  VENYA_SKIP_PROMPT=yes \
  VENYA_SERVER_URL=https://<core-host> \
  VENYA_EXECUTOR_ID=<executor-id> \
  VENYA_EXECUTOR_ENROLLMENT_TOKEN=<token> \
  bash -s
```

**Docker account credentials are required.** The sbx sandbox runtime pulls
its agent template from Docker: the installer prompts for a Docker username
and API key/access token (interactive runs), or takes
`VENYA_DOCKER_USERNAME` + `VENYA_DOCKER_API_KEY` (piped/non-interactive
runs). The token is handled **stdin-only** — never in process arguments,
never written by the installer (sbx keeps it in its own credential store
under the service account's home). Without credentials the installer
**fails closed**; `VENYA_SKIP_DOCKER_LOGIN=yes` forces a degraded install
(executor runs, but every sandbox execution fails 503 until
`sudo -H -u venya sbx login` is done by hand).

The installer also starts `venya-sandboxd.service` (the sbx daemon,
persistent across reboots, ordered before `venya-executor.service`) and
initializes the sbx global network policy to **deny-all** (per-sandbox
allow rules come from the egress allowlist at execution time).

Hostname resolution: the installer uses the provisioned `/etc/hosts` entry
for the core if present, else DNS. If the core hostname resolves neither way,
the installer **fails closed** and tells you to set `VENYA_CORE_IP=<ip>` —
it never guesses an IP (a wrong guess silently misroutes mTLS). An explicit
`VENYA_CORE_IP` always wins over an existing hosts entry.

What it creates: `venya` service account; Rust toolchain + the compiled
redaction filter (`venya_filter.*.so`); Python venv (executor+core+cli);
sbx (Docker Sandboxes) CLI; mTLS certificate registration with the core at
install time; egress allowlist (`/etc/venya/egress-allowlist.txt`,
deny-by-default); `venya-executor.service` with seccomp profile; and the
secrets tmpfs mount.

Verify:

```bash
systemctl is-active venya-executor        # active
ss -tln | grep 8443                        # relay listener bound
journalctl -u venya-executor -n 20         # heartbeat POST ... 200 OK
```

## 4. Install the workstation bundle

On each operator workstation (Linux, **non-root — no sudo**; the installer
refuses root):

```bash
curl -fsSL https://github.com/tabith-llc/venya/releases/latest/download/install-venya-cli.sh | \
  VENYA_SKIP_PROMPT=yes bash
```

Installs `venya` (CLI) and `venya-mcp` (MCP server for LLM clients) as
isolated `uv tool` venvs with shims in `~/.local/bin`. Set
`VENYA_INSTALL_MCP=no` for CLI-only. If the FIDO2 key is not reachable as
your user, the installer prints the exact udev/plugdev commands to fix it.

Day-one:

```bash
venya config set-server https://<core-host>
SSL_CERT_FILE=~/.config/venya-ca.crt venya login <user-id>
```

## 5. Enroll regular users

```bash
SSL_CERT_FILE=~/.config/venya-ca.crt \
VENYA_ADMIN_CERT=admin-cert/admin.crt VENYA_ADMIN_KEY=admin-cert/admin.key \
venya admin create-user <user-id> --roles user
```

The response carries a 15-minute single-use enrollment token; the user runs
`venya enroll <token>` on their own workstation with their own key.

## 6. MCP client wiring (LLM operators)

```json
{
  "mcpServers": {
    "venya": {
      "command": "venya-mcp",
      "env": {
        "VENYA_CONFIG": "/home/you/.config/venya/config.json",
        "VENYA_CA_CERT": "/home/you/.config/venya-ca.crt"
      }
    }
  }
}
```

`VENYA_CA_CERT` is required at startup (fail-closed TLS; the internal CA is
not in the system trust store).

### opencode

Project-level config (`opencode.json` in your working directory) or global
(`~/.config/opencode/opencode.json`). Note the different shape — opencode
does not use the `mcpServers` convention:

```json
{
  "$schema": "https://opencode.ai/config.json",
  "mcp": {
    "venya": {
      "type": "local",
      "command": ["/home/you/.local/bin/venya-mcp"],
      "enabled": true,
      "environment": {
        "VENYA_CONFIG": "/home/you/.config/venya/config.json",
        "VENYA_CA_CERT": "/home/you/.config/venya-ca.crt"
      }
    }
  }
}
```

Restart opencode after config changes (config loads once at startup). The
tools are model-invoked, not slash commands: ask "list the venya secrets",
don't type `/list_secrets`. On 401/expired: `venya login <user-id>` (key
touch) and retry — the MCP server reads the refreshed token from the same
`VENYA_CONFIG` file.

## Uninstalling

One uninstaller per artifact, published alongside the installers:

```bash
# core / executor VMs (root)
curl -fsSL https://github.com/tabith-llc/venya/releases/latest/download/uninstall-venya-core.sh | sudo VENYA_SKIP_PROMPT=yes bash
curl -fsSL https://github.com/tabith-llc/venya/releases/latest/download/uninstall-venya-executor.sh | sudo VENYA_SKIP_PROMPT=yes bash

# workstation (non-root; VENYA_PURGE_CONFIG=yes also removes ~/.config/venya)
curl -fsSL https://github.com/tabith-llc/venya/releases/latest/download/uninstall-venya-cli.sh | VENYA_SKIP_PROMPT=yes bash
```

The core uninstaller also drops the PostgreSQL database and role. Shared
infrastructure (nginx/postgres/sbx packages) is kept; revoking a removed
executor's certificate is a core-side admin operation.

## Air-gapped networks

Full offline installation is a tracked beta goal, not yet turnkey: the
installers fetch Python toolchains and package dependencies at install time.
For air-gapped alpha sites, contact info@tabith.com — a local mirror
procedure exists but is not yet packaged.

## Troubleshooting

- `502` from nginx immediately after core install: give the backend a few
  seconds to bind; re-probe `api/v1/health`.
- **First** `run_command`/`venya run` after an executor install times out
  client-side: the first sandbox create pulls the agent template (~60 s+).
  The command usually still completes server-side — check the executor
  journal (`journalctl -u venya-executor`) and the target's actual state
  before retrying; the warm rerun is seconds-scale.
- `503` with `Not authenticated to Docker` in the executor journal: sbx
  login missing/expired — rerun the installer with Docker credentials or
  `sudo -H -u venya sbx login` on the executor.
- `503` with `global network policy has not been initialized`: run
  `sudo -H -u venya sbx policy init deny-all` on the executor (the
  installer does this automatically since the 2026-09 fix).
- `503` on otherwise-valid commands: the executor's trusted-path validation
  requires absolute binary paths (`/bin/echo`, `/usr/bin/ssh`) — shell
  builtins and bare command names are rejected by design. Also do not pass a
  `--` separator to `venya run`: the CLI captures it literally into the
  command string (known quirk, ticketed).
- `Host key verification failed` / TLS failures between components: the CA
  must be provisioned, never verification disabled. Re-fetch
  `/.well-known/venya-ca.crt` after any core reinstall (every install mints
  a new CA).
- Admin endpoints return 403: admin mTLS is enforced — pass
  `VENYA_ADMIN_CERT`/`VENYA_ADMIN_KEY` from the current core install.
- Executor relay rejects the core (403 at handshake): the core's relay
  client-cert CN must be `<core-hostname>-relay` and listed in the
  executor's `relay_client_ids` — both are derived from the same hostname;
  mismatches happen only when core and executor disagree about
  `CORE_HOSTNAME`/`VENYA_SERVER_URL`.
