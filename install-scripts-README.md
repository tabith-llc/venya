# Venya HTTP Install Scripts

Installation scripts for Venya components, served via HTTP for VM provisioning.

## Scripts

### `install-venya-core.sh`

Installs the Venya Core server on a fresh VM. Includes:

- **venya** service account (nologin + locked; no password)
- System packages: `curl`, `sudo`
- **Nginx** reverse proxy (installed first for TLS)
- **PostgreSQL** (user, database, trust auth for localhost)
- Python virtual environment + core/server packages
- Code fixes (database_url, imports, timezone handling)
- Configuration: `server.toml`, `.env`, Nginx site config
- Nginx CA trust installation
- Database migrations
- `venya-core.service` systemd unit

**Usage:**
```bash
curl -fsSL http://10.27.27.35:8080/install-venya-core.sh | sudo bash
```

**Environment variables:**

| Variable | Default | Description |
|---|---|---|
| `VENYA_INSTALL_DIR` | `/opt/venya` | Install location |
| `VENYA_SKIP_PROMPT` | (empty) | Set to `yes` to skip confirmation prompts |
| `VENYA_DB_PASSWORD` | (prompt) | PostgreSQL venya user password |
| `VENYA_DB_PASSPHRASE` | `venya_test_passphrase_2024` | Server encryption passphrase |
| `VENYA_TARBALL` | `http://10.27.27.35:8080/venya-core-install.tar.gz` | Tarball URL |
| `CORE_HOSTNAME` | `$(hostname)` | Hostname for TLS/Nginx (auto-detected by default) |
| `TLS_MODE` | `internal` | Nginx TLS mode (internal = self-signed, manual = provide certs) |
| `VENYA_ADMIN_MTLS_ENABLED` | `true` | Enforce admin mTLS (admin client cert required) |
| `VENYA_ADMIN_IDENTITY` | (empty) | Admin CN identity for the admin CA |
| `VENYA_ADMIN_CA_PASSPHRASE` | (empty) | Passphrase protecting the admin CA key |

### `install-venya-executor.sh`

Installs the Venya Executor daemon on a fresh VM. Includes:

- **venya** service account (nologin + locked; no password)
- System packages: `curl`, `sudo`, `build-essential`
- **Rust** toolchain (venya user)
- Python virtual environment + executor/core packages
- Rust extension build (`venya_filter.so`)
- Code fixes (same as core)
- **sbx** CLI (Docker Sandboxes)
- Configuration: `executor.toml`
- `venya-executor.service` systemd unit

**Usage:**
```bash
curl -fsSL http://10.27.27.35:8080/install-venya-executor.sh | sudo bash
```

**Environment variables:**

| Variable | Default | Description |
|---|---|---|
| `VENYA_INSTALL_DIR` | `/opt/venya` | Install location |
| `VENYA_SKIP_PROMPT` | (empty) | Set to `yes` to skip confirmation prompts |
| `VENYA_TARBALL` | `http://10.27.27.35:8080/venya-executor-install.tar.gz` | Tarball URL |
| `VENYA_EXECUTOR_ID` | `jump-1` | Executor identifier |
| `VENYA_SERVER_URL` | `https://venya-core` | Core server URL |
| `VENYA_EXECUTOR_ENROLLMENT_TOKEN` | (empty) | Bootstrap enrollment token — enables mTLS cert registration and heartbeat bootstrap at install time |

### `install-debug-tools.sh`

Installs development/debugging packages not needed for runtime. Only needed for troubleshooting.

**Packages:** `strace`, `ltrace`, `gdb`, `tcpdump`, `net-tools`, `iproute2`, `wget`, `rsync`, `iptables`

**Usage:**
```bash
curl -fsSL http://10.27.27.35:8080/install-debug-tools.sh | sudo bash
```

## Deployment

### Build and serve

```bash
cd /media/dust/dust-ext1/projects/venya-installer
./create-tarball-and-serve.sh
```

This creates two tarballs (`venya-core-install.tar.gz` and `venya-executor-install.tar.gz`), copies the install scripts **and the shared `venya-common.sh` library** to the serving directory, and starts an HTTP server on port 8080.

The piped install one-liners below work because the install scripts self-fetch `venya-common.sh` from the same origin as `VENYA_TARBALL` when it is not next to the script (no-`$0` case, i.e. `curl | sudo bash`).

### Install on VMs

```bash
# Core VM
curl -fsSL http://10.27.27.35:8080/install-venya-core.sh | sudo bash

# Executor VM
curl -fsSL http://10.27.27.35:8080/install-venya-executor.sh | sudo bash

# Stop the server
pkill -f 'python3 -m http.server 8080'
```

## Dependency Summary

| Dependency | Core | Executor | Debug Tools |
|---|---|---|---|
| `curl` | Yes | Yes | — |
| `sudo` | Yes | Yes | — |
| `build-essential` | No | Yes | — |
| `Rust / cargo` | No | Yes | — |
| `Nginx` | Yes | No | — |
| `PostgreSQL` | Yes | No | — |
| `sbx CLI` | No | Yes | — |
| Debug packages | — | — | Yes |

## Post-Install

### Core

```bash
sudo systemctl start venya-core
curl -sk https://<core-hostname>/api/v1/health
# Expected: {"status":"ok"}
```

### Executor

```bash
# 1. Generate mTLS certs on core server
# 2. Copy ca.crt, executor.crt, executor.key to /etc/venya/executor/
sudo systemctl start venya-executor
```

### Service account (both)

`venya` is a **locked, nologin service account** — no interactive login (ssh/console/PAM) and no password is set. Root operates it with `sudo -u venya <cmd>` or an interactive `sudo -u venya bash` (break-glass; the account's own shell is nologin, so `su - venya` is refused by design).
