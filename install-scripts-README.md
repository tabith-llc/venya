# Venya HTTP Install Scripts

Installation scripts for Venya components, served via HTTP for VM provisioning.

## Scripts

### `install-venya-vault.sh`

Installs the Venya Vault server on a fresh VM. Includes:

- **venya** user creation
- System packages: `curl`, `sudo`
- **Caddy** reverse proxy (installed first for TLS)
- **PostgreSQL** (user, database, trust auth for localhost)
- Python virtual environment + vault/server packages
- Code fixes (database_url, imports, timezone handling)
- Configuration: `server.toml`, `.env`, `Caddyfile`
- Caddy CA trust installation
- Database migrations
- `venya-vault.service` systemd unit

**Usage:**
```bash
curl -fsSL http://10.27.27.35:8080/install-venya-vault.sh | sudo bash
```

**Environment variables:**

| Variable | Default | Description |
|---|---|---|
| `VENYA_INSTALL_DIR` | `/opt/venya` | Install location |
| `VENYA_SKIP_PROMPT` | (empty) | Set to `yes` to skip confirmation prompts |
| `VENYA_PASSWORD` | (prompt) | OS venya user password |
| `VENYA_DB_PASSWORD` | (prompt) | PostgreSQL venya user password |
| `VENYA_DB_PASSPHRASE` | `venya_test_passphrase_2024` | Server encryption passphrase |
| `VENYA_TARBALL` | `http://10.27.27.35:8080/venya-vault-install.tar.gz` | Tarball URL |
| `VAULT_HOSTNAME` | `$(hostname)` | Hostname for TLS/Caddy (auto-detected by default) |
| `TLS_MODE` | `internal` | Caddy TLS mode (`internal`, `manual`, `email`) |

### `install-venya-executor.sh`

Installs the Venya Executor daemon on a fresh VM. Includes:

- **venya** user creation
- System packages: `curl`, `sudo`, `build-essential`
- **Rust** toolchain (root + venya user)
- Python virtual environment + executor/vault packages
- Rust extension build (`venya_filter.so`)
- Code fixes (same as vault)
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
| `VENYA_PASSWORD` | (prompt) | OS venya user password |
| `VENYA_TARBALL` | `http://10.27.27.35:8080/venya-executor-install.tar.gz` | Tarball URL |
| `VENYA_EXECUTOR_ID` | `jump-1` | Executor identifier |
| `VENYA_SERVER_URL` | `http://localhost:8080` | Vault server URL |

### `install-debug-tools.sh`

Installs development/debugging packages not needed for runtime. Only needed for troubleshooting.

**Packages:** `strace`, `ltrace`, `gdb`, `tcpdump`, `net-tools`, `iproute2`, `wget`, `rsync`, `iptables`

**Usage:**
```bash
curl -fsSL http://10.27.27.35:8080/install-debug-tools.sh | sudo bash
```

### `install.sh` (original)

The original monolithic installer. Supports `VENYA_MODE=vault`, `VENYA_MODE=executor`, or `VENYA_MODE=both`. **Not modified** — kept for reference and backward compatibility.

**Usage:**
```bash
curl -fsSL http://10.27.27.35:8080/install.sh | sudo VENYA_MODE=vault bash -
```

## Deployment

### Build and serve

```bash
cd /media/dust/dust-ext1/projects/venya-installer
./create-tarball-and-serve.sh
```

This creates two tarballs (`venya-vault-install.tar.gz` and `venya-executor-install.tar.gz`), copies all install scripts to the serving directory, and starts an HTTP server on port 8080.

### Install on VMs

```bash
# Vault VM
curl -fsSL http://10.27.27.35:8080/install-venya-vault.sh | sudo bash

# Executor VM
curl -fsSL http://10.27.27.35:8080/install-venya-executor.sh | sudo bash

# Stop the server
pkill -f 'python3 -m http.server 8080'
```

## Dependency Summary

| Dependency | Vault | Executor | Debug Tools |
|---|---|---|---|
| `curl` | Yes | Yes | — |
| `sudo` | Yes | Yes | — |
| `build-essential` | No | Yes | — |
| `Rust / cargo` | No | Yes | — |
| `Caddy` | Yes | No | — |
| `PostgreSQL` | Yes | No | — |
| `sbx CLI` | No | Yes | — |
| Debug packages | — | — | Yes |

## Post-Install

### Vault

```bash
sudo systemctl start venya-vault
curl -sk https://<vault-hostname>/api/v1/health
# Expected: {"status":"ok"}
```

### Executor

```bash
# 1. Generate mTLS certs on vault server
# 2. Copy ca.crt, executor.crt, executor.key to /etc/venya/executor/
sudo systemctl start venya-executor
```
