#!/usr/bin/env bash
set -euo pipefail

###############################################################################
# Venya Executor Installer
#
# Installs Venya Executor on a fresh VM:
#   - venya user, system packages, Rust, uv
#   - Python venv, executor + vault packages
#   - Rust extension build
#   - sbx CLI, executor.toml
#   - venya-executor.service
#
# Environment variables:
#   VENYA_INSTALL_DIR   - Install location (default: /opt/venya)
#   VENYA_SKIP_PROMPT   - Set to "yes" to skip the confirmation prompt
#   VENYA_PASSWORD      - OS venya user password (prompts if unset)
#   VENYA_TARBALL       - URL of the tarball to install (auto-detected if on same host)
#   VENYA_EXECUTOR_ID              - Executor ID (default: jump-1)
#   VENYA_SERVER_URL               - Vault server URL (default: https://venya-vault)
#   VENYA_EXECUTOR_ENROLLMENT_TOKEN - Bootstrap enrollment token for auto-registration
###############################################################################

# --- Defaults ---
INSTALL_DIR="${VENYA_INSTALL_DIR:-}"
SKIP_PROMPT="${VENYA_SKIP_PROMPT:-}"
TARBALL_URL="${VENYA_TARBALL:-http://10.27.27.35:8080/venya-executor-install.tar.gz}"
EXECUTOR_ID="${VENYA_EXECUTOR_ID:-jump-1}"
SERVER_URL="${VENYA_SERVER_URL:-https://venya-vault}"

# --- Colors ---
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

info()  { echo -e "${GREEN}[INFO]${NC}  $*"; }
warn()  { echo -e "${YELLOW}[WARN]${NC}  $*"; }
error() { echo -e "${RED}[ERROR]${NC} $*"; }

# --- Root check ---
if [ "$(id -u)" -ne 0 ]; then
    error "This script must be run as root (or with sudo)."
    exit 1
fi

# --- Determine install directory ---
INSTALL_DIR="${VENYA_INSTALL_DIR:-}"
reply=""

if [ -z "$INSTALL_DIR" ]; then
    DEFAULT_DIR="/opt/venya"
    echo -n "Install to $DEFAULT_DIR? [Y/n] "
    if [ "$SKIP_PROMPT" = "yes" ]; then
        echo ""
        reply="y"
    else
        read -r reply || reply=""
    fi
    if [ -z "$reply" ] || [ "$reply" = "y" ] || [ "$reply" = "Y" ]; then
        INSTALL_DIR="$DEFAULT_DIR"
    else
        read -rp "Enter install directory: " INSTALL_DIR
    fi
fi

# Ensure path ends without trailing slash
INSTALL_DIR="${INSTALL_DIR%/}"

# --- Check for existing installation ---
reply=""
if [ -d "$INSTALL_DIR" ] && [ -f "$INSTALL_DIR/pyproject.toml" ]; then
    warn "Existing installation found at $INSTALL_DIR"
    echo -n "Reinstall? [y/N] "
    if [ "$SKIP_PROMPT" = "yes" ]; then
        echo ""
        reply="y"
    else
        read -r reply || reply=""
    fi
    if [ -z "$reply" ] || [ "$reply" = "n" ] || [ "$reply" = "N" ]; then
        info "Aborted."
        exit 0
    fi
fi

info "Installing Venya Executor to $INSTALL_DIR"

# --- Create venya user ---
if ! id venya &>/dev/null; then
    if [ -z "$VENYA_PASSWORD" ]; then
        echo -n "Enter password for venya user: "
        read -rs VENYA_PASSWORD
        echo ""
    fi
    # Password strength check
    if [ "${#VENYA_PASSWORD}" -lt 8 ]; then
        error "Password must be at least 8 characters long."
        exit 1
    fi
    useradd -m -s /bin/bash venya
    # Write password to secure temp file to avoid exposing it in process list
    PW_FILE=$(mktemp /tmp/venya-pw-XXXXXX)
    chmod 600 "$PW_FILE"
    printf 'venya:%s\n' "$VENYA_PASSWORD" > "$PW_FILE"
    chpasswd < "$PW_FILE"
    rm -f "$PW_FILE"
    info "Created venya user"
fi

# --- Install system packages ---
info "Installing system packages..."
apt-get update -qq
apt-get install -y -qq curl sudo build-essential > /dev/null 2>&1

# --- Install Rust ---
if ! command -v rustc &>/dev/null; then
    info "Installing Rust..."
    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y > /dev/null 2>&1
else
    info "Rust already installed: $(rustc --version)"
fi

# --- Install Rust for venya user ---
SU_CARGO="/home/venya/.cargo/bin/cargo"
if [ ! -f "$SU_CARGO" ]; then
    info "Installing Rust for venya user..."
    sudo -u venya bash -c "curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y" > /dev/null 2>&1
fi

# --- Install uv (for both root and venya user) ---
if ! command -v uv &>/dev/null; then
    info "Installing uv..."
    curl -LsSf https://astral.sh/uv/install.sh | sh > /dev/null 2>&1
else
    info "uv already installed: $(uv --version)"
fi

# Source paths for root
source "$HOME/.cargo/env" 2>/dev/null || true
source "$HOME/.local/bin/env" 2>/dev/null || true

# --- Install uv for venya user ---
SU_UV_BIN="/home/venya/.local/bin/uv"
if [ ! -f "$SU_UV_BIN" ]; then
    info "Installing uv for venya user..."
    sudo -u venya bash -c "curl -LsSf https://astral.sh/uv/install.sh | sh" > /dev/null 2>&1
fi

# --- Get tarball ---
if [ -z "$TARBALL_URL" ]; then
    if [ -f "/tmp/venya-install.tar.gz" ]; then
        TARBALL_URL="file:///tmp/venya-executor-install.tar.gz"
    elif [ -f "/opt/venya-install.tar.gz" ]; then
        TARBALL_URL="file:///opt/venya-executor-install.tar.gz"
    else
        error "No tarball found. Set VENYA_TARBALL to a URL or place venya-executor-install.tar.gz in /tmp/"
        exit 1
    fi
fi

info "Downloading tarball from $TARBALL_URL..."
TARBALL_FILE=$(mktemp /tmp/venya-install-XXXXXX.tar.gz)

if [[ "$TARBALL_URL" == file://* ]]; then
    cp "${TARBALL_URL#file://}" "$TARBALL_FILE"
else
    curl -fsSL "$TARBALL_URL" -o "$TARBALL_FILE"
fi

# --- Create install directory and extract ---
mkdir -p "$INSTALL_DIR"
tar xzf "$TARBALL_FILE" -C "$INSTALL_DIR" --strip-components=1
rm -f "$TARBALL_FILE"
chown -R venya:venya "$INSTALL_DIR"

# --- Build Python environment (as venya user) ---
info "Creating Python virtual environment..."
VENYA_UV="/home/venya/.local/bin/uv"
sudo -u venya env PATH="/home/venya/.local/bin:/home/venya/.cargo/bin:$PATH" bash -c "cd $INSTALL_DIR && UV_VENV_CLEAR=1 $VENYA_UV venv .venv"

info "Installing Python packages..."
sudo -u venya env PATH="/home/venya/.local/bin:/home/venya/.cargo/bin:$PATH" bash -c "cd $INSTALL_DIR && $VENYA_UV pip install -r $INSTALL_DIR/venya-executor-requirements.txt"

# --- Build Rust extension (as venya user) ---
info "Building Rust filter extension..."
VENYA_CARGO="/home/venya/.cargo/bin/cargo"
RUST_LOG="/var/log/venya/rust-build.log"
mkdir -p "$(dirname "$RUST_LOG")"
sudo -u venya env PATH="/home/venya/.local/bin:/home/venya/.cargo/bin:$PATH" bash -c "cd $INSTALL_DIR/packages/executor && $VENYA_CARGO build --release" > "$RUST_LOG" 2>&1
if [ $? -ne 0 ]; then
    error "Rust build failed. See $RUST_LOG"
    cat "$RUST_LOG"
    exit 1
fi
if [ ! -f "$INSTALL_DIR/packages/executor/target/release/libvenya_filter.so" ]; then
    error "Rust build completed but libvenya_filter.so not found"
    exit 1
fi
info "Rust build complete"
PYTHON_PATH=$(find "$INSTALL_DIR/.venv" -type d -name 'site-packages' | head -1)
cp "$INSTALL_DIR/packages/executor/target/release/libvenya_filter.so" "$PYTHON_PATH/venya_filter.so"
chown venya:venya "$PYTHON_PATH/venya_filter.so"
cd ../..

# --- Apply code fixes ---
info "Applying code fixes..."

# Fix 1: Update init_db to use db_config.database_url in dependencies.py
if grep -q 'database_url = os.environ.get("VENYA_DB_URL")' "$INSTALL_DIR/packages/server/src/server/dependencies.py" 2>/dev/null; then
    sed -i 's|database_url = os.environ.get("VENYA_DB_URL")|database_url = db_config.database_url or os.environ.get("VENYA_DB_URL")|' \
        "$INSTALL_DIR/packages/server/src/server/dependencies.py"
    if ! head -10 "$INSTALL_DIR/packages/server/src/server/dependencies.py" | grep -q "^import os"; then
        sed -i '/from __future__ import annotations/a\\nimport os' \
            "$INSTALL_DIR/packages/server/src/server/dependencies.py"
    fi
    info "  Fixed init_db to use db_config.database_url"
fi

# Fix 2: Fix init.py imports (from ..iam.models → from vault.iam.models)
for f in "$INSTALL_DIR/packages/server/src/server/routes/init.py"; do
    if [ -f "$f" ]; then
        sed -i 's/from \.\.iam\.models/from vault.iam.models/g' "$f"
        info "  Fixed init.py imports"
    fi
done

# Fix 3: Ensure db.flush() after admin_role creation in init.py
for f in "$INSTALL_DIR/packages/server/src/server/routes/init.py"; do
    if [ -f "$f" ]; then
        if ! grep -q 'db\.flush()' "$f" 2>/dev/null; then
            sed -i '/db\.add(admin_role)/a\        db.flush()' "$f"
            info "  Added db.flush() after admin_role creation"
        fi
    fi
done

# Fix 4: Ensure timezone-aware datetimes in executors.py heartbeat
for f in "$INSTALL_DIR/packages/server/src/server/routes/executors.py"; do
    if [ -f "$f" ]; then
        if ! grep -q 'not_after\.tzinfo' "$f" 2>/dev/null; then
            sed -i '/not_after = current_cert\.not_after/a\                if not_after.tzinfo is None:\n                    not_after = not_after.replace(tzinfo=timezone.utc)' "$f"
            info "  Fixed timezone-aware datetime in heartbeat"
        fi
    fi
done

# --- Create directories and set ownership ---
mkdir -p /var/lib/venya/ca
mkdir -p /var/log/venya
chown -R venya:venya /var/lib/venya
chown -R venya:venya /var/log/venya
chown -R venya:venya "$INSTALL_DIR"
chmod 700 /var/lib/venya/ca

# --- Harden permissions on sensitive paths ---
if [ -d /etc/venya/executor ]; then
    chmod 700 /etc/venya/executor
fi
if [ -f /etc/venya/executor.toml ]; then
    chmod 600 /etc/venya/executor.toml
fi
if [ -d /etc/venya/executor ]; then
    find /etc/venya/executor -name '*.key' -exec chmod 600 {} \; 2>/dev/null || true
    find /etc/venya/executor -name '*.crt' -exec chmod 644 {} \; 2>/dev/null || true
fi
chmod 750 /var/log/venya
chown venya:adm /var/log/venya 2>/dev/null || chown venya:venya /var/log/venya

# --- Install Docker Sandboxes (sbx) CLI ---
info "Installing Docker Sandboxes (sbx) CLI..."
if ! command -v sbx &>/dev/null; then
    curl -fsSL https://get.docker.com | REPO_ONLY=1 sh > /dev/null 2>&1
    apt-get install -y -qq docker-sbx > /dev/null 2>&1
    usermod -aG kvm venya 2>/dev/null || true
    info "sbx CLI installed. venya user added to kvm group."
else
    info "sbx CLI already installed: $(sbx --version 2>/dev/null || echo 'unknown')"
fi

# --- Write executor config ---
mkdir -p /etc/venya/executor
mkdir -p /var/log/venya

cat > /etc/venya/executor.toml << EOF
server_url = "$SERVER_URL"
executor_id = "$EXECUTOR_ID"
log_level = "info"
daemonize = false
injection_method = "sbx"
secret_base_fd = 100

[mtls]
ca_cert = "/etc/venya/executor/ca.crt"
cert = "/etc/venya/executor/executor.crt"
key = "/etc/venya/executor/executor.key"
EOF

info "Executor config written to /etc/venya/executor.toml"

# --- Register mTLS certificate (if enrollment token provided and vault reachable) ---
if [ -n "$VENYA_EXECUTOR_ENROLLMENT_TOKEN" ]; then
    info "Attempting mTLS certificate registration..."

    # Retry loop: wait for vault to be reachable
    VAULT_REACHABLE=false
    for i in $(seq 1 5); do
        if curl -sf --insecure "$SERVER_URL/api/v1/health" >/dev/null 2>&1; then
            VAULT_REACHABLE=true
            break
        fi
        if [ "$i" -lt 5 ]; then
            info "Vault not reachable at $SERVER_URL — retrying ($i/5), waiting 10s..."
            sleep 10
        fi
    done

    if [ "$VAULT_REACHABLE" = true ]; then
        # Run registration
        REG_OUTPUT=$("$INSTALL_DIR/.venv/bin/venya" exec register \
            --executor-id "$EXECUTOR_ID" \
            --vault-url "$SERVER_URL" \
            --output-dir /etc/venya/executor \
            --enrollment-token "$VENYA_EXECUTOR_ENROLLMENT_TOKEN" \
            2>&1) || true
        echo "$REG_OUTPUT"

        # Check if certs were created
        if [ -f /etc/venya/executor/executor.crt ] && [ -f /etc/venya/executor/executor.key ]; then
            info "mTLS certificates generated successfully"
        else
            warn "Certificate registration completed but cert files not found"
            warn "Check output above for errors"
        fi
    else
        warn "Vault unreachable at $SERVER_URL after 5 attempts — skipping cert registration"
        echo ""
        echo "  Run this after vault is reachable:"
        echo "    $INSTALL_DIR/.venv/bin/venya exec register \\"
        echo "      --executor-id $EXECUTOR_ID \\"
        echo "      --vault-url $SERVER_URL \\"
        echo "      --output-dir /etc/venya/executor \\"
        echo "      --enrollment-token '$VENYA_EXECUTOR_ENROLLMENT_TOKEN'"
        echo ""
    fi
fi

# --- Write bootstrap config (enrollment token for heartbeat) ---
if [ -n "$VENYA_EXECUTOR_ENROLLMENT_TOKEN" ]; then
    cat >> /etc/venya/executor.toml << EOF

[bootstrap]
enrollment_token = "$VENYA_EXECUTOR_ENROLLMENT_TOKEN"
tls_verify = true
EOF
    info "Bootstrap enrollment token configured"
fi

# --- Install systemd service and mount unit ---
info "Installing systemd service..."
SYSTEMD_DIR="/etc/systemd/system"
cp "$INSTALL_DIR/systemd/venya-executor.service" "$SYSTEMD_DIR/"
cp "$INSTALL_DIR/systemd/tmp-venya_secrets.mount" "$SYSTEMD_DIR/"
cp "$INSTALL_DIR/systemd/venya-executor.seccomp" "$SYSTEMD_DIR/"
systemctl daemon-reload
systemctl enable venya-executor.service tmp-venya_secrets.mount
systemctl start venya-executor.service

# Wait for service to be running (retry up to 5 times)
RETRY=0
MAX_RETRY=5
while [ $RETRY -lt $MAX_RETRY ]; do
    if systemctl is-active --quiet venya-executor.service 2>/dev/null; then
        break
    fi
    RETRY=$((RETRY + 1))
    info "Service not ready, retrying ($RETRY/$MAX_RETRY)..."
    sleep 2
    systemctl restart venya-executor.service
done

if [ $RETRY -eq $MAX_RETRY ]; then
    error "venya-executor.service failed to start after $MAX_RETRY attempts"
    systemctl status venya-executor.service --no-pager
    exit 1
fi

info "venya-executor.service is running"

# --- Verification ---
info "Verifying installation..."
ERRORS=0
if [ ! -f "$INSTALL_DIR/.venv/bin/venya" ]; then
    error "venya binary not found at $INSTALL_DIR/.venv/bin/venya"
    ERRORS=$((ERRORS + 1))
fi
VENYA_FILTER_PATH=$(find "$INSTALL_DIR/.venv" -type f -name 'venya_filter*' 2>/dev/null | head -1)
if [ -z "$VENYA_FILTER_PATH" ]; then
    warn "venya_filter.so not found in site-packages"
fi
if [ ! -f /etc/venya/executor.toml ]; then
    error "executor.toml not found at /etc/venya/executor.toml"
    ERRORS=$((ERRORS + 1))
fi
if [ ! -f /etc/systemd/system/venya-executor.service ]; then
    error "venya-executor.service not found"
    ERRORS=$((ERRORS + 1))
fi
if [ ! -f /etc/systemd/system/tmp-venya_secrets.mount ]; then
    error "tmp-venya_secrets.mount not found"
    ERRORS=$((ERRORS + 1))
fi
if [ "$ERRORS" -gt 0 ]; then
    error "Installation completed with $ERRORS error(s). Check output above."
    exit 1
fi
info "Installation verified successfully"

# --- Summary ---
echo ""
echo "============================================"
echo "  Venya Executor installed to $INSTALL_DIR"
echo "============================================"
echo ""
echo "Manage the executor:"
echo "  systemctl start|stop|restart|status venya-executor"
echo ""
echo "Next steps:"
echo "  1. Run 'newgrp kvm' or re-login to activate KVM group"
echo ""
