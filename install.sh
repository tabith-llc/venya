#!/usr/bin/env bash
set -euo pipefail

###############################################################################
# Venya Installer
#
# Usage:
#   curl -fsSL https://venya.ai/install | bash
#
# Or download and run:
#   wget -qO- https://venya.ai/install | bash
#
# Environment variables:
#   VENYA_INSTALL_DIR  - Install location (default: /opt/venya)
#   VENYA_SKIP_PROMPT  - Set to "yes" to skip the confirmation prompt
#   VENYA_DB_PASSPHRASE - Server passphrase (default: venya_test_passphrase_2024)
#   VENYA_TARBALL      - URL of the tarball to install (auto-detected if on same host)
###############################################################################

# --- Defaults ---
INSTALL_DIR="${VENYA_INSTALL_DIR:-}"
DB_PASSPHRASE="${VENYA_DB_PASSPHRASE:-venya_test_passphrase_2024}"
SKIP_PROMPT="${VENYA_SKIP_PROMPT:-}"
TARBALL_URL="${VENYA_TARBALL:-}"
MODE="${VENYA_MODE:-}"  # REQUIRED: "vault", "executor", or "both"
EXECUTOR_ID="${VENYA_EXECUTOR_ID:-jump-1}"
SERVER_URL="${VENYA_SERVER_URL:-http://localhost:8080}"

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

info "Installing Venya to $INSTALL_DIR"

# --- Validate MODE ---
if [ -z "$MODE" ]; then
    error "MODE is required. Set VENYA_MODE=vault, VENYA_MODE=executor, or VENYA_MODE=both"
    exit 1
fi

if [ "$MODE" != "vault" ] && [ "$MODE" != "executor" ] && [ "$MODE" != "both" ]; then
    error "Invalid MODE '$MODE'. Must be 'vault', 'executor', or 'both'"
    exit 1
fi

# --- Create venya user ---
if ! id venya &>/dev/null; then
    if [ "$SKIP_PROMPT" = "yes" ]; then
        VENYA_PASSWORD="${VENYA_PASSWORD:-venya12}"
    else
        echo -n "Enter password for venya user: "
        read -rs VENYA_PASSWORD
        echo ""
    fi
    useradd -m -s /bin/bash venya
    echo "venya:$VENYA_PASSWORD" | chpasswd
    info "Created venya user"
fi

# --- Install system packages ---
info "Installing system packages..."
apt-get update -qq
apt-get install -y -qq curl wget strace ltrace gdb tcpdump net-tools iproute2 \
                    build-essential rsync sudo iptables > /dev/null 2>&1

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
    # Try to find a local tarball
    if [ -f "/tmp/venya-install.tar.gz" ]; then
        TARBALL_URL="file:///tmp/venya-install.tar.gz"
    elif [ -f "/opt/venya-install.tar.gz" ]; then
        TARBALL_URL="file:///opt/venya-install.tar.gz"
    else
        error "No tarball found. Set VENYA_TARBALL to a URL or place venya-install.tar.gz in /tmp/"
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
chown venya:venya "$INSTALL_DIR"

# --- Build Python environment (as venya user) ---
info "Creating Python virtual environment..."
VENYA_UV="/home/venya/.local/bin/uv"
sudo -u venya env PATH="/home/venya/.local/bin:/home/venya/.cargo/bin:$PATH" bash -c "cd $INSTALL_DIR && UV_VENV_CLEAR=1 $VENYA_UV venv .venv"

info "Installing Python packages..."
if [ "$MODE" = "executor" ] || [ "$MODE" = "both" ]; then
    sudo -u venya env PATH="/home/venya/.local/bin:/home/venya/.cargo/bin:$PATH" bash -c "cd $INSTALL_DIR && $VENYA_UV pip install -r $INSTALL_DIR/venya-executor-requirements.txt"
fi
if [ "$MODE" = "vault" ] || [ "$MODE" = "both" ]; then
    sudo -u venya env PATH="/home/venya/.local/bin:/home/venya/.cargo/bin:$PATH" bash -c "cd $INSTALL_DIR && $VENYA_UV pip install -r $INSTALL_DIR/venya-vault-requirements.txt"
fi

# --- Build Rust extension (as venya user) ---
info "Building Rust filter extension..."
VENYA_CARGO="/home/venya/.cargo/bin/cargo"
sudo -u venya env PATH="/home/venya/.local/bin:/home/venya/.cargo/bin:$PATH" bash -c "cd $INSTALL_DIR/packages/executor && $VENYA_CARGO build --release" > /dev/null 2>&1
PYTHON_PATH=$(find "$INSTALL_DIR/.venv" -type d -name 'site-packages' | head -1)
cp "$INSTALL_DIR/packages/executor/target/release/libvenya_filter.so" "$PYTHON_PATH/venya_filter.so"
chown venya:venya "$PYTHON_PATH/venya_filter.so"
cd ../..

# --- Apply code fixes ---
info "Applying code fixes..."

# Fix 1: Add database_url field to DatabaseConfig in config.py
if ! grep -q "database_url: str | None" "$INSTALL_DIR/packages/server/src/server/config.py" 2>/dev/null; then
    sed -i '/database_path: str = Field/i\    database_url: str | None = Field(default=None, description="PostgreSQL database URL")' \
        "$INSTALL_DIR/packages/server/src/server/config.py"
    info "  Added database_url field to DatabaseConfig"
fi

# Fix 2: Update init_db to use db_config.database_url in dependencies.py
if grep -q 'database_url = os.environ.get("VENYA_DB_URL")' "$INSTALL_DIR/packages/server/src/server/dependencies.py" 2>/dev/null; then
    sed -i 's|database_url = os.environ.get("VENYA_DB_URL")|database_url = db_config.database_url or os.environ.get("VENYA_DB_URL")|' \
        "$INSTALL_DIR/packages/server/src/server/dependencies.py"
    # Ensure import os is at module level
    if ! head -10 "$INSTALL_DIR/packages/server/src/server/dependencies.py" | grep -q "^import os"; then
        sed -i '/from __future__ import annotations/a\\nimport os' \
            "$INSTALL_DIR/packages/server/src/server/dependencies.py"
    fi
    info "  Fixed init_db to use db_config.database_url"
fi

# Fix 3: Fix init.py imports (from ..iam.models → from vault.iam.models)
for f in "$INSTALL_DIR/packages/server/src/server/routes/init.py"; do
    if [ -f "$f" ]; then
        sed -i 's/from \.\.iam\.models/from vault.iam.models/g' "$f"
        info "  Fixed init.py imports"
    fi
done

# Fix 4: Ensure db.flush() after admin_role creation in init.py
for f in "$INSTALL_DIR/packages/server/src/server/routes/init.py"; do
    if [ -f "$f" ]; then
        if ! grep -q 'db\.flush()' "$f" 2>/dev/null; then
            sed -i '/db\.add(admin_role)/a\        db.flush()' "$f"
            info "  Added db.flush() after admin_role creation"
        fi
    fi
done

# Fix 5: Ensure timezone-aware datetimes in executors.py heartbeat
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

# --- Server configuration (if MODE=vault or both) ---
if [ "$MODE" = "vault" ] || [ "$MODE" = "both" ]; then
    info "Configuring server..."

    # --- Install and setup PostgreSQL ---
    info "Installing PostgreSQL..."
    apt-get install -y -qq postgresql > /dev/null 2>&1

    info "Setting up PostgreSQL..."
    systemctl start postgresql
    systemctl enable postgresql

    sudo -u postgres psql -tAc "SELECT 1 FROM pg_roles WHERE rolname='venya'" 2>/dev/null | grep -q 1 || \
        sudo -u postgres psql -c "CREATE USER venya WITH PASSWORD 'venya_dev_password';" > /dev/null 2>&1

    sudo -u postgres psql -tAc "SELECT 1 FROM pg_database WHERE datname='venya'" 2>/dev/null | grep -q 1 || \
        sudo -u postgres psql -c "CREATE DATABASE venya OWNER venya;" > /dev/null 2>&1

    # --- Select bind address ---
    info "Scanning network interfaces..."
    BIND_ADDRESS="0.0.0.0"
    OPTIONS=()
    
    # Add localhost
    OPTIONS+=("127.0.0.1")
    
    # Add all interfaces
    OPTIONS+=("0.0.0.0")
    
    # Add discovered IPs (exclude loopback)
    while IFS= read -r ip; do
        # Skip loopback and already-added
        if [[ "$ip" != "127.0.0.1" ]] && [[ "$ip" != "0.0.0.0" ]] && [[ ! " ${OPTIONS[*]} " =~ " $ip " ]]; then
            OPTIONS+=("$ip")
        fi
    done < <(ip -4 addr show 2>/dev/null | grep -oP 'inet \K[\d.]+' | sort -u)
    
    # Add IPv6 addresses
    while IFS= read -r ip; do
        if [[ -n "$ip" ]] && [[ ! " ${OPTIONS[*]} " =~ " $ip " ]]; then
            OPTIONS+=("$ip")
        fi
    done < <(ip -6 addr show 2>/dev/null | grep -oP 'inet6 \K[0-9a-f:]+' | grep -v "^fe80:" | grep -v "^::1" | sort -u)
    
    # Deduplicate
    readarray -t OPTIONS < <(printf '%s\n' "${OPTIONS[@]}" | sort -u)
    
    if [ "$SKIP_PROMPT" = "yes" ]; then
        BIND_ADDRESS="0.0.0.0"
    else
        echo ""
        echo "Select bind address for the server:"
        for i in "${!OPTIONS[@]}"; do
            marker=""
            if [ "${OPTIONS[$i]}" = "0.0.0.0" ]; then
                marker=" (default - listen on all interfaces)"
            fi
            echo "  $((i+1)). ${OPTIONS[$i]}$marker"
        done
        echo ""
        echo -n "Enter option number (default: 2 for 0.0.0.0): "
        read -r choice
        if [ -z "$choice" ] || [ "$choice" -lt 1 ] || [ "$choice" -gt "${#OPTIONS[@]}" ]; then
            BIND_ADDRESS="0.0.0.0"
        else
            BIND_ADDRESS="${OPTIONS[$((choice-1))]}"
        fi
    fi
    info "Server will bind to: $BIND_ADDRESS"

    # --- Write server.toml ---
    mkdir -p /etc/venya

    cat > /etc/venya/server.toml << EOF
host = "$BIND_ADDRESS"
port = 8080

[db]
database_url = "postgresql://venya:venya_dev_password@localhost/venya"
database_path = "venya.db"
passphrase = "$DB_PASSPHRASE"
wal_mode = true

[fido2]
rp_id = "vault"
rp_name = "Venya Vault"
origins = ["https://vault"]
enrollment_token_ttl = 15
unmask_auto_hide_timeout = 30

[session]
session_timeout = 900
access_token_ttl = 300
max_session_duration = 14400

[rate_limit]
max_attempts = 5
window_seconds = 300.0
ip_rate_limit = 100

[ca_dir]
ca_dir = "/var/lib/venya/ca"

[cors_origins]
cors_origins = ["https://vault"]

[audit]
audit_remote_url = null
audit_local_retention_days = 90
EOF

    info "Server config written to /etc/venya/server.toml"

    # --- Write .env ---
    cat > "$INSTALL_DIR/.env" << EOF
VENYA_HOST=$BIND_ADDRESS
VENYA_DB__DATABASE_URL=postgresql://venya:venya_dev_password@localhost/venya
VENYA_DB__PASSPHRASE=$DB_PASSPHRASE
VENYA_FIDO2__RP_ID=vault
VENYA_FIDO2__RP_NAME=Venya Vault
VENYA_CORS_ORIGINS=["https://vault"]
EOF

    info ".env written to $INSTALL_DIR/.env"

    # --- Run database migrations ---
    info "Running database migrations..."
    sudo -u venya env PATH="/home/venya/.local/bin:/home/venya/.cargo/bin:$PATH" bash -c "cd $INSTALL_DIR/packages/vault && VENYA_DB_URL='postgresql://venya:venya_dev_password@localhost/venya' /home/venya/.local/bin/uv run alembic -c alembic.ini upgrade head"
    info "Database migrations complete"
fi

# --- Executor configuration (if MODE=executor or both) ---
if [ "$MODE" = "executor" ] || [ "$MODE" = "both" ]; then
    info "Configuring executor..."

    # --- Install Docker Sandboxes (sbx) CLI ---
    info "Installing Docker Sandboxes (sbx) CLI..."
    if ! command -v sbx &>/dev/null; then
        curl -fsSL https://get.docker.com | REPO_ONLY=1 sh > /dev/null 2>&1
        apt-get install -y -qq docker-sbx > /dev/null 2>&1
        # Add venya user to kvm group for libvirt access
        usermod -aG kvm venya 2>/dev/null || true
        info "sbx CLI installed. venya user added to kvm group."
    else
        info "sbx CLI already installed: $(sbx --version 2>/dev/null || echo 'unknown')"
    fi

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
    info "Note: mTLS certs must be generated on the vault server and copied here."
fi

# --- Install systemd services ---
info "Installing systemd services..."

SYSTEMD_DIR="/etc/systemd/system"
cp "$INSTALL_DIR/systemd/venya-vault.service" "$SYSTEMD_DIR/"
cp "$INSTALL_DIR/systemd/venya-executor.service" "$SYSTEMD_DIR/"
systemctl daemon-reload

if [ "$MODE" = "vault" ] || [ "$MODE" = "both" ]; then
    systemctl enable venya-vault.service
    info "Enabled venya-vault.service"
fi
if [ "$MODE" = "executor" ] || [ "$MODE" = "both" ]; then
    systemctl enable venya-executor.service
    info "Enabled venya-executor.service"
fi

# --- Summary ---
echo ""
echo "============================================"
echo "  Venya installed to $INSTALL_DIR"
echo "============================================"
echo ""
echo "To activate:"
echo "  cd $INSTALL_DIR"
echo "  source .venv/bin/activate"
echo ""

if [ "$MODE" = "vault" ] || [ "$MODE" = "both" ]; then
    echo "To start the vault server:"
    echo "  systemctl start venya-vault"
    echo "  # or manually: $INSTALL_DIR/.venv/bin/venya-server --config /etc/venya/server.toml"
    echo ""
    echo "Next steps:"
    echo "  1. Verify health: curl http://localhost:8080/api/v1/health"
    echo "  2. Initialize vault: POST /api/v1/init"
fi

if [ "$MODE" = "executor" ] || [ "$MODE" = "both" ]; then
    echo "To start the executor:"
    echo "  systemctl start venya-executor"
    echo "  # or manually: $INSTALL_DIR/.venv/bin/venya-executor --config /etc/venya/executor.toml"
    echo ""
    echo "Next steps:"
    echo "  1. Generate mTLS certs on vault server"
    echo "  2. Copy ca.crt, executor.crt, executor.key to /etc/venya/executor/"
    echo "  3. systemctl start venya-executor"
    echo "  4. Run 'newgrp kvm' or re-login to activate KVM group"
fi
echo ""
