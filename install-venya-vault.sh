#!/usr/bin/env bash
set -euo pipefail

###############################################################################
# Venya Vault Installer
#
# Installs Venya Vault on a fresh VM:
#   - venya user, system packages, Caddy, PostgreSQL
#   - Python venv, server + vault packages
#   - server.toml, .env, Caddyfile, DB migrations
#   - venya-vault.service
#
# Environment variables:
#   VENYA_INSTALL_DIR   - Install location (default: /opt/venya)
#   VENYA_SKIP_PROMPT   - Set to "yes" to skip the confirmation prompt
#   VENYA_PASSWORD      - OS venya user password (prompts if unset)
#   VENYA_DB_PASSWORD   - PostgreSQL venya user password (prompts if unset)
#   VENYA_DB_PASSPHRASE - Server passphrase (default: venya_test_passphrase_2024)
#   VENYA_TARBALL       - URL of the tarball to install (auto-detected if on same host)
#   VAULT_HOSTNAME      - Hostname for TLS/Caddy (default: localhost)
#   TLS_MODE            - Caddy TLS mode (default: internal)
###############################################################################

# --- Defaults ---
INSTALL_DIR="${VENYA_INSTALL_DIR:-}"
DB_PASSPHRASE="${VENYA_DB_PASSPHRASE:-venya_test_passphrase_2024}"
SKIP_PROMPT="${VENYA_SKIP_PROMPT:-}"
TARBALL_URL="${VENYA_TARBALL:-http://10.27.27.35:8080/venya-vault-install.tar.gz}"
VAULT_HOSTNAME="${VAULT_HOSTNAME:-$(hostname)}"
TLS_MODE="${TLS_MODE:-internal}"

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

info "Installing Venya Vault to $INSTALL_DIR"

# --- Create venya user ---
if ! id venya &>/dev/null; then
    if [ -z "$VENYA_PASSWORD" ]; then
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
apt-get install -y -qq curl sudo > /dev/null 2>&1

# --- Install Caddy (first — before anything else that may depend on TLS) ---
info "Installing Caddy reverse proxy..."
if ! command -v caddy &>/dev/null; then
    apt-get install -y -qq debian-keyring debian-archive-keyring apt-transport-https curl > /dev/null 2>&1
    curl -1sLf 'https://dl.cloudsmith.io/public/caddy/stable/gpg.key' | gpg --dearmor -o /usr/share/keyrings/caddy-stable-archive-keyring.gpg
    curl -1sLf 'https://dl.cloudsmith.io/public/caddy/stable/debian.deb.txt' | tee /etc/apt/sources.list.d/caddy-stable.list
    apt-get update > /dev/null 2>&1
    apt-get install -y -qq caddy > /dev/null 2>&1
    info "Caddy installed: $(caddy version)"
else
    info "Caddy already installed: $(caddy version)"
fi

# --- Install uv (for both root and venya user) ---
if ! command -v uv &>/dev/null; then
    info "Installing uv..."
    curl -LsSf https://astral.sh/uv/install.sh | sh > /dev/null 2>&1
else
    info "uv already installed: $(uv --version)"
fi

# Source paths for root
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
        TARBALL_URL="file:///tmp/venya-vault-install.tar.gz"
    elif [ -f "/opt/venya-install.tar.gz" ]; then
        TARBALL_URL="file:///opt/venya-vault-install.tar.gz"
    else
        error "No tarball found. Set VENYA_TARBALL to a URL or place venya-vault-install.tar.gz in /tmp/"
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
sudo -u venya env PATH="/home/venya/.local/bin:$PATH" bash -c "cd $INSTALL_DIR && UV_VENV_CLEAR=1 $VENYA_UV venv .venv"

info "Installing Python packages..."
sudo -u venya env PATH="/home/venya/.local/bin:$PATH" bash -c "cd $INSTALL_DIR && $VENYA_UV pip install -r $INSTALL_DIR/venya-vault-requirements.txt"

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

# --- Install and setup PostgreSQL ---
info "Installing PostgreSQL..."
apt-get install -y -qq postgresql > /dev/null 2>&1

if [ -z "$VENYA_DB_PASSWORD" ]; then
    echo -n "Enter PostgreSQL password for venya user: "
    read -rs VENYA_DB_PASSWORD
    echo ""
fi

info "Setting up PostgreSQL..."
systemctl start postgresql
systemctl enable postgresql

sudo -u postgres psql -tAc "SELECT 1 FROM pg_roles WHERE rolname='venya'" 2>/dev/null | grep -q 1 || \
    sudo -u postgres psql -c "CREATE USER venya WITH PASSWORD '$VENYA_DB_PASSWORD';" > /dev/null 2>&1

sudo -u postgres psql -tAc "SELECT 1 FROM pg_database WHERE datname='venya'" 2>/dev/null | grep -q 1 || \
    sudo -u postgres psql -c "CREATE DATABASE venya OWNER venya;" > /dev/null 2>&1

# --- Server binds to localhost only — Caddy terminates TLS ---
BIND_ADDRESS="127.0.0.1"
info "Server will bind to: $BIND_ADDRESS (Caddy handles TLS)"

# --- Write server.toml ---
mkdir -p /etc/venya

cat > /etc/venya/server.toml << EOF
host = "127.0.0.1"
port = 8080

[db]
database_url = "postgresql://venya:$VENYA_DB_PASSWORD@localhost/venya"
database_path = "venya.db"
passphrase = "$DB_PASSPHRASE"
wal_mode = true

[fido2]
rp_id = "$VAULT_HOSTNAME"
rp_name = "Venya Vault"
origins = ["https://$VAULT_HOSTNAME"]
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
cors_origins = ["https://$VAULT_HOSTNAME"]

[audit]
audit_remote_url = null
audit_local_retention_days = 90
EOF

info "Server config written to /etc/venya/server.toml"

# --- Write .env ---
cat > "$INSTALL_DIR/.env" << EOF
VENYA_HOST=127.0.0.1
VENYA_DB__DATABASE_URL=postgresql://venya:$VENYA_DB_PASSWORD@localhost/venya
VENYA_DB__PASSPHRASE=$DB_PASSPHRASE
VENYA_FIDO2__RP_ID=$VAULT_HOSTNAME
VENYA_FIDO2__RP_NAME=Venya Vault
VENYA_CORS_ORIGINS=["https://$VAULT_HOSTNAME"]
EOF

info ".env written to $INSTALL_DIR/.env"

# --- Write Caddyfile ---
cat > /etc/venya/Caddyfile << EOF
$VAULT_HOSTNAME {
    reverse_proxy 127.0.0.1:8080 {
        header_up X-Real-IP {remote_host}
        header_up X-Forwarded-For {remote_host}
    }

    tls $TLS_MODE

    # Security headers
    header {
        Strict-Transport-Security "max-age=31536000"
        X-Content-Type-Options nosniff
        X-Frame-Options DENY
    }
}
EOF

info "Caddyfile written to /etc/venya/Caddyfile (TLS mode: $TLS_MODE)"

# Copy Caddyfile to Caddy's default location
sudo cp /etc/venya/Caddyfile /etc/caddy/Caddyfile

# --- Start Caddy and install CA trust ---
info "Starting Caddy..."
systemctl enable --now caddy > /dev/null 2>&1
sleep 2

info "Installing Caddy internal CA..."
CADDY_ROOT_CA="/var/lib/caddy/.local/share/caddy/pki/authorities/local/root.crt"
if [ -f "$CADDY_ROOT_CA" ]; then
    cp "$CADDY_ROOT_CA" /usr/local/share/ca-certificates/caddy-local-ca.crt
    chmod 644 /usr/local/share/ca-certificates/caddy-local-ca.crt
    update-ca-certificates > /dev/null 2>&1
    info "Caddy root CA installed to system trust store"
else
    warn "Caddy CA not found — TLS may not be trusted"
fi
systemctl restart caddy > /dev/null 2>&1
info "Caddy enabled and started"

# --- Run database migrations ---
info "Running database migrations..."
sudo -u venya env PATH="/home/venya/.local/bin:$PATH" bash -c "cd $INSTALL_DIR/packages/vault && VENYA_DB_URL='postgresql://venya:$VENYA_DB_PASSWORD@localhost/venya' /home/venya/.local/bin/uv run alembic -c alembic.ini upgrade head"
info "Database migrations complete"

# --- Install systemd service ---
info "Installing systemd service..."
SYSTEMD_DIR="/etc/systemd/system"
cp "$INSTALL_DIR/systemd/venya-vault.service" "$SYSTEMD_DIR/"
systemctl daemon-reload
systemctl enable venya-vault.service
info "Enabled venya-vault.service"

# --- Verification ---
info "Verifying installation..."
ERRORS=0
if [ ! -f "$INSTALL_DIR/.venv/bin/venya" ]; then
    error "venya binary not found at $INSTALL_DIR/.venv/bin/venya"
    ERRORS=$((ERRORS + 1))
fi
if [ ! -f /etc/venya/server.toml ]; then
    error "server.toml not found at /etc/venya/server.toml"
    ERRORS=$((ERRORS + 1))
fi
if [ ! -f /etc/venya/Caddyfile ]; then
    error "Caddyfile not found at /etc/venya/Caddyfile"
    ERRORS=$((ERRORS + 1))
fi
if [ ! -f /etc/systemd/system/venya-vault.service ]; then
    error "venya-vault.service not found"
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
echo "  Venya Vault installed to $INSTALL_DIR"
echo "============================================"
echo ""
echo "To start the vault server:"
echo "  systemctl start venya-vault"
echo ""
echo "Caddy reverse proxy:"
echo "  Config: /etc/venya/Caddyfile"
echo "  TLS mode: $TLS_MODE"
echo "  Access: https://$VAULT_HOSTNAME"
echo ""
echo "Next steps:"
echo "  1. Verify health: curl -sk https://$VAULT_HOSTNAME/api/v1/health"
echo "  3. Enroll admin: open https://$VAULT_HOSTNAME/enroll-admin in browser"
echo ""
