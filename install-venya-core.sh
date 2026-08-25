#!/usr/bin/env bash
set -euo pipefail

###############################################################################
# Venya Core Installer
#
# Installs Venya Core on a fresh VM:
#   - venya user, system packages, Caddy, PostgreSQL
#   - Python venv, server + core packages
#   - server.toml, .env, Caddyfile
#   - venya-core.service
#
# Environment variables:
#   VENYA_INSTALL_DIR   - Install location (default: /opt/venya)
#   VENYA_SKIP_PROMPT   - Set to "yes" to skip the confirmation prompt
#   VENYA_DB_PASSWORD   - PostgreSQL venya user password (prompts if unset)
#   VENYA_DB_PASSPHRASE - Server passphrase (default: venya_test_passphrase_2024)
#   VENYA_TARBALL       - URL of the tarball to install (auto-detected if on same host)
#   CORE_HOSTNAME      - Hostname for TLS/Caddy (default: localhost)
#   TLS_MODE            - Caddy TLS mode (default: internal)
###############################################################################

# --- Defaults ---
# NOTE: This is a development-only default. Production must override via VENYA_DB_PASSPHRASE.
DB_PASSPHRASE="${VENYA_DB_PASSPHRASE:-venya_test_passphrase_2024}"
TARBALL_URL="${VENYA_TARBALL:-http://10.27.27.35:8080/venya-core-install.tar.gz}"
CORE_HOSTNAME="${CORE_HOSTNAME:-$(hostname)}"
TLS_MODE="${TLS_MODE:-internal}"

# Admin mTLS
ADMIN_MTLS_ENABLED="${VENYA_ADMIN_MTLS_ENABLED:-true}"
ADMIN_IDENTITY="${VENYA_ADMIN_IDENTITY:-}"
ADMIN_CA_PASSPHRASE="${VENYA_ADMIN_CA_PASSPHRASE:-}"

# Recovery code pepper — random secret used to derive recovery code hashes
RECOVERY_PEPPER="${VENYA_RECOVERY_PEPPER:-$(openssl rand -base64 32)}"

# --- Source common library ---
# Direct execution: the library sits next to the script. Piped execution
# (curl | sudo bash): $0 has no directory — fetch from the tarball origin.
COMMON_DIR="$(cd "$(dirname "$0")" && pwd)"
if [ -f "$COMMON_DIR/venya-common.sh" ]; then
    source "$COMMON_DIR/venya-common.sh"
else
    FETCH_DIR="$(mktemp -d)"
    trap 'rm -rf "$FETCH_DIR"' EXIT
    echo "Fetching shared installer library from ${TARBALL_URL%/*}/venya-common.sh" >&2
    curl -fsSL "${TARBALL_URL%/*}/venya-common.sh" -o "$FETCH_DIR/venya-common.sh" || exit 1
    source "$FETCH_DIR/venya-common.sh"
fi

venya_print_colors
venya_check_root
venya_determine_install_dir /opt/venya
venya_check_existing

info "Installing Venya Core to $INSTALL_DIR"

# --- Create venya service account (no password, nologin, locked) ---
venya_create_user

# --- Install system packages ---
venya_install_system_pkgs curl sudo

# --- Install Caddy (core-specific) ---
info "Installing Caddy reverse proxy..."
if ! command -v caddy &>/dev/null; then
    apt-get install -y -qq debian-keyring debian-archive-keyring apt-transport-https curl > /dev/null 2>&1
    curl -1sLf 'https://dl.cloudsmith.io/public/caddy/stable/gpg.key' | gpg --dearmor -o /usr/share/keyrings/caddy-stable-archive-keyring.gpg
    curl -1sLf 'https://dl.cloudsmith.io/public/caddy/stable/debian.deb.txt' | tee /etc/apt/sources.list.d/caddy-stable.list
    apt-get install -y -qq caddy > /dev/null 2>&1
    info "Caddy installed: $(caddy version)"
else
    info "Caddy already installed: $(caddy version)"
fi

# --- Install uv for venya user ---
venya_install_uv_user

# --- Install Python 3.14 for venya user ---
venya_install_python314

# --- Download and extract tarball ---
venya_download_tarball core
venya_extract_tarball

# --- Build Python venv ---
venya_create_venv "venya-core-requirements.txt"

# --- Apply shared code fixes ---
venya_apply_code_fixes

# --- Create directories ---
venya_create_directories

# --- Admin mTLS bootstrap (core-specific) ---
ADMIN_CA_DIR="/var/lib/venya/ca/admin-ca"
ADMIN_CERT_DIR="/etc/venya/admin"

if [ "$ADMIN_MTLS_ENABLED" = "true" ]; then
    info "Configuring admin mTLS..."

    # Generate passphrase if not provided
    if [ -z "$ADMIN_CA_PASSPHRASE" ]; then
        ADMIN_CA_PASSPHRASE=$(openssl rand -base64 32)
    fi

    # Derive default identity
    if [ -z "$ADMIN_IDENTITY" ]; then
        ADMIN_IDENTITY="admin@${CORE_HOSTNAME}"
    fi

    # Create directories
    mkdir -p "$ADMIN_CA_DIR"
    chmod 700 "$ADMIN_CA_DIR"
    chown venya:venya "$ADMIN_CA_DIR"
    mkdir -p "$ADMIN_CERT_DIR"
    chmod 700 "$ADMIN_CERT_DIR"
    chown venya:venya "$ADMIN_CERT_DIR"

    # Generate admin CA
    export VENYA_ADMIN_CA_KEY_PASSPHRASE="$ADMIN_CA_PASSPHRASE"
    sudo -u venya env PATH="$INSTALL_DIR/.venv/bin:$PATH" \
        python -c "
from pathlib import Path
from server.ca import AdminCAManager
from server.config import CASecurityConfig
cm = AdminCAManager(Path('$ADMIN_CA_DIR'), CASecurityConfig())
if not cm.has_ca:
    cm.initialize()
print('Admin CA initialized')
"

    # Copy CA cert to Caddy's cert directory (IT1-013: Caddy needs read access)
    # CA storage stays hardened (0700 venya:venya); Caddy reads from /etc/caddy/certs/
    CADDY_CERTS_DIR="/etc/caddy/certs"
    mkdir -p "$CADDY_CERTS_DIR"
    chmod 755 "$CADDY_CERTS_DIR"
    if [ -f "$ADMIN_CA_DIR/admin-ca.crt" ]; then
        cp "$ADMIN_CA_DIR/admin-ca.crt" "$CADDY_CERTS_DIR/admin-ca.crt"
        chmod 644 "$CADDY_CERTS_DIR/admin-ca.crt"
        info "CA cert copied to $CADDY_CERTS_DIR/admin-ca.crt"
    fi

    # Generate first admin cert
    sudo -u venya env PATH="$INSTALL_DIR/.venv/bin:$PATH" \
        python -c "
from pathlib import Path
from server.ca import AdminCAManager
from server.config import CASecurityConfig
cm = AdminCAManager(Path('$ADMIN_CA_DIR'), CASecurityConfig())
cert, key_pem, cert_pem = cm.sign_admin_cert('$ADMIN_IDENTITY')
Path('$ADMIN_CERT_DIR/admin.crt').write_bytes(cert_pem)
Path('$ADMIN_CERT_DIR/admin.key').write_bytes(key_pem)
Path('$ADMIN_CERT_DIR/admin.crt').chmod(0o644)
Path('$ADMIN_CERT_DIR/admin.key').chmod(0o600)
print('Admin cert generated for $ADMIN_IDENTITY')
"

    info "Admin CA and first admin cert generated for $ADMIN_IDENTITY"
fi

# --- Install and setup PostgreSQL (core-specific) ---
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

# Create the venya DB role if missing. Password is fed to psql on stdin (here-doc)
# so it never appears on any process's /proc/*/cmdline (M-59, same pattern as M-56).
if ! sudo -u postgres psql -tAc "SELECT 1 FROM pg_roles WHERE rolname='venya'" 2>/dev/null | grep -q 1; then
    sudo -u postgres psql > /dev/null 2>&1 <<PSL_EOT
CREATE USER venya WITH PASSWORD '$VENYA_DB_PASSWORD';
PSL_EOT
fi

sudo -u postgres psql -tAc "SELECT 1 FROM pg_database WHERE datname='venya'" 2>/dev/null | grep -q 1 || \
    sudo -u postgres psql -c "CREATE DATABASE venya OWNER venya;" > /dev/null 2>&1

# --- Server binds to localhost only — Caddy terminates TLS ---
BIND_ADDRESS="127.0.0.1"
info "Server will bind to: $BIND_ADDRESS (Caddy handles TLS)"

# --- Write server.toml (core-specific) ---
mkdir -p /etc/venya

cat > /etc/venya/server.toml << EOF
host = "127.0.0.1"
port = 8080

[db]
database_url = "postgresql://venya:$VENYA_DB_PASSWORD@localhost/venya"
passphrase = "$DB_PASSPHRASE"
wal_mode = true

[fido2]
rp_id = "$CORE_HOSTNAME"
rp_name = "Venya Core"
origins = ["https://$CORE_HOSTNAME"]
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

ca_dir = "/var/lib/venya/ca"
cors_origins = ["https://$CORE_HOSTNAME"]

[audit]
audit_remote_url = null
audit_local_retention_days = 90

recovery_code_pepper = "$RECOVERY_PEPPER"
EOF

if [ "$ADMIN_MTLS_ENABLED" = "true" ]; then
    cat >> /etc/venya/server.toml << EOF

[admin_mtls]
enabled = true
ca_cert = "$ADMIN_CA_DIR/admin-ca.crt"
known_admin_ids = ["$ADMIN_IDENTITY"]
EOF
    info "Admin mTLS section appended to server.toml"
fi

# server.toml holds the DB password + encryption passphrase — root-only, venya-owned.
chmod 600 /etc/venya/server.toml
chown venya:venya /etc/venya/server.toml

info "Server config written to /etc/venya/server.toml"

# --- Write .env (core-specific) ---
cat > "$INSTALL_DIR/.env" << EOF
VENYA_HOST=127.0.0.1
VENYA_DB_URL=postgresql://venya:$VENYA_DB_PASSWORD@localhost/venya
VENYA_DB__DATABASE_URL=postgresql://venya:$VENYA_DB_PASSWORD@localhost/venya
VENYA_DB__PASSPHRASE=$DB_PASSPHRASE
VENYA_FIDO2__RP_ID=$CORE_HOSTNAME
VENYA_FIDO2__RP_NAME=Venya Core
VENYA_CORS_ORIGINS=["https://$CORE_HOSTNAME"]
VENYA_RECOVERY_CODE_PEPPER=$RECOVERY_PEPPER
EOF

if [ "$ADMIN_MTLS_ENABLED" = "true" ]; then
    cat >> "$INSTALL_DIR/.env" << EOF
VENYA_ADMIN_CA_KEY_PASSPHRASE="$ADMIN_CA_PASSPHRASE"
EOF
fi

# .env holds the DB password + passphrase — always root/venya-only, even without mTLS.
chmod 600 "$INSTALL_DIR/.env"
chown venya:venya "$INSTALL_DIR/.env"

info ".env written to $INSTALL_DIR/.env"

# --- Write Caddyfile (core-specific) ---
if [ "$ADMIN_MTLS_ENABLED" = "true" ]; then
    cat > /etc/venya/Caddyfile << EOF
$CORE_HOSTNAME {
    tls $TLS_MODE {
        client_auth {
            mode verify_if_given
            trusted_ca_cert_file /etc/caddy/certs/admin-ca.crt
        }
    }

    # Admin routes — require verified client cert
    @admin path /api/v1/admin/*
    handle @admin {
        @verified header X-Client-Verified true
        handle @verified {
            reverse_proxy 127.0.0.1:8080 {
                header_up X-Client-Cert-Base64 {http.request.tls.client.certificate_der_base64}
                header_up X-Client-Verified {http.request.tls.client.verified}
            }
        }
        # Admin route but no valid cert → 403
        handle {
            respond "Admin access requires valid client certificate" 403
        }
    }

    # Non-admin routes — pass through, no cert required
    handle {
        reverse_proxy 127.0.0.1:8080 {
            header_up X-Real-IP {remote_host}
            header_up X-Forwarded-For {remote_host}
        }
    }

    header {
        Strict-Transport-Security "max-age=31536000"
        X-Content-Type-Options nosniff
        X-Frame-Options DENY
    }
}
EOF
    info "Caddyfile written (TLS mode: $TLS_MODE, admin mTLS: enabled)"
else
    cat > /etc/venya/Caddyfile << EOF
$CORE_HOSTNAME {
    reverse_proxy 127.0.0.1:8080 {
        header_up X-Real-IP {remote_host}
        header_up X-Forwarded-For {remote_host}
    }

    tls $TLS_MODE

    header {
        Strict-Transport-Security "max-age=31536000"
        X-Content-Type-Options nosniff
        X-Frame-Options DENY
    }
}
EOF
    info "Caddyfile written (TLS mode: $TLS_MODE, admin mTLS: disabled)"
fi

# --- Admin mTLS bootstrap instructions ---
if [ "$ADMIN_MTLS_ENABLED" = "true" ]; then
    echo ""
    echo "==============================================================="
    echo "  ADMIN mTLS IS ENABLED"
    echo "==============================================================="
    echo "  Your admin certificate is at:"
    echo "    $ADMIN_CERT_DIR/admin.crt"
    echo "    $ADMIN_CERT_DIR/admin.key"
    echo ""
    echo "  Copy these to your workstation:"
    echo "    scp root@${CORE_HOSTNAME}:$ADMIN_CERT_DIR/admin.crt ~/venya-admin.crt"
    echo "    scp root@${CORE_HOSTNAME}:$ADMIN_CERT_DIR/admin.key ~/venya-admin.key"
    echo ""
    echo "  Admin CA passphrase saved to: $INSTALL_DIR/.env"
    echo "  Read it with: cat $INSTALL_DIR/.env"
    echo ""
    echo "  Until you do, admin endpoints will return 403."
    echo "  To disable: set VENYA_ADMIN_MTLS_ENABLED=false and reinstall."
    echo "==============================================================="
    echo ""
fi

# --- Executor enrollment token instructions ---
echo ""
echo "==============================================================="
echo "  EXECUTOR ENROLLMENT"
echo "==============================================================="
echo ""
echo "To register an executor, run on this core server:"
echo ""
echo "  sudo -u venya PATH='$INSTALL_DIR/.venv/bin:\$PATH' \\"
echo "    $INSTALL_DIR/.venv/bin/venya admin executor-enroll <executor-id>"
echo ""
echo "Then pass the printed token to the executor operator."
echo "The token is consumed on first use and cannot be reused."
echo ""
echo "==============================================================="
echo ""

# Copy Caddyfile to Caddy's default location
sudo cp /etc/venya/Caddyfile /etc/caddy/Caddyfile

# --- Start Caddy and install CA trust (core-specific) ---
info "Starting Caddy..."
systemctl start caddy > /dev/null 2>&1 || true

info "Installing Caddy internal CA..."
CADDY_ROOT_CA="${VENYA_CADDY_ROOT_CA:-/var/lib/caddy/.local/share/caddy/pki/authorities/local/root.crt}"
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

# --- Run database migrations (core-specific) ---
info "Running database migrations..."
# DB URL via stdin (here-doc): keeps $VENYA_DB_PASSWORD off every process's /proc/*/cmdline.
sudo -u venya env PATH="$INSTALL_DIR/.venv/bin:$PATH" bash -c '
  set -a; read -r VENYA_DB_URL
  cd "$1" && python -c "from core.cli.commands import _run_migrations; _run_migrations()"
' _ "$INSTALL_DIR" <<VENYA_EOT
postgresql://venya:$VENYA_DB_PASSWORD@localhost/venya
VENYA_EOT
info "Database migrations complete"

# --- Install systemd service (core-specific) ---
info "Installing systemd service..."
SYSTEMD_DIR="/etc/systemd/system"
sed "s|VENYA_ENV_DIR=/opt/venya|VENYA_ENV_DIR=$INSTALL_DIR|" "$INSTALL_DIR/systemd/venya-core.service" > "$SYSTEMD_DIR/venya-core.service"
systemctl daemon-reload
systemctl enable venya-core.service
systemctl start venya-core.service

# --- Service retry ---
venya_service_retry venya-core

# --- Verification ---
venya_verify_install \
    /etc/venya/server.toml \
    /etc/venya/Caddyfile \
    /etc/systemd/system/venya-core.service

# --- Summary ---
echo ""
echo "============================================"
echo "  Venya Core installed to $INSTALL_DIR"
echo "============================================"
echo ""
echo "Manage the core server:"
echo "  systemctl start|stop|restart|status venya-core"
echo ""
echo "Caddy reverse proxy:"
echo "  Config: /etc/venya/Caddyfile"
echo "  TLS mode: $TLS_MODE"
echo "  Access: https://$CORE_HOSTNAME"
echo ""
echo "Next steps:"
echo "  1. Verify health: curl -sk https://$CORE_HOSTNAME/api/v1/health"
echo "  2. Enroll admin: open https://$CORE_HOSTNAME/enroll-admin in browser"
echo ""
