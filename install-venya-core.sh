#!/usr/bin/env bash
set -euo pipefail

###############################################################################
# Venya Core Installer
#
# Installs Venya Core on a fresh VM:
#   - venya user, system packages, Nginx, PostgreSQL
#   - Python venv, server + core packages
#   - server.toml, .env, Nginx site config
#   - venya-core.service
#
# Environment variables:
#   VENYA_INSTALL_DIR   - Install location (default: /opt/venya)
#   VENYA_SKIP_PROMPT   - Set to "yes" to skip the confirmation prompt
#   VENYA_DB_PASSWORD   - PostgreSQL venya user password (prompts if unset)
#   VENYA_DB_PASSPHRASE - Server passphrase (default: venya_test_passphrase_2024)
#   VENYA_TARBALL       - URL of the tarball to install (auto-detected if on same host)
#   CORE_HOSTNAME      - Hostname for TLS/Nginx (default: localhost)
#   TLS_MODE            - Nginx TLS mode (default: internal)
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

# --- Install Nginx (core-specific) ---
info "Installing Nginx reverse proxy..."
if ! command -v nginx &>/dev/null; then
    apt-get install -y -qq nginx > /dev/null 2>&1
    info "Nginx installed: $(nginx -v 2>&1)"
else
    info "Nginx already installed: $(nginx -v 2>&1)"
fi

# --- Install uv for venya user ---
venya_install_uv_user

# --- Install Python 3.14 for venya user ---
venya_install_python314

# --- Download and extract tarball ---
venya_download_tarball core
venya_extract_tarball

# --- Apply shared code fixes (patch source BEFORE building) ---
venya_apply_code_fixes

# --- Build Python venv ---
venya_create_venv "venya-core-requirements.txt"

# --- Verify deployed code ---
venya_verify_deployment core

# --- Create directories ---
venya_create_directories

# --- Admin mTLS bootstrap (core-specific) ---
ADMIN_CA_DIR="/var/lib/venya/ca/admin-ca"
ADMIN_CERT_DIR="/etc/venya/admin"

if [ "$ADMIN_MTLS_ENABLED" = "true" ]; then
    info "Configuring admin mTLS..."

    # Passphrase acquisition: prompt when interactive, strong random when
    # piped/unattended. Either way validated non-empty — an empty passphrase
    # would silently yield an UNENCRYPTED admin CA key. Nobody needs to
    # memorize a CA key passphrase, so unattended keeps the strong random
    # default; typing is for delivery hygiene, not for replacing randomness.
    if [ -z "$ADMIN_CA_PASSPHRASE" ]; then
        if [ -t 0 ] && [ "${VENYA_SKIP_PROMPT:-}" != "yes" ]; then
            while :; do
                echo -n "Admin CA key passphrase: "
                IFS= read -rs ADMIN_CA_PASSPHRASE
                echo ""
                [ -n "$ADMIN_CA_PASSPHRASE" ] && break
                warn "Passphrase cannot be empty."
            done
        else
            ADMIN_CA_PASSPHRASE=$(openssl rand -base64 32)
            info "Unattended install: generated a random admin CA passphrase."
        fi
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

    # Generate admin CA. The passphrase crosses the sudo boundary on STDIN —
    # never via export (sudo's env_reset strips it) and never on argv (visible
    # in /proc/*/cmdline). The child reads it into VENYA_ADMIN_CA_KEY_PASSPHRASE
    # and the manager is wired to that exact var name (matches app.py runtime +
    # the startup enforcement). Path passed as a positional so nothing
    # interpolates inside the single-quoted child script.
    sudo -u venya env PATH="$INSTALL_DIR/.venv/bin:$PATH" bash -c '
        IFS= read -r VENYA_ADMIN_CA_KEY_PASSPHRASE
        export VENYA_ADMIN_CA_KEY_PASSPHRASE
        exec python -c "
from pathlib import Path
from server.ca import AdminCAManager
from server.config import CASecurityConfig
cm = AdminCAManager(Path(\"$1\"), CASecurityConfig(key_passphrase_env=\"VENYA_ADMIN_CA_KEY_PASSPHRASE\"))
if not cm.has_ca:
    cm.initialize()
print(\"Admin CA initialized\")
"
    ' _ "$ADMIN_CA_DIR" <<<"$ADMIN_CA_PASSPHRASE"

    # Generate first admin cert. sign_admin_cert loads the CA key — now
    # encrypted — so this block needs the passphrase on stdin too (identical
    # carry). $1=ca_dir $2=cert_dir $3=identity, all positional.
    sudo -u venya env PATH="$INSTALL_DIR/.venv/bin:$PATH" bash -c '
        IFS= read -r VENYA_ADMIN_CA_KEY_PASSPHRASE
        export VENYA_ADMIN_CA_KEY_PASSPHRASE
        exec python -c "
from pathlib import Path
from server.ca import AdminCAManager
from server.config import CASecurityConfig
cm = AdminCAManager(Path(\"$1\"), CASecurityConfig(key_passphrase_env=\"VENYA_ADMIN_CA_KEY_PASSPHRASE\"))
cert, key_pem, cert_pem = cm.sign_admin_cert(\"$3\")
Path(\"$2/admin.crt\").write_bytes(cert_pem)
Path(\"$2/admin.key\").write_bytes(key_pem)
Path(\"$2/admin.crt\").chmod(0o644)
Path(\"$2/admin.key\").chmod(0o600)
print(\"Admin cert generated for $3\")
"
    ' _ "$ADMIN_CA_DIR" "$ADMIN_CERT_DIR" "$ADMIN_IDENTITY" <<<"$ADMIN_CA_PASSPHRASE"

    info "Admin CA and first admin cert generated for $ADMIN_IDENTITY"

fi

# --- Install and setup PostgreSQL (core-specific) ---
info "Installing PostgreSQL..."
apt-get install -y -qq postgresql > /dev/null 2>&1

if [ -z "$VENYA_DB_PASSWORD" ]; then
    if [ -t 0 ] && [ "${VENYA_SKIP_PROMPT:-}" != "yes" ]; then
        while :; do
            echo -n "Enter PostgreSQL password for venya user: "
            IFS= read -rs VENYA_DB_PASSWORD
            echo ""
            [ -n "$VENYA_DB_PASSWORD" ] && break
            warn "Password cannot be empty."
        done
    else
        error "VENYA_DB_PASSWORD is required for unattended install (stdin is not a TTY)."
        exit 1
    fi
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
info "Server will bind to: $BIND_ADDRESS (Nginx handles TLS)"

# --- Write server.toml (core-specific) ---
mkdir -p /etc/venya

cat > /etc/venya/server.toml << EOF
host = "127.0.0.1"
port = 8080
ca_dir = "/var/lib/venya/ca"
recovery_code_pepper = "$RECOVERY_PEPPER"

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

[cors]
origins = ["https://$CORE_HOSTNAME"]

[audit]
audit_remote_url = null
audit_local_retention_days = 90
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
    # NOTE: the passphrase is NOT written here. pydantic reads .env into the
    # settings object, not into os.environ — and ca.py/app.py read os.environ.
    # The passphrase reaches the daemon via the 0640 EnvironmentFile below.
    cat >> "$INSTALL_DIR/.env" << EOF
VENYA_ADMIN_MTLS__ENABLED=true
VENYA_ADMIN_MTLS__CA_CERT="$ADMIN_CA_DIR/admin-ca.crt"
VENYA_ADMIN_MTLS__KNOWN_ADMIN_IDS=["$ADMIN_IDENTITY"]
EOF

    # Runtime passphrase delivery: a 0640 root:venya EnvironmentFile that
    # systemd (PID1, as root) reads into the service's os.environ — the only
    # thing ca.py reads. Replaces the old inline Environment= injection into
    # the 0644 unit (which leaked the secret to every local user). Value is
    # unquoted base64: systemd strips quotes but unquoted avoids any
    # version-dependent ambiguity, and base64 has no systemd-special chars.
    cat > /etc/venya/venya-core.env << EOF
VENYA_ADMIN_CA_KEY_PASSPHRASE=$ADMIN_CA_PASSPHRASE
EOF
    chown root:venya /etc/venya/venya-core.env
    chmod 0640 /etc/venya/venya-core.env
fi

# .env holds the DB password + passphrase — always root/venya-only, even without mTLS.
chmod 600 "$INSTALL_DIR/.env"
chown venya:venya "$INSTALL_DIR/.env"

info ".env written to $INSTALL_DIR/.env"

# --- Generate Venya CA (Python) and sign server cert (openssl CLI) ---
info "Generating Venya CA and signing server TLS certificate..."
mkdir -p /etc/venya/tls
chown venya:venya /etc/venya/tls

# Generate CA with Python (CAManager works for generation)
sudo -u venya env PATH="$INSTALL_DIR/.venv/bin:$PATH" \
    python -c "
import os
from pathlib import Path
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID
from datetime import UTC, datetime, timedelta

ca_dir = Path('/var/lib/venya/ca')
ca_dir.mkdir(parents=True, exist_ok=True)
os.chmod(str(ca_dir), 0o700)

ca_key_path = ca_dir / 'ca.key'
ca_cert_path = ca_dir / 'ca.crt'

if not ca_key_path.exists():
    ca_key = ec.generate_private_key(ec.SECP256R1())
    ca_key_path.write_bytes(ca_key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
    ca_key_path.chmod(0o600)
    now = datetime.now(UTC)
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, 'Venya'),
        x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, 'Venya Certificate Authority'),
        x509.NameAttribute(NameOID.COMMON_NAME, 'Venya Root CA'),
    ])
    ski = x509.SubjectKeyIdentifier.from_public_key(ca_key.public_key())
    aki = x509.AuthorityKeyIdentifier.from_issuer_subject_key_identifier(ski)
    builder = (x509.CertificateBuilder()
        .subject_name(subject).issuer_name(issuer)
        .public_key(ca_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + timedelta(days=3650))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .add_extension(x509.KeyUsage(digital_signature=False, key_encipherment=False, content_commitment=False, data_encipherment=False, key_agreement=False, key_cert_sign=True, crl_sign=True, encipher_only=False, decipher_only=False), critical=True)
        .add_extension(ski, critical=False)
        .add_extension(aki, critical=False))
    ca_cert = builder.sign(ca_key, hashes.SHA256())
    ca_cert_path.write_bytes(ca_cert.public_bytes(serialization.Encoding.PEM))
    ca_cert_path.chmod(0o644)
    print('CA generated')
else:
    print('CA already exists')
"

# Sign server cert with openssl CLI (cryptography 50.0.1 Rust backend bug:
# builder.sign() rejects valid ECPrivateKey from _rust.openssl.ec module)
openssl ecparam -genkey -name prime256v1 -noout -out /etc/venya/tls/server.key
chown venya:venya /etc/venya/tls/server.key
chmod 600 /etc/venya/tls/server.key

openssl req -new -key /etc/venya/tls/server.key -out /tmp/server.csr \
    -subj "/O=Venya/CN=$CORE_HOSTNAME"

openssl x509 -req -in /tmp/server.csr \
    -CA /var/lib/venya/ca/ca.crt -CAkey /var/lib/venya/ca/ca.key \
    -CAcreateserial -out /etc/venya/tls/server.crt -days 365 \
    -extfile <(echo "subjectAltName=DNS:$CORE_HOSTNAME")

chown venya:venya /etc/venya/tls/server.crt
chmod 644 /etc/venya/tls/server.crt
rm -f /tmp/server.csr

info "Server TLS certificate signed with Venya CA"

# --- Relay client cert: self-provisioned from the Venya CA ---
# The core presents this client cert when calling the executor relay listener.
# CN="${CORE_HOSTNAME}-relay" is the canonical relay identity; the executor
# installer derives the same value for relay_client_ids.
# CA premise (guarded, not asserted): the CA above is generated UNENCRYPTED
# (NoEncryption() in the CA block), so openssl signs without -passin. If the
# CA is missing, fail the install here — not at the physical e2e.
if [ ! -f /var/lib/venya/ca/ca.crt ] || [ ! -f /var/lib/venya/ca/ca.key ]; then
    error "Venya CA missing at /var/lib/venya/ca (ca.crt/ca.key) — cannot sign relay client cert"
    exit 1
fi

RELAY_DIR="/etc/venya/relay"
mkdir -p "$RELAY_DIR"
chown venya:venya "$RELAY_DIR"
chmod 700 "$RELAY_DIR"

openssl ecparam -genkey -name prime256v1 -noout -out "$RELAY_DIR/relay-client.key"
chown venya:venya "$RELAY_DIR/relay-client.key"
chmod 600 "$RELAY_DIR/relay-client.key"

openssl req -new -key "$RELAY_DIR/relay-client.key" \
    -out /tmp/relay-client.csr \
    -subj "/O=Venya/CN=${CORE_HOSTNAME}-relay"

# SKI + AKI are non-optional: Python 3.14 ssl rejects a chain without an
# Authority Key Identifier (33bc4b4); a lenient s_client smoke masks the
# absence. EKU is clientAuth-only: the core relay cert never serves a server
# role (the executor leaf is dual-purpose by design — do not "unify").
openssl x509 -req -in /tmp/relay-client.csr \
    -CA /var/lib/venya/ca/ca.crt -CAkey /var/lib/venya/ca/ca.key \
    -CAcreateserial -out "$RELAY_DIR/relay-client.crt" -days 365 \
    -extfile <(printf 'extendedKeyUsage=clientAuth\nsubjectAltName=DNS:%s-relay\nsubjectKeyIdentifier=hash\nauthorityKeyIdentifier=keyid,issuer\n' "${CORE_HOSTNAME}")

chown venya:venya "$RELAY_DIR/relay-client.crt"
chmod 644 "$RELAY_DIR/relay-client.crt"
rm -f /tmp/relay-client.csr

# Self-check: fail the install loudly on a half-wired relay cert.
if ! openssl verify -CAfile /var/lib/venya/ca/ca.crt "$RELAY_DIR/relay-client.crt" >/dev/null 2>&1; then
    error "Relay client cert failed verification against the Venya CA"
    exit 1
fi
ACTUAL_RELAY_CN=$(openssl x509 -in "$RELAY_DIR/relay-client.crt" -noout -subject -nameopt multiline | sed -n 's/^ *commonName *= *//p')
if [ "$ACTUAL_RELAY_CN" != "${CORE_HOSTNAME}-relay" ]; then
    error "Relay client cert CN mismatch: expected '${CORE_HOSTNAME}-relay', got '${ACTUAL_RELAY_CN}'"
    exit 1
fi

# Purpose self-check: assert the asymmetric-EKU contract (client Yes / server
# No) at install time. `openssl verify` does NOT check EKU, so without this an
# EKU/SAN defect would surface only at the deploy stop-check, not at install.
PURPOSE_OUT=$(openssl x509 -in "$RELAY_DIR/relay-client.crt" -noout -purpose 2>/dev/null)
if ! printf '%s\n' "$PURPOSE_OUT" | grep -qE '^[[:space:]]*SSL client[[:space:]]+: Yes'; then
    error "Relay client cert purpose self-check failed: expected 'SSL client : Yes'"
    exit 1
fi
if ! printf '%s\n' "$PURPOSE_OUT" | grep -qE '^[[:space:]]*SSL server[[:space:]]+: No'; then
    error "Relay client cert purpose self-check failed: expected 'SSL server : No'"
    exit 1
fi

info "Relay client certificate signed and verified: CN=${CORE_HOSTNAME}-relay (client Yes / server No)"

# Functional wiring: the server reads .env at runtime (server.toml is never
# read). The appended values are non-secret paths only.
cat >> "$INSTALL_DIR/.env" << EOF
VENYA_MTLS_CERT=$RELAY_DIR/relay-client.crt
VENYA_MTLS_KEY=$RELAY_DIR/relay-client.key
EOF

# Install Venya CA into system trust store
# Clean stale symlinks/files from previous installs
rm -f /etc/ssl/certs/venya-*.pem
rm -f /etc/ssl/certs/$(openssl x509 -in /var/lib/venya/ca/ca.crt -noout -subject_hash 2>/dev/null).*
rm -f /usr/local/share/ca-certificates/venya-*.crt /usr/local/share/ca-certificates/venya-*.der
cp /var/lib/venya/ca/ca.crt /usr/local/share/ca-certificates/venya-root-ca.crt
chmod 644 /usr/local/share/ca-certificates/venya-root-ca.crt
update-ca-certificates > /dev/null 2>&1
info "Venya CA installed to system trust store"

# Copy CA cert to servable path for executor bootstrap
mkdir -p /var/www/.well-known
cp /var/lib/venya/ca/ca.crt /var/www/.well-known/venya-ca.crt
chmod 644 /var/www/.well-known/venya-ca.crt
info "CA cert served at /.well-known/venya-ca.crt"

# --- Write Nginx config (core-specific) ---
mkdir -p /etc/nginx/ssl

# Copy Admin CA to Nginx-readable location (www-data can't traverse /var/lib/venya/ca)
if [ "$ADMIN_MTLS_ENABLED" = "true" ]; then
    cp /var/lib/venya/ca/admin-ca/admin-ca.crt /etc/nginx/ssl/client-ca.crt
    chmod 644 /etc/nginx/ssl/client-ca.crt
    ADMIN_CA_PATH="/etc/nginx/ssl/client-ca.crt"
else
    rm -f /etc/nginx/ssl/client-ca.crt
    ADMIN_CA_PATH=""
fi

# Create CA bundle: Venya Root CA + Admin CA.
# Nginx needs both to verify admin client certs (Admin CA) and executor certs (Root CA).
cat /var/lib/venya/ca/ca.crt /etc/nginx/ssl/client-ca.crt > /etc/nginx/ssl/client-ca-bundle.crt 2>/dev/null || true
chmod 644 /etc/nginx/ssl/client-ca-bundle.crt 2>/dev/null || true

cat > /etc/nginx/sites-available/venya << EOF
server {
    listen 443 ssl;
    server_name $CORE_HOSTNAME;

    ssl_certificate /etc/venya/tls/server.crt;
    ssl_certificate_key /etc/venya/tls/server.key;
    ssl_client_certificate /etc/nginx/ssl/client-ca-bundle.crt;
    ssl_verify_client optional;

    location /.well-known/venya-ca.crt {
        alias /var/www/.well-known/venya-ca.crt;
        default_type application/x-x509-ca-cert;
    }

    location /api/v1/health {
        proxy_pass http://127.0.0.1:8080;
    }

    location / {
        proxy_pass http://127.0.0.1:8080;
        proxy_set_header X-Client-Verified \$ssl_client_verify;
        proxy_set_header X-Client-Subject \$ssl_client_s_dn;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto https;
    }
}
EOF

# Enable site, disable default
ln -sf /etc/nginx/sites-available/venya /etc/nginx/sites-enabled/venya
rm -f /etc/nginx/sites-enabled/default

info "Nginx config written (TLS mode: $TLS_MODE, admin mTLS: $([ "$ADMIN_MTLS_ENABLED" = "true" ] && echo enabled || echo disabled))"

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
    echo "  Admin CA passphrase stored in: /etc/venya/venya-core.env (0640 root:venya)."
    echo "  The venya-core service loads it via EnvironmentFile; it is NOT in .env"
    echo "  or the unit file. On an unattended install it was randomly generated."
    echo "  Read it (root) with: sudo cat /etc/venya/venya-core.env"
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
echo "  Relay: the core relay-client cert was auto-provisioned at install"
echo "  (/etc/venya/relay/relay-client.crt, CN=${CORE_HOSTNAME}-relay)."
echo "  Point the executor installer at this hostname:"
echo "    VENYA_SERVER_URL=https://${CORE_HOSTNAME}"
echo ""
echo "==============================================================="
echo ""

# Start Nginx
info "Starting Nginx..."
systemctl enable nginx > /dev/null 2>&1
systemctl restart nginx > /dev/null 2>&1 || true
info "Nginx enabled and started"

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

# NOTE: no passphrase is injected into the unit here. The unit template carries
# EnvironmentFile=-/etc/venya/venya-core.env (0640 root:venya, written above),
# so the secret never lands in this 0644 root:root unit. The leading '-' makes
# it optional: admin-mTLS-disabled installs (no env file) still start cleanly.

systemctl daemon-reload
systemctl enable venya-core.service
systemctl start venya-core.service

# --- Service retry ---
venya_service_retry venya-core

# --- Verification ---
venya_verify_install \
    /etc/venya/server.toml \
    /etc/nginx/sites-available/venya \
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
echo "Nginx reverse proxy:"
echo "  Config: /etc/nginx/sites-available/venya"
echo "  TLS mode: $TLS_MODE"
echo "  Access: https://$CORE_HOSTNAME"
echo ""
echo "Next steps:"
echo "  1. Verify health: curl -sk https://$CORE_HOSTNAME/api/v1/health"
echo "  2. Enroll admin: open https://$CORE_HOSTNAME/enroll-admin in browser"
echo "  3. Mint an executor enrollment token (command above) with the admin"
echo "     credential."
echo "  4. Install the executor with VENYA_EXECUTOR_ENROLLMENT_TOKEN=<token>."
echo "     Registration happens inside that install; the token is single-use."
echo ""
