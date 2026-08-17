#!/usr/bin/env bash
set -euo pipefail

###############################################################################
# Venya Executor Installer
#
# Installs Venya Executor on a fresh VM:
#   - venya user, system packages, Rust, uv
#   - Python venv, executor + core packages
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
#   VENYA_SERVER_URL               - Core server URL (default: https://venya-core)
#   VENYA_EXECUTOR_ENROLLMENT_TOKEN - Bootstrap enrollment token for auto-registration
###############################################################################

# --- Defaults ---
TARBALL_URL="${VENYA_TARBALL:-http://10.27.27.35:8080/venya-executor-install.tar.gz}"
EXECUTOR_ID="${VENYA_EXECUTOR_ID:-jump-1}"
SERVER_URL="${VENYA_SERVER_URL:-https://venya-core}"

# --- Source common library ---
COMMON_DIR="$(cd "$(dirname "$0")" && pwd)"
source "$COMMON_DIR/venya-common.sh"

venya_print_colors
venya_check_root
venya_determine_install_dir /opt/venya
venya_check_existing

info "Installing Venya Executor to $INSTALL_DIR"

# --- Create venya user (secure password handling) ---
venya_create_user true

# --- Install system packages ---
venya_install_system_pkgs curl sudo build-essential

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

# --- Install uv (root + venya user) ---
venya_install_uv
venya_source_paths true
venya_install_uv_user

# --- Download and extract tarball ---
venya_download_tarball executor
venya_extract_tarball

# --- Build Python venv ---
venya_create_venv "venya-executor-requirements.txt" "/home/venya/.cargo/bin"

# --- Build Rust extension (executor-specific) ---
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

# --- Apply shared code fixes ---
venya_apply_code_fixes

# --- Create directories ---
venya_create_directories

# --- Harden permissions on sensitive paths (executor-specific) ---
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

# --- Install Docker Sandboxes (sbx) CLI (executor-specific) ---
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

# --- Register mTLS certificate (if enrollment token provided and core reachable) ---
if [ -n "$VENYA_EXECUTOR_ENROLLMENT_TOKEN" ]; then
    info "Attempting mTLS certificate registration..."

    # Retry loop: wait for core to be reachable
    CORE_REACHABLE=false
    for i in $(seq 1 5); do
        if curl -sf --insecure "$SERVER_URL/api/v1/health" >/dev/null 2>&1; then
            CORE_REACHABLE=true
            break
        fi
        if [ "$i" -lt 5 ]; then
            info "Core not reachable at $SERVER_URL — retrying ($i/5), waiting 10s..."
            sleep 10
        fi
    done

    if [ "$CORE_REACHABLE" = true ]; then
        # Run registration
        REG_OUTPUT=$("$INSTALL_DIR/.venv/bin/venya" exec register \
            --executor-id "$EXECUTOR_ID" \
            --core-url "$SERVER_URL" \
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
        warn "Core unreachable at $SERVER_URL after 5 attempts — skipping cert registration"
        echo ""
        echo "  Run this after core is reachable:"
        echo "    $INSTALL_DIR/.venv/bin/venya exec register \\"
        echo "      --executor-id $EXECUTOR_ID \\"
        echo "      --core-url $SERVER_URL \\"
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

# --- Install systemd service and mount unit (executor-specific) ---
info "Installing systemd service..."
SYSTEMD_DIR="/etc/systemd/system"
cp "$INSTALL_DIR/systemd/venya-executor.service" "$SYSTEMD_DIR/"
cp "$INSTALL_DIR/systemd/tmp-venya_secrets.mount" "$SYSTEMD_DIR/"
cp "$INSTALL_DIR/systemd/venya-executor.seccomp" "$SYSTEMD_DIR/"
systemctl daemon-reload
systemctl enable venya-executor.service tmp-venya_secrets.mount
systemctl start venya-executor.service

# --- Service retry ---
venya_service_retry venya-executor

# --- Verification ---
venya_verify_install \
    /etc/venya/executor.toml \
    /etc/systemd/system/venya-executor.service \
    /etc/systemd/system/tmp-venya_secrets.mount

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
