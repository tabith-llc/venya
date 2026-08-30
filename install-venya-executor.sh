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
#   VENYA_TARBALL       - URL of the tarball to install (auto-detected if on same host)
#   VENYA_EXECUTOR_ID              - Executor ID (default: jump-1)
#   VENYA_SERVER_URL               - Core server URL (required)
#   VENYA_CORE_HOSTNAME    - Core hostname for /etc/hosts resolution (default: venya-core-1)
#   VENYA_CORE_IP          - Core IP for /etc/hosts resolution (default: 10.27.28.11)
#   VENYA_VENYA_CA_FILE    - Path to pre-copied Venya CA cert (offline/air-gapped deployments)
#   VENYA_EXECUTOR_ENROLLMENT_TOKEN - Bootstrap enrollment token for auto-registration
###############################################################################

# --- Defaults ---
TARBALL_URL="${VENYA_TARBALL:-http://10.27.27.35:8080/venya-executor-install.tar.gz}"
EXECUTOR_ID="${VENYA_EXECUTOR_ID:-jump-1}"

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

# --- Require VENYA_SERVER_URL (no default — server hostname is unknown) ---
if [ -z "${VENYA_SERVER_URL:-}" ]; then
    error "VENYA_SERVER_URL is required."
    error "Set it to your core server URL, e.g.: https://venya-core or https://10.0.1.50"
    exit 1
fi
SERVER_URL="$VENYA_SERVER_URL"

info "Installing Venya Executor to $INSTALL_DIR"

# --- Create venya service account (no password, nologin, locked) ---
venya_create_user

# --- Install system packages ---
venya_install_system_pkgs curl sudo build-essential

# --- Install Rust for venya user ---
SU_CARGO="/home/venya/.cargo/bin/cargo"
if [ ! -f "$SU_CARGO" ]; then
    info "Installing Rust for venya user..."
    sudo -u venya bash -c "curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y" > /dev/null 2>&1
fi

# --- Install uv for venya user ---
venya_install_uv_user

# --- Install Python 3.14 for venya user ---
venya_install_python314

# --- Download and extract tarball ---
venya_download_tarball executor
venya_extract_tarball

# --- Apply shared code fixes (patch source BEFORE building) ---
venya_apply_code_fixes

# --- Build Python venv ---
venya_create_venv "venya-executor-requirements.txt" "/home/venya/.cargo/bin"

# --- Verify deployed code ---
venya_verify_deployment executor

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
cd "$INSTALL_DIR"

# --- Create directories ---
venya_create_directories

# --- Write egress allowlist ---
venya_write_egress_allowlist

# --- Harden log dir (executor-specific) ---
# NOTE: /etc/venya/executor.toml + /etc/venya/executor creds are hardened AFTER they are
# written (see "Harden executor credentials" block near the end). Hardening them here was
# a no-op — the dir/files do not exist yet at this point.
chmod 750 /var/log/venya
chown venya:adm /var/log/venya 2>/dev/null || chown venya:venya /var/log/venya

# --- Install Docker Sandboxes (sbx) CLI (executor-specific) ---
info "Installing Docker Sandboxes (sbx) CLI..."
if ! command -v sbx &>/dev/null; then
    SBX_SCRIPT=$(mktemp /tmp/docker-sbx-install-XXXXXX.sh)
    curl -fsSL https://get.docker.com -o "$SBX_SCRIPT"
    REPO_ONLY=1 sh "$SBX_SCRIPT" > /dev/null 2>&1
    rm -f "$SBX_SCRIPT"
    apt-get install -y -qq docker-sbx > /dev/null 2>&1
    usermod -aG kvm venya 2>/dev/null || true
    info "sbx CLI installed. venya user added to kvm group."
else
    info "sbx CLI already installed: $(sbx --version 2>/dev/null || echo 'unknown')"
fi

# --- Resolve Core Hostname ---
CORE_HOSTNAME="${VENYA_CORE_HOSTNAME:-venya-core-1}"
CORE_IP="${VENYA_CORE_IP:-10.27.28.11}"

# Ensure the core hostname is resolvable in /etc/hosts
if ! grep -q " ${CORE_HOSTNAME}$" /etc/hosts 2>/dev/null; then
    info "Adding ${CORE_HOSTNAME} (${CORE_IP}) to /etc/hosts"
    echo "${CORE_IP} ${CORE_HOSTNAME}" >> /etc/hosts
else
    # Verify the IP matches if strictness is desired
    EXISTING_IP=$(grep " ${CORE_HOSTNAME}$" /etc/hosts | awk '{print $1}')
    if [ "$EXISTING_IP" != "$CORE_IP" ]; then
        warn "Found ${CORE_HOSTNAME} in /etc/hosts with IP ${EXISTING_IP}, expected ${CORE_IP}. Updating."
        sed -i "/ ${CORE_HOSTNAME}$/d" /etc/hosts
        echo "${CORE_IP} ${CORE_HOSTNAME}" >> /etc/hosts
    fi
fi

# --- Install Venya CA into system trust store (for TLS verification) ---
# TOFU bootstrap: --insecure is the only insecure connection. This fetches a
# public root CA cert — explicitly sanctioned by the Production Mandate.
VENYA_CA_URL="${SERVER_URL%/}/.well-known/venya-ca.crt"
CA_BUNDLE_PATH="/usr/local/share/ca-certificates/venya-local-ca.crt"
CA_INSTALLED=false
if [ -n "${VENYA_VENYA_CA_FILE:-}" ] && [ -f "$VENYA_VENYA_CA_FILE" ]; then
    cp "$VENYA_VENYA_CA_FILE" "$CA_BUNDLE_PATH"
    chmod 644 "$CA_BUNDLE_PATH"
    update-ca-certificates > /dev/null 2>&1
    CA_INSTALLED=true
    info "Venya CA installed from $VENYA_VENYA_CA_FILE"
else
    for i in $(seq 1 5); do
        if curl -sf --insecure "$VENYA_CA_URL" -o "$CA_BUNDLE_PATH" 2>/dev/null; then
            chmod 644 "$CA_BUNDLE_PATH"
            update-ca-certificates > /dev/null 2>&1
            CA_INSTALLED=true
            info "Venya CA installed to system trust store from $VENYA_CA_URL"
            break
        fi
        if [ "$i" -lt 5 ]; then
            info "Core not reachable at $SERVER_URL — retrying CA fetch ($i/5), waiting 10s..."
            sleep 10
        fi
    done
    if [ "$CA_INSTALLED" = false ]; then
        warn "Could not fetch Venya CA from $VENYA_CA_URL after 5 attempts — TLS verification may fail"
        warn "Pre-copy the CA cert to $CA_BUNDLE_PATH and rerun"
    fi
fi

# --- Write executor config (after CA installation so ca_bundle path is valid) ---
mkdir -p /etc/venya/executor
mkdir -p /var/log/venya

cat > /etc/venya/executor.toml << EOF
server_url = "$SERVER_URL"
executor_id = "$EXECUTOR_ID"
log_level = "info"
daemonize = false
injection_method = "sbx"
secret_base_fd = 100
ca_bundle = "$CA_BUNDLE_PATH"

[mtls]
ca_cert = "/etc/venya/executor/ca.crt"
cert = "/etc/venya/executor/executor.crt"
key = "/etc/venya/executor/executor.key"
EOF

info "Executor config written to /etc/venya/executor.toml"

# --- Register mTLS certificate (if enrollment token provided) ---
if [ -n "${VENYA_EXECUTOR_ENROLLMENT_TOKEN:-}" ]; then
    info "Attempting mTLS certificate registration..."

    if [ "$CA_INSTALLED" = true ]; then
        # Health check with proper TLS (CA is now trusted)
        if curl -sf "$SERVER_URL/api/v1/health" >/dev/null 2>&1; then
            info "Core health check passed (TLS verified)"
        else
            warn "Core health check failed — proceeding with registration anyway"
        fi

        # Run registration — do NOT use || true, failures must abort install
        REG_OUTPUT=$("$INSTALL_DIR/.venv/bin/venya" exec register \
            --executor-id "$EXECUTOR_ID" \
            --core-url "$SERVER_URL" \
            --output-dir /etc/venya/executor \
            --enrollment-token "${VENYA_EXECUTOR_ENROLLMENT_TOKEN:-}" \
            2>&1)
        REG_EXIT=$?
        echo "$REG_OUTPUT"

        if [ "$REG_EXIT" -ne 0 ]; then
            error "Executor registration failed (exit $REG_EXIT)"
            error "Output: $REG_OUTPUT"
            error "Check that VENYA_EXECUTOR_ENROLLMENT_TOKEN is valid and core is reachable"
            exit 1
        fi

        # Verify certs were actually written (catches silent partial failures)
        # Exit code 0 from venya exec register does not guarantee cert files were written
        # A bug, permission issue, or partial network failure could cause CLI to exit 0
        # without writing certs. Using -s (exists and non-empty) catches empty files.
        CERT_DIR="/etc/venya/executor"
        for cert_file in "$CERT_DIR/executor.crt" "$CERT_DIR/executor.key"; do
            if [ ! -s "$cert_file" ]; then
                error "Registration reported success but $cert_file is missing or empty"
                error "This indicates a bug in venya exec register or a permission issue"
                exit 1
            fi
        done

        info "Executor registered and mTLS certificates verified"
    else
        warn "Venya CA not installed — skipping cert registration"
        echo ""
        echo "  Run this after core is reachable:"
        echo "    $INSTALL_DIR/.venv/bin/venya exec register \\"
        echo "      --executor-id $EXECUTOR_ID \\"
        echo "      --core-url $SERVER_URL \\"
        echo "      --output-dir /etc/venya/executor \\"
        echo "      --enrollment-token '${VENYA_EXECUTOR_ENROLLMENT_TOKEN:-}'"
        echo ""
    fi
fi

# --- Write bootstrap config (enrollment token for heartbeat) ---
if [ -n "${VENYA_EXECUTOR_ENROLLMENT_TOKEN:-}" ]; then
    cat >> /etc/venya/executor.toml << EOF

[bootstrap]
enrollment_token = "${VENYA_EXECUTOR_ENROLLMENT_TOKEN:-}"
tls_verify = true
EOF
    info "Bootstrap enrollment token configured"
    # Clear enrollment token from config — daemon runs with ReadOnlyPaths=/etc/venya
    # and cannot write to clear it at startup. Root clears it here after registration.
    sed -i '/^\[bootstrap\]/,/^$/d' /etc/venya/executor.toml
    sed -i '/^enrollment_token = /d' /etc/venya/executor.toml
    sed -i '/^tls_verify = /d' /etc/venya/executor.toml
fi

# --- Harden executor credentials (executor-specific) ---
# Runs AFTER the config + any registered certs exist. chown venya:venya (not just chmod
# 600): venya-executor.service runs User=venya with ReadOnlyPaths=/etc/venya and must READ
# these — a root-owned 600 file would EACCES and break mTLS.
chown venya:venya /etc/venya/executor.toml
chmod 600 /etc/venya/executor.toml
chown -R venya:venya /etc/venya/executor
chmod 700 /etc/venya/executor
find /etc/venya/executor -name '*.key' -exec   chmod 600 {} \; 2>/dev/null || true
find /etc/venya/executor -name '*.crt' -exec   chmod 644 {} \; 2>/dev/null || true
info "Executor credentials hardened (venya:venya, dir 700, key 600, cert 644)"

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
echo "  1. Run 'newgrp kvm' or re-login to activate KVM group (needed for Docker sandbox/KVM access)"
echo ""
