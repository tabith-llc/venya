#!/usr/bin/env bash

# Copyright (c) 2026 Tabith LLC.
# Use of this source code is governed by the Business Source License 1.1
# included in the LICENSE file at the root of this repository. As of the
# Change Date listed there, the work is available under MPL 2.0.
# SPDX-License-Identifier: BUSL-1.1

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
#   VENYA_EXECUTOR_ID              - Executor ID (default: venya-exec-1). CONTRACT: the ID
#                                    is the relay dial hostname + client-cert SAN — it MUST
#                                    be resolvable from every core (e.g. via /etc/hosts or DNS).
#   VENYA_SERVER_URL               - Core server URL (required)
#   VENYA_CORE_HOSTNAME    - Core hostname for /etc/hosts resolution (default: venya-core-1)
#   VENYA_CORE_IP          - Core IP for /etc/hosts resolution (no default —
#                            required only when the core hostname resolves
#                            neither via /etc/hosts nor DNS; explicit value
#                            always wins over an existing hosts entry)
#   VENYA_VENYA_CA_FILE    - Path to pre-copied Venya CA cert (offline/air-gapped deployments)
#   VENYA_EXECUTOR_ENROLLMENT_TOKEN - Bootstrap enrollment token for auto-registration
#   VENYA_DOCKER_USERNAME  - Docker account for sbx agent-template pulls (prompted if TTY)
#   VENYA_DOCKER_API_KEY   - Docker access token — handled stdin-only, never argv/disk
#                            (required unless already authenticated or skipped)
#   VENYA_SKIP_DOCKER_LOGIN - "yes" = degraded install: executor runs, but sandbox
#                            execution fails 503 until `sudo -H -u venya sbx login`
###############################################################################

# --- Defaults ---
TARBALL_URL="${VENYA_TARBALL:-http://10.27.27.35:8080/venya-executor-install.tar.gz}"
EXECUTOR_ID="${VENYA_EXECUTOR_ID:-venya-exec-1}"

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

# --- Build Rust extension (executor-specific) ---
# Mechanism: direct `cargo build --release` with PYO3_PYTHON set to the venv's Python,
# then copy the .so into site-packages with the CPython extension tag.
#
# The packaging backend (`uv pip install .` → setuptools-rust) was chosen to set
# PYO3_PYTHON by construction and produce a correctly-tagged .so. Empirical evidence
# shows setuptools-rust silently skips the Rust extension in this environment:
# `build_wheel` emits `executor-0.1.0-py3-none-any.whl` with no .so. Verified by
# capturing the uv build log — no build_ext, no rust compilation output.
#
# Mechanism revised to cargo + tagged copy. The goal and verification assertions
# are unchanged: correct interpreter target, correctly-tagged .so, hard verifier.
# See Bug B tracker for full evidence chain.

# PYO3_PYTHON is set explicitly to the venv's Python. Without it, pyo3-build-config
# falls back to /usr/bin/python3 (3.12.3 on Ubuntu 24.04), producing an extension
# compiled against the wrong CPython version. (Root cause of Bug B — SEGV at
# filter.py:87 when the 3.12-targeted .so was loaded on 3.14.7.)

info "Building Rust filter extension (cargo + tagged copy)..."
SITE_PACKAGES=$(find "$INSTALL_DIR/.venv" -type d -name 'site-packages' | head -1)
VENV_PYTHON="$INSTALL_DIR/.venv/bin/python3.14"
RUST_LOG="/var/log/venya/rust-build.log"
mkdir -p "$(dirname "$RUST_LOG")"
chown venya:venya "$(dirname "$RUST_LOG")"

# Derive the CPython extension suffix from the interpreter that will load it.
# EXT_SUFFIX is the exact suffix CPython expects — can't get it wrong.
TAG=$("$VENV_PYTHON" -c 'import sysconfig; print(sysconfig.get_config_var("EXT_SUFFIX"))')
DEST="$SITE_PACKAGES/venya_filter${TAG}"

# Remove any incorrect bare-named .so left by a previous (pre-fix) install
sudo -u venya rm -f "$SITE_PACKAGES/venya_filter.so" 2>/dev/null

sudo -H -u venya env \
    HOME=/home/venya \
    PATH="/home/venya/.cargo/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin" \
    PYO3_PYTHON="$VENV_PYTHON" \
    RUST_LOG="$RUST_LOG" \
    DEST="$DEST" \
    bash -c 'cd "$1/packages/executor" && cargo build --release >"$RUST_LOG" 2>&1 && cp target/release/libvenya_filter.so "$DEST"' \
        _ "$INSTALL_DIR"
BUILD_RC=$?
if [ $BUILD_RC -ne 0 ]; then
    error "Rust build failed. See $RUST_LOG"
    cat "$RUST_LOG"
    exit 1
fi

# Verify the tagged .so exists
if [ ! -f "$DEST" ]; then
    error "venya_filter${TAG} not found in site-packages after build"
    exit 1
fi

# Build-id verification — catches partial copies
SRC_BUILD_ID=$(readelf -n "$INSTALL_DIR/packages/executor/target/release/libvenya_filter.so" 2>/dev/null | grep "Build ID" | awk '{print $3}')
DEST_BUILD_ID=$(readelf -n "$DEST" 2>/dev/null | grep "Build ID" | awk '{print $3}')
if [ "$SRC_BUILD_ID" != "$DEST_BUILD_ID" ]; then
    error "Build-id mismatch: source=$SRC_BUILD_ID dest=$DEST_BUILD_ID"
    exit 1
fi

# Post-install assertion: import resolves to the tagged path
IMPORT_CHECK=$("$VENV_PYTHON" -c "import venya_filter; print(venya_filter.__file__)" 2>&1)
if ! echo "$IMPORT_CHECK" | grep -q "venya_filter${TAG}"; then
    error "venya_filter import resolves to unexpected path: $IMPORT_CHECK"
    exit 1
fi
info "Rust filter extension built: $(basename "$DEST")"
info "venya_filter import verified: $IMPORT_CHECK"
cd "$INSTALL_DIR"

# --- Verify deployed code (after Rust build, so the .so tag check is effective) ---
venya_verify_deployment executor

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

# Ensure sbx state directory exists with correct ownership (runs every install;
# sbx daemon fails as venya if root-owned from a prior degraded install)
mkdir -p /home/venya/.local/share/sandboxes
chown venya:venya /home/venya/.local/share/sandboxes
chmod 700 /home/venya/.local/share/sandboxes

# --- Docker auth (sbx template pulls) + sandboxd daemon ---
# sbx runs microVMs via KVM but pulls its agent template from Docker and
# requires a per-user sandboxd daemon. Without auth the executor installs
# fine but every sandbox create fails 503 ("Not authenticated to Docker").
# The API key travels stdin-only (never argv, never written by this script;
# sbx stores it in its own credential store under /home/venya).
if [ "${VENYA_SKIP_DOCKER_LOGIN:-}" = "yes" ]; then
    warn "VENYA_SKIP_DOCKER_LOGIN=yes — skipping Docker auth."
    warn "Sandbox execution will fail (503) until: sudo -H -u venya sbx login"
elif sudo -H -u venya sbx ls < /dev/null > /dev/null 2>&1; then
    info "sbx already authenticated (sbx ls OK)"
else
    DOCKER_USER="${VENYA_DOCKER_USERNAME:-}"
    DOCKER_KEY="${VENYA_DOCKER_API_KEY:-}"
    if { [ -z "$DOCKER_USER" ] || [ -z "$DOCKER_KEY" ]; } && [ -t 0 ]; then
        [ -z "$DOCKER_USER" ] && read -r -p "Docker username (sbx template pulls): " DOCKER_USER
        if [ -z "$DOCKER_KEY" ]; then
            read -r -s -p "Docker API key / access token (input hidden): " DOCKER_KEY
            echo
        fi
    fi
    if [ -n "$DOCKER_USER" ] && [ -n "$DOCKER_KEY" ]; then
        info "Authenticating sbx to Docker as '${DOCKER_USER}' (token via stdin)..."
        if printf '%s' "$DOCKER_KEY" | sudo -H -u venya sbx login --username "$DOCKER_USER" --password-stdin > /dev/null 2>&1; then
            info "Docker auth OK"
        else
            error "sbx login failed for '${DOCKER_USER}'. Check the API key/token."
            error "Re-run the installer with corrected VENYA_DOCKER_USERNAME/VENYA_DOCKER_API_KEY."
            exit 1
        fi
    else
        error "Docker credentials are required for sandbox execution."
        error "Set VENYA_DOCKER_USERNAME + VENYA_DOCKER_API_KEY (token; stdin-only handling),"
        error "or run this installer interactively to be prompted."
        error "Degraded install (executor runs, sandbox executes fail 503): VENYA_SKIP_DOCKER_LOGIN=yes"
        exit 1
    fi
fi

# --- sandboxd daemon (system-managed, persists across reboots) ---
cat > /etc/systemd/system/venya-sandboxd.service <<'SANDBOXD_UNIT'
[Unit]
Description=Venya sbx sandboxd (Docker Sandboxes daemon, user venya)
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
Restart=on-failure
RestartSec=5
User=venya
Environment=HOME=/home/venya
ExecStart=/usr/bin/sbx daemon start
TimeoutStartSec=60

[Install]
WantedBy=multi-user.target
SANDBOXD_UNIT
# Executor ordering drop-in (does not touch the vendored unit template)
mkdir -p /etc/systemd/system/venya-executor.service.d
cat > /etc/systemd/system/venya-executor.service.d/10-sandboxd.conf <<'DROPIN'
[Unit]
Wants=venya-sandboxd.service
After=venya-sandboxd.service
DROPIN
systemctl daemon-reload
systemctl enable venya-sandboxd.service > /dev/null 2>&1
systemctl restart venya-sandboxd.service
sleep 2
if systemctl is-active --quiet venya-sandboxd.service && sudo -H -u venya sbx daemon status < /dev/null > /dev/null 2>&1; then
    info "sandboxd running (venya-sandboxd.service, enabled)"
else
    warn "sandboxd not healthy yet — check: journalctl -u venya-sandboxd; sudo -H -u venya sbx diagnose"
fi

# --- sbx global network policy (required before any sandbox create) ---
# deny-all baseline; per-sandbox allow rules are applied from the egress
# allowlist at execution time. Without this, every sbx create fails with
# "global network policy has not been initialized".
if sudo -H -u venya sbx policy init deny-all < /dev/null > /dev/null 2>&1; then
    info "sbx global network policy initialized (deny-all)"
else
    warn "sbx policy init deny-all failed or policy already initialized — verify manually if sandbox creates fail"
fi

# --- Resolve Core Hostname ---
# CORE_HOSTNAME is the relay CN-derivation base: the core signs its
# relay-client cert with CN="${CORE_HOSTNAME}-relay". Formula: explicit
# VENYA_CORE_HOSTNAME wins; otherwise the host component of VENYA_SERVER_URL
# (scheme/port/path stripped) — so the value tracks the URL the operator
# actually used instead of a hardcoded default that can silently diverge
# (a diverged CN surfaces as relay 403 with nothing in the install output).
CORE_HOSTNAME="${VENYA_CORE_HOSTNAME:-$(printf '%s' "$SERVER_URL" | sed -E 's#^[a-zA-Z][a-zA-Z0-9+.-]*://##; s#/.*$##; s#:.*$##')}"

# Ensure the core hostname is resolvable in /etc/hosts (skip IP hosts: an IP
# needs no resolution, and writing an IP "name" would misroute).
# Resolution precedence (fail-closed — no hardcoded default IP; guessing one
# silently misroutes TLS to the wrong core, see ticket
# executor-installer-core-ip-misroute):
#   1. Explicit VENYA_CORE_IP wins: add/update the /etc/hosts entry to it.
#   2. No explicit IP + existing /etc/hosts entry: KEEP the provisioned entry
#      (provisioning owns /etc/hosts; the old code overwrote a correct entry
#      with a hardcoded default — the 2026-09-15 exec-3 clobber variant).
#   3. No explicit IP + no entry: accept DNS resolution if it works.
#   4. Nothing resolves: abort with an actionable error (set VENYA_CORE_IP).
if [[ "$CORE_HOSTNAME" =~ ^[0-9]+(\.[0-9]+){3}$ ]]; then
    info "VENYA_SERVER_URL host is an IP — no /etc/hosts entry needed"
else
    EXISTING_IP=$( (grep " ${CORE_HOSTNAME}$" /etc/hosts 2>/dev/null || true) | awk '{print $1}' | head -1)
    if [ -n "${VENYA_CORE_IP:-}" ]; then
        if [ -n "$EXISTING_IP" ] && [ "$EXISTING_IP" != "$VENYA_CORE_IP" ]; then
            warn "Found ${CORE_HOSTNAME} in /etc/hosts with IP ${EXISTING_IP}; explicit VENYA_CORE_IP=${VENYA_CORE_IP} wins. Updating."
            sed -i "/ ${CORE_HOSTNAME}$/d" /etc/hosts
            echo "${VENYA_CORE_IP} ${CORE_HOSTNAME}" >> /etc/hosts
        elif [ -z "$EXISTING_IP" ]; then
            info "Adding ${CORE_HOSTNAME} (${VENYA_CORE_IP}) to /etc/hosts"
            echo "${VENYA_CORE_IP} ${CORE_HOSTNAME}" >> /etc/hosts
        else
            info "/etc/hosts entry for ${CORE_HOSTNAME} matches VENYA_CORE_IP (${VENYA_CORE_IP})"
        fi
    elif [ -n "$EXISTING_IP" ]; then
        info "Using provisioned /etc/hosts entry: ${CORE_HOSTNAME} -> ${EXISTING_IP} (set VENYA_CORE_IP to override)"
    elif RESOLVED_IP=$(getent hosts "$CORE_HOSTNAME" 2>/dev/null | awk '{print $1}' | head -1) && [ -n "$RESOLVED_IP" ]; then
        info "Resolved ${CORE_HOSTNAME} -> ${RESOLVED_IP} via name service (no /etc/hosts entry needed)"
    else
        error "Cannot resolve ${CORE_HOSTNAME}: no /etc/hosts entry, no DNS resolution, and VENYA_CORE_IP not set."
        error "Set VENYA_CORE_IP=<core-ip> (or fix provisioning). Refusing to guess a default IP — a wrong guess silently misroutes mTLS/CA fetches to another host."
        exit 1
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

# Relay CN allowlist — MUST stay top-level (not under [mtls]). Value mirrors
# the core's relay-client cert CN (core installer). 'venya exec register'
# writes only cert files, so this line survives registration.
relay_client_ids = ["${CORE_HOSTNAME}-relay"]

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
echo "==============================================================="
echo "  RELAY WIRING (CN match contract)"
echo "==============================================================="
echo ""
echo "  relay_client_ids = [\"${CORE_HOSTNAME}-relay\"]"
echo ""
echo "  CORE_HOSTNAME was derived from VENYA_SERVER_URL (host component,"
echo "  scheme/port/path stripped) unless VENYA_CORE_HOSTNAME was set."
echo "  The core's relay-client cert (auto-signed at core install) must"
echo "  carry the SAME CN, or relay calls are rejected at handshake (403)."
echo "  Verify on the core:"
echo "    openssl x509 -in /etc/venya/relay/relay-client.crt -noout -subject"
echo ""
echo "  Fail-closed: an empty allowlist prevents the relay listener from"
echo "  binding at all (ERROR at daemon start). A mismatch means closed,"
echo "  never open."
echo "==============================================================="
echo ""
