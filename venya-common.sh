#!/usr/bin/env bash
###############################################################################
# Venya Installer Common Library
#
# Shared functions for install-venya-core.sh and install-venya-executor.sh.
# Source this file from your installer script before using any functions.
#
# Required variables (must be set by the caller before sourcing):
#   None — all parameters are passed as function arguments.
#
# Functions provided:
#   venya_print_colors          # Define RED/GREEN/YELLOW/NC + info/warn/error
#   venya_check_root            # Exit if not root
#   venya_determine_install_dir # Set INSTALL_DIR interactively or from var
#   venya_check_existing        # Prompt to reinstall if exists
#   venya_create_user           # Create venya user with password
#   venya_install_system_pkgs   # apt-get install (pkg list as args)
#   venya_install_uv            # Install uv for root
#   venya_source_paths          # Source shell env files
#   venya_install_uv_user       # Install uv for venya user
#   venya_download_tarball      # Download tarball (type=core|executor)
#   venya_extract_tarball       # Extract tarball to INSTALL_DIR
#   venya_create_venv           # Create Python venv + install packages
#   venya_apply_code_fixes      # Apply Python code patches (sed)
#   venya_create_directories    # Create runtime directories
#   venya_service_retry         # Retry loop for systemctl start
#   venya_verify_install        # Verify installation (file checks)
###############################################################################

# --- 1. Colors and logging ---

venya_print_colors() {
    RED='\033[0;31m'
    GREEN='\033[0;32m'
    YELLOW='\033[1;33m'
    NC='\033[0m'

    info()  { echo -e "${GREEN}[INFO]${NC}  $*"; }
    warn()  { echo -e "${YELLOW}[WARN]${NC}  $*"; }
    error() { echo -e "${RED}[ERROR]${NC} $*"; }
}

# --- 2. Root check ---

venya_check_root() {
    if [ "$(id -u)" -ne 0 ]; then
        error "This script must be run as root (or with sudo)."
        exit 1
    fi
}

# --- 3. Determine install directory ---

venya_determine_install_dir() {
    local default_dir="${1:-/opt/venya}"
    INSTALL_DIR="${VENYA_INSTALL_DIR:-}"
    reply=""

    if [ -z "$INSTALL_DIR" ]; then
        echo -n "Install to $default_dir? [Y/n] "
        if [ "$VENYA_SKIP_PROMPT" = "yes" ]; then
            echo ""
            reply="y"
        else
            read -r reply || reply=""
        fi
        if [ -z "$reply" ] || [ "$reply" = "y" ] || [ "$reply" = "Y" ]; then
            INSTALL_DIR="$default_dir"
        else
            read -rp "Enter install directory: " INSTALL_DIR
        fi
    fi

    # Ensure path ends without trailing slash
    INSTALL_DIR="${INSTALL_DIR%/}"
}

# --- 4. Check for existing installation ---

venya_check_existing() {
    reply=""
    if [ -d "$INSTALL_DIR" ] && [ -f "$INSTALL_DIR/pyproject.toml" ]; then
        warn "Existing installation found at $INSTALL_DIR"
        echo -n "Reinstall? [y/N] "
        if [ "$VENYA_SKIP_PROMPT" = "yes" ]; then
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
}

# --- 5. Create venya user ---

venya_create_user() {
    # Args: $1 = secure_pw_file (true/false) — whether to use temp file for password
    local secure_pw_file="${1:-true}"

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
        if [ "$secure_pw_file" = "true" ]; then
            # Use secure temp file to avoid exposing password in process list
            PW_FILE=$(mktemp /tmp/venya-pw-XXXXXX)
            chmod 600 "$PW_FILE"
            printf 'venya:%s\n' "$VENYA_PASSWORD" > "$PW_FILE"
            chpasswd < "$PW_FILE"
            rm -f "$PW_FILE"
        else
            echo "venya:$VENYA_PASSWORD" | chpasswd
        fi
        info "Created venya user"
    fi
}

# --- 6. Install system packages ---

venya_install_system_pkgs() {
    # Args: space-separated package names
    if [ $# -eq 0 ]; then
        return
    fi
    info "Installing system packages..."
    apt-get update -qq
    apt-get install -y -qq "$@" > /dev/null 2>&1
}

# --- 7. Install uv (root) ---

venya_install_uv() {
    if ! command -v uv &>/dev/null; then
        info "Installing uv..."
        curl -LsSf https://astral.sh/uv/install.sh | sh > /dev/null 2>&1
    else
        info "uv already installed: $(uv --version)"
    fi
}

# --- 8. Source shell env files ---

venya_source_paths() {
    # Args: $1 = source_cargo (true/false)
    local source_cargo="${1:-false}"
    source "$HOME/.local/bin/env" 2>/dev/null || true
    if [ "$source_cargo" = "true" ]; then
        source "$HOME/.cargo/env" 2>/dev/null || true
    fi
}

# --- 9. Install uv for venya user ---

venya_install_uv_user() {
    SU_UV_BIN="/home/venya/.local/bin/uv"
    if [ ! -f "$SU_UV_BIN" ]; then
        info "Installing uv for venya user..."
        sudo -u venya bash -c "curl -LsSf https://astral.sh/uv/install.sh | sh" > /dev/null 2>&1
    fi
}

# --- 10. Download tarball ---

venya_download_tarball() {
    # Args: $1 = tarball_type (core|executor)
    local tarball_type="${1:-core}"
    if [ -z "$TARBALL_URL" ]; then
        if [ -f "/tmp/venya-install.tar.gz" ]; then
            TARBALL_URL="file:///tmp/venya-${tarball_type}-install.tar.gz"
        elif [ -f "/opt/venya-install.tar.gz" ]; then
            TARBALL_URL="file:///opt/venya-${tarball_type}-install.tar.gz"
        else
            error "No tarball found. Set VENYA_TARBALL to a URL or place venya-${tarball_type}-install.tar.gz in /tmp/"
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
}

# --- 11. Extract tarball ---

venya_extract_tarball() {
    mkdir -p "$INSTALL_DIR"
    tar xzf "$TARBALL_FILE" -C "$INSTALL_DIR" --strip-components=1
    rm -f "$TARBALL_FILE"
    chown -R venya:venya "$INSTALL_DIR"
}

# --- 12. Create Python venv ---

venya_create_venv() {
    # Args: $1 = requirements_file, $2+ = extra PATH entries
    local requirements_file="${1:-}"
    shift || true
    local extra_paths="$@"
    local full_path="/home/venya/.local/bin:${extra_paths}"

    info "Creating Python virtual environment..."
    VENYA_UV="/home/venya/.local/bin/uv"
    sudo -u venya env PATH="${full_path}" bash -c "cd $INSTALL_DIR && UV_VENV_CLEAR=1 $VENYA_UV venv .venv"

    if [ -n "$requirements_file" ]; then
        info "Installing Python packages..."
        sudo -u venya env PATH="${full_path}" bash -c "cd $INSTALL_DIR && $VENYA_UV pip install -r $INSTALL_DIR/$requirements_file"
    fi
}

# --- 13. Apply code fixes (sed patches) ---

venya_apply_code_fixes() {
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

    # Fix 2: Fix init.py imports (from ..iam.models -> from core.iam.models)
    for f in "$INSTALL_DIR/packages/server/src/server/routes/init.py"; do
        if [ -f "$f" ]; then
            sed -i 's/from \.\.iam\.models/from core.iam.models/g' "$f"
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
}

# --- 14. Create directories ---

venya_create_directories() {
    mkdir -p /var/lib/venya/ca
    mkdir -p /var/log/venya
    chown -R venya:venya /var/lib/venya
    chown -R venya:venya /var/log/venya
    chown -R venya:venya "$INSTALL_DIR"
    chmod 700 /var/lib/venya/ca
}

# --- 15. Service start retry loop ---

venya_service_retry() {
    # Args: $1 = service_name (e.g., venya-core, venya-executor)
    local service_name="${1:-}"
    if [ -z "$service_name" ]; then
        error "venya_service_retry requires service_name argument"
        exit 1
    fi

    # Wait for service to be running (retry up to 5 times)
    RETRY=0
    MAX_RETRY=5
    while [ $RETRY -lt $MAX_RETRY ]; do
        if systemctl is-active --quiet "${service_name}.service" 2>/dev/null; then
            break
        fi
        RETRY=$((RETRY + 1))
        info "Service not ready, retrying ($RETRY/$MAX_RETRY)..."
        sleep 2
        systemctl restart "${service_name}.service"
    done

    if [ $RETRY -eq $MAX_RETRY ]; then
        error "${service_name}.service failed to start after $MAX_RETRY attempts"
        systemctl status "${service_name}.service" --no-pager
        exit 1
    fi

    info "${service_name}.service is running"
}

# --- 16. Verify installation ---

venya_verify_install() {
    # Args: file paths to check (one per arg)
    info "Verifying installation..."
    ERRORS=0
    local check_files=("$@")

    # Common check: venya binary
    if [ ! -f "$INSTALL_DIR/.venv/bin/venya" ]; then
        error "venya binary not found at $INSTALL_DIR/.venv/bin/venya"
        ERRORS=$((ERRORS + 1))
    fi

    # Check caller-specified files
    for f in "${check_files[@]}"; do
        if [ ! -f "$f" ]; then
            error "$f not found"
            ERRORS=$((ERRORS + 1))
        fi
    done

    if [ "$ERRORS" -gt 0 ]; then
        error "Installation completed with $ERRORS error(s). Check output above."
        exit 1
    fi
    info "Installation verified successfully"
}
