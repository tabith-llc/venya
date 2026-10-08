#!/usr/bin/env bash

# Copyright (c) 2026 Tabith LLC.
# Use of this source code is governed by the Business Source License 1.1
# included in the LICENSE file at the root of this repository. As of the
# Change Date listed there, the work is available under MPL 2.0.
# SPDX-License-Identifier: BUSL-1.1

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
#   venya_check_no_colocation   # HARD STOP if the other component is installed
#   venya_create_user           # Create locked nologin service account (no password)
#   venya_install_system_pkgs   # apt-get install (pkg list as args)
#   venya_install_uv            # Install uv for root
#   venya_install_uv_user       # Install uv for venya user
#   venya_install_python314     # Install Python 3.14 for venya user
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

# --- Config-injection fail-closed gate (ticket #326) ---
# Shared by the core and executor installers: operator values that
# interpolate into installer-written config files must not contain
# newline/CR (splits into EXTRA config lines) or the listed characters.
venya_guard_injection() {
    # usage: venya_guard_injection LABEL VALUE [FORBIDDEN_CHAR ...]
    local label="$1" value="$2" bad
    shift 2
    case "$value" in
        *$'\n'*|*$'\r'*)
            error "$label must not contain newline/CR — it would inject extra config lines."
            exit 1 ;;
    esac
    for bad in "$@"; do
        case "$value" in
            *"$bad"*)
                error "$label must not contain the character: $bad"
                exit 1 ;;
        esac
    done
}

# --- 2. Root check ---

venya_check_root() {
    if [ "$(id -u)" -ne 0 ]; then
        error "This script must be run as root (or with sudo)."
        exit 1
    fi
}

# --- 3. Determine install directory ---

# Prompt gate (ticket skip-prompt-prints-before-check-389). Every confirmation
# caller must run this BEFORE printing its question:
#   return 0 -> VENYA_SKIP_PROMPT=yes: caller silently takes its documented
#               default (NO question line is ever printed).
#   return 1 -> interactive TTY: caller prints the question and reads, exactly
#               as before (#389 changes the TTY path not at all).
#   exit 1   -> non-TTY without the skip flag: fail loud with guidance instead
#               of consuming EOF defaults silently (the piped-idiom accident
#               class this ticket was born from).
# $1 is the question text, used ONLY in the error message — never printed here.
# This gate NEVER touches the #203/EXEC co-location hard stop below it: that
# block is a design boundary, not a confirmation, and stays prompt-free and
# un-skipable.
venya_prompt_gate() {
    if [ "${VENYA_SKIP_PROMPT:-}" = "yes" ]; then
        return 0
    fi
    if [ ! -t 0 ]; then
        error "Not a terminal and VENYA_SKIP_PROMPT is not set — refusing to answer '$1' from EOF."
        error "For an unattended run set VENYA_SKIP_PROMPT=yes (documented idiom), or run this installer interactively."
        exit 1
    fi
    return 1
}

venya_determine_install_dir() {
    local default_dir="${1:-/opt/venya}"
    INSTALL_DIR="${VENYA_INSTALL_DIR:-}"
    reply=""

    if [ -z "$INSTALL_DIR" ]; then
        if venya_prompt_gate "Install to $default_dir? [Y/n]"; then
            reply="y"
        else
            echo -n "Install to $default_dir? [Y/n] "
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
        if venya_prompt_gate "Reinstall? [y/N]"; then
            reply="y"
        else
            echo -n "Reinstall? [y/N] "
            read -r reply || reply=""
        fi
        if [ -z "$reply" ] || [ "$reply" = "n" ] || [ "$reply" = "N" ]; then
            info "Aborted."
            exit 0
        fi
    fi
}

# --- 4b. Co-location guard (ticket installer-colocation-silent-core-kill) ---
#
# Venya's trust model puts the core (CA keys, encrypted secret store, audit DB)
# on its own protected host and treats executors as COMPROMISED by design. Both
# services run as the same `venya` uid and share /etc/venya + /opt/venya, so a
# co-located box makes executor-compromise == core-compromise by construction.
# Worse, each installer rebuilds the venv with UV_VENV_CLEAR=1
# (venya_create_venv), which deletes the OTHER component's binary
# (bin/venya-server or bin/venya-executor) and kills its service with systemd
# 203/EXEC -- silently, under the documented unattended VENYA_SKIP_PROMPT=yes
# path. Co-location is design-REJECTED, not a packaging gap.
#
# This is a HARD STOP, not a confirmation prompt: VENYA_SKIP_PROMPT=yes must NOT
# bypass it (it enforces a design boundary, not an "are you sure"). Detection is
# SYSTEM-WIDE (systemd units / config files) and NEVER keyed on $INSTALL_DIR, so
# a custom VENYA_INSTALL_DIR cannot sneak past (that knob is broken for custom
# paths anyway -- never recommend it here). Same-component re-runs are allowed:
# only the OTHER component triggers refusal, preserving installer idempotency
# (installer-rerun-no-service-restart behavior unchanged).
#
# Args: $1 = component being installed ("core" or "executor")
venya_check_no_colocation() {
    local this_component="${1:-}"
    local core_present=0 executor_present=0

    if [ -f /etc/systemd/system/venya-core.service ] \
        || systemctl cat venya-core.service >/dev/null 2>&1; then
        core_present=1
    fi
    if [ -f /etc/systemd/system/venya-executor.service ] \
        || [ -f /etc/venya/executor.toml ]; then
        executor_present=1
    fi

    local other=""
    if [ "$this_component" = "executor" ] && [ "$core_present" -eq 1 ]; then
        other="core"
    elif [ "$this_component" = "core" ] && [ "$executor_present" -eq 1 ]; then
        other="executor"
    else
        # No cross-component collision (includes the same-component re-run path).
        return 0
    fi

    error "REFUSING TO INSTALL: detected a venya ${other} installation on this host."
    cat >&2 <<EOF

  Venya core and executor must run on SEPARATE hosts; co-location is not supported.

  Why: the core is the trust anchor (CA keys, encrypted secret store, audit DB) and
  must run on its own protected host. Executors are treated as COMPROMISED by design.
  Both run as the same 'venya' user and share /etc/venya and /opt/venya, so on one
  box an executor compromise equals a core compromise -- and installing the
  ${this_component} here would wipe the live ${other} venv and kill it (systemd 203/EXEC).

  What to do: install the ${this_component} on its OWN machine. On a single physical
  host, run separate VMs -- one for core, one for the executor. A single-node
  co-located mode is not offered.

EOF
    exit 1
}

# --- 5. Create venya user ---

venya_create_user() {
    if ! id venya &>/dev/null; then
        # Service account — no interactive login, no password set anywhere (nothing to
        # leak: M-57 gone by construction). nologin shell + locked account block
        # ssh/console/PAM login. Root operates it via `sudo -u venya <cmd>` and the
        # services run as User=venya with an absolute ExecStart — neither needs a usable
        # password or a login shell.
        useradd -m -s /usr/sbin/nologin venya
        usermod -L venya
        info "Created venya user (service account: nologin + locked)"
    fi
}

# --- 6. Install system packages ---

# apt-get wrapper: waits for the dpkg/apt lock via apt's NATIVE timeout (no
# fuser/psmic bootstrap dependency — fuser is not guaranteed present at the
# first apt call on a fresh cloud image) and surfaces the output tail on failure
# instead of dying silently under `set -e`. Without this, an apt-daily /
# unattended-upgrades lock race makes apt-get exit 100 pre-transaction with zero
# diagnostics (ticket installer-apt-lock-silent-fail). On failure the log is kept
# and its path printed. Override the wait with VENYA_APT_LOCK_TIMEOUT (seconds).
venya_apt() {
    local log rc=0
    log=$(mktemp /tmp/venya-apt-XXXXXX.log)
    apt-get -o DPkg::Lock::Timeout="${VENYA_APT_LOCK_TIMEOUT:-120}" "$@" > "$log" 2>&1 || rc=$?
    if [ "$rc" -ne 0 ]; then
        error "apt-get $* failed (exit $rc). Last 25 lines:"
        tail -25 "$log" >&2
        error "Full apt log: $log"
        return "$rc"
    fi
    rm -f "$log"
}

venya_install_system_pkgs() {
    # Args: space-separated package names
    if [ $# -eq 0 ]; then
        return
    fi
    info "Installing system packages..."
    venya_apt update -qq
    venya_apt install -y -qq "$@"
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

# --- 9. Install uv for venya user ---

venya_install_uv_user() {
    SU_UV_BIN="/home/venya/.local/bin/uv"
    if [ ! -f "$SU_UV_BIN" ]; then
        info "Installing uv for venya user..."
        # sudo -H ensures HOME is set from passwd db (/home/venya), not preserved
        # from the invoking user (bot). Without -H, sudo may keep HOME=/home/bot.
        sudo -H -u venya bash -c "curl -LsSf https://astral.sh/uv/install.sh | sh" > /dev/null 2>&1
    fi
}

# --- 9.5. Install Python 3.14 for venya user ---

venya_install_python314() {
    SU_UV_BIN="/home/venya/.local/bin/uv"
    if [ ! -f "$SU_UV_BIN" ]; then
        error "uv binary not found at $SU_UV_BIN"
        exit 1
    fi

    # #358: the entry umask 077 makes a root mkdir -p create the parent chain
    # 0700 root:root, and the venya uv run below cannot traverse it (physically
    # proven 2026-10-02: fresh core install aborted at Python-3.14, os error 13
    # on /opt/venya/.local/share/uv/python). Explicit pins: 0750 root:venya on
    # traverse-only parents (no runtime reader of /opt/venya besides venya —
    # the shipped nginx config has no location under it; server + venv steps
    # run as venya = group), 0770 venya:venya on the managed-python leaf.
    install -d -m 0750 -g venya "$INSTALL_DIR" "$INSTALL_DIR/.local" "$INSTALL_DIR/.local/share" "$INSTALL_DIR/.local/share/uv"
    install -d -m 0770 -o venya -g venya "$INSTALL_DIR/.local/share/uv/python"

    # CRITICAL: Must run as venya (sudo -H -u venya) so uv resolves its config
    # path from getpwuid(getuid()) → /home/venya, not /home/bot (the SSH login
    # user who invoked curl | sudo bash).
    #
    # cd /tmp avoids uv's current-directory config file discovery: uv checks
    # for uv.toml in the CWD first. If CWD is /home/bot (SSH user's home),
    # uv tries to stat /home/bot/uv.toml and gets Permission denied because
    # the venya user can't traverse /home/bot/ (750 bot:bot).
    #
    # UV_PYTHON_INSTALL_DIR tells uv where to find the managed Python 3.14
    # installation. UV_NO_PROGRESS + < /dev/null prevent the progress-display
    # hang in non-interactive (piped) contexts.
    sudo -H -u venya env \
        HOME=/home/venya \
        UV_NO_PROGRESS=1 \
        UV_PYTHON_INSTALL_DIR="$INSTALL_DIR/.local/share/uv/python" \
        bash -c 'cd /tmp && exec "$0" python install 3.14' "$SU_UV_BIN" < /dev/null

    chown -R venya:venya "$INSTALL_DIR/.local/share/uv/python"
    info "Python 3.14 ensured for venya user"
}

# --- 10. Download tarball ---

venya_download_tarball() {
    # Args: $1 = tarball_type (core|executor)
    local tarball_type="${1:-core}"
    if [ -z "$TARBALL_URL" ]; then
        if [ -f "/tmp/venya-${tarball_type}-install.tar.gz" ]; then
            TARBALL_URL="file:///tmp/venya-${tarball_type}-install.tar.gz"
        elif [ -f "/opt/venya-${tarball_type}-install.tar.gz" ]; then
            TARBALL_URL="file:///opt/venya-${tarball_type}-install.tar.gz"
        else
            error "No tarball found. Set VENYA_TARBALL to a URL, or place venya-${tarball_type}-install.tar.gz in /tmp/ AND set VENYA_TARBALL_SHA256 (#327)."
            exit 1
        fi
    fi

    if [[ "$TARBALL_URL" == file://* && -L "${TARBALL_URL#file://}" ]]; then
        error "Tarball source is a symlink: ${TARBALL_URL#file://} — refusing to follow it (#327)."
        exit 1
    fi
    if [[ "$TARBALL_URL" != https://* && -z "${VENYA_TARBALL_SHA256:-}" ]]; then
        error "Tarball origin '$TARBALL_URL' is not https and VENYA_TARBALL_SHA256 is not set: the .sha256 sidecar would come from the SAME (unauthenticated or attacker-writable) origin — self-attesting, not integrity (#375, #327)."
        error "Pass VENYA_TARBALL_SHA256=<sha256> — the serve script prints it — or use an https:// source. Aborting before any fetch or write."
        exit 1
    fi

    info "Downloading tarball from $TARBALL_URL..."
    TARBALL_FILE=$(mktemp /tmp/venya-install-XXXXXX.tar.gz)

    if [[ "$TARBALL_URL" == file://* ]]; then
        cp "${TARBALL_URL#file://}" "$TARBALL_FILE"
    else
        curl -fsSL "$TARBALL_URL" -o "$TARBALL_FILE"
    fi

    # Integrity verification — always runs, fail-closed (user ruling 2026-09-16).
    # Threat model:
    #   - VENYA_TARBALL_SHA256 set (operator-pinned hash): full integrity AND
    #     authenticity — the pin breaks the origin trust chain. This is the
    #     real security mechanism; prefer it in any security-sensitive deploy.
    #   - Unset: the expected hash is fetched from "${TARBALL_URL}.sha256" on
    #     the SAME origin as the tarball. That is a corruption/wrong-version
    #     guardrail, NOT a security boundary — whoever controls the origin
    #     controls both files. (A piped install already grants the origin code
    #     execution, so a same-origin hash adds no attacker protection.)
    #   - Non-https origins (file://, plain http://, anything whose scheme is
    #     not https): the sidecar would be read from the SAME unauthenticated
    #     (possibly attacker-writable) origin — self-attesting. An
    #     operator-supplied VENYA_TARBALL_SHA256 pin is REQUIRED on every
    #     non-https source (#375, extending #327's file:// rule to http);
    #     guarded above, BEFORE any fetch or write, with no sidecar fallback.
    # Sidecar fetch failure or empty sidecar aborts — never install unverified.
    EXPECTED_SHA256="${VENYA_TARBALL_SHA256:-}"
    if [ -z "$EXPECTED_SHA256" ]; then
        info "VENYA_TARBALL_SHA256 not set — fetching checksum sidecar from origin..."
        SIDECAR_FILE=$(mktemp /tmp/venya-sidecar-XXXXXX.sha256)
        if ! curl -fsSL "${TARBALL_URL}.sha256" -o "$SIDECAR_FILE"; then
            error "Cannot fetch checksum sidecar: ${TARBALL_URL}.sha256"
            error "Aborting — refusing to install without integrity verification."
            error "(Set VENYA_TARBALL_SHA256 explicitly to pin the expected hash.)"
            rm -f "$SIDECAR_FILE" "$TARBALL_FILE"
            exit 1
        fi
        EXPECTED_SHA256=$(awk 'NR==1 {print $1}' "$SIDECAR_FILE")
        rm -f "$SIDECAR_FILE"
        if [ -z "$EXPECTED_SHA256" ]; then
            error "Sidecar ${TARBALL_URL}.sha256 contained no hash. Aborting."
            rm -f "$TARBALL_FILE"
            exit 1
        fi
    fi

    info "Verifying tarball SHA-256..."
    # Portable: sha256sum (Linux/coreutils) or shasum (macOS/BSD).
    if command -v sha256sum > /dev/null 2>&1; then
        ACTUAL_SHA256=$(sha256sum "$TARBALL_FILE" | awk '{print $1}')
    else
        ACTUAL_SHA256=$(shasum -a 256 "$TARBALL_FILE" | awk '{print $1}')
    fi
    if [ "$ACTUAL_SHA256" != "$EXPECTED_SHA256" ]; then
        error "Tarball SHA-256 mismatch!"
        error "  Expected: $EXPECTED_SHA256"
        error "  Actual:   $ACTUAL_SHA256"
        error "Possible MITM or corrupted download. Aborting."
        rm -f "$TARBALL_FILE"
        exit 1
    fi
    info "SHA-256 verified."
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

    # Build PATH for the venya user: uv bin + cargo bin + system paths + extras
    local venv_path="/home/venya/.local/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
    if [ -n "$extra_paths" ]; then
        venv_path="$venv_path:$extra_paths"
    fi

    info "Creating Python virtual environment at $INSTALL_DIR/.venv..."

    # CRITICAL: Must run as venya (sudo -H -u venya) so uv resolves its config
    # path from getpwuid(getuid()) → /home/venya, not /home/bot (the SSH login
    # user who invoked curl | sudo bash).
    #
    # cd /tmp avoids uv's current-directory config file discovery (see
    # venya_install_python314 for details).
    #
    # --python 3.14 is explicit: uv's discovery order is not guaranteed to
    # prefer the managed Python (UV_PYTHON_INSTALL_DIR) over system Python
    # (3.12 on Ubuntu 24.04). The codebase uses compression.zstd (PEP 784,
    # Python 3.14+), so a wrong Python version would fail at runtime.
    #
    # UV_NO_PROGRESS + < /dev/null prevent the progress-display hang in
    # non-interactive (piped) contexts.
    sudo -H -u venya env \
        HOME=/home/venya \
        PATH="$venv_path" \
        UV_NO_PROGRESS=1 \
        UV_PYTHON_INSTALL_DIR="$INSTALL_DIR/.local/share/uv/python" \
        UV_PYTHON_BIN_DIR=/home/venya/.local/bin \
        UV_VENV_CLEAR=1 \
        bash -c 'cd "$1" && exec "$0" venv --python 3.14 .venv' \
            /home/venya/.local/bin/uv "$INSTALL_DIR" < /dev/null

    if [ -n "$requirements_file" ] && [ -f "$INSTALL_DIR/$requirements_file" ]; then
        info "Installing requirements from $requirements_file..."
        sudo -H -u venya env \
            HOME=/home/venya \
            PATH="$INSTALL_DIR/.venv/bin:$venv_path" \
            UV_NO_PROGRESS=1 \
            UV_NO_CACHE=1 \
            UV_PYTHON_INSTALL_DIR="$INSTALL_DIR/.local/share/uv/python" \
            bash -c 'cd "$1" && exec "$0" pip install --force-reinstall -r "$2"' \
                /home/venya/.local/bin/uv "$INSTALL_DIR" "$requirements_file" < /dev/null
    elif [ -n "$requirements_file" ]; then
        warn "Requirements file $requirements_file not found — skipping dependency install"
    fi

    # Clear stale bytecode to prevent old .py from being used with new .pyc
    info "Clearing bytecode cache..."
    sudo -H -u venya bash -c 'find "$1/.venv" -type d -name "__pycache__" -exec rm -rf {} + 2>/dev/null || true; find "$1/.venv" -name "*.pyc" -delete 2>/dev/null || true' _ "$INSTALL_DIR"

    chown -R venya:venya "$INSTALL_DIR/.venv"
    info "Python venv created at $INSTALL_DIR/.venv"
}

# --- 13. Apply code fixes (sed patches) ---

venya_apply_code_fixes() {
    info "Applying code fixes..."

    # #519 installer-sed-fake-success: `sed` exits 0 whether it replaced
    # 100 lines or zero, so the old unconditional info lines could claim a
    # fix that did nothing. Each fix now verifies a PATCH-SITE post-condition
    # (no file-wide pre-checks — an unrelated occurrence used to mask a
    # needed fix) and reports exactly one outcome:
    #   applied / already clean / FAILED-ANCHOR-MISSING (loud warn, never a
    #   success line). Idempotent: a second run on a patched tree reports
    #   "already clean". set -euo pipefail safe: every count capture ends in
    #   `|| true` because grep exits 1 on zero matches.
    local f n_applied=0 n_clean=0 n_failed=0

    # --- Fix 1: dependencies.py — init_db reads db_config.database_url ---
    f="$INSTALL_DIR/packages/server/src/server/dependencies.py"
    if [ ! -f "$f" ]; then
        warn "  Fix 1 (dependencies.py db_config): FAILED-ANCHOR-MISSING - file absent"
        n_failed=$((n_failed + 1))
    elif grep -qF 'database_url = db_config.database_url or os.environ.get("VENYA_DB_URL")' "$f"; then
        info "  Fix 1 (dependencies.py db_config): already clean"
        n_clean=$((n_clean + 1))
    elif grep -qF 'database_url = os.environ.get("VENYA_DB_URL")' "$f"; then
        sed -i 's|database_url = os.environ.get("VENYA_DB_URL")|database_url = db_config.database_url or os.environ.get("VENYA_DB_URL")|' "$f"
        if ! head -10 "$f" | grep -q "^import os"; then
            sed -i '/from __future__ import annotations/a\\nimport os' "$f"
        fi
        if grep -qF 'database_url = db_config.database_url or os.environ.get("VENYA_DB_URL")' "$f"; then
            info "  Fix 1 (dependencies.py db_config): applied"
            n_applied=$((n_applied + 1))
        else
            warn "  Fix 1 (dependencies.py db_config): FAILED-ANCHOR-MISSING - sed did not land the patch"
            n_failed=$((n_failed + 1))
        fi
    else
        warn "  Fix 1 (dependencies.py db_config): FAILED-ANCHOR-MISSING - anchor absent from installed source (upstream shape changed)"
        n_failed=$((n_failed + 1))
    fi

    # --- Fix 2: init.py relative imports (from ..iam.models -> core) ---
    f="$INSTALL_DIR/packages/server/src/server/routes/init.py"
    if [ ! -f "$f" ]; then
        warn "  Fix 2 (init.py imports): FAILED-ANCHOR-MISSING - file absent"
        n_failed=$((n_failed + 1))
    elif grep -qF 'from ..iam.models' "$f"; then
        sed -i 's/from \.\.iam\.models/from core.iam.models/g' "$f"
        if grep -qF 'from ..iam.models' "$f"; then
            warn "  Fix 2 (init.py imports): FAILED-ANCHOR-MISSING - relative import survived the sed"
            n_failed=$((n_failed + 1))
        else
            info "  Fix 2 (init.py imports): applied"
            n_applied=$((n_applied + 1))
        fi
    elif grep -qF 'from core.iam.models' "$f"; then
        info "  Fix 2 (init.py imports): already clean"
        n_clean=$((n_clean + 1))
    else
        warn "  Fix 2 (init.py imports): FAILED-ANCHOR-MISSING - neither import form present (upstream shape changed)"
        n_failed=$((n_failed + 1))
    fi

    # --- Fix 3: init.py — db.flush() immediately after db.add(admin_role) ---
    # Patch-site-specific anchor (#519 criterion 2): the old file-wide
    # 'db.flush()' grep let any unrelated occurrence mask a missing site
    # flush. Every db.add(admin_role) line must now be followed by the flush.
    if [ ! -f "$f" ]; then
        warn "  Fix 3 (init.py admin_role flush): FAILED-ANCHOR-MISSING - file absent"
        n_failed=$((n_failed + 1))
    else
        local n_anchor n_paired
        n_anchor=$(grep -cF 'db.add(admin_role)' "$f" || true)
        n_paired=$(grep -A1 -F 'db.add(admin_role)' "$f" | grep -cE '^[[:space:]]*db\.flush\(\)[[:space:]]*$' || true)
        if [ "${n_anchor:-0}" -eq 0 ]; then
            warn "  Fix 3 (init.py admin_role flush): FAILED-ANCHOR-MISSING - db.add(admin_role) anchor absent (upstream shape changed)"
            n_failed=$((n_failed + 1))
        elif [ "$n_paired" -ge "$n_anchor" ]; then
            info "  Fix 3 (init.py admin_role flush): already clean"
            n_clean=$((n_clean + 1))
        else
            sed -i '/db\.add(admin_role)/a\        db.flush()' "$f"
            n_paired=$(grep -A1 -F 'db.add(admin_role)' "$f" | grep -cE '^[[:space:]]*db\.flush\(\)[[:space:]]*$' || true)
            if [ "$n_paired" -ge "$n_anchor" ]; then
                info "  Fix 3 (init.py admin_role flush): applied"
                n_applied=$((n_applied + 1))
            else
                warn "  Fix 3 (init.py admin_role flush): FAILED-ANCHOR-MISSING - sed did not land the flush"
                n_failed=$((n_failed + 1))
            fi
        fi
    fi

    # --- Fix 4: executors.py — timezone check AT the not_after site ---
    # Patch-site-specific anchor (#519 criterion 2): the old file-wide
    # 'not_after.tzinfo' grep was satisfied by any occurrence, not the guard
    # this patch appends. The check now looks within the anchor's own lines.
    f="$INSTALL_DIR/packages/server/src/server/routes/executors.py"
    if [ ! -f "$f" ]; then
        warn "  Fix 4 (executors.py heartbeat tz guard): FAILED-ANCHOR-MISSING - file absent"
        n_failed=$((n_failed + 1))
    elif ! grep -qF 'not_after = current_cert.not_after' "$f"; then
        warn "  Fix 4 (executors.py heartbeat tz guard): FAILED-ANCHOR-MISSING - not_after anchor absent (upstream shape changed)"
        n_failed=$((n_failed + 1))
    elif grep -A2 -F 'not_after = current_cert.not_after' "$f" | grep -qF 'not_after.tzinfo'; then
        info "  Fix 4 (executors.py heartbeat tz guard): already clean"
        n_clean=$((n_clean + 1))
    else
        sed -i '/not_after = current_cert\.not_after/a\                if not_after.tzinfo is None:\n                    not_after = not_after.replace(tzinfo=timezone.utc)' "$f"
        if grep -A2 -F 'not_after = current_cert.not_after' "$f" | grep -qF 'not_after.tzinfo'; then
            info "  Fix 4 (executors.py heartbeat tz guard): applied"
            n_applied=$((n_applied + 1))
        else
            warn "  Fix 4 (executors.py heartbeat tz guard): FAILED-ANCHOR-MISSING - sed did not land the guard"
            n_failed=$((n_failed + 1))
        fi
    fi

    if [ "$n_failed" -gt 0 ]; then
        warn "Code fixes summary: $n_applied applied, $n_clean already clean, $n_failed anchor-missing failures (see [WARN] lines above)"
    else
        info "Code fixes summary: $n_applied applied, $n_clean already clean, 0 failures"
    fi
}

# --- 14. Create directories ---

venya_create_directories() {
    mkdir -p /var/lib/venya/ca
    mkdir -p /var/lib/venya/executor
    mkdir -p /var/log/venya
    chown -R venya:venya /var/lib/venya
    chown -R venya:venya /var/log/venya
    chown -R venya:venya "$INSTALL_DIR"
    chmod 700 /var/lib/venya/ca
}

# --- 14b. Write egress allowlist ---

# Validate a bare IPv4 address: exactly four dot-separated numeric octets.
# Digits-and-dots input with an out-of-range octet fails here (loud) rather
# than masquerading as an inert hostname entry later.
_venya_valid_ipv4() {
    local ip="$1" o count=0
    local IFS=.
    case "$ip" in
        *.*.*.*) ;;
        *) return 1 ;;
    esac
    for o in $ip; do
        count=$((count + 1))
        case "$o" in
            ''|*[!0-9]*) return 1 ;;
        esac
        [ "${#o}" -le 3 ] || return 1
        [ "$((10#$o))" -le 255 ] || return 1
    done
    [ "$count" -eq 4 ]
}

# Validate one egress allowlist entry: IPv4 CIDR, bare IPv4, or hostname
# (conservative RFC1123 shape: alphanumeric labels, inner hyphens, dots).
venya_validate_egress_entry() {
    local entry="$1" ip prefix
    case "$entry" in
        '')
            return 1
            ;;
        */*)
            ip="${entry%%/*}"
            prefix="${entry#*/}"
            case "$prefix" in
                ''|*[!0-9]*) return 1 ;;
            esac
            [ "${#prefix}" -le 2 ] || return 1
            [ "$((10#$prefix))" -le 32 ] || return 1
            _venya_valid_ipv4 "$ip"
            ;;
        *[!0-9.]*)
            printf '%s' "$entry" | grep -Eq '^([A-Za-z0-9]([A-Za-z0-9-]*[A-Za-z0-9])?)(\.[A-Za-z0-9]([A-Za-z0-9-]*[A-Za-z0-9])?)*$'
            ;;
        *)
            _venya_valid_ipv4 "$entry"
            ;;
    esac
}

venya_write_egress_allowlist() {
    EGRESS_ALLOWLIST="/etc/venya/egress-allowlist.txt"
    # #317 umask 077 guard: parent-script umask is inherited into common
    # helpers; pin the traverse bit the old inherited dir mode provided.
    install -d -m 0755 /etc/venya

    if [ -f "$EGRESS_ALLOWLIST" ]; then
        info "Egress allowlist already exists at $EGRESS_ALLOWLIST — not overwriting"
        return 0
    fi

    # Owner ruling 2026-09-23 (ticket installer-default-egress-allowlist-dev-subnet):
    # (a) teaching-empty default — Venya never guesses the operator's network.
    #     Empty file = fail-closed (all sandbox egress blocked except DNS), and
    #     the file itself teaches the mechanism.
    # (c) VENYA_EGRESS_ALLOW (comma/space-separated IPs, CIDRs, hostnames)
    #     seeds the file explicitly at install time. Invalid input ABORTS the
    #     install loudly BEFORE anything is written — a partially-applied
    #     allowlist looks configured, which is worse than empty.
    local entries=()
    local raw="${VENYA_EGRESS_ALLOW:-}"
    if [ -n "$raw" ]; then
        local normalized tokens=() entry bad=0
        normalized="$(printf '%s' "$raw" | tr ',' ' ')"
        read -r -a tokens <<< "$normalized"
        for entry in "${tokens[@]}"; do
            if venya_validate_egress_entry "$entry"; then
                entries+=("$entry")
            else
                error "VENYA_EGRESS_ALLOW: invalid entry '$entry' — expected IPv4 CIDR (e.g. 203.0.113.0/24), IPv4 address, or hostname"
                bad=1
            fi
        done
        if [ "$bad" -ne 0 ]; then
            error "VENYA_EGRESS_ALLOW contains invalid entries — aborting install; nothing was written to $EGRESS_ALLOWLIST"
            exit 1
        fi
        if [ "${#entries[@]}" -eq 0 ]; then
            error "VENYA_EGRESS_ALLOW is set but empty after parsing — aborting install (set real entries, or unset it for the fail-closed default)"
            exit 1
        fi
    fi

    {
        echo "# Venya Egress Allowlist"
        echo "# One entry per line: IP, CIDR, or hostname"
        echo "# Lines starting with # are comments. Blank lines ignored."
        echo "# Missing or empty file = fail-closed (all egress blocked except DNS)"
        if [ "${#entries[@]}" -eq 0 ]; then
            echo "#"
            echo "# EMPTY BY DESIGN — Venya never guesses your network. Add the ranges"
            echo "# or hosts your sandboxed commands must reach, one per line, e.g.:"
            echo "#   203.0.113.0/24"
            echo "#   198.51.100.7"
            echo "# Read at sandbox creation: edits apply on the next command run."
        else
            echo "#"
            echo "# Seeded from VENYA_EGRESS_ALLOW at install time."
            printf '%s\n' "${entries[@]}"
        fi
    } > "$EGRESS_ALLOWLIST"
    chmod 644 "$EGRESS_ALLOWLIST"

    if [ "${#entries[@]}" -gt 0 ]; then
        info "Egress allowlist written to $EGRESS_ALLOWLIST (${#entries[@]} entries from VENYA_EGRESS_ALLOW)"
        info "Sandbox egress: deny-by-default; listed entries + DNS allowed"
    else
        info "Egress allowlist written to $EGRESS_ALLOWLIST — EMPTY BY DESIGN (fail-closed: all sandbox egress blocked except DNS)"
        info "Venya never guesses your network. To allow traffic: edit $EGRESS_ALLOWLIST"
        info "and add your target ranges/hosts (one per line). No restart needed — the"
        info "file is read at sandbox creation, so edits apply on the next command run."
    fi
}

# --- 14c. Resolve the sandbox DNS resolver (no default — owner ruling D1 option (a)) ---

# Sets DNS_RESOLVER globally. Precedence: VENYA_DNS_RESOLVER env > existing
# /etc/venya/executor.toml value (re-run reuse — the installer's toml write
# OVERWRITES, so dropping the stored value would brick a working executor) >
# fail loudly with discovery guidance. Strict IPv4: a hostname resolver is
# chicken-and-egg (sandbox DNS is what this value serves).
venya_resolve_dns_resolver() {
    DNS_RESOLVER="${VENYA_DNS_RESOLVER:-}"
    DNS_RESOLVER_REUSED=0
    if [ -z "$DNS_RESOLVER" ] && [ -f /etc/venya/executor.toml ]; then
        DNS_RESOLVER="$(sed -n 's/^dns_resolver = "\(.*\)"$/\1/p' /etc/venya/executor.toml | head -1)"
        if [ -n "$DNS_RESOLVER" ]; then
            DNS_RESOLVER_REUSED=1
            info "Reusing dns_resolver from existing /etc/venya/executor.toml"
        fi
    fi
    if [ -z "$DNS_RESOLVER" ]; then
        error "VENYA_DNS_RESOLVER is required — the IP always allowed for sandbox egress (hostname targets resolve only when the hostname itself is in the egress allowlist)."
        error "Find yours with: resolvectl status   (or: grep nameserver /etc/resolv.conf)"
        error "Example: VENYA_DNS_RESOLVER=198.51.100.53"
        exit 1
    fi
    if ! _venya_valid_ipv4 "$DNS_RESOLVER"; then
        error "VENYA_DNS_RESOLVER='$DNS_RESOLVER' is not a valid IPv4 address (hostnames are not accepted — the resolver must be reachable by IP)."
        exit 1
    fi
    # #428 (shape (c), owner ruling 2026-10-04): a carried-forward value is the
    # only one the operator never re-asserted this run — probe it. HARD
    # placement pin: runs ONLY after _venya_valid_ipv4, so nothing but a
    # validated IPv4 ever reaches the bash -c interpolation. The explicit
    # VENYA_DNS_RESOLVER path stays unprobed (operator intent; the documented
    # bypass when this abort fires). timeout 3 caps the probe; TCP/53 needs no
    # internet — same LAN/offline constraint as everything else here.
    if [ "${DNS_RESOLVER_REUSED}" -eq 1 ]; then
        if ! timeout 3 bash -c "exec 3<>/dev/tcp/${DNS_RESOLVER}/53" 2>/dev/null; then
            error "Stored dns_resolver=${DNS_RESOLVER} in /etc/venya/executor.toml is unreachable (TCP/53 probe failed within 3s)."
            error "Fix the stored value, or re-run with an explicit resolver: VENYA_DNS_RESOLVER=<ip> (find yours: resolvectl status; or: grep nameserver /etc/resolv.conf)"
            exit 1
        fi
        info "Stored dns_resolver=${DNS_RESOLVER} reachable (TCP/53 probe OK)"
    fi
}

# --- 14d. Secret prompt with confirm-at-entry (ticket 31-confirm-at-entry) ---

# venya_read_secret_confirm <PROMPT_TEXT> <VAR_NAME>
# Reads a secret twice from the TTY (echo-off) and retries until both
# entries match and are non-empty. A mistyped single entry no longer
# becomes the stored secret — the typo is caught at the keyboard instead
# of at recovery time. TTY-only by contract: callers keep their
# non-TTY error/random branches. The value is assigned via nameref to
# <VAR_NAME> in the caller scope; it is never echoed.
venya_read_secret_confirm() {
    local _venya_prompt="$1"
    local _venya_out="$2"
    # shellcheck disable=SC2155
    local -n _venya_ref="$_venya_out"
    local _venya_first _venya_second
    while :; do
        printf '%s: ' "$_venya_prompt" >&2
        IFS= read -rs _venya_first
        printf '\n' >&2
        printf '%s (confirm): ' "$_venya_prompt" >&2
        IFS= read -rs _venya_second
        printf '\n' >&2
        if [ -z "$_venya_first" ]; then
            warn "Value cannot be empty."
            continue
        fi
        if [ "$_venya_first" != "$_venya_second" ]; then
            warn "Entries did not match — re-enter."
            continue
        fi
        _venya_ref="$_venya_first"
        return 0
    done
}

# --- 15. Service start retry loop ---

venya_service_retry() {
    # Args: $1 = service_name (e.g., venya-core, venya-executor)
    local service_name="${1:-}"
    if [ -z "$service_name" ]; then
        error "venya_service_retry requires service_name argument"
        exit 1
    fi

    # Check current state first — if already running, nothing to do.
    if systemctl is-active --quiet "${service_name}.service" 2>/dev/null; then
        info "${service_name}.service is already running"
        return 0
    fi

    # Try a single start; if that fails, enter retry loop with restarts.
    systemctl start "${service_name}.service" 2>/dev/null || true
    sleep 2

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

# --- 15b. Fresh-bytes service sync (ticket installer-rerun-no-service-restart) ---
# Installer re-runs swap site-packages bytes while the long-lived Python
# process keeps its old in-memory imports (Python never hot-reloads) and
# `systemctl start` is a NO-OP on a running unit — verification then probes
# the STALE process wearing a success stamp. These helpers compare the
# service start time against a deploy stamp written by the installer and
# restart-when-stale with a loud notice naming both timestamps (detection
# PROOF, not a blind restart).

venya_service_sync() {
    # Args: $1 = service name (e.g. venya-core), $2 = deploy-stamp file
    local service_name="${1:-}" stamp="${2:-}"
    if [ -z "$service_name" ] || [ -z "$stamp" ]; then
        error "venya_service_sync requires service_name and stamp arguments"
        exit 1
    fi

    if systemctl is-failed --quiet "${service_name}.service" 2>/dev/null; then
        warn "${service_name}.service is in failed state — resetting before start"
        systemctl reset-failed "${service_name}.service" 2>/dev/null || true
    fi

    if ! systemctl is-active --quiet "${service_name}.service" 2>/dev/null; then
        info "${service_name}.service is not running — starting"
        systemctl start "${service_name}.service"
        return 0
    fi

    local start_raw start_epoch stamp_epoch
    start_raw="$(systemctl show -p ActiveEnterTimestamp --value "${service_name}.service")"
    start_epoch="$(date -d "$start_raw" +%s 2>/dev/null || echo 0)"
    stamp_epoch="$(stat -c %Y "$stamp" 2>/dev/null || echo 0)"
    if [ "$start_epoch" -eq 0 ] || [ "$stamp_epoch" -eq 0 ]; then
        warn "Cannot compare timestamps (start='$start_raw' stamp='$stamp') — restarting to be safe"
        systemctl restart "${service_name}.service"
    elif [ "$start_epoch" -le "$stamp_epoch" ]; then
        warn "NOTICE: running ${service_name} process started ${start_raw} — BEFORE the bytes just deployed ($(date -d "@${stamp_epoch}"))"
        warn "RESTARTING ${service_name}.service to load the new build (re-run swaps packages under the live process; Python does not hot-reload)"
        systemctl restart "${service_name}.service"
    else
        info "${service_name}.service already runs bytes at least as new as this deploy (started ${start_raw}) — no restart needed"
    fi
}

venya_service_freshness() {
    # Args: $1 = service name, $2 = deploy-stamp file
    # Post-start verification proof: the running process must be NEWER than
    # the deployed bytes, so every probe that follows attests the new build
    # (PROCESS RULE: proof-of-new-bytes before mutating probes).
    local service_name="${1:-}" stamp="${2:-}"
    local start_raw start_epoch stamp_epoch
    start_raw="$(systemctl show -p ActiveEnterTimestamp --value "${service_name}.service" 2>/dev/null)"
    start_epoch="$(date -d "$start_raw" +%s 2>/dev/null || echo 0)"
    stamp_epoch="$(stat -c %Y "$stamp" 2>/dev/null || echo 0)"
    if [ "$start_epoch" -gt 0 ] && [ "$start_epoch" -ge "$stamp_epoch" ]; then
        info "PROOF-OF-FRESH-BYTES: ${service_name} started ${start_raw} >= deploy stamp $(date -d "@${stamp_epoch}") — verification probes the NEW process"
    else
        warn "PROOF-OF-FRESH-BYTES FAILED: ${service_name} start '${start_raw}' is not at/after the deploy stamp — do NOT trust verification probes"
    fi
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

# --- 17. Verify deployed code ---

venya_verify_deployment() {
    local tarball_type="${1:-}"
    local python_bin="$INSTALL_DIR/.venv/bin/python3.14"

    info "Verifying deployed code..."

    if [ ! -x "$python_bin" ]; then
        error "Cannot find Python executable at $python_bin"
        exit 1
    fi

    local errors=0

    # Check that core package is deployed (always required)
    if ! sudo -H -u venya "$python_bin" -c "import core" 2>/dev/null; then
        error "core package not importable"
        errors=$((errors + 1))
    fi

    # Check server package if this was a core install
    if [ "$tarball_type" = "core" ]; then
        if ! sudo -H -u venya "$python_bin" -c "import server" 2>/dev/null; then
            error "server package not importable"
            errors=$((errors + 1))
        fi

        # Verify the deployed auth.py matches the source auth.py
        local source_auth="$INSTALL_DIR/packages/server/src/server/middleware/auth.py"
        local deployed_auth
        # `|| true`: an unimportable server package is the drift condition this
        # verifier diagnoses — without it set -e kills the whole verify pass at
        # the assignment (REG_OUTPUT incident class). Empty result → the [ -f ]
        # guard below skips this check; the site-packages checks still run.
        deployed_auth=$(sudo -H -u venya "$python_bin" -c "import server; import os; print(os.path.dirname(server.__file__))" 2>/dev/null || true)/middleware/auth.py
        if [ -f "$source_auth" ] && [ -f "$deployed_auth" ]; then
            if ! diff -q "$source_auth" "$deployed_auth" >/dev/null 2>&1; then
                error "DEPLOYMENT MISMATCH: auth.py in site-packages differs from source"
                error "  Source:  $source_auth"
                error "  Deployed: $deployed_auth"
                errors=$((errors + 1))
            fi
        fi
    fi

    # Check executor package if this was an executor install
    if [ "$tarball_type" = "executor" ]; then
        local site_packages
        # -print -quit, not `| head -1`: head exiting early can SIGPIPE find
        # (141) → pipefail → set -e kills the verify pass at the assignment.
        site_packages=$(find "$INSTALL_DIR/.venv" -type d -name 'site-packages' -print -quit)
        if [ -z "$site_packages" ]; then
            error "Cannot find site-packages directory"
            errors=$((errors + 1))
        elif [ ! -d "$site_packages/executor" ]; then
            error "executor package not found in site-packages"
            errors=$((errors + 1))
        else
            # Assert the Rust extension was built for the correct Python version.
            # A missing cpython-314 tag (or a bare venya_filter.so) means the
            # extension was compiled against the wrong interpreter. (Bug B root cause.)
            local tagged_so bare_so
            tagged_so=$(find "$site_packages" -name 'venya_filter.cpython-314-*.so' -print -quit 2>/dev/null)
            bare_so=$(find "$site_packages" -name 'venya_filter.so' -not -name '*.cpython-*' -print -quit 2>/dev/null)
            if [ -n "$bare_so" ]; then
                error "DEPLOYMENT MISMATCH: bare-named venya_filter.so in site-packages (wrong-interpreter build)"
                error "  File: $bare_so"
                error "  Expected: venya_filter.cpython-314-x86_64-linux-gnu.so"
                errors=$((errors + 1))
            elif [ -z "$tagged_so" ]; then
                error "DEPLOYMENT MISMATCH: venya_filter.cpython-314-*.so not found in site-packages"
                error "  Rust extension was not built for the venv's Python 3.14"
                errors=$((errors + 1))
            fi
        fi
    fi

    if [ "$errors" -gt 0 ]; then
        error "Deployment verification FAILED with $errors error(s)"
        error "The installed code in site-packages does not match the source tarball"
        error "This is a critical failure — do not start services"
        exit 1
    fi

    info "Deployment verified — site-packages matches source tarball"
}
