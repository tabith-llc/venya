#!/usr/bin/env bash

# Copyright (c) 2026 Tabith LLC.
# Use of this source code is governed by the Business Source License 1.1
# included in the LICENSE file at the root of this repository. As of the
# Change Date listed there, the work is available under MPL 2.0.
# SPDX-License-Identifier: BUSL-1.1

set -euo pipefail

# #317: close create-then-chmod windows (executor.toml :435->613, bootstrap-token
# :600->602). Deliberate world-readables carry explicit chmod lines.
umask 077

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
# Re-run behavior: executor.toml and /etc/venya/venya-executor.env are rebuilt from the
# installer's own values, and every setting an operator added to either file is read back
# BEFORE the write, re-appended after it, and named in the output (#738). The installer's
# own keys keep taking the installer's value; a key set inside one of its tables ([mtls],
# [audit]) is the one case that cannot be carried, and the run names it as a drop.
#
# Environment variables:
#   VENYA_INSTALL_DIR   - Install location (default: /opt/venya)
#   VENYA_SKIP_PROMPT   - Set to "yes" to skip the confirmation prompt. It skips
#                         prompts only: an unattended re-run still refuses to
#                         change this executor's identity (#746).
#   VENYA_TARBALL       - Tarball URL (default: latest GitHub release asset —
#                         https://github.com/tabith-llc/venya/releases/latest/download/venya-executor-install.tar.gz)
#   VENYA_TARBALL_SHA256 - Pin the expected sha256 (recommended: strict integrity).
#                         If unset, the installer fetches <tarball-url>.sha256 from the
#                         same origin as a corruption guardrail and fail-closes on error.
#                         REQUIRED (no sidecar fallback) when the tarball source is NOT
#                         https (file:// or plain http://) — #375/#327.
#   VENYA_EXECUTOR_ID              - Executor ID (default: this host's own name, `hostname`;
#                                    fall back to venya-exec-1 only if the name query answers
#                                    nothing). CONTRACT: the ID
#                                    is the relay dial hostname + client-cert SAN — it MUST
#                                    be resolvable from every core (e.g. via /etc/hosts or DNS).
#                                    On a RE-RUN: an unattended run (skip flag, or no terminal)
#                                    that would change the installed ID refuses and writes
#                                    nothing; naming a value here is the consent that change
#                                    needs (#746).
#   VENYA_SERVER_URL               - Core server URL (required)
#   VENYA_DNS_RESOLVER         - Sandbox DNS resolver IP (required, no default — strict
#                                IPv4, validated; re-runs reuse the stored toml value). Find
#                                yours: resolvectl status / grep nameserver /etc/resolv.conf
#   VENYA_CORE_HOSTNAME    - Core hostname for /etc/hosts resolution (default: venya-core-1)
#   VENYA_CORE_IP          - Core IP for /etc/hosts resolution (no default —
#                            required only when the core hostname resolves
#                            neither via /etc/hosts nor DNS; explicit value
#                            always wins over an existing hosts entry; STRICT
#                            IPv4 — a value that is not four dot-separated
#                            numeric octets aborts the install (#490))
#   VENYA_HOSTS_FILE       - The hosts file this installer reads and updates
#                            (default: /etc/hosts). Test/packaging seam for the
#                            #490 core-entry cells; when SET it must name an
#                            EXISTING writable regular file — a mistyped value
#                            aborts the install rather than creating a file no
#                            resolver reads. The entry is matched on the SECOND
#                            whitespace field (the name), and a file with no
#                            trailing newline gains exactly one newline in total
#                            on append — the row is never concatenated.
#   VENYA_VENYA_CA_FILE    - Path to pre-copied Venya CA cert (offline/air-gapped deployments)
#   VENYA_EXECUTOR_ENROLLMENT_TOKEN - Bootstrap enrollment token for auto-registration
#                                    (REQUIRED on a fresh install — no executor
#                                    certificate yet; not needed to re-run over an
#                                    existing certificate)
#   VENYA_DOCKER_USERNAME  - Docker account for sbx agent-template pulls (prompted if TTY)
#   VENYA_DOCKER_API_KEY   - Docker access token — handled stdin-only, never argv/disk
#                            (required unless already authenticated or skipped)
#   VENYA_SKIP_DOCKER_LOGIN - "yes" = degraded install: executor runs, but sandbox
#                            execution fails 503 until `sudo -H -u venya sbx login`
###############################################################################

# --- Defaults ---
TARBALL_URL="${VENYA_TARBALL:-https://github.com/tabith-llc/venya/releases/latest/download/venya-executor-install.tar.gz}"
# The ID is the relay dial hostname and the client-cert SAN, so a default can only be
# a name the rest of the fleet is able to resolve: this host's own name (#745, the same
# idiom install-venya-core.sh uses for CORE_HOSTNAME). The old default 'venya-exec-1'
# was the one value guaranteed to violate the contract on a host carrying no such
# entry, and it was chosen in silence. It stays as the last resort for a host whose
# name query answers nothing at all. An explicit VENYA_EXECUTOR_ID still wins.
EXECUTOR_ID="${VENYA_EXECUTOR_ID:-$(hostname)}"
if [ -z "$EXECUTOR_ID" ]; then
    EXECUTOR_ID="venya-exec-1"
fi

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
    # #360 (installer-common-self-fetch-unhashed): VERIFY before source. The
    # serve-time runner sed-embeds the expected sha256 into the placeholder
    # below; VENYA_COMMON_SHA256 is the operator pin and wins over it. With
    # neither (raw-checkout bytes without embedding), fall back to the origin
    # sidecar; if that is unobtainable too, abort FAIL-CLOSED — an unverified
    # library is never sourced as root (mirrors the #327 tarball guard).
    # #368: the placeholder-as-literal NEVER appears contiguous outside the
    # assignment default — the split-quote idiom below is invisible to the
    # serve-time sed, so only the ${VENYA_COMMON_SHA256:-...} default is
    # substituted and the guard cannot self-null into self-attestation.
    EXPECTED_COMMON_SHA="${VENYA_COMMON_SHA256:-__VENYA_COMMON_SHA256__}"
    if [ "$EXPECTED_COMMON_SHA" = '__VENYA''_COMMON_SHA256__' ]; then
        EXPECTED_COMMON_SHA=""
    fi
    if [ -z "$EXPECTED_COMMON_SHA" ]; then
        echo "No embedded/pinned common-library hash — fetching sidecar ${TARBALL_URL%/*}/venya-common.sh.sha256" >&2
        curl -fsSL "${TARBALL_URL%/*}/venya-common.sh.sha256" -o "$FETCH_DIR/venya-common.sh.sha256" || {
            echo "[ERROR] VENYA_COMMON_SHA256 unset and no hash sidecar at the origin — refusing to source an unverified library." >&2
            exit 1
        }
        EXPECTED_COMMON_SHA="$(awk '{print $1}' "$FETCH_DIR/venya-common.sh.sha256")"
    fi
    ACTUAL_COMMON_SHA="$(sha256sum "$FETCH_DIR/venya-common.sh" | awk '{print $1}')"
    if [ "$ACTUAL_COMMON_SHA" != "$EXPECTED_COMMON_SHA" ]; then
        echo "[ERROR] venya-common.sh SHA-256 MISMATCH — expected $EXPECTED_COMMON_SHA, got $ACTUAL_COMMON_SHA. Refusing to source." >&2
        exit 1
    fi
    echo "venya-common.sh verified (sha256 $ACTUAL_COMMON_SHA)" >&2
    source "$FETCH_DIR/venya-common.sh"
    # #475: sourcing the library installs the temp registry, and the single
    # EXIT trap set after this block REPLACES the FETCH_DIR trap set above
    # (bash holds one EXIT trap per shell). Hand the directory to the list
    # here, so the pre-source trap covers the fetch and the list covers it
    # from here on.
    register_install_temp "$FETCH_DIR"
fi

# --- One EXIT trap for every temp this installer creates (#475) ---
# `set -euo pipefail` ends this script wherever it stands, so temp cleanup
# cannot live only in the inline `rm` calls the success paths reach. There is
# ONE trap, and it drains the list that venya-common.sh defines and the sites
# below fill — per-file traps would replace each other, not add up. The
# inline removals stay (they release the files as soon as they are spent);
# this trap is what makes an abort leave nothing behind.
trap 'cleanup_install_temps' EXIT

venya_print_colors
venya_check_root
venya_check_no_colocation executor
venya_determine_install_dir /opt/venya
venya_check_existing

# --- Require VENYA_SERVER_URL (no default — server hostname is unknown) ---
if [ -z "${VENYA_SERVER_URL:-}" ]; then
    error "VENYA_SERVER_URL is required."
    error "Set it to your core server URL, e.g.: https://venya-core or https://198.51.100.50"
    exit 1
fi
SERVER_URL="$VENYA_SERVER_URL"

# --- Require VENYA_EXECUTOR_ENROLLMENT_TOKEN on a fresh install (ticket #28) ---
# Mirrors the VENYA_SERVER_URL Require block above: fail loudly BEFORE any
# system write (apt/venv/toml) instead of letting an empty token ride through
# to the daemon, where it surfaced minutes later as a boot failure. A re-run
# with an existing executor certificate legitimately needs no token (the
# register section skips itself there), so cert incumbency gates the need.
if [ ! -s /etc/venya/executor/executor.crt ] && [ -z "${VENYA_EXECUTOR_ENROLLMENT_TOKEN:-}" ]; then
    error "VENYA_EXECUTOR_ENROLLMENT_TOKEN is required for a fresh executor install."
    error "Mint one from an admin workstation: venya admin executor-enroll $EXECUTOR_ID"
    error "Tokens are single-use with a ~30-minute TTL — mint immediately before re-running the installer."
    exit 1
fi

# --- Confirm a defaulted executor ID (#745) ---
# Only the DERIVED value is asked about: an operator who named one is never asked
# to approve their own words. The read is TTY-gated because a piped install
# (curl | sudo bash — the shape this script's own library lookup supports) carries
# the remainder of the script on stdin, so an unguarded read would consume
# installer lines. Unattended: print what was chosen and why, and carry on.
if [ -z "${VENYA_EXECUTOR_ID:-}" ]; then
    if [ -t 0 ] && [ "${VENYA_SKIP_PROMPT:-}" != "yes" ]; then
        read -r -p "Executor ID defaults to this host's own name: '$EXECUTOR_ID' (relay dial hostname + client-cert SAN; every core must resolve it). Press Enter to keep it, or type another: " _executor_id_reply
        if [ -n "$_executor_id_reply" ]; then
            EXECUTOR_ID="$_executor_id_reply"
            info "Executor ID for this run: '$EXECUTOR_ID'."
        fi
    else
        info "Unattended install: executor ID defaults to this host's own name '$EXECUTOR_ID' (#745) — set VENYA_EXECUTOR_ID to choose another."
    fi
fi

# --- Fail-closed config-injection gate (ticket #326, F-2) ---
# These values interpolate raw into installer-written config files:
# /etc/venya/executor.toml (TOML basic strings) below. Newline/CR splits a
# value into EXTRA config lines (built-in rejection); a double quote
# terminates the TOML basic string (same-line key breakout); a backslash
# starts an escape or eats the closing quote. Space and '#', '@', '%' are
# TOML-safe INSIDE the quoted values this file writes, so they stay
# accepted (minimal contract — cannot brick a working re-run). DNS_RESOLVER
# needs no call: venya_resolve_dns_resolver strict-IPv4-validates it;
# CA_BUNDLE_PATH is a script constant; the enrollment token is written by
# a single-quoted printf and never interpolated.
venya_guard_injection "SERVER_URL" "$SERVER_URL" '"' '\'
venya_guard_injection "EXECUTOR_ID" "$EXECUTOR_ID" '"' '\'

# --- Re-run identity stop (#746) ---
# The ID below is written into /etc/venya/executor.toml by a whole-file rebuild through a
# truncating redirect, and the script keeps no copy of the previous face. So on a re-run
# over an existing install, the installed ID is the only record of what this executor has
# been dialling as and what its client certificate carries as SAN — and an unattended run
# that quietly replaced it left the operator with a sentence that reads like a status line
# and nothing to compare against. This run therefore refuses to CHANGE the identity when
# nobody is there to see it: both values are named and nothing is written.
#
# A HARD STOP, not a confirmation prompt — the posture this installer already states for a
# design boundary: venya-common.sh's co-location guard says it in its own words, "This is a
# HARD STOP, not a confirmation prompt: VENYA_SKIP_PROMPT=yes must NOT bypass it". The skip
# flag answers prompts; it does not authorise an identity change.
# What is deliberately NOT changed here: (1) an operator who NAMED a VENYA_EXECUTOR_ID is
# never refused — naming one is the consent; (2) an interactive run keeps its #745
# confirmation and is warned, not stopped; (3) a missing or unreadable installed ID is not
# a refusal — the rebuild that follows is the installer's ordinary job.
if [ -z "${VENYA_EXECUTOR_ID:-}" ] && [ -f /etc/venya/executor.toml ]; then
    INSTALLED_EXECUTOR_ID="$(sed -n 's/^executor_id = "\(.*\)"$/\1/p' /etc/venya/executor.toml | head -1)"
    if [ -n "$INSTALLED_EXECUTOR_ID" ] && [ "$INSTALLED_EXECUTOR_ID" != "$EXECUTOR_ID" ]; then
        if [ "${VENYA_SKIP_PROMPT:-}" = "yes" ] || [ ! -t 0 ]; then
            error "Re-run would change this executor's identity unattended — writing nothing."
            error "  installed: executor_id = '$INSTALLED_EXECUTOR_ID' (/etc/venya/executor.toml)"
            error "  this run:  executor_id = '$EXECUTOR_ID' (this host's name; VENYA_EXECUTOR_ID unset)"
            error "The ID is the relay dial hostname and the client-cert SAN, and the config file is"
            error "rebuilt in place with no copy of the previous face kept, so the installed value"
            error "cannot be read back off this host after this run."
            error "To continue deliberately, name one:"
            error "  VENYA_EXECUTOR_ID='$INSTALLED_EXECUTOR_ID'  keeps the identity this executor already has"
            error "  VENYA_EXECUTOR_ID='$EXECUTOR_ID'  makes the change by name"
            exit 1
        fi
        warn "Re-run changes this executor's identity: '$INSTALLED_EXECUTOR_ID' -> '$EXECUTOR_ID'."
        warn "CONTRACT: the ID is the relay dial hostname + client-cert SAN — every core must resolve"
        warn "the new one, and the old certificate's SAN no longer names this executor."
    fi
fi

# --- Executor-id dial contract: checked while the install is still cheap (#745) ---
# This block used to sit at the foot of the script, after the toolchain install,
# the venv, and the Rust release build. The contract it states has not changed and
# neither has its NON-FATAL ruling — local getent is a weak proxy, authoritative
# resolvability is core-side, an Ubuntu '127.0.1.1 <hostname>' entry makes an ID
# equal to the own-hostname pass trivially here, and a core-side-only /etc/hosts
# entry is a valid strategy, so aborting on the proxy would false-positive a
# working install. What changed is WHEN the look happens: the operator learns it
# before paying for a build, and a re-install whose name stopped resolving is
# caught here rather than at registration.
if getent hosts "$EXECUTOR_ID" > /dev/null 2>&1; then
    info "Executor ID '$EXECUTOR_ID' resolves locally."
    info "CONTRACT: every CORE must also resolve '$EXECUTOR_ID' (relay dial hostname + cert SAN) —"
    info "local resolution does not prove core-side resolution (127.0.1.1 own-hostname trap)."
else
    warn "Executor ID '$EXECUTOR_ID' does NOT resolve locally."
    warn "CONTRACT: the ID is the relay dial hostname + client-cert SAN — it must resolve FROM EVERY CORE,"
    warn "or the core rejects registration (400) and relay calls cannot dial this executor."
    warn "A rejected attempt does NOT burn the enrollment token — retry is free."
    warn "Remedy — on EACH core host: add one '<executor-ip> $EXECUTOR_ID' line to /etc/hosts — address first, the name as the SECOND field (the shape this installer writes and matches; #490) — or add a DNS record"
fi

venya_resolve_dns_resolver

info "Installing Venya Executor to $INSTALL_DIR"

# --- Create venya service account (no password, nologin, locked) ---
venya_create_user

# --- Install system packages ---
venya_install_system_pkgs curl sudo build-essential sshpass

# --- Install Rust for venya user ---
SU_CARGO="/home/venya/.cargo/bin/cargo"
if [ ! -f "$SU_CARGO" ]; then
    info "Installing Rust for venya user..."
    sudo -H -u venya bash -c "curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y" > /dev/null 2>&1
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
# -print -quit, not `| head -1`: under set -o pipefail, head exiting early can
# SIGPIPE find (141) and kill the script silently at the assignment.
SITE_PACKAGES=$(find "$INSTALL_DIR/.venv" -type d -name 'site-packages' -print -quit)
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
# `|| true` inside the substitutions: grep-no-match (no readelf, no Build ID)
# would fail the pipeline → set -e kills the script AT the assignment, making
# the mismatch error below unreachable (REG_OUTPUT incident class).
SRC_BUILD_ID=$(readelf -n "$INSTALL_DIR/packages/executor/target/release/libvenya_filter.so" 2>/dev/null | grep "Build ID" | awk '{print $3}' || true)
DEST_BUILD_ID=$(readelf -n "$DEST" 2>/dev/null | grep "Build ID" | awk '{print $3}' || true)
if [ "$SRC_BUILD_ID" != "$DEST_BUILD_ID" ]; then
    error "Build-id mismatch: source=$SRC_BUILD_ID dest=$DEST_BUILD_ID"
    exit 1
fi

# Post-install assertion: import resolves to the tagged path
# `|| true`: a FAILING import is exactly what this check reports — without it,
# set -e kills the script at the assignment and the diagnostic below never runs.
IMPORT_CHECK=$("$VENV_PYTHON" -c "import venya_filter; print(venya_filter.__file__)" 2>&1 || true)
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
# written (see "Harden executor credentials", right after registration and before the
# Docker gate — #370). Hardening them here was
# a no-op — the dir/files do not exist yet at this point.
chmod 750 /var/log/venya
chown venya:adm /var/log/venya 2>/dev/null || chown venya:venya /var/log/venya

# --- Install Docker Sandboxes (sbx) CLI (executor-specific) ---
info "Installing Docker Sandboxes (sbx) CLI..."
if ! command -v sbx &>/dev/null; then
    # #475: both files sit between creation and the rm below, and a curl or
    # repo-setup failure used to leave them behind — registered here, and the
    # inline removals stay as the prompt-release path.
    SBX_SCRIPT=$(mktemp /tmp/docker-sbx-install-XXXXXX.sh)
    register_install_temp "$SBX_SCRIPT"
    SBX_LOG=$(mktemp /tmp/venya-sbx-repo-XXXXXX.log)   # #317: static name = root symlink-clobber
    register_install_temp "$SBX_LOG"
    curl -fsSL https://get.docker.com -o "$SBX_SCRIPT"
    if ! REPO_ONLY=1 sh "$SBX_SCRIPT" > "$SBX_LOG" 2>&1; then
        error "Docker sbx apt-repo setup failed; last 25 lines:"
        tail -25 "$SBX_LOG" >&2
        rm -f "$SBX_SCRIPT" "$SBX_LOG"
        exit 1
    fi
    rm -f "$SBX_SCRIPT" "$SBX_LOG"
    # refs ticket apt-repo-file-mode-unreadable-sbx-upgrade (#434): apt's _apt
    # downloader cannot read a 600 sources file, and the get.docker.com helper
    # leaves the mode to the invoking umask (entry umask 077) — deliberate
    # world-readables carry an explicit chmod line (#317 convention).
    chmod 644 /etc/apt/sources.list.d/docker.list
    venya_apt install -y -qq docker-sbx
    info "sbx CLI installed. kvm group is re-asserted on every install (see #384 block below)."
else
    # refs ticket sbx-exec-env-file-noop (fix B'): DETECT AND TELL ONLY.
    # An old sbx makes `sbx exec --env-file` a silent no-op, so the executor
    # would refuse to start; the admin upgrades the vendor package on their
    # own policy. This path NEVER runs apt — Venya does not manage vendor
    # packages on customer machines.
    SBX_MIN_VERSION="0.39.0"
    # `|| true` inside the substitution: grep-no-match would fail the
    # pipeline at the assignment under set -o pipefail (same guard class as
    # the build-id block above).
    SBX_FOUND=$(sbx version 2>/dev/null | grep -oE "v?[0-9]+\.[0-9]+\.[0-9]+" | head -n1 || true)
    if [ -z "$SBX_FOUND" ]; then
        error "sbx found on PATH but 'sbx version' gave no version — repair the vendor package yourself, then re-run this installer. Venya does not manage vendor packages."
        exit 1
    fi
    SBX_FOUND="${SBX_FOUND#v}"
    if [ "$(printf '%s\n%s\n' "$SBX_MIN_VERSION" "$SBX_FOUND" | sort -V | head -n1)" = "$SBX_MIN_VERSION" ]; then
        info "sbx CLI $SBX_FOUND meets the requirement (>= $SBX_MIN_VERSION) — no change made."
    else
        error "Docker Sandboxes CLI $SBX_FOUND is older than the required $SBX_MIN_VERSION. Older versions silently ignore the secret-injection file Venya depends on, so the executor would refuse to start. Venya will not upgrade your Docker installation — versions of vendor packages on your machines are yours to choose. Upgrade the docker-sbx package yourself (for example: sudo apt-get install docker-sbx), then re-run this installer."
        exit 1
    fi
fi

# Ensure sbx state directory exists with correct ownership (runs every install;
# sbx daemon fails as venya if root-owned from a prior degraded install)
# #358: same pin class as the uv tree — under the entry umask 077 a root
# mkdir -p here left .local/share 0700 root:root, blocking the venya sbx
# daemon traversal; parents pinned 0750 root:venya, leaf 0770 venya:venya.
install -d -m 0750 -g venya /home/venya/.local /home/venya/.local/share
install -d -m 0770 -o venya -g venya /home/venya/.local/share/sandboxes

# --- Resolve Core Hostname ---
# CORE_HOSTNAME is the relay CN-derivation base: the core signs its
# relay-client cert with CN="${CORE_HOSTNAME}-relay". Formula: explicit
# VENYA_CORE_HOSTNAME wins; otherwise the host component of VENYA_SERVER_URL
# (scheme/port/path stripped) — so the value tracks the URL the operator
# actually used instead of a hardcoded default that can silently diverge
# (a diverged CN surfaces as relay 403 with nothing in the install output).
CORE_HOSTNAME="${VENYA_CORE_HOSTNAME:-$(printf '%s' "$SERVER_URL" | sed -E 's#^[a-zA-Z][a-zA-Z0-9+.-]*://##; s#/.*$##; s#:.*$##')}"

# #326 F-2: gate the composed CORE_HOSTNAME — explicit VENYA_CORE_HOSTNAME
# bypasses the SERVER_URL entry guard, and the URL-derived path can carry a
# newline when it appears AFTER the first '/'. Quote/backslash/space match
# the core installer's identical CORE_HOSTNAME contract (this value seeds
# the relay CN + a /etc/hosts entry).
venya_guard_injection "CORE_HOSTNAME" "$CORE_HOSTNAME" '"' '\' ' '

# Ensure the core hostname is resolvable in the hosts file (skip IP hosts: an IP
# needs no resolution, and writing an IP "name" would misroute).
# VENYA_HOSTS_FILE (#490, test seam) names the file; the default is /etc/hosts.
HOSTS_FILE="${VENYA_HOSTS_FILE:-/etc/hosts}"
# Resolution precedence (fail-closed — no hardcoded default IP; guessing one
# silently misroutes TLS to the wrong core, see ticket
# executor-installer-core-ip-misroute):
#   1. Explicit VENYA_CORE_IP wins: add/update the hosts entry to it. An
#      explicit value must be a bare IPv4 — #490 refuses anything else here,
#      before any read or write, rather than interpolating it into the file.
#   2. No explicit IP + existing hosts entry: KEEP the provisioned entry
#      (provisioning owns /etc/hosts; the old code overwrote a correct entry
#      with a hardcoded default — the 2026-09-15 exec-3 clobber variant).
#   3. No explicit IP + no entry: accept DNS resolution if it works.
#   4. Nothing resolves: abort with an actionable error (set VENYA_CORE_IP).
# Entry matching is FIELD-BASED (#490): the hosts file has no syntax a hostname
# can escape, so field 2 (the primary name) is compared as data, never as a
# pattern. The old `grep " ${CORE_HOSTNAME}$"` / `sed -i "..."` pair read and
# deleted through a regex built from an operator-supplied name — a `/` or a
# sed delimiter in the value aborted the install, and a `.` or `*` matched
# unrelated rows.
if [[ "$CORE_HOSTNAME" =~ ^[0-9]+(\.[0-9]+){3}$ ]]; then
    info "VENYA_SERVER_URL host is an IP — no ${HOSTS_FILE} entry needed"
else
    # #490 addendum: an EXPLICITLY supplied VENYA_HOSTS_FILE must name an
    # existing, writable regular file. Without this the seam recreates the
    # silent-wrong-target class the ticket just closed: a mistyped path plus a
    # VALID VENYA_CORE_IP would create that file, append the row to it, and
    # continue as a successful install — the mapping lands in a file no resolver
    # reads, and the real failure surfaces much later as a relay dial error. No
    # create-if-missing path is offered: that would make the typo permanent. The
    # guard is conditional on the variable being set, so the /etc/hosts default
    # (present on every real host) is untouched. Ordered BEFORE the validator
    # gate and before any read or write.
    if [ -n "${VENYA_HOSTS_FILE:-}" ] && { [ ! -f "$HOSTS_FILE" ] || [ ! -w "$HOSTS_FILE" ]; }; then
        error "VENYA_HOSTS_FILE is set to '$HOSTS_FILE', which is not an existing, writable regular file."
        error "Point VENYA_HOSTS_FILE at the real hosts file (the default is /etc/hosts), or unset it. Nothing was written."
        exit 1
    fi
    # #490: the validator is the whole gate. A string that passes strict IPv4
    # validation carries no space, newline, ';' or metacharacter, so
    # _venya_valid_ipv4 subsumes venya_guard_injection here (R3) — and an
    # operator who SUPPLIES a bad value is refused, not coerced (R5).
    if [ -n "${VENYA_CORE_IP:-}" ] && ! _venya_valid_ipv4 "$VENYA_CORE_IP"; then
        error "VENYA_CORE_IP is not a bare IPv4 address (four dot-separated numeric octets, each 0-255): the supplied value carries characters a hosts entry cannot hold."
        error "Fix it to the core's address (example: VENYA_CORE_IP=203.0.113.10), or unset it to use the provisioned ${HOSTS_FILE} entry or DNS. Nothing was written."
        exit 1
    fi
    # Field-2 equality, first match only; `exit` stops awk, no pipe to close, so no
    # SIGPIPE→141→pipefail silent death in the duplicate-entry case handled. A line
    # whose first token starts with '#' is a hosts(5) comment, never a mapping, so a
    # comment naming the hostname is not read as an entry and not deleted by the
    # rewrite below (R2 byte-preservation).
    EXISTING_IP=$(awk -v host="$CORE_HOSTNAME" 'substr($1, 1, 1) != "#" && $2 == host { print $1; exit }' "$HOSTS_FILE" 2>/dev/null || true)
    if [ -n "${VENYA_CORE_IP:-}" ]; then
        if [ -n "$EXISTING_IP" ] && [ "$EXISTING_IP" != "$VENYA_CORE_IP" ]; then
            warn "Found ${CORE_HOSTNAME} in ${HOSTS_FILE} with IP ${EXISTING_IP}; explicit VENYA_CORE_IP=${VENYA_CORE_IP} wins. Updating."
            # Line-level deletion of exact field-2 matches. Every other line —
            # comments, aliases, the localhost row — is printed verbatim ($0 is
            # not rebuilt, so its spacing is preserved), and the rewrite goes back
            # through the target with `cat >` so its owner and mode survive. The
            # comment test is the KEEP half here: a comment is kept by definition,
            # only a non-comment line whose field 2 is the name is dropped.
            HOSTS_TMP=$(mktemp)
            register_install_temp "$HOSTS_TMP"   # #475: backstop if the rewrite aborts
            awk -v host="$CORE_HOSTNAME" 'substr($1, 1, 1) == "#" || $2 != host' "$HOSTS_FILE" > "$HOSTS_TMP" 2>/dev/null
            cat "$HOSTS_TMP" > "$HOSTS_FILE"
            rm -f "$HOSTS_TMP"
            printf '%s\n' "${VENYA_CORE_IP} ${CORE_HOSTNAME}" >> "$HOSTS_FILE"
        elif [ -z "$EXISTING_IP" ]; then
            info "Adding ${CORE_HOSTNAME} (${VENYA_CORE_IP}) to ${HOSTS_FILE}"
            # The new row always starts on its own line: a hosts file whose last
            # byte is not a newline is given the ONE newline it is missing first,
            # so an append can never concatenate onto the incumbent row.
            if [ -s "$HOSTS_FILE" ] && [ -n "$(tail -c 1 "$HOSTS_FILE")" ]; then
                printf '\n' >> "$HOSTS_FILE"
            fi
            # `printf '%s\n'` so the write is a copy of the validated value, with
            # no escape interpretation between validation and the file (R5).
            printf '%s\n' "${VENYA_CORE_IP} ${CORE_HOSTNAME}" >> "$HOSTS_FILE"
        else
            info "${HOSTS_FILE} entry for ${CORE_HOSTNAME} matches VENYA_CORE_IP (${VENYA_CORE_IP})"
        fi
    elif [ -n "$EXISTING_IP" ]; then
        info "Using provisioned ${HOSTS_FILE} entry: ${CORE_HOSTNAME} -> ${EXISTING_IP} (set VENYA_CORE_IP to override)"
    elif RESOLVED_IP=$(getent hosts "$CORE_HOSTNAME" 2>/dev/null | awk '{print $1}' | head -1) && [ -n "$RESOLVED_IP" ]; then
        info "Resolved ${CORE_HOSTNAME} -> ${RESOLVED_IP} via name service (no ${HOSTS_FILE} entry needed)"
    else
        error "Cannot resolve ${CORE_HOSTNAME}: no ${HOSTS_FILE} entry, no DNS resolution, and VENYA_CORE_IP not set."
        error "Set VENYA_CORE_IP=<core-ip> (a bare IPv4; or fix provisioning). Refusing to guess a default IP — a wrong guess silently misroutes mTLS/CA fetches to another host."
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

# --- Executor key passphrase (VENYA_EXECUTOR_KEY_PASSPHRASE) --- #565
# The executor now writes its own mTLS leaf key encrypted at rest
# (packages/executor/src/executor/key_passphrase.py, plus the CLI's aligned copy), and
# the daemon that reads it is unattended, so the passphrase must exist BEFORE
# registration runs. Acquisition and re-run idempotency mirror install-venya-core.sh's
# CA-key pattern: explicit env (operator override; a WRONG value fails loudly
# downstream at decrypt) > stored in the EnvironmentFile (a re-run PRESERVES the
# encrypted executor.key, so regenerating the passphrase would make it undecryptable) >
# TTY prompt > strong random. Generated before the EnvironmentFile write and before
# every consumer below.
#
# INTERIM SHAPE, ruled 2026-10-10 (R7-Q3, decisions.md commit 1bf25ae): a file
# passphrase is DISK PROTECTION, not hardware custody. It retires when a production
# fleet host gains authenticator attachment, or when a CSR lifecycle means private
# material never lands on the host. No banner below may imply a hardware key.
EXECUTOR_KEY_PASSPHRASE="${VENYA_EXECUTOR_KEY_PASSPHRASE:-}"
if [ -z "$EXECUTOR_KEY_PASSPHRASE" ] && [ -f /etc/venya/venya-executor.env ]; then
    EXECUTOR_KEY_PASSPHRASE=$(sed -n 's/^VENYA_EXECUTOR_KEY_PASSPHRASE=//p' /etc/venya/venya-executor.env | head -n1)
    if [ -n "$EXECUTOR_KEY_PASSPHRASE" ]; then
        info "Existing install: reusing stored executor key passphrase from /etc/venya/venya-executor.env."
    fi
fi
if [ -z "$EXECUTOR_KEY_PASSPHRASE" ]; then
    if [ -t 0 ] && [ "${VENYA_SKIP_PROMPT:-}" != "yes" ]; then
        venya_read_secret_confirm "Executor key passphrase" EXECUTOR_KEY_PASSPHRASE
    else
        EXECUTOR_KEY_PASSPHRASE=$(openssl rand -base64 32)
        info "Unattended install: generated a random executor key passphrase."
    fi
fi
# #326 F-1 shape: gate the finalized value before it is written anywhere or handed to
# a child's environment -- a newline/CR would split the EnvironmentFile line.
venya_guard_injection "EXECUTOR_KEY_PASSPHRASE" "$EXECUTOR_KEY_PASSPHRASE"

# --- Write executor config (after CA installation so ca_bundle path is valid) ---
# #317 umask 077 guard: root-owned /etc/venya needs the inherited 0755 traverse
# bit for the venya daemon (inner files/dirs individually protected as before).
install -d -m 0755 /etc/venya
mkdir -p /etc/venya/executor
mkdir -p /var/log/venya

# --- Preserve operator-added executor.toml keys across a re-run (#738) ---
# The rebuild below owns MANAGED_TOML_KEYS and MANAGED_TOML_TABLES; every other
# setting in an existing /etc/venya/executor.toml was put there by an operator, and
# docs/deployment-config.md tells them to do it. Capture before the truncating
# redirect, re-append after it, and name both halves in the output — the same shape
# install-venya-core.sh uses for its .env (installer-rerun-env-custom-keys-clobbered).
# An operator key inside an installer-owned table cannot be carried without fighting
# the installer's own value for that table (#738 AC2), so it is dropped and NAMED.
MANAGED_TOML_KEYS="server_url executor_id log_level daemonize injection_method secret_base_fd ca_bundle dns_resolver relay_client_ids"
MANAGED_TOML_TABLES="mtls audit"
MANAGED_TOML_TABLE_KEYS="mtls:ca_cert mtls:cert mtls:key audit:remote_url audit:ca_cert_path"

# One program read three times over a small file: `keep` prints the lines to carry,
# `name` prints one label per carried setting, `drop` prints the operator keys that
# sit inside an installer-owned table. Section bodies travel verbatim, so a multi-line
# value inside an operator table survives intact.
venya_toml_scan() {  # $1 = keep|name|drop, $2 = file
    awk -v mode="$1" -v keys="$MANAGED_TOML_KEYS" -v tables="$MANAGED_TOML_TABLES" -v tkeys="$MANAGED_TOML_TABLE_KEYS" '
        function trim(s) { gsub(/^[ \t]+|[ \t]+$/, "", s); return s }
        BEGIN {
            n = split(keys, k, " ");  for (i = 1; i <= n; i++) top[k[i]] = 1
            n = split(tables, t, " "); for (i = 1; i <= n; i++) tab[t[i]] = 1
            n = split(tkeys, q, " ");  for (i = 1; i <= n; i++) own[q[i]] = 1
            cur = ""; keep = 1; cont = 0
        }
        /^[ \t]*\[/ {
            name = trim(substr($0, index($0, "[") + 1)); sub(/\].*$/, "", name)
            cur = name; keep = !(name in tab); cont = 0
            if (!keep) next
            if (mode == "keep") print
            else if (mode == "name") print "[" name "]"
            next
        }
        {
            key = ""
            if ($0 ~ /^[ \t]*[A-Za-z_][A-Za-z0-9_.-]*[ \t]*=/) {
                eq = index($0, "="); key = trim(substr($0, 1, eq - 1))
            }
            if (cur == "") {                    # preamble: top-level keys only
                if (key == "") { if (cont && mode == "keep") print; next }
                cont = (key in top) ? 0 : 1
                if (!cont) next
                if (mode == "keep") print
                else if (mode == "name") print key
                next
            }
            if (keep) { if (mode == "keep") print; next }
            if (key != "" && !((cur ":" key) in own) && mode == "drop") print cur "." key
        }
    ' "$2"
}
PRESERVED_TOML_LINES=""
PRESERVED_TOML_NAMES=""
DROPPED_TOML_KEYS=""
if [ -f /etc/venya/executor.toml ]; then
    PRESERVED_TOML_LINES=$(venya_toml_scan keep /etc/venya/executor.toml)
    PRESERVED_TOML_NAMES=$(venya_toml_scan name /etc/venya/executor.toml)
    DROPPED_TOML_KEYS=$(venya_toml_scan drop /etc/venya/executor.toml)
fi

# #326 F-2: printf writer — interpolated values pass as ARGUMENTS (no
# format-string exposure, no implicit expansion in the sink body); static
# lines keep their exact bytes and order.
{
    printf 'server_url = "%s"\n' "$SERVER_URL"
    printf 'executor_id = "%s"\n' "$EXECUTOR_ID"
    printf 'log_level = "info"\n'
    printf 'daemonize = false\n'
    printf 'injection_method = "sbx"\n'
    printf 'secret_base_fd = 100\n'
    printf 'ca_bundle = "%s"\n' "$CA_BUNDLE_PATH"
    printf 'dns_resolver = "%s"\n' "$DNS_RESOLVER"
    printf '\n'
    printf '# Relay CN allowlist — MUST stay top-level (not under [mtls]). Value mirrors\n'
    printf '# the core'\''s relay-client cert CN (core installer). %s\n' "'venya exec register'"
    printf '# writes only cert files, so this line survives registration.\n'
    printf 'relay_client_ids = ["%s-relay"]\n' "$CORE_HOSTNAME"
    printf '\n'
    printf '[mtls]\n'
    printf 'ca_cert = "/etc/venya/executor/ca.crt"\n'
    printf 'cert = "/etc/venya/executor/executor.crt"\n'
    printf 'key = "/etc/venya/executor/executor.key"\n'
    case "$SERVER_URL" in
      https://*)
        if [ "$CA_INSTALLED" = true ]; then
          printf '\n'
          printf '[audit]\n'
          printf 'remote_url = "%s"\n' "${SERVER_URL%/}/api/v1/audit/ingest"
          printf 'ca_cert_path = "%s"\n' "$CA_BUNDLE_PATH"
        fi ;;
    esac
} > /etc/venya/executor.toml

if [ -n "$PRESERVED_TOML_LINES" ]; then
    {
        printf '\n'
        echo '# --- operator-added keys preserved across re-run (installer, #738) ---'
        printf '%s\n' "$PRESERVED_TOML_LINES"
    } >> /etc/venya/executor.toml
    info "Preserved $(printf '%s\n' "$PRESERVED_TOML_NAMES" | wc -l) operator-added executor.toml key(s) across regeneration: $(printf '%s\n' "$PRESERVED_TOML_NAMES" | tr '\n' ' ')"
fi
if [ -n "$DROPPED_TOML_KEYS" ]; then
    warn "Dropped operator-added executor.toml key(s) inside an installer-owned table: $(printf '%s\n' "$DROPPED_TOML_KEYS" | tr '\n' ' ')"
fi

info "Executor config written to /etc/venya/executor.toml"

# --- Runtime passphrase delivery: root-only systemd EnvironmentFile (#565) ---
# Same shape and same mode as the core's /etc/venya/venya-core.env: delete-then-create
# for a fresh inode (#381 posture), chown root:venya, chmod 0640. systemd reads it as
# root into the service environment. The value is NOT written into executor.toml --
# that file is venya:venya 0600 config the service user can rewrite; keeping the
# secret in a root-owned file is what makes the mode the control.
# MEASURED: the core installer's EnvironmentFile is 0640 root:venya, NOT 0600
# venya-owned (install-venya-core.sh, the venya-core.env write). Copied deliberately,
# per the correction booked in docs/design-fido2-keywrap.md section 6.
# AC4 (#738): this carrier follows the same rule as executor.toml, so an operator
# cannot be left with one file that preserves and one that silently does not. Only
# the passphrase line is installer-owned; every other VENYA_ line in the incumbent
# file is captured before the delete and re-appended after the write — the
# install-venya-core.sh .env idiom, verbatim in shape.
MANAGED_ENV_KEYS="VENYA_EXECUTOR_KEY_PASSPHRASE"
PRESERVED_ENV_LINES=""
if [ -f /etc/venya/venya-executor.env ]; then
    PRESERVED_ENV_LINES=$(awk -F= -v managed="$MANAGED_ENV_KEYS" '
        BEGIN { n = split(managed, m, " "); for (i = 1; i <= n; i++) skip[m[i]] = 1 }
        /^VENYA_/ && !($1 in skip)
    ' /etc/venya/venya-executor.env)
fi
rm -f /etc/venya/venya-executor.env
printf 'VENYA_EXECUTOR_KEY_PASSPHRASE=%s\n' "$EXECUTOR_KEY_PASSPHRASE" > /etc/venya/venya-executor.env
if [ -n "$PRESERVED_ENV_LINES" ]; then
    {
        echo "# --- operator-added keys preserved across re-run (installer, #738) ---"
        printf '%s\n' "$PRESERVED_ENV_LINES"
    } >> /etc/venya/venya-executor.env
    info "Preserved $(printf '%s\n' "$PRESERVED_ENV_LINES" | wc -l) operator-added EnvironmentFile key(s) across regeneration: $(printf '%s\n' "$PRESERVED_ENV_LINES" | cut -d= -f1 | tr '\n' ' ')"
fi
chown root:venya /etc/venya/venya-executor.env
chmod 0640 /etc/venya/venya-executor.env
info "Executor key passphrase delivered via /etc/venya/venya-executor.env (0640 root:venya)."
info "Sandbox DNS resolver: $DNS_RESOLVER"

# --- Register mTLS certificate (if enrollment token provided) ---
# The dial-contract look moved up to the parameter region with its own guidance
# (#745); the 400 this section can still get from a core is answered by the same
# remedy text printed there, and by the failure branch below.
if [ -n "${VENYA_EXECUTOR_ENROLLMENT_TOKEN:-}" ]; then
    # TTL timing guidance (ticket installer-enrollment-token-expiry-guidance):
    # what burns on a failed install is the WALL CLOCK, not the token.
    info "Enrollment token provided — TTL ~30 min by default (server knob: executor_enrollment.token_ttl_seconds)."
    info "Registration runs near the END of install — mint the token immediately before running the installer."
    info "Attempting mTLS certificate registration..."

    if [ "$CA_INSTALLED" = true ]; then
        # Class-aware health probe (ticket health-probe-401-installer-diagnostics
        # scope b): `curl -sf` conflated unreachable / unauthorized / unhealthy
        # into one generic warn — exactly when diagnostics matter most. The HTTP
        # code splits the classes (connection failure -> 000). `|| true` inside
        # the substitution: a failing curl would otherwise die at the assignment
        # under set -e (the REG_OUTPUT incident class noted below).
        HEALTH_CODE=$(curl -s -o /dev/null -w '%{http_code}' "$SERVER_URL/api/v1/health" 2>/dev/null || true)
        if [ "$HEALTH_CODE" = "200" ]; then
            info "Core health check passed (TLS verified)"
        elif [ "$HEALTH_CODE" = "000" ] || [ -z "$HEALTH_CODE" ]; then
            warn "Core UNREACHABLE at $SERVER_URL (network/DNS/TLS) — check VENYA_SERVER_URL, firewall, CA."
            warn "Proceeding with registration anyway."
        elif [ "$HEALTH_CODE" = "401" ] || [ "$HEALTH_CODE" = "403" ]; then
            warn "Core REACHABLE but UNAUTHORIZED (HTTP $HEALTH_CODE) — proxy/path/middleware misconfig."
            warn "Proceeding with registration anyway."
        else
            warn "Core reachable but UNHEALTHY (HTTP $HEALTH_CODE)."
            warn "Proceeding with registration anyway."
        fi

        # Run registration — failures must abort install WITH diagnostics.
        # `|| REG_EXIT=$?` is required: under set -e a failing command
        # substitution in an assignment kills the script at the assignment,
        # making the handler below unreachable and swallowing REG_OUTPUT
        # (observed live 2026-09-17: bad token → silent exit, no error shown).
        # Token passes via ENV, not argv (ticket cli-exec-register-token-env-unsupported):
        # --enrollment-token exposed the live token in /proc/*/cmdline to any
        # local user during the install window (Docker-API-key stdin-only precedent).
        REG_EXIT=0
        # VENYA_EXECUTOR_KEY_PASSPHRASE passes by ENV, exactly like the token above:
        # argv would put the live secret in /proc/*/cmdline for the install window. If
        # it is absent the CLI writer REFUSES and writes nothing -- which is the point.
        REG_OUTPUT=$(VENYA_EXECUTOR_ENROLLMENT_TOKEN="${VENYA_EXECUTOR_ENROLLMENT_TOKEN:-}" \
            VENYA_EXECUTOR_KEY_PASSPHRASE="$EXECUTOR_KEY_PASSPHRASE" \
            "$INSTALL_DIR/.venv/bin/venya" exec register \
            --executor-id "$EXECUTOR_ID" \
            --core-url "$SERVER_URL" \
            --output-dir /etc/venya/executor \
            2>&1) || REG_EXIT=$?
        echo "$REG_OUTPUT"

        if [ "$REG_EXIT" -ne 0 ]; then
            error "Executor registration failed (exit $REG_EXIT)"
            error "Output: $REG_OUTPUT"
            # Class-aware guidance (tickets installer-enrollment-token-expiry-guidance +
            # installer-executor-id-precheck-guidance): match the server's STABLE
            # detail substrings — a soft cross-package contract already pinned by
            # server tests (routes/executors.py), no new pin here. ANY non-match
            # falls through to the generic hint: never mislabel a class.
            if printf '%s' "$REG_OUTPUT" | grep -qiF "Enrollment token has expired"; then
                error "CLASS: enrollment token EXPIRED. TTL is ~30 min by default (server knob:"
                error "  executor_enrollment.token_ttl_seconds). Expiration is wall-clock: the failed"
                error "  attempt did NOT consume the token — but the token is now past its window."
                error "Re-mint on a core (admin mTLS):"
                error "  venya admin executor-enroll $EXECUTOR_ID"
                error "  (offline/air-gapped: 'venya admin executor-enroll --bundle ...' copies CA + token together)"
                error "Then re-run this installer with the fresh token — the re-run is FAST (idempotent:"
                error "  apt/Docker/sbx steps skip or cache, so TTL window pressure mostly evaporates):"
                error "  VENYA_EXECUTOR_ENROLLMENT_TOKEN=<new-token> <same installer command as before>"
            elif printf '%s' "$REG_OUTPUT" | grep -qiF "must never be stored unencrypted"; then
                error "CLASS: executor key passphrase NOT AVAILABLE to the register step."
                error "  The CLI refuses to write an unencrypted executor key (#565): nothing was"
                error "  written, and the enrollment token was NOT consumed (the refusal precedes"
                error "  the POST), so the SAME token is still live."
                error "  Fix: this installer writes the passphrase to /etc/venya/venya-executor.env"
                error "  (0640 root:venya) before this step. If that file is missing or holds a"
                error "  different value, re-run with VENYA_EXECUTOR_KEY_PASSPHRASE set explicitly."
                error "  This is disk protection by a file passphrase, NOT hardware-key custody."
            elif printf '%s' "$REG_OUTPUT" | grep -qiF "does not resolve"; then
                error "CLASS: executor-id NOT RESOLVABLE from the core. The ID is the relay dial"
                error "  hostname + cert SAN — every core must resolve it. The rejected attempt did"
                error "  NOT burn the enrollment token (the check precedes the token gate)."
                error "Remedy — on EACH core host: add one '<executor-ip> $EXECUTOR_ID' line to /etc/hosts — address first, name as the SECOND field (#490 shape) — or a DNS record"
                error "Then re-run this installer (or just the registration) with the SAME token."
            else
                error "Check that VENYA_EXECUTOR_ENROLLMENT_TOKEN is valid (server detail above names the"
                error "  class: invalid / revoked / consumed / bound to a different executor_id), that the"
                error "  core is reachable, and that every core can resolve '$EXECUTOR_ID' (relay dial"
                error "  hostname + cert SAN — remedy: one '<executor-ip> $EXECUTOR_ID' line per core in its /etc/hosts, address first and the name as the SECOND field (#490 shape))."
            fi
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
        echo "  The enrollment token will be written to:"
        echo "    /var/lib/venya/executor/bootstrap-token   (0600 venya:venya)"
        echo "  The daemon registers automatically at service start once the core"
        echo "  is reachable, and clears the token file after success."
        echo "  Retry at any time with: sudo systemctl restart venya-executor"
        echo ""
    fi
else
    if [ -s /etc/venya/executor/executor.crt ]; then
        info "Existing executor certificate found — registration skipped (no token needed on re-run)."
    else
        warn "mTLS registration SKIPPED — VENYA_EXECUTOR_ENROLLMENT_TOKEN is empty."
        warn "The server rejects tokenless registration (executor_enrollment.require_token, enforced by default); the daemon will exit 1 on boot with an actionable error."
        warn "Re-run the installer with VENYA_EXECUTOR_ENROLLMENT_TOKEN set (admin mints one: venya admin executor-enroll <executor-id>)."
    fi
fi

# --- #380 (option a): UNCONDITIONAL daemon ReadWritePath pin -----------
# The 0750 dir pin was born inside the deferred-token guard below, so the
# immediate-register path (CA_INSTALLED=true) skipped it and a pre-existing
# world-writable /var/lib/venya/executor survived a fully green install
# (physical: a prior worker lane's LEG-3 sweep X7, venya-exec-2, 2026-10-02; re-confirmed
# clean re-run + lead live stat). Readers: the daemon (User=venya = owner)
# and root only. Runs EVERY install; `install -d` resets mode AND owner on
# existing dirs. Placed after the common venya_create_directories chown-R
# (:247 -> venya-common.sh:514, owner-only) so this pin is the final word.
install -d -m 0750 -o venya -g venya /var/lib/venya/executor

# --- Deferred daemon-side registration: persist the token where the daemon
# can CLEAR it (ticket daemon-bootstrap-token-clear-erofs). /etc/venya is
# ReadOnlyPaths for the daemon; /var/lib/venya/executor is in its
# ReadWritePaths. Written ONLY when install-time registration did not run —
# a completed registration consumed the token, so nothing is persisted.
# The legacy [bootstrap] section in executor.toml is NEVER written by this
# installer: the daemon can read but not clear it (EROFS), which used to
# crash-loop the boot. The daemon still honors a hand-placed legacy section
# (loud non-fatal clear failure) until old installs are cut over.
if [ -n "${VENYA_EXECUTOR_ENROLLMENT_TOKEN:-}" ] && [ "$CA_INSTALLED" != true ]; then
    # #317: the dir is pinned 0750 unconditionally above (#380 — the pin was
    # born inside this guard, so the immediate-register path skipped it); the
    # token file lands 0600: the old world-traversable dir plus the
    # :600->602 chmod window made a persisted token locally readable.
    # #381: fresh inode (chmod 600 below stays the final-state pin)
    rm -f /var/lib/venya/executor/bootstrap-token
    printf '%s\n' "$VENYA_EXECUTOR_ENROLLMENT_TOKEN" > /var/lib/venya/executor/bootstrap-token
    chown venya:venya /var/lib/venya/executor/bootstrap-token
    chmod 600 /var/lib/venya/executor/bootstrap-token
    info "Bootstrap token written to /var/lib/venya/executor/bootstrap-token (0600 venya:venya)"
    info "The daemon clears it automatically after successful registration;"
    info "trigger/retry registration with: sudo systemctl restart venya-executor"
fi

# Reordered AFTER enrollment (#363 ruled A, executor-docker-gate-before-enrollment):
# the CSR/register section runs first so a certificate/identity ALWAYS lands even
# when the optional Docker chain aborts or degrades below.
# Moved BEFORE the Docker gate (#370 ruled, executor-installer-docker-abort-before-
# harden-leaves-root-owned-keys): hardening ran after the whole Docker chain, so a
# creds-less abort left root-owned /etc/venya/executor keys and a crash-looping
# daemon until a completing re-run. Hardening right after cert creation means any
# later abort leaves a bootable degraded install (sandbox 503s, daemon runs).
# --- Harden executor credentials (executor-specific) ---
# chown venya:venya (not just chmod 600): venya-executor.service runs User=venya
# with ReadOnlyPaths=/etc/venya and must READ these — a root-owned 600 file would
# EACCES and break mTLS.
chown venya:venya /etc/venya/executor.toml
chmod 600 /etc/venya/executor.toml
chown -R venya:venya /etc/venya/executor
chmod 700 /etc/venya/executor
# --- #457: the mode pin is not believed until stat() says so -----------------
# The old shape was `find ... -exec chmod 600 {} \; 2>/dev/null || true`: it
# discarded chmod's stderr AND its exit status, so a pin that never landed was
# indistinguishable from one that did, and the install still printed
# "credentials hardened". That is the exact :600 -> :602 exposure window this
# script documents for this file class (bootstrap-token block above).
# Now: (a) the chmod pass keeps its diagnostics and its exit code is captured
# with `|| RC=$?` -- the same pattern the REG_EXIT site above uses, so set -e
# cannot swallow it -- and (b) every mode is re-read with stat(1). A key file
# not at 600, or a certificate not at 644, names the path and the mode found and
# fails the install (exit 1) instead of claiming success (venya_verify_install
# ERRORS-counter idiom, venya-common.sh).
# The `-exec ... +` batch form is part of the fix, not cosmetics: measured at
# this tip, `find ... -exec chmod 600 {} \;` exits 0 even when chmod exits 1
# (a false per-file predicate does not set find's status), so dropping `|| true`
# alone would STILL have swallowed a failed chmod. The batch form propagates it.
# The stat() pass above it stays the authority either way -- it also catches a
# chmod that exits 0 having changed nothing.
# Scope notes: MODE ONLY -- ownership stays venya:venya from the chown -R above,
# because venya-executor.service runs User=venya with ReadOnlyPaths=/etc/venya
# and must READ these files. The globs are extension-specific (*.key / *.crt),
# so no .pub, no other file class and no directory is inspected here. A host
# with no key material yet (registration deferred -- the CA/token guard above)
# has nothing to verify and still completes: this pass refuses a bad mode,
# never an absent file.
CRED_ERRORS=0
KEY_PIN_RC=0
find /etc/venya/executor -name '*.key' -exec chmod 600 {} + || KEY_PIN_RC=$?
if [ "$KEY_PIN_RC" -ne 0 ]; then
    error "chmod 600 pass over /etc/venya/executor key material failed (exit $KEY_PIN_RC)"
    CRED_ERRORS=$((CRED_ERRORS + 1))
fi
# #565: the EnvironmentFile carries the passphrase that unlocks the executor identity,
# so its mode and ownership are verified with the same authority as the key/cert pins.
# This pass REFUSES a bad mode; it never silently re-chmods a file it did not create.
if [ -f /etc/venya/venya-executor.env ]; then
    ENV_MODE=$(stat -c '%a' /etc/venya/venya-executor.env)
    ENV_OWNER=$(stat -c '%U:%G' /etc/venya/venya-executor.env)
    if [ "$ENV_MODE" != "640" ] || [ "$ENV_OWNER" != "root:venya" ]; then
        error "/etc/venya/venya-executor.env is $ENV_OWNER mode $ENV_MODE; expected root:venya mode 640"
        CRED_ERRORS=$((CRED_ERRORS + 1))
    fi
fi
CRT_PIN_RC=0
find /etc/venya/executor -name '*.crt' -exec chmod 644 {} + || CRT_PIN_RC=$?
if [ "$CRT_PIN_RC" -ne 0 ]; then
    error "chmod 644 pass over /etc/venya/executor certificates failed (exit $CRT_PIN_RC)"
    CRED_ERRORS=$((CRED_ERRORS + 1))
fi
while IFS= read -r -d '' KEY_FILE; do
    if ! KEY_MODE="$(stat -c '%a' "$KEY_FILE")"; then
        error "Cannot read the mode of $KEY_FILE -- cannot confirm it is pinned 600"
        CRED_ERRORS=$((CRED_ERRORS + 1))
        continue
    fi
    if [ "$KEY_MODE" != "600" ]; then
        error "Executor key material is not mode 600: $KEY_FILE is mode $KEY_MODE"
        CRED_ERRORS=$((CRED_ERRORS + 1))
    fi
done < <(find /etc/venya/executor -type f -name '*.key' -print0)
while IFS= read -r -d '' CRT_FILE; do
    if ! CRT_MODE="$(stat -c '%a' "$CRT_FILE")"; then
        error "Cannot read the mode of $CRT_FILE -- cannot confirm it is pinned 644"
        CRED_ERRORS=$((CRED_ERRORS + 1))
        continue
    fi
    if [ "$CRT_MODE" != "644" ]; then
        error "Executor certificate is not mode 644: $CRT_FILE is mode $CRT_MODE"
        CRED_ERRORS=$((CRED_ERRORS + 1))
    fi
done < <(find /etc/venya/executor -type f -name '*.crt' -print0)
if [ "$CRED_ERRORS" -gt 0 ]; then
    error "Executor credential hardening FAILED with $CRED_ERRORS error(s) -- not reporting a hardened install"
    exit 1
fi
info "Executor credentials hardened (venya:venya, dir 700, key 600, cert 644)"

# --- #384: UNCONDITIONAL kvm group re-assert for the daemon user ----------------
# The kvm group add was born inside the fresh-sbx-install guard above, so a
# re-install (sbx CLI persists, guard short-circuits) never re-asserted it:
# hosts that rebuild or lose the venya user's supplemental groups silently
# lose sandbox capability while the daemon stays active + heartbeats
# (live: exec-1 'id venya' missing 993, 2026-10-03; exec-3 keeps its copy).
# Idempotent re-assert on EVERY install path, after venya_create_user (:135)
# and before the optional Docker chain, so a Docker-gate abort still lands
# the capability (#370 lesson). The getent guard skips hosts without a kvm
# group; usermod -aG is a no-op when the group is already set.
getent group kvm >/dev/null && usermod -aG kvm venya 2>/dev/null || true

# --- Docker auth (sbx template pulls) + sandboxd daemon ---
# sbx runs microVMs via KVM but pulls its agent template from Docker and
# requires a per-user sandboxd daemon. Without auth the executor installs
# fine but every sandbox create fails with the vendor's "You are not
# authenticated to Docker" (docs.docker.com/ai/sandboxes/troubleshooting/,
# accessed 2026-10-09). The 503 we hand back is Venya's own mapping of an
# unauthenticated executor, not a vendor status code.
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
            venya_read_secret_confirm "Docker API key / access token" DOCKER_KEY
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
# #381: fresh inode (cat > over an incumbent unit kept its stale mode)
rm -f /etc/systemd/system/venya-sandboxd.service
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
chmod 600 /etc/systemd/system/venya-sandboxd.service
# Executor ordering drop-in (does not touch the vendored unit template)
mkdir -p /etc/systemd/system/venya-executor.service.d
# #381: fresh inode; the .d dir itself is installer-created 0700 under the
# entry umask and self-consistent across re-runs (no incumbent-widening path)
rm -f /etc/systemd/system/venya-executor.service.d/10-sandboxd.conf
cat > /etc/systemd/system/venya-executor.service.d/10-sandboxd.conf <<'DROPIN'
[Unit]
Wants=venya-sandboxd.service
After=venya-sandboxd.service
DROPIN
chmod 600 /etc/systemd/system/venya-executor.service.d/10-sandboxd.conf
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

# --- sbx agent-template warm (ticket sbx-cold-start-prepull) ---
# The first `sbx create` on a fresh host pulls the multi-GiB `shell` agent
# template inside the first relayed command's request path (~60-90 s on a
# fast uplink; longer on slow links). Warm the cache here with a throwaway
# sandbox so every real command takes the ~5 s cached path. Prereq order is
# load-bearing: Docker auth + sandboxd + deny-all policy init all precede
# this (a create without the global policy fails). Failure is NON-FATAL by
# design: the product still works, the first run is merely slow (the pre-fix
# behavior) — warn loudly and continue. Skipped under the documented
# degraded install (no Docker auth → the pull cannot work).
if [ "${VENYA_SKIP_DOCKER_LOGIN:-}" = "yes" ]; then
    info "Skipping agent-template warm (VENYA_SKIP_DOCKER_LOGIN=yes — no Docker auth)."
else
    info "Warming sbx agent template (throwaway sandbox; multi-GiB pull on a fresh host can take several minutes)..."
    WARM_SANDBOX="venya-install-warm"
    sudo -H -u venya mkdir -p /home/venya/.venya-workspaces 2>/dev/null || true
    WARM_WS="$(sudo -H -u venya mktemp -d /home/venya/.venya-workspaces/warm.XXXXXX 2>/dev/null || true)"
    # #475: deliberately NOT registered with the EXIT-cleanup list. It is not
    # an installer temp — the venya user creates it inside its own home, and
    # the throwaway retire below is a non-fatal rmdir on purpose (an
    # in-progress sandbox dir is the service user's to keep, and a root
    # `rm -rf` at script exit would be a new capability, not a leak fix).
    # Clear a stale warm sandbox from a previous failed run (create would refuse the name).
    sudo -H -u venya sbx rm --force "$WARM_SANDBOX" < /dev/null > /dev/null 2>&1 || true
    if [ -n "$WARM_WS" ] && timeout 1800 sudo -H -u venya sbx create --name "$WARM_SANDBOX" shell "$WARM_WS" < /dev/null > /dev/null 2>&1; then
        info "Agent template warm (first sandbox create is now seconds-scale)"
    else
        warn "Agent-template warm FAILED — the first sandbox execution will pull the template itself (~60-90 s+; slow but within the timeout chain). Check disk free (>= ~3.5 GiB), Docker auth, and: sudo -H -u venya sbx diagnose"
        warn "Manual warm: sudo -H -u venya sbx create --name warm shell <existing-empty-dir> && sudo -H -u venya sbx rm --force warm"
    fi
    sudo -H -u venya sbx rm --force "$WARM_SANDBOX" < /dev/null > /dev/null 2>&1 || true
    if [ -n "$WARM_WS" ]; then
        sudo -H -u venya rmdir "$WARM_WS" < /dev/null 2>/dev/null || true
    fi
fi

# NOTE: executor credential hardening ("Harden executor credentials") runs
# immediately after registration and BEFORE the Docker gate (#370) — an abort
# in the optional Docker chain below must leave a bootable degraded install.

# --- Install systemd service and mount unit (executor-specific) ---
info "Installing systemd service..."
SYSTEMD_DIR="/etc/systemd/system"
# #381: install (unlink+create, mode pinned) instead of cp — cp over an
# incumbent unit/mount/seccomp file preserved its stale mode (X13/X14/X15)
install -m 0600 "$INSTALL_DIR/systemd/venya-executor.service" "$SYSTEMD_DIR/"
install -m 0600 "$INSTALL_DIR/systemd/tmp-venya_secrets.mount" "$SYSTEMD_DIR/"
install -m 0600 "$INSTALL_DIR/systemd/venya-executor.seccomp" "$SYSTEMD_DIR/"
systemctl daemon-reload
systemctl enable venya-executor.service tmp-venya_secrets.mount

# Fresh-bytes sync (ticket installer-rerun-no-service-restart — same defect
# class as the core installer: `systemctl start` is a no-op on a running unit,
# leaving the re-run's verification probing stale in-memory imports).
touch "$INSTALL_DIR/.deploy-stamp"
venya_service_sync venya-executor "$INSTALL_DIR/.deploy-stamp"

# --- Service retry ---
venya_service_retry venya-executor
# #587: the outcome is consumed by the success claim below — STALE refuses it,
# UNDECIDABLE withholds it, FRESH proceeds.
VENYA_FRESHNESS_RC=0
VENYA_FRESHNESS_SERVICE=venya-executor
venya_service_freshness venya-executor "$INSTALL_DIR/.deploy-stamp" || VENYA_FRESHNESS_RC=$?

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
echo "Executor ID contract:"
echo "  '$EXECUTOR_ID' is the relay dial hostname + client-cert SAN — EVERY core"
echo "  must resolve it (DNS or core-side /etc/hosts:"
echo "  one '<executor-ip> $EXECUTOR_ID' line — address first, the name as the SECOND field, which is how this installer matches entries (#490))."
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
echo "  Safe by design: the relay opens only when correctly wired. An empty"
echo "  allowlist means the relay listener stays down (noted when the daemon"
echo "  starts), and a CN mismatch is refused at the handshake - both keep"
echo "  the relay closed rather than open. That is the intended, secure"
echo "  outcome, not a fault."
echo "==============================================================="
echo ""
