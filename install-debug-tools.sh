#!/usr/bin/env bash
set -euo pipefail

###############################################################################
# Venya Debug Tools Installer
#
# Usage:
#   curl -fsSL http://10.27.27.35:8080/install-debug-tools.sh | sudo bash
#
# Or download and run:
#   wget -qO- http://10.27.27.35:8080/install-debug-tools.sh | sudo bash
#
# Installs development/debugging packages not needed for runtime:
#   strace, ltrace, gdb, tcpdump, net-tools, iproute2, wget, rsync, iptables
###############################################################################

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

info "Installing debug tools..."
apt-get update -qq
apt-get install -y -qq strace ltrace gdb tcpdump net-tools iproute2 wget rsync iptables > /dev/null 2>&1

info "Debug tools installed."
