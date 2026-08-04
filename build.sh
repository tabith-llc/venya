#!/usr/bin/env bash
set -euo pipefail

# Source rustup if cargo not in PATH
if ! command -v cargo &>/dev/null; then
    if [ -f "$HOME/.cargo/env" ]; then
        source "$HOME/.cargo/env"
    fi
fi

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
CARGO_TARGET="$SCRIPT_DIR/packages/executor/target/release/libvenya_filter.so"
SO_TOP="$SCRIPT_DIR/.venv/lib/python3.13/site-packages/venya_filter.so"
SO_PKG="$SCRIPT_DIR/.venv/lib/python3.13/site-packages/venya_filter/venya_filter.cpython-313-x86_64-linux-gnu.so"

echo "==> cargo build --release"
cd "$SCRIPT_DIR/packages/executor"
rm -rf target/release
cargo build --release

echo "==> copying .so to both locations"
cp "$CARGO_TARGET" "$SO_TOP"
cp "$CARGO_TARGET" "$SO_PKG"

echo "==> build complete"
