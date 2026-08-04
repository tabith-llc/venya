#!/usr/bin/env bash
set -euo pipefail

# Source rustup if cargo not in PATH
if ! command -v cargo &>/dev/null; then
    if [ -f "$HOME/.cargo/env" ]; then
        source "$HOME/.cargo/env"
    fi
fi

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

echo "==> uv pip install -e packages/executor/"
cd "$SCRIPT_DIR"
uv pip install -e packages/executor/ --python .venv/bin/python --reinstall-package venya-executor

echo "==> build complete"
