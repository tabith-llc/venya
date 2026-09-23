#!/usr/bin/env bash

# Copyright (c) 2026 Tabith LLC.
# Use of this source code is governed by the Business Source License 1.1
# included in the LICENSE file at the root of this repository. As of the
# Change Date listed there, the work is available under MPL 2.0.
# SPDX-License-Identifier: BUSL-1.1

# Render the docs/example-workflow.md companion diagrams from their d2 sources.
#
# Sources live in docs/diagrams/: lanes.d2 holds the swimlanes, steps/*.d2 hold
# the messages for one narrative step each, and workflow.d2 / frames.d2 spread-
# import them. Message text therefore exists in exactly one place and cannot
# drift between the overview and the per-step frames.
#
# Output is SVG with both themes embedded (--dark-theme), so a single file reads
# correctly in GitHub's light and dark modes.
#
# Usage:
#   scripts/render-diagrams.sh          # render overview + frames
#   scripts/render-diagrams.sh --check  # exit non-zero if renders are stale

set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
src="${repo_root}/docs/diagrams"

LAYOUT="elk"
THEME=0        # Neutral Default
DARK_THEME=200 # Dark Mauve
PAD=40

if ! command -v d2 >/dev/null 2>&1; then
  echo "error: d2 not found (brew install d2)" >&2
  exit 1
fi

render() {
  d2 --layout="${LAYOUT}" --theme="${THEME}" --dark-theme="${DARK_THEME}" \
     --pad="${PAD}" "$1" "$2"
}

check_mode=0
[[ "${1:-}" == "--check" ]] && check_mode=1

if (( check_mode )); then
  tmp="$(mktemp -d)"
  trap 'rm -rf "${tmp}"' EXIT
  render "${src}/workflow.d2" "${tmp}/workflow.svg" >/dev/null
  render "${src}/frames.d2" "${tmp}/frames.svg" >/dev/null
  if ! diff -rq "${tmp}/workflow.svg" "${src}/workflow.svg" >/dev/null 2>&1 \
     || ! diff -rq "${tmp}/frames" "${src}/frames" >/dev/null 2>&1; then
    echo "error: rendered diagrams are stale — run scripts/render-diagrams.sh" >&2
    exit 1
  fi
  echo "diagrams up to date"
  exit 0
fi

render "${src}/workflow.d2" "${src}/workflow.svg"
render "${src}/frames.d2" "${src}/frames.svg"
echo "rendered ${src}/workflow.svg and ${src}/frames/"
