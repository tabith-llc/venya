#!/usr/bin/env bash
# Copyright (c) 2026 Tabith LLC.
# Use of this source code is governed by the Business Source License 1.1
# included in the LICENSE file at the root of this repository. As of the
# Change Date listed there, the work is available under MPL 2.0.
# SPDX-License-Identifier: BUSL-1.1
#
# Deploy-source record + drift classifier (ticket #16, dev-deploy half).
#
# Release builds are already structural: create-tarball-and-serve.sh --ref
# builds from git archive only. This tool covers hand-deploys (scp/rsync of
# changed files): it records what the source tree looked like at deploy time,
# then classifies any later deploy-vs-source sha256 difference as known
# (committed or recorded-dirty) or unexplained (= STOP).
#
# Usage:
#   deploy-record.sh record [REPO_DIR]
#       Prints a deploy record to stdout. Redirect into the run's results
#       file BEFORE building/copying any artifact.
#   deploy-record.sh classify REPO_DIR RECORD_FILE PATH OBSERVED_SHA256
#       Prints exactly one verdict and exits 0 on MATCH-COMMITTED /
#       ATTRIBUTED-DIRTY, 1 on STOP-UNEXPLAINED.
#       PATH is repo-relative. OBSERVED_SHA256 is the hash of the deployed
#       runtime file (e.g. from the VM's site-packages copy).
#   deploy-record.sh selftest
#       Runs the classifier against a throwaway git repo (positive and
#       negative halves). Prints SELFTEST PASS or fails loudly.
set -euo pipefail

_usage() {
    echo "Usage: deploy-record.sh record [REPO_DIR]"
    echo "       deploy-record.sh classify REPO_DIR RECORD_FILE PATH OBSERVED_SHA256"
    echo "       deploy-record.sh selftest"
    exit 2
}

_record() {
    local repo="${1:-.}"
    local commit dirty lines f hash
    commit=$(git -C "$repo" rev-parse HEAD)
    echo "# venya-deploy-record v1"
    echo "commit=$commit"
    echo "recorded_utc=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
    # -uall so untracked dirs are listed file-by-file (clean-tree checks
    # cannot catch untracked bytes, e.g. an old .so shipped by hand).
    lines=$(git -C "$repo" status --porcelain -uall)
    if [ -z "$lines" ]; then
        echo "tree=CLEAN"
        return 0
    fi
    echo "tree=DIRTY"
    while IFS= read -r entry; do
        f="${entry:3}"
        # renames are reported as "old -> new"; the working-tree file is new.
        f="${f##* -> }"
        [ -f "$repo/$f" ] || continue
        hash=$(sha256sum "$repo/$f" | cut -d' ' -f1)
        printf 'dirty %s %s\n' "$hash" "$f"
    done <<<"$lines"
}

_dirty_hash() {
    # $1 record file, $2 path -> echoes recorded hash or empty.
    awk -v p="$2" '$1 == "dirty" && $3 == p { print $2 }' "$1" | head -1
}

_classify() {
    local repo="$1" record="$2" path="$3" observed="$4"
    local commit recorded committed
    commit=$(awk -F= '$1 == "commit" { print $2 }' "$record")
    [ -n "$commit" ] || { echo "STOP-UNEXPLAINED (no commit in record)"; exit 1; }
    recorded=$(_dirty_hash "$record" "$path")
    if [ -n "$recorded" ] && [ "$recorded" = "$observed" ]; then
        echo "ATTRIBUTED-DIRTY"
        return 0
    fi
    committed=$(git -C "$repo" show "$commit:$path" 2>/dev/null | sha256sum | cut -d' ' -f1)
    if [ "$committed" = "$observed" ]; then
        echo "MATCH-COMMITTED"
        return 0
    fi
    echo "STOP-UNEXPLAINED"
    return 1
}

_selftest() {
    local tmp repo recfile a_hash b_dirty_hash verdict
    tmp=$(mktemp -d)
    # shellcheck disable=SC2064  # expand tmp now, at trap registration
    trap "rm -rf '$tmp'" EXIT
    repo="$tmp/repo"
    mkdir -p "$repo"
    git -C "$repo" init -q
    git -C "$repo" config user.email t@t.invalid
    git -C "$repo" config user.name t
    echo "committed-a" > "$repo/a.txt"
    echo "committed-b" > "$repo/b.txt"
    git -C "$repo" add a.txt b.txt
    git -C "$repo" commit -qm init
    # dirty one file, add one untracked file
    echo "dirty-b" > "$repo/b.txt"
    echo "untracked-c" > "$repo/c.txt"

    recfile="$tmp/record"
    _record "$repo" > "$recfile"
    grep -q "^dirty .* b.txt$" "$recfile" || { echo "SELFTEST FAIL: dirty b.txt missing from record"; exit 1; }
    grep -q "^dirty .* c.txt$" "$recfile" || { echo "SELFTEST FAIL: untracked c.txt missing from record"; exit 1; }

    # Positive half 1: clean file matches committed blob.
    a_hash=$(git -C "$repo" show "HEAD:a.txt" | sha256sum | cut -d' ' -f1)
    verdict=$(_classify "$repo" "$recfile" a.txt "$a_hash")
    [ "$verdict" = "MATCH-COMMITTED" ] || { echo "SELFTEST FAIL: clean file verdict '$verdict'"; exit 1; }

    # Positive half 2: dirty file at deploy-time content is attributed.
    b_dirty_hash=$(sha256sum "$repo/b.txt" | cut -d' ' -f1)
    verdict=$(_classify "$repo" "$recfile" b.txt "$b_dirty_hash")
    [ "$verdict" = "ATTRIBUTED-DIRTY" ] || { echo "SELFTEST FAIL: dirty file verdict '$verdict'"; exit 1; }

    # Negative half: bytes matching neither committed nor recorded state STOP.
    if _classify "$repo" "$recfile" b.txt "deadbeef" >/dev/null 2>&1; then
        echo "SELFTEST FAIL: unexplained bytes were not stopped"
        exit 1
    fi
    # Negative half: committed tree records CLEAN, no dirty entries.
    git -C "$repo" add -A
    git -C "$repo" commit -qm tidy
    _record "$repo" | grep -q "tree=CLEAN" || { echo "SELFTEST FAIL: clean tree not CLEAN"; exit 1; }

    trap - EXIT
    rm -rf "$tmp"
    echo "SELFTEST PASS"
}

main() {
    case "${1:-}" in
        record) _record "${2:-.}" ;;
        classify)
            shift
            [ $# -eq 4 ] || _usage
            _classify "$1" "$2" "$3" "$4"
            ;;
        selftest) _selftest ;;
        *) _usage ;;
    esac
}
main "${@:-}"
