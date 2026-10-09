# Copyright (c) 2026 Tabith LLC.
# Use of this source code is governed by the Business Source License 1.1
# included in the LICENSE file at the root of this repository. As of the
# Change Date listed there, the work is available under MPL 2.0.
# SPDX-License-Identifier: BUSL-1.1

"""Guard the shared detect-secrets baseline against a silent shrink (refs #546).

The upstream ``detect-secrets`` pre-commit hook rewrites ``.detect-secrets-baseline``
in place while a commit is being attempted and prints a prompt that asks the
committer to stage the file. A lane that obeys that prompt can commit a baseline
with FEWER detections than HEAD carries, with nothing in the reviewed diff
objecting; the interlock that catches it lives in the core suite, so a changeset
that never runs core ships the weakened gate (ticket #546).

One implementation, two thin hook entries (R9.1 as amended by
``wave13-specs-20261009/s79-ruling-546-precommit-stage.md``):

* ``--stage pre-commit`` — fails a vanished set that is NOT staged, i.e. the
  blind-rewrite state where the tool edited the worktree under the lane and the
  correct action is stop-and-inspect, never stage-blind. A staged shrink is
  DEFERRED to the commit-msg entry, which is where intent is judged. This entry
  never reads a commit message at all: at the pre-commit stage git has not
  written the message yet, and ``.git/COMMIT_EDITMSG`` holds the PREVIOUS
  commit's message — a stale trailer would false-pass the current shrink.
* ``--stage commit-msg`` — the same authoritative comparison (the content being
  committed against HEAD), red unless the message this entry is handed as
  ``argv[1]`` declares the removal with a ``Baseline-removal-reason:`` trailer.

The laws this module implements (R2/R3/R7/R9/R9.1 + the s79 amendment):

* CONTENT is authoritative: the baseline being committed against the
  HEAD-committed baseline. Staging carries zero intent authority — it only
  decides fail-vs-defer at the pre-commit stage, never a pass (R9).
* Only VANISHING is guarded (R2). A moved file or a line-number refresh keeps
  its ``(filename, type, hashed_secret)`` triple and passes; a whole-file diff
  check is rejected on purpose because it goes false-red on ordinary edits.
* No env hatch (R3): the friction of declaring the removal in the message IS the
  feature. The hook chain is UX; the core interlock cell is the enforcement.
* The failure text names both states and both upstream prompts that invite blind
  staging, and never repeats the staging command they print (R7 rewrite).

Findings are keyed by the same ``(filename, type, hashed_secret)`` triple the core
interlock uses (``packages/core/tests/test_detect_secrets_baseline.py``), so both
halves compare the same thing.
"""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
from pathlib import Path

BASELINE_FILENAME = ".detect-secrets-baseline"

#: The trailer that declares an intentional removal (R9 intent authority).
TRAILER_KEY = "Baseline-removal-reason"

#: Exclusion patterns every detect-secrets scan path in this repo must use
#: (refs #546 R6 — the hook used to carry only the first, the core interlock
#: both; that asymmetry is the reproduced shrink mechanism).
EXCLUDE_FILE_PATTERNS = ("target/", r"\.detect-secrets-baseline$")

#: The exclusion half of those args, shared by the hook entries and the interlock.
EXCLUDE_ARGS = [x for pattern in EXCLUDE_FILE_PATTERNS for x in ("--exclude-files", pattern)]

#: The detect-secrets hook args this repo ships, built from the canonical values.
#: `config_hook_args()` reads the committed config and the #546 cells compare the
#: two, so the scan paths cannot drift apart again. The baseline path is NOT part
#: of this list: the hook gets the tracked file, the interlock scans into a temp
#: copy so the repo file is never mutated.
HOOK_ARGS = ["--baseline", BASELINE_FILENAME, *EXCLUDE_ARGS]

#: The two upstream prompts that invite blind staging (R7: name them, do not
#: repeat the command they print — that command is the laundering path).
BLIND_STAGING_PROMPTS = (
    (
        'rc=3 "The baseline file was updated. Probably to keep line numbers of '
        'secrets up-to-date." — it then asks you to stage the baseline file'
    ),
    (
        'rc=1 "Your baseline file (.detect-secrets-baseline) is unstaged." — it '
        "also tells you to stage the baseline file to fix it"
    ),
)


def _git(args: list[str], cwd: Path) -> subprocess.CompletedProcess[str]:
    # check=False on purpose: callers branch on returncode (an absent path at
    # HEAD is a normal answer here, not an exception).
    return subprocess.run(args, cwd=str(cwd), capture_output=True, text=True, check=False)


def repo_root(start: Path | None = None) -> Path:
    """Git's toplevel for ``start`` (defaults to this process' cwd)."""
    out = _git(["git", "rev-parse", "--show-toplevel"], start or Path.cwd())
    if out.returncode != 0:
        raise RuntimeError(f"not inside a git repository: {out.stderr.strip()}")
    return Path(out.stdout.strip())


def git_show(rev: str, path: str, cwd: Path) -> str | None:
    """Content of ``path`` at ``rev`` (``HEAD`` or ``:`` for the index), None if absent."""
    out = _git(["git", "show", f"{rev}{path}"], cwd)
    if out.returncode != 0:
        return None
    return out.stdout


def worktree_text(path: Path) -> str | None:
    """The working-copy baseline, None when the file is gone from disk."""
    if not path.exists():
        return None
    return path.read_text(encoding="utf-8")


def findings_of(baseline_text: str | None) -> set[tuple[str, str, str]]:
    """The ``(filename, type, hashed_secret)`` triple set of one baseline.

    Absent content contributes no findings; unparseable content raises so a guard
    never reports a clean run on a file it could not read.
    """
    if baseline_text is None:
        return set()
    try:
        data = json.loads(baseline_text)
    except json.JSONDecodeError as exc:  # fail loud, never silently "no findings"
        raise ValueError(f"baseline content is not valid JSON: {exc}") from exc
    results = data.get("results")
    if not isinstance(results, dict):
        raise TypeError("baseline content has no 'results' object")
    return {
        (filename, str(secret.get("type")), str(secret.get("hashed_secret")))
        for filename, secrets in results.items()
        for secret in secrets
    }


def vanished_findings(
    head: set[tuple[str, str, str]], covering: set[tuple[str, str, str]]
) -> set[tuple[str, str, str]]:
    """R2: findings HEAD carries that ``covering`` no longer covers."""
    return head - covering


def declared_removal_reason(message_text: str | None) -> str | None:
    """The trailer value, or None when the message declares nothing.

    A bare ``Baseline-removal-reason:`` with an empty value is NOT a declaration,
    and neither is one sitting on a comment line (git strips those later).
    """
    if message_text is None:
        return None
    pattern = re.compile(rf"^{re.escape(TRAILER_KEY)}:\s*(.*)$")
    for line in message_text.splitlines():
        if line.startswith("#"):
            continue
        match = pattern.match(line)
        if match and match.group(1).strip():
            return match.group(1).strip()
    return None


def config_hook_args(config_path: Path) -> list[str]:
    """The ``args:`` list of the detect-secrets entry in .pre-commit-config.yaml.

    Read as text on purpose: the guard carries no third-party deps and the config
    keeps the args on one line (the shape this repo ships). An entry whose args
    are spread over several lines is reported as unreadable, not guessed at.
    """
    text = config_path.read_text(encoding="utf-8")
    in_secrets_block = False
    for line in text.splitlines():
        if re.match(r"^\s*-\s+id:\s+detect-secrets\s*$", line):
            in_secrets_block = True
            continue
        if in_secrets_block:
            match = re.match(r"^\s*args:\s*(\[.*\])\s*$", line)
            if match:
                try:
                    args = json.loads(match.group(1).replace("'", '"'))
                except json.JSONDecodeError as exc:
                    raise ValueError(f"cannot parse detect-secrets hook args: {exc}") from exc
                if not isinstance(args, list):
                    raise ValueError("detect-secrets hook args are not a list")
                return [str(a) for a in args]
            if line.strip() and not line.lstrip().startswith("#"):
                raise ValueError("detect-secrets hook entry has no single-line args list")
    raise ValueError("no detect-secrets hook entry in the pre-commit config")


def _listing(vanished: set[tuple[str, str, str]]) -> str:
    return "\n".join(
        f"    - {filename} | {secret_type} | {hashed}" for filename, secret_type, hashed in sorted(vanished)
    )


def _banner(
    vanished: set[tuple[str, str, str]],
    count_head: int,
    count_covering: int,
    covering_label: str,
) -> str:
    return (
        "ERROR: the detect-secrets baseline is about to lose detections (refs #546)\n\n"
        f"  HEAD covers {count_head} findings; {covering_label} covers {count_covering}.\n"
        f"  {len(vanished)} finding(s) present at HEAD would vanish from the shared gate:\n\n"
        f"{_listing(vanished)}\n\n"
        "  Two states, so this is never a guess:\n"
        "    * a line-only refresh — the same findings at moved offsets — is normal.\n"
        "      The upstream hook prints its refresh notice for it and this guard\n"
        "      passes it silently. Nothing is asked of you.\n"
        "    * vanished findings — the gate stops covering what HEAD covers — is NOT\n"
        "      fixed by staging the file. The upstream hook invites exactly that in\n"
        f"      two places: {'; '.join(BLIND_STAGING_PROMPTS)}.\n"
        "      Obeying either accomplishes nothing against this guard: it compares\n"
        "      the content being committed with HEAD, so a staged shrink is judged\n"
        "      on its findings, not on the fact that you staged it.\n\n"
        f"  If the removal is intended (the secret genuinely left the tree), declare\n"
        f"  it in the commit message — one trailer per file, what left and why:\n\n"
        f"      {TRAILER_KEY}: packages/<...> — <reason the secret no longer exists>\n\n"
        "  Otherwise stop and restore the baseline. Do not ship a narrower gate, and\n"
        "  do not reach for the bypass the repo rules already forbid.\n"
    )


def guard_result(
    root: Path, stage: str, message_path: Path | None, baseline_name: str = BASELINE_FILENAME
) -> tuple[int, str]:
    """(rc, output) for one guard run. Shared by BOTH hook entries (R9.1).

    ``stage`` selects only WHEN intent is judgeable, never what is compared: the
    vanished set is always the HEAD-committed baseline against the content being
    committed (the index copy).
    """
    head = findings_of(git_show("HEAD:", baseline_name, root))
    index = findings_of(git_show(":", baseline_name, root))
    worktree = findings_of(worktree_text(root / baseline_name))

    vanished_committed = vanished_findings(head, index)

    if stage == "pre-commit":
        # This entry MUST NOT read any message: at this stage .git/COMMIT_EDITMSG
        # holds the PREVIOUS commit's message (s79 ruling §2), so a stale trailer
        # would false-pass today's shrink.
        vanished_worktree = vanished_findings(head, worktree)
        unstaged_vanish = vanished_worktree - vanished_committed
        if not unstaged_vanish:
            if vanished_committed:
                return 0, (
                    f"Noted: {len(vanished_committed)} finding(s) vanish from the staged baseline; the\n"
                    f"declaration is judged by the commit-msg stage, which reads {TRAILER_KEY} in the\n"
                    "message this commit supplies.\n"
                )
            return 0, ""
        return 1, (
            _banner(unstaged_vanish, len(head), len(worktree), "the working copy")
            + "  This is the blind-rewrite state: the shrink is in the working copy and NOT\n"
            "  staged. Stop and inspect it — restore the baseline, or stage the edit and\n"
            "  let the commit-msg stage judge the declaration.\n"
        )

    if not vanished_committed:
        return 0, ""

    if message_path is None:
        return 1, (
            _banner(vanished_committed, len(head), len(index), "the content being committed")
            + "  This run was not given a commit message to read, so nothing declares the\n"
            "  removal. Re-run through the commit-msg hook, which passes the message file.\n"
        )
    reason = declared_removal_reason(message_path.read_text(encoding="utf-8") if message_path.exists() else None)
    if reason:
        return 0, f"Declared baseline removal ({len(vanished_committed)} finding(s)): {TRAILER_KEY}: {reason}\n"
    return (
        1,
        _banner(vanished_committed, len(head), len(index), "the content being committed")
        + "  This commit message declares nothing, so the removal stays undeclared.\n"
        f"  Add a '{TRAILER_KEY}: <what/why>' trailer, or abort and restore the baseline.\n",
    )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Fail a commit that shrinks the shared secret-detection gate.")
    parser.add_argument("--stage", choices=("pre-commit", "commit-msg"), required=True)
    parser.add_argument(
        "message",
        nargs="?",
        help="commit message file — supplied by the commit-msg stage only; this tool never "
        "reads .git/COMMIT_EDITMSG at the pre-commit stage (a stale message false-passes)",
    )
    parser.add_argument("--repo", help="repository root (default: git's toplevel for the cwd)")
    parser.add_argument("--baseline", default=BASELINE_FILENAME, help="baseline path, repo-relative")
    args = parser.parse_args(argv)

    root = Path(args.repo).resolve() if args.repo else repo_root()
    message_path = None
    if args.stage == "commit-msg":
        if args.message:
            message_path = Path(args.message)
            if not message_path.is_absolute():
                message_path = root / message_path
        else:
            # Fail closed rather than guess: reading COMMIT_EDITMSG here would
            # evaluate the PREVIOUS commit's trailer (s79 ruling §2).
            message_path = None

    try:
        rc, output = guard_result(root, args.stage, message_path, args.baseline)
    except (ValueError, TypeError, RuntimeError) as exc:
        print(f"detect-secrets baseline guard cannot decide: {exc}", file=sys.stderr)
        return 1

    if output:
        sys.stdout.write(output if output.endswith("\n") else output + "\n")
    return rc


if __name__ == "__main__":
    sys.exit(main())
