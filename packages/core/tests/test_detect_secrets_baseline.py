# Copyright (c) 2026 Tabith LLC.
# Use of this source code is governed by the Business Source License 1.1
# included in the LICENSE file at the root of this repository. As of the
# Change Date listed there, the work is available under MPL 2.0.
# SPDX-License-Identifier: BUSL-1.1

"""Interlock: the committed .detect-secrets-baseline must cover the full tree.

The detect-secrets pre-commit hook refreshes the baseline only for the files it
is passed (staged files), so findings in never-staged files never enter the
baseline and resurface as a confusing NEW finding in some future changeset
(ticket detect-secrets-baseline-scope-drift). This test runs the same scan the
hook runs (detect-secrets 1.5.0, same --exclude-files arg) over the whole tree
and asserts zero delta against the committed baseline.

Hosted in core alongside the other repo-wide generated-artifact interlocks
(test_bandit_suppressions_doc.py); the baseline is a scan artifact with no
runtime import.

## #546 — the baseline cannot shrink silently

The hook rewrites this file mid-commit and asks the committer to stage it, so a
lane that obeys can commit a gate with FEWER detections than HEAD carries and
nothing in the reviewed diff objects (the core interlock caught it, but a
changeset that never runs core shipped the weakening anyway). The cells below
hold the guard that closes it: findings are compared by the
`(filename, type, hashed_secret)` triple, so a line-number refresh is free and
only VANISHING is red; the comparison is always the content being committed
against HEAD, so staging the shrink buys nothing; an intended removal has to be
declared by a `Baseline-removal-reason:` trailer in the commit message. One
shared implementation lives in `scripts/detect_secrets_baseline_guard.py` and
both hook entries call it — the pre-commit stage catches a vanish the lane has
not staged (the blind-rewrite state) and never reads a message, because at that
stage the message file still holds the PREVIOUS commit's text; the commit-msg
stage is where a declared removal is honoured. This file is the enforcement half
(the hook chain is UX): a trailer can excuse the hook, it cannot excuse the
committed-state cells above.
"""

import importlib.util
import json
import shutil
import subprocess
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[3]
BASELINE = REPO_ROOT / ".detect-secrets-baseline"
CONFIG = REPO_ROOT / ".pre-commit-config.yaml"
_GUARD_SCRIPT = REPO_ROOT / "scripts" / "detect_secrets_baseline_guard.py"

_spec = importlib.util.spec_from_file_location("detect_secrets_baseline_guard", _GUARD_SCRIPT)
guard = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(guard)


def _findings(scan_output: dict) -> set:
    return {
        (filename, secret["type"], secret["hashed_secret"])
        for filename, secrets in scan_output["results"].items()
        for secret in secrets
    }


def _full_tree_scan(tmp_path: Path) -> dict:
    """Run the hook's scan semantics over every tracked file.

    The temp copy stands in for the committed baseline so the repo file is
    never mutated; the tracked baseline itself is excluded from the scan
    (mirroring the hook's is_baseline_file self-exclusion).
    """
    tool = shutil.which("detect-secrets")
    assert tool, "detect-secrets missing from the test env (core dev group)"
    copy = tmp_path / BASELINE.name
    copy.write_text(BASELINE.read_text(encoding="utf-8"), encoding="utf-8")
    subprocess.run(
        [tool, "scan", "--baseline", str(copy), *guard.EXCLUDE_ARGS],
        cwd=REPO_ROOT,
        check=True,
        capture_output=True,
        text=True,
    )
    return json.loads(copy.read_text(encoding="utf-8"))


def test_scanner_version_matches_baseline_version():
    """The dev-group pin and the hook rev must agree (tool-drift half)."""
    committed = json.loads(BASELINE.read_text(encoding="utf-8"))
    tool = shutil.which("detect-secrets")
    assert tool, "detect-secrets missing from the test env (core dev group)"
    out = subprocess.run([tool, "--version"], check=True, capture_output=True, text=True)
    assert out.stdout.strip() == committed["version"], (
        "installed detect-secrets != baseline's recording version — "
        "sync the core dev-group pin with the .pre-commit-config.yaml rev"
    )


def test_full_tree_scan_equals_committed_baseline(tmp_path):
    committed = json.loads(BASELINE.read_text(encoding="utf-8"))
    fresh = _full_tree_scan(tmp_path)
    added = _findings(fresh) - _findings(committed)
    stale = _findings(committed) - _findings(fresh)
    assert not added, (
        "unbaselined findings — the committed baseline does not cover the full tree; "
        "resync: detect-secrets scan --baseline .detect-secrets-baseline --exclude-files 'target/'\n"
        + "\n".join(f"  + {f} | {t} | {h}" for f, t, h in sorted(added))
    )
    assert not stale, "stale baseline entries — recorded secrets no longer scan in the tree\n" + "\n".join(
        f"  - {f} | {t} | {h}" for f, t, h in sorted(stale)
    )


# ---------------------------------------------------------------------------------------------
# ## #546 — the baseline cannot shrink silently (guard cells)
#
# Paired halves: what must pass, and what must be rejected. Shapes follow R2/R9/R9.1 as amended
# by `s79-ruling-546-precommit-stage.md`: the vanished set is always the HEAD-committed baseline
# against the content being committed; at the pre-commit stage an UNSTAGED vanish (the
# blind-rewrite state) is red and a staged one defers to commit-msg, where the trailer is the
# only intent authority. The pre-commit entry never reads a message — at that stage
# .git/COMMIT_EDITMSG holds the PREVIOUS commit's message, so a stale trailer would false-pass.
#
# Every cell drives the guard against a throwaway repo, so the venue's index is never touched.


def _git(root: Path, *args: str) -> None:
    subprocess.run(
        ["git", "-c", "user.email=guard@invalid", "-c", "user.name=guard", "-C", str(root), *args],
        check=True,
        capture_output=True,
        text=True,
    )


def _scratch_repo(tmp_path: Path, baseline_text: str) -> Path:
    """A throwaway repo whose HEAD carries `baseline_text` as the committed baseline."""
    subprocess.run(["git", "init", "-q", str(tmp_path)], check=True)
    (tmp_path / BASELINE.name).write_text(baseline_text, encoding="utf-8")
    _git(tmp_path, "add", BASELINE.name)
    _git(tmp_path, "commit", "-q", "-m", "committed baseline")
    return tmp_path


def _with_line_moves(baseline_text: str, delta: int = 7) -> str:
    """Same findings, every line_number shifted — the refresh shape a guard must allow."""
    data = json.loads(baseline_text)
    for secrets in data["results"].values():
        for secret in secrets:
            secret["line_number"] = int(secret["line_number"]) + delta
    return json.dumps(data, indent=2) + "\n"


def _without_one_finding(baseline_text: str) -> tuple[str, tuple[str, str, str]]:
    """Drop exactly one recorded finding with its file still tracked — the shape that must be red."""
    data = json.loads(baseline_text)
    for filename, secrets in sorted(data["results"].items()):
        removed = secrets.pop(0)
        if not secrets:
            del data["results"][filename]
        return json.dumps(data, indent=2) + "\n", (filename, removed["type"], removed["hashed_secret"])
    raise AssertionError("baseline has no findings to remove")


def _write(root: Path, text: str, staged: bool) -> None:
    (root / BASELINE.name).write_text(text, encoding="utf-8")
    if staged:
        _git(root, "add", BASELINE.name)


def test_line_only_refresh_passes_the_guard(tmp_path):
    """Positive half (R2): offsets move, nothing vanishes → rc 0 at both stages."""
    committed = BASELINE.read_text(encoding="utf-8")
    root = _scratch_repo(tmp_path, committed)
    _write(root, _with_line_moves(committed), staged=True)

    for stage in ("pre-commit", "commit-msg"):
        rc, output = guard.guard_result(root, stage, tmp_path / "absent-msg", BASELINE.name)
        assert rc == 0, f"a line-number-only refresh must pass the {stage} entry, got:\n{output}"


def test_unstaged_vanish_fails_the_pre_commit_guard(tmp_path):
    """Negative half — the one that matters: the tool rewrote the baseline under the lane and
    the finding is gone from the working copy. Red at the pre-commit stage, and the failure
    text never repeats the staging command the upstream hook prints."""
    committed = BASELINE.read_text(encoding="utf-8")
    root = _scratch_repo(tmp_path, committed)
    shrunk, removed = _without_one_finding(committed)
    _write(root, shrunk, staged=False)  # the blind-rewrite state

    rc, output = guard.guard_result(root, "pre-commit", None, BASELINE.name)
    assert rc == 1, "a vanished finding in the working copy must fail the commit"
    assert guard.vanished_findings(guard.findings_of(committed), guard.findings_of(shrunk)) == {removed}
    assert removed[0] in output and removed[2] in output, f"the vanished finding is not named:\n{output}"
    assert "git add" not in output.lower(), f"the failure text reprints the blind-staging command:\n{output}"
    assert "line-only refresh" in output, f"the two states are not named:\n{output}"
    assert "blind-rewrite" in output, f"the state is not named:\n{output}"


def test_staged_vanish_without_trailer_fails_the_commit_msg_guard(tmp_path):
    """Negative half (R9 laundering): a lane obeyed the tool's stage-me prompt. Staging is not
    intent — the same vanished set is red at commit-msg when the message declares nothing."""
    committed = BASELINE.read_text(encoding="utf-8")
    root = _scratch_repo(tmp_path, committed)
    shrunk, _ = _without_one_finding(committed)
    _write(root, shrunk, staged=True)
    message = tmp_path / "msg"
    message.write_text("fix(x): touch a source file\n\nSigned-off-by: nobody\n", encoding="utf-8")

    rc, defer_output = guard.guard_result(root, "pre-commit", message, BASELINE.name)
    assert rc == 0, f"a staged shrink defers to commit-msg, got:\n{defer_output}"
    assert "commit-msg" in defer_output, "the deferral is not explained"

    rc, output = guard.guard_result(root, "commit-msg", message, BASELINE.name)
    assert rc == 1, f"staging alone must not satisfy the guard:\n{output}"
    assert guard.TRAILER_KEY in output


def test_staged_vanish_with_trailer_passes_the_guard(tmp_path):
    """Positive half (R3/R9): the same removal, declared in the message, is allowed through."""
    committed = BASELINE.read_text(encoding="utf-8")
    root = _scratch_repo(tmp_path, committed)
    shrunk, removed = _without_one_finding(committed)
    _write(root, shrunk, staged=True)
    message = tmp_path / "msg"
    message.write_text(
        "fix(server): retire the rotated test credential\n\n"
        f"{guard.TRAILER_KEY}: {removed[0]} — the secret left the tree in this changeset\n",
        encoding="utf-8",
    )

    rc, output = guard.guard_result(root, "commit-msg", message, BASELINE.name)
    assert rc == 0, f"a declared removal must pass, got:\n{output}"
    assert removed[0] in output


def test_pre_commit_entry_never_reads_a_message_even_when_one_is_supplied(tmp_path):
    """s79 ruling §2: at the pre-commit stage the message file holds the PREVIOUS commit's
    text. A stale trailer there must not excuse today's shrink — the entry ignores it."""
    committed = BASELINE.read_text(encoding="utf-8")
    root = _scratch_repo(tmp_path, committed)
    shrunk, _ = _without_one_finding(committed)
    _write(root, shrunk, staged=False)
    stale = root / ".git" / "COMMIT_EDITMSG"
    stale.write_text(
        f"previous commit\n\n{guard.TRAILER_KEY}: docs/UPGRADE.md — from an unrelated older commit\n",
        encoding="utf-8",
    )

    rc, output = guard.guard_result(root, "pre-commit", stale, BASELINE.name)
    assert rc == 1, f"a stale trailer must not false-pass:\n{output}"
    # and through the CLI, which is the shape the hook entry actually runs
    assert guard.main(["--stage", "pre-commit", "--repo", str(root), str(stale)]) == 1


def test_commit_msg_entry_without_a_message_file_fails_closed(tmp_path):
    """No message supplied at the commit-msg stage is NOT a pass: the guard refuses to read
    .git/COMMIT_EDITMSG outside the stage that owns it."""
    committed = BASELINE.read_text(encoding="utf-8")
    root = _scratch_repo(tmp_path, committed)
    shrunk, _ = _without_one_finding(committed)
    _write(root, shrunk, staged=True)
    (root / ".git" / "COMMIT_EDITMSG").write_text(
        f"older commit\n\n{guard.TRAILER_KEY}: docs/UPGRADE.md — stale\n", encoding="utf-8"
    )

    rc, output = guard.guard_result(root, "commit-msg", None, BASELINE.name)
    assert rc == 1, f"a missing message must fail closed:\n{output}"


def test_empty_trailer_value_is_not_a_declaration(tmp_path):
    """Paired negative: a bare `Baseline-removal-reason:` declares nothing."""
    assert guard.declared_removal_reason(f"subject\n\n{guard.TRAILER_KEY}:\n") is None
    assert guard.declared_removal_reason(f"subject\n\n{guard.TRAILER_KEY}: rotated credential removed\n")
    # a commented-out trailer (git strips those before the commit exists) is not a declaration
    assert guard.declared_removal_reason(f"subject\n\n# {guard.TRAILER_KEY}: nope\n") is None


def test_hook_args_and_interlock_scan_agree(tmp_path):
    """R6 alignment: the committed hook args ARE the canonical args, and the scan path they
    describe yields the finding set the committed baseline carries.

    #546's mechanism is two scan paths that stopped agreeing on the arg set, so the hook's
    `trim()` dropped entries the recorded baseline still had. This is the cell that makes
    that drift red rather than silent.
    """
    config_args = guard.config_hook_args(CONFIG)
    assert config_args == guard.HOOK_ARGS, (
        f".pre-commit-config.yaml carries {config_args} but the guard/interlock path uses "
        f"{guard.HOOK_ARGS} — the two scan arg sets have drifted (the #546 mechanism)"
    )
    patterns = tuple(config_args[i + 1] for i, a in enumerate(config_args) if a == "--exclude-files")
    assert (
        patterns == guard.EXCLUDE_FILE_PATTERNS
    ), f"the hook excludes {patterns}, the shared scan path excludes {guard.EXCLUDE_FILE_PATTERNS}"

    committed = _findings(json.loads(BASELINE.read_text(encoding="utf-8")))
    scanned = _findings(_full_tree_scan(tmp_path))
    assert scanned == committed, (
        f"the config-driven scan path and the committed baseline disagree: "
        f"+{sorted(scanned - committed)} -{sorted(committed - scanned)}"
    )
