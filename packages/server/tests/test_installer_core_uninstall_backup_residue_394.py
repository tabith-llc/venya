# Copyright (c) 2026 Tabith LLC.
# Use of this source code is governed by the Business Source License 1.1
# included in the LICENSE file at the root of this repository. As of the
# Change Date listed there, the work is available under MPL 2.0.
# SPDX-License-Identifier: BUSL-1.1

"""Static cells: core uninstaller removes /var/backups/venya residue (#394).

install-venya-core.sh writes full pre-upgrade pg_dump snapshots into
/var/backups/venya; uninstall-venya-core.sh dropped everything else and
left the dumps behind an exit-0 "Removes everything" header claim.

Why static and not a behavioral tmpdir run (the #390 idiom): the core
uninstaller is root-gated (id -u) and every rm target is an absolute
system path (/opt, /etc, /var). Executing the REAL script against a
tmpdir tree would require rewriting those paths, and a rewritten copy is
not the script under test. These cells pin the source instead.

Truth table, both halves: (i) the header Removes-list and an rm line
cover /var/backups/venya; (ii) paired negative — the ONLY /var/backups
rm target is exactly /var/backups/venya (parent untouched, no globs),
and the path is not in the NOT-removed/Kept disclosure lists.
"""

import re
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[3]
SCRIPT = REPO_ROOT / "uninstall-venya-core.sh"


def _rm_targets(src: str) -> list[str]:
    """Absolute path targets of every rm command (continuations joined)."""
    joined = src.replace("\\\n", " ")
    targets: list[str] = []
    for line in joined.splitlines():
        stripped = line.strip()
        if stripped.startswith("#") or not stripped.startswith("rm "):
            continue
        targets.extend(t for t in stripped.split()[1:] if t.startswith("/"))
    return targets


def _source() -> str:
    return SCRIPT.read_text(encoding="utf-8")


def test_removes_list_and_rm_line_cover_backup_dir() -> None:
    """Positive half: header claim + an actual rm line name the dir."""
    src = _source()
    header = src.split("NOT removed")[0]
    assert "/var/backups/venya" in header, "Removes-list omits the backup dir"
    assert "/var/backups/venya" in _rm_targets(src), "no rm covers it"
    assert re.search(
        r'info "Removed /var/backups/venya', src
    ), "loud-removal printed line missing"


def test_only_venya_under_var_backups_is_removed() -> None:
    """Negative half: an unrelated pre-existing /var/backups path is
    untouched — the sole /var/backups target is exactly /var/backups/venya,
    no parent removal, no glob."""
    backups_targets = [t for t in _rm_targets(_source()) if "/var/backups" in t]
    assert backups_targets == ["/var/backups/venya"], backups_targets


def test_backup_dir_is_not_disclosed_as_kept() -> None:
    """The NOT-removed header block and the closing Kept echo must not
    claim the dumps are kept."""
    lines = _source().splitlines()
    start = next(i for i, l in enumerate(lines) if "NOT removed" in l)
    block = []
    for line in lines[start:]:
        if not line.startswith("#"):
            break
        block.append(line)
    kept_echo = [l for l in lines if "Kept (" in l]
    assert not any("/var/backups" in l for l in block + kept_echo)
    assert not any("/var/backups" in l for l in block + kept_echo)
