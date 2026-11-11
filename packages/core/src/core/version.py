# Copyright (c) 2026 Tabith LLC.
# Use of this source code is governed by the Business Source License 1.1
# included in the LICENSE file at the root of this repository. As of the
# Change Date listed there, the work is available under MPL 2.0.
# SPDX-License-Identifier: BUSL-1.1

"""One canonical version rendering, and the face a running install came from.

Why this module exists: all seven plates declare the same string
(``version = "0.1.0beta3"``), but two build backends write that declaration into
installed metadata differently — hatchling copies it verbatim, setuptools (which
builds the executor, for its Rust extension) normalizes it to the PEP 440
canonical form. On one tree an operator could therefore read ``0.1.0beta3`` from
``venya --version`` and ``0.1.0b3`` from ``venya-executor --version`` and
reasonably conclude they were looking at two builds.

The direction chosen is *the surfaces move to the declaration*, not the other
way: the plates stay ``0.1.0beta3``, which is a PEP 440 legal declaration —
installers normalize it themselves, which is why all six ``dist-info``
directories already read ``0.1.0b3``. PEP 440 legality is therefore untouched,
the release record and the nameplate guard (which read the declaration) need no
edit, and every layer now answers with the string the repo declares.

Nothing here guesses. Absent metadata answers ``unknown``, an unreadable
repository answers ``unknown``, and a dirty working tree says so.
"""

from __future__ import annotations

import argparse
import os
import re
import subprocess  # nosec B404 — the build-face answer reads `git` beside the artifact; same system-tool seam as utils/disk_encryption.py
import sys
from importlib.metadata import PackageNotFoundError
from importlib.metadata import version as _pkg_version
from pathlib import Path

#: Operator-settable answer to "which face is this" — a release recipe, an
#: ``Environment=`` line in a unit, or a packaging job sets it, and it is printed
#: verbatim because it is an explicit statement, not an inference.
BUILD_COMMIT_ENV = "VENYA_BUILD_COMMIT"

#: Optional stamped file, read from this package's own directory: the
#: artifact-only route to a commit id, for a build that wants to carry one
#: without depending on the environment.
BUILD_COMMIT_FILENAME = "BUILD_COMMIT"

UNKNOWN = "unknown"

#: A version whose prerelease is in PEP 440 canonical letter form. Spelled
#: declarations do not match, so they pass through untouched and nothing is mapped twice.
_CANONICAL_PRE = re.compile(r"^(?P<base>\d+(?:\.\d+)*)(?P<pre>a|b|rc|c)(?P<num>\d+)$")

#: Canonical letter -> the spelling this repo uses in its plates and release record.
_SPELLED = {"a": "alpha", "b": "beta", "rc": "rc", "c": "rc"}


def dist_version(dist_name: str) -> str:
    """The version installed metadata carries for ``dist_name``.

    ``unknown`` when the distribution is not installed — never a literal, never a
    default that could pass for a release.
    """
    try:
        return _pkg_version(dist_name)
    except PackageNotFoundError:
        return UNKNOWN


def canonical_release(raw: str) -> str:
    """Render one version string in the spelling this repo declares.

    ``0.1.0b3`` -> ``0.1.0beta3``; an already-spelled or unrecognized value comes
    back untouched. A ``pre`` or ``c`` declaration normalizes to ``rc`` in metadata
    and renders as ``rc`` — that one step is not round-trippable, which is why the
    release record reads the plate directly instead of deriving a claim from here.
    """
    match = _CANONICAL_PRE.match(raw or "")
    if match is None:
        return raw
    return f"{match['base']}{_SPELLED[match['pre']]}{match['num']}"


def release_version(dist_name: str) -> str:
    """The one string every layer shows for ``dist_name``."""
    return canonical_release(dist_version(dist_name))


def _git(cwd: Path, *args: str) -> str | None:
    """Run git beside ``cwd``, or answer None. Never raises."""
    try:
        out = (
            subprocess.run(  # nosec B603 B607 — fixed argv, shell disabled, constant "git" on PATH, bounded by timeout
                ["git", *args],
                cwd=cwd,
                capture_output=True,
                text=True,
                timeout=5,
                check=False,
            )
        )
    except (OSError, subprocess.SubprocessError):
        return None
    if out.returncode != 0:
        return None
    return out.stdout.strip()


def _stamp_path() -> Path:
    """Where an installed ``BUILD_COMMIT`` stamp would sit: beside this module."""
    return Path(__file__).resolve().parent / BUILD_COMMIT_FILENAME


def build_identity() -> str:
    """Answer which face this code is, reachable from the running artifact.

    Priority: ``VENYA_BUILD_COMMIT`` → a ``BUILD_COMMIT`` file installed beside
    this module → the repository a checkout lives in → ``unknown``. An installed
    wheel or a tarball build has no ``.git``, so the honest answer there is
    ``unknown`` until someone stamps it; this function never prints a
    clean-looking sha it cannot prove. A checkout with uncommitted changes says
    ``<sha>+dirty``.
    """
    env_value = (os.environ.get(BUILD_COMMIT_ENV) or "").strip()
    if env_value:
        return env_value

    here = Path(__file__).resolve().parent
    stamp = _stamp_path()
    if stamp.is_file():
        try:
            tokens = stamp.read_text(encoding="utf-8").split()
        except (OSError, UnicodeDecodeError):
            # A stamp that cannot be decoded is not an answer, and it is not a reason to
            # stop the tool that reads it: `UnicodeDecodeError` is a `ValueError`, so
            # `except OSError` alone let it climb out of `--version` and past every
            # command that builds a parser (ticket #768, leg 1237's B1).
            tokens = []
        if tokens:
            return tokens[0]

    head = _git(here, "rev-parse", "--short", "HEAD")
    if not head:
        return UNKNOWN
    return f"{head}+dirty" if _git(here, "status", "--porcelain") else head


def version_line(dist_name: str) -> str:
    """The full answer a binary gives for ``--version``: the canonical release,
    then the face it was built from. The version stays the first token, so
    anything that parses it reads the same string it always read.
    """
    return f"{release_version(dist_name)} (build {build_identity()})"


class VersionAction(argparse._VersionAction):
    """An argparse ``--version`` action that renders when the flag is used.

    Why not ``action="version", version=version_line(...)``: that answer is built while
    the parser is being CONSTRUCTED, so every invocation of a binary — ``--help``, a
    subcommand, a daemon start — pays a file read and a ``git`` probe, and a failure
    inside that read stops the tool before it can do anything else. A version surface
    must not be able to brick the thing it describes (ticket #768, leg 1237's B1), so the
    line is produced here, when it is asked for.

    Printed plain, not through the help formatter: the formatter wraps at terminal width,
    and a wrapped face breaks the rule that the version is the first token.

    ``source`` is the caller's own answer, so this class invents nothing — ``core.version``
    renders for the layers that depend on core, and a standalone layer passes its reader.
    """

    def __init__(
        self,
        option_strings,
        version=None,
        dest=argparse.SUPPRESS,
        default=argparse.SUPPRESS,
        help=None,
        *,
        source,
    ):
        super().__init__(option_strings, version=version, dest=dest, default=default, help=help)
        self.source = source

    def __call__(self, parser, namespace, values, option_string=None):
        parser._print_message(f"{self.source()}\n", sys.stdout)
        parser.exit()
