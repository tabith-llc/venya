# Copyright (c) 2026 Tabith LLC.
# Use of this source code is governed by the Business Source License 1.1
# included in the LICENSE file at the root of this repository. As of the
# Change Date listed there, the work is available under MPL 2.0.
# SPDX-License-Identifier: BUSL-1.1

"""#447 guard — the shipped CLI caps its httpx2 range at the tested line.

``install-venya-cli.sh`` runs ``uv tool install .../packages/cli``, which
re-resolves ``httpx2`` from the DECLARED range: ``uv.lock`` does not travel to
the customer. An unbounded ``>=0.27.0`` lets an install pick a version no
gated suite ever ran (today's BETA DAY step 3 resolved 2.13.1).

This cell is the loud failure for a future edit that drops the bound. It reads
the shipped package's own ``pyproject.toml`` (no subprocess), asserts the
declaration carries an upper bound equal to the ruled cap, and checks the
range admits the tested line and refuses the line above it.
"""

import tomllib
from pathlib import Path

_CLI_PKG = Path(__file__).resolve().parents[1]
_PYPROJECT = _CLI_PKG / "pyproject.toml"

HTTPX2_NAME = "httpx2"
TESTED_LINE = "2.12.0"
UNTESTED_NEXT = "2.13.0"
RULED_RANGE = ">=0.27.0,<2.13.0"


def _dependencies() -> list[str]:
    with _PYPROJECT.open("rb") as handle:
        return list(tomllib.load(handle)["project"]["dependencies"])


def _httpx2_declaration() -> str:
    matches = [d for d in _dependencies() if d.startswith(HTTPX2_NAME)]
    assert matches, f"{HTTPX2_NAME} must stay declared in {_PYPROJECT.name}"
    return matches[0]


def _specifier(declaration: str) -> str:
    return declaration[len(HTTPX2_NAME) :]


def _bounds(specifier: str) -> tuple[tuple[int, ...], tuple[int, ...] | None]:
    """(floor, cap) — cap is None when the declaration carries no upper bound."""
    lower, _, upper = specifier.partition(",")
    floor = _version(lower.strip().removeprefix(">=").removeprefix(">"))
    cap_text = upper.strip().removeprefix("<=").removeprefix("<")
    return floor, _version(cap_text) if cap_text else None


def _version(text: str) -> tuple[int, ...]:
    return tuple(int(x) for x in text.split("."))


def test_httpx2_declaration_carries_an_upper_bound() -> None:
    """A dropped cap is a silent regression — this is the guard."""
    assert "<" in _specifier(_httpx2_declaration()), (
        f"{HTTPX2_NAME} must declare an upper bound; installs resolve a version " "no gated suite ran (refs #447)"
    )


def test_httpx2_declaration_is_the_ruled_range() -> None:
    assert _httpx2_declaration() == f"{HTTPX2_NAME}{RULED_RANGE}"


def test_range_admits_the_tested_line() -> None:
    floor, cap = _bounds(_specifier(_httpx2_declaration()))
    assert cap is not None, "httpx2 range must be capped (refs #447)"
    assert floor <= _version(TESTED_LINE) < cap


def test_range_refuses_the_untested_line_above() -> None:
    _floor, cap = _bounds(_specifier(_httpx2_declaration()))
    assert cap is not None, "httpx2 range must be capped (refs #447)"
    assert not _version(UNTESTED_NEXT) < cap
