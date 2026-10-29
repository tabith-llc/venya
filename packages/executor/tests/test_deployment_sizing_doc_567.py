# Copyright (c) 2026 Tabith LLC.
# Use of this source code is governed by the Business Source License 1.1
# included in the LICENSE file at the root of this repository. As of the
# Change Date listed there, the work is available under MPL 2.0.
# SPDX-License-Identifier: BUSL-1.1

"""Guard: docs/deployment-sizing.md keeps stating the sizing truth that shipped (#567).

**The defect this exists to stop.** The #567 narrowing (merges `705de4e`, `9094a92`, `bffcde2`)
landed and NOTHING reads the page: `git grep -ln 'deployment-sizing' <dev> -- 'packages/*/tests/*'`
hits two files, and both only NAME the path inside their own strings (one asserts the doc path sits
in an executor refusal log line, one uses "deployment-sizing" as prose in a docstring). Neither opens
the file. So an edit that re-widens a claim — drops "unmeasured beyond 2", calls the 5 GB figure a
floor again, publishes a concurrency number, or lets the page's shipped default drift from the code
constant — lands green. That is the doc-drift class this repo has a law about, and the shape follows
the two shipped siblings: the beta-terms cite interlock and the #683 wording guard (positive pins plus
paired negatives fed to the same predicate, so a green run is a reading and not an absence).
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

import executor.config as _config_mod
from executor.config import SANDBOX_MEMORY_DEFAULT_MB, ExecutorConfig

REPO_ROOT = Path(__file__).resolve().parents[3]
DOC = REPO_ROOT / "docs" / "deployment-sizing.md"

#: The narrowed claims exactly as they shipped after #567. Each is one durable sentence,
#: whitespace-flattened on both sides so markdown line-wrap cannot rot the pin.
PINNED_CLAIMS = (
    "**concurrent active agent sessions**, not total enrolled users",
    "concurrent-sandbox RAM on this shape is **unmeasured beyond 2**",
    'The "5–8 GB RAM" sizing figure is **headroom**, not a floor',
    "this guide publishes **no** concurrency capacity",
)

#: The page's own per-sandbox default, checked against the CODE constant — not a hardcoded
#: number. If the shipped default moves and the page is not re-cut, this regex plus the
#: comparison in _doc_problems() is what reddens the run.
_DEFAULT_RE = re.compile(r"Shipped default: (\d+) MiB")

#: Carrier names the page advertises. If the module that owns the knob renames either, the
#: page is stale and this cell says so; the toml key is asserted on the model itself.
_ENV_NAME = "VENYA_EXECUTOR_SANDBOX_MEMORY_MB"
_TOML_KEY = "sandbox_memory_mb"


def _flat(text: str) -> str:
    return " ".join(text.split())


def _doc_problems(text: str, code_default_mib: int) -> list[str]:
    """Empty list = the page states the shipped sizing truth. Anything else names the drift."""
    flat = _flat(text)
    problems = [f"lost the claim: {claim!r}" for claim in PINNED_CLAIMS if _flat(claim) not in flat]
    match = _DEFAULT_RE.search(flat)
    if match is None:
        problems.append("the page no longer states a shipped per-sandbox default")
    elif int(match.group(1)) != code_default_mib:
        problems.append(
            f"page ships {match.group(1)} MiB; the code constant SANDBOX_MEMORY_DEFAULT_MB is "
            f"{code_default_mib} MiB — one of them is stale"
        )
    return problems


class TestSizingDocGuard567:
    def test_page_exists(self):
        assert DOC.exists(), "docs/deployment-sizing.md is gone — retire this guard deliberately, not by accident"

    def test_shipped_page_states_the_narrowed_claims(self):
        problems = _doc_problems(DOC.read_text(), SANDBOX_MEMORY_DEFAULT_MB)
        assert not problems, "\n".join(problems)

    def test_default_interlock_input_is_the_code_constant(self):
        # The guard compares the page against ExecutorConfig's real default, not a number
        # re-typed here: if the field default and the module constant ever disagree, the
        # page-pin below would greenly compare against the wrong one.
        assert ExecutorConfig.model_fields[_TOML_KEY].default == SANDBOX_MEMORY_DEFAULT_MB

    def test_carrier_names_advertised_by_the_page_still_exist_in_code(self):
        config_src = Path(_config_mod.__file__).read_text()
        assert _ENV_NAME in config_src, f"the page names {_ENV_NAME}; the config module no longer contains it"
        assert _TOML_KEY in ExecutorConfig.model_fields, f"the page's toml key {_TOML_KEY!r} is not a config field"


class TestSizingDocGuardIsFailable:
    """Paired negatives (AGENTS.md truth-table law): each form below re-widens one pinned claim
    the way it read BEFORE the #567 narrowing. The guard must call every one of them a problem,
    so the green cell above is a reading of the page, not an absence of detection.
    """

    _PAGE = DOC.read_text()

    # (label, true-string, false-form) — the replace MUST land, asserted, so a future
    # re-wording of the page turns this probe red instead of silently vacuating it.
    FALSE_FORMS = (
        (
            "capacity re-widened to users",
            "**concurrent active agent sessions**, not total enrolled users",
            "**total enrolled users**",
        ),
        ("concurrency silently budgeted", "is **unmeasured beyond 2**", "is measured sound up to four"),
        (
            "headroom re-claimed as a floor",
            "sizing figure is **headroom**, not a\nfloor",
            "sizing figure is the required\nfloor",
        ),
        ("default drifted from the code", "Shipped default: 1024 MiB", "Shipped default: 2449 MiB"),
    )

    @pytest.mark.parametrize("label,true_str,false_str", FALSE_FORMS, ids=[f for _, f, _ in FALSE_FORMS])
    def test_guard_goes_red_on_a_false_form(self, label, true_str, false_str):
        mutated = self._PAGE.replace(true_str, false_str)
        assert (
            mutated != self._PAGE
        ), f"probe {label!r} did not modify the page — the true string moved; re-pair this cell"
        problems = _doc_problems(mutated, SANDBOX_MEMORY_DEFAULT_MB)
        assert problems, f"the guard stayed green over a re-widened claim ({label})"
