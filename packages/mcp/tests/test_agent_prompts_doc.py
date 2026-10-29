# Copyright (c) 2026 Tabith LLC.
# Use of this source code is governed by the Business Source License 1.1
# included in the LICENSE file at the root of this repository. As of the
# Change Date listed there, the work is available under MPL 2.0.
# SPDX-License-Identifier: BUSL-1.1

"""Interlock: the paste-ready agent prompt stays true to the tool surface.

Ticket mcp-agents-md-prompt-guidance (vehicle ruling (b)+(d), owner
2026-09-25): docs/agent-prompts.md is the customer-facing operating
contract pasted into agent instruction files. Its load-bearing claims are
pinned here to the live MCP tool surface so the doc cannot silently rot —
the same drift class as the list_secrets description (b06d2c4 promised what
the rendering never delivered), in documentation form.
"""

import asyncio
import re
from pathlib import Path

import pytest
from venya_mcp.server import list_tools

REPO_ROOT = Path(__file__).resolve().parents[3]
DOC = REPO_ROOT / "docs" / "agent-prompts.md"

# --- #683: the command-gate wording guard -------------------------------------------
# The needle test below only asked that "503" appeared in the paste-block, so the block
# could carry the claim "shell builtins are rejected (503) by design" and stay green —
# which it did until leg 199 fixed the wording. This guard reads the SENTENCE against
# what the shipped validator does (`packages/executor/src/executor/command_validator.py`:
# `_extract_command_path` resolves the token with shutil.which, `_validate_balanced`
# compares it to policy.trusted_paths, and the only refusal this gate emits reads
# "Command not in trusted paths"; there is no builtin table in the package at all).
# So a true statement of the rule (a) ties refusal to resolution into a trusted
# directory and (b) never says builtins are refused as a class.
# docs/secret-shapes.md carried the last surviving false sentence and had no guard of
# any kind before this file; it is covered here along with the other five pages.
GATE_PAGES = (
    "agent-prompts.md",
    "agents.md",
    "alpha-demo.md",
    "architecture.md",
    "installation.md",
    "secret-shapes.md",
)

_SENTENCE_SPLIT = re.compile(r"[.;]")
# "non-builtin" is a shape-taxonomy word, and BUILTIN_SHAPES is a secrets constant —
# neither is a claim about the command gate.
_BUILTIN_MENTION = re.compile(r"(?<!non-)\bbuiltins?\b", re.IGNORECASE)
_REFUSAL_VERB = re.compile(r"reject|refus|block|disallow|banned", re.IGNORECASE)
_RESOLUTION_CLAIM = re.compile(r"\bresolv\w*\b|\bresolution\b", re.IGNORECASE)
_TRUSTED_MENTION = re.compile(r"\btrusted\b", re.IGNORECASE)
_ADMISSION_VERB = re.compile(r"reject|refus|accept|qualif|\b503\b", re.IGNORECASE)
# Every honest sentence about this gate says one of these; a class claim says none.
_CLASS_EXEMPT = re.compile(
    r"\bno\b[^.;]{0,24}\bbuiltins?\b"  # "there is no builtin table"
    r"|\bbuiltins?\b[^.;]{0,24}\bnot\b"  # "builtins are not a refused class"
    r"|\bnot\b[^.;]{0,24}\bbuiltins?\b"  # "refusal is ... not by a builtin table"
    r"|\bnot\s+shell-ness\b|\bnot\s+a\s+refused\s+class\b|\bbut\s+not\b"
    r"|\bpass(?:es|ed)?\b",  # the builtins-with-a-real-binary half is stated
    re.IGNORECASE,
)


def _sentences(text: str) -> list[str]:
    """Whitespace-flattened, split on '.' and ';'.

    Flattening first is the point: the false sentence shipped wrapped across three
    lines in three different pages, so a line-by-line scan would have missed it.
    """
    return [s.strip() for s in _SENTENCE_SPLIT.split(" ".join(text.split())) if s.strip()]


def _class_assertions(text: str) -> list[str]:
    """Sentences asserting builtins are refused as a CLASS — the claim the gate does not implement."""
    hits = []
    for sentence in _sentences(text):
        if not _BUILTIN_MENTION.search(sentence) or not _REFUSAL_VERB.search(sentence):
            continue
        if _CLASS_EXEMPT.search(sentence):
            continue
        hits.append(sentence)
    return hits


def _resolution_claim_missing(text: str) -> bool:
    """True when no sentence ties command admission to resolution into a trusted directory."""
    return not any(
        _RESOLUTION_CLAIM.search(s) and _TRUSTED_MENTION.search(s) and _ADMISSION_VERB.search(s)
        for s in _sentences(text)
    )


def _gate_wording_problems(text: str, label: str) -> list[str]:
    """Empty list = this text states the shipped rule. Anything else says what is wrong."""
    problems = []
    if _resolution_claim_missing(text):
        problems.append(f"{label}: no sentence ties command refusal to resolution into a trusted directory")
    for sentence in _class_assertions(text):
        problems.append(f"{label}: class assertion over builtins: {sentence!r}")
    return problems


def _block() -> str:
    text = DOC.read_text()
    m = re.search(r"<!-- snippet-start -->(.*)<!-- snippet-end -->", text, re.DOTALL)
    assert m, (
        "paste-block markers (<!-- snippet-start/end -->) missing from "
        "docs/agent-prompts.md — the doc was restructured without updating "
        "the interlock"
    )
    block = m.group(1)
    # Paired negative: the guard must not pass because the block shrank to nothing.
    assert len(block.strip()) > 400, f"paste-block shrank to {len(block.strip())} chars — content drift?"
    return block


class TestAgentPromptsDocPinned:
    def test_every_mcp_tool_is_named_in_the_block(self):
        tools = asyncio.run(list_tools())
        assert tools, "list_tools() returned nothing — tool surface collapsed?"
        block = _block()
        missing = [t.name for t in tools if t.name not in block]
        assert not missing, (
            f"snippet omits tool(s) {missing} — either the tool surface grew "
            "(update the snippet + this interlock deliberately) or a tool was "
            "renamed (the snippet is now teaching a dead name)"
        )

    def test_block_carries_the_contract_claims(self):
        block = _block()
        for needle in (
            "[REDACTED:",  # marker format (filter.rs contract)
            "/run/secrets/venya",  # injection path contract (a2 resolved-usage)
            "usage",  # the ready-to-run template flow
            "503",  # status code for refusals (wording truth is guarded below)
            "401",  # human re-authentication rule
        ):
            assert needle in block, f"snippet lost the '{needle}' contract claim"

    def test_block_never_directs_a_web_fetch(self):
        block = _block()
        assert "http" not in block, (
            "paste-block contains a URL — the block is self-contained by design; "
            "agents must never need a web fetch to operate (owner ruling "
            "2026-09-25, live-cell evidence: the brief-fetch line cost a webfetch "
            "of GitHub navigation chrome)"
        )

    def test_doc_points_at_the_full_brief(self):
        text = DOC.read_text()
        assert "agents.md" in text, "doc no longer links the full operating brief"


class TestCommandGateWording:
    """#683: the command-gate sentence is pinned to what the validator does.

    The needle test above cannot see this class of error — a block carrying "shell
    builtins are rejected (503) by design" satisfies every needle, and that block was
    green for the whole period the claim was false. These cells read the wording instead.
    """

    def test_paste_block_states_the_shipped_rule(self):
        problems = _gate_wording_problems(_block(), "docs/agent-prompts.md paste-block")
        assert not problems, "\n".join(problems)

    def test_every_page_describing_the_gate_states_the_shipped_rule(self):
        problems = []
        for name in GATE_PAGES:
            page = REPO_ROOT / "docs" / name
            assert page.exists(), f"docs/{name} is gone — update GATE_PAGES deliberately"
            problems += _gate_wording_problems(page.read_text(), f"docs/{name}")
        assert not problems, "\n".join(problems)

    # Paired negative (AGENTS.md truth-table law): the guard must be capable of red, so a
    # green run is a reading and not an absence. Each form below is wording that actually
    # shipped before leg 199 swept it (pre-a230099e0 face, docs/agents.md:37,
    # docs/architecture.md:190, docs/installation.md:681, docs/secret-shapes.md:111).
    FALSE_CLAIMS = (
        "Commands: use absolute binary paths. Shell builtins are rejected (503) by design.",
        "Commands: absolute paths or bare PATH names; builtins and unresolvable tokens are refused.",
        "Commands: a name must resolve into a trusted directory. Shell builtins are refused by design.",
        # The sharpest form: the resolution half stated TRUE and present, so only the
        # class detector can catch it — a guard that passed on the missing-resolution
        # half alone would stay green here and miss the sentence that actually shipped.
        (
            "Commands: a command must resolve into a trusted directory or be refused (503). "
            "Shell builtins are rejected by design."
        ),
    )

    @pytest.mark.parametrize("claim", FALSE_CLAIMS)
    def test_guard_goes_red_on_a_class_claim(self, claim):
        assert _class_assertions(claim), f"guard let a class claim through: {claim!r}"
        problems = _gate_wording_problems(claim, "false block")
        assert problems, f"the wording guard as wired would stay green over: {claim!r}"

    def test_guard_does_not_flag_the_honest_form_alone(self):
        # Positive control for the negative control: the true sentence, same shape, same
        # verbs — if this went red the detector is blind to negation, not to drift.
        honest = (
            "Commands: a name that does not resolve into a trusted directory is refused (503); "
            "builtins are not a refused class, and `echo` has a real binary and passes."
        )
        assert not _class_assertions(honest), _class_assertions(honest)
        assert not _gate_wording_problems(honest, "honest block")
