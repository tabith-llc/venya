# Copyright (c) 2026 Tabith LLC.
# Use of this source code is governed by the Business Source License 1.1
# included in the LICENSE file at the root of this repository. As of the
# Change Date listed there, the work is available under MPL 2.0.
# SPDX-License-Identifier: BUSL-1.1

"""#732 — the redirect-target refusal names the failing index and the bound count,
and the docs teach the shape the guard actually accepts.

Two halves, one row. The gate's accept set is built in
`executor.py:_bound_secret_paths` as `{CONTAINER_SECRET_DIR}/{secret_id}` where
`secret_id` is `str()` of an **Integer** DB primary key — decimal digits, never a
key name. Half (a): the unbound-target refusal said only "SESSION-BOUND secret
path", naming neither the element nor how many paths were bound, so an operator
reading a 422 detail could not tell which argument died or whether the run bound
anything. The sibling arms in the same loop already name `Argument {i}` (the
fused-`<` arm, and the metacharacter arm of #713 form B); this arm now follows
that shape. Half (b): the documentation taught `/run/secrets/venya/<secret-id>`
and one literal `/run/secrets/venya/deploy_key` — a NAME — which is a target that
can never validate.

`#713 AC6` is preserved, not re-litigated: the fused-`<` raise keeps its own
sentence, names the SHAPE it tested, and carries no class word. The cells below
assert that arm is untouched by this change.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

from executor.executor import CONTAINER_SECRET_DIR, _validate_command_structure

REPO_ROOT = Path(__file__).resolve().parents[3]


class TestRefusalNamesIndexAndBoundCount:
    """Half (a) — the mechanism lives in one sentence, and it must teach two numbers."""

    def test_refusal_names_the_failing_index(self):
        """Positive: the `<` sits at argv index 3 here — the refusal must say 3,
        not leave the operator to count by hand."""
        with pytest.raises(ValueError) as got:
            _validate_command_structure(
                ["/usr/bin/sort", "-n", "-k", "2", "<", "/etc/passwd"],
                frozenset({f"{CONTAINER_SECRET_DIR}/1"}),
            )
        assert "Argument 4" in str(got.value), str(got.value)

    def test_refusal_names_the_bound_count_when_paths_are_bound(self):
        """Positive: two secrets bound -> the sentence says 2. That is the number
        that tells the operator whether the run bound anything at all."""
        with pytest.raises(ValueError) as got:
            _validate_command_structure(
                ["/usr/bin/cat", "<", "/run/secrets/venya/9"],
                frozenset({f"{CONTAINER_SECRET_DIR}/1", f"{CONTAINER_SECRET_DIR}/2"}),
            )
        assert "2 SESSION-BOUND secret path(s)" in str(got.value), str(got.value)

    def test_refusal_says_zero_when_nothing_is_bound(self):
        """Paired negative (the case the old sentence hid entirely): a run with NO
        secrets bound cannot validate ANY redirect target, and the refusal now says
        `0 SESSION-BOUND secret path(s)` instead of inviting another guess."""
        with pytest.raises(ValueError) as got:
            _validate_command_structure(["/usr/bin/sort", "<", f"{CONTAINER_SECRET_DIR}/4"], frozenset())
        assert "Argument 1" in str(got.value)
        assert "0 SESSION-BOUND secret path(s)" in str(got.value), str(got.value)

    def test_refusal_teaches_the_decimal_shape_and_rejects_a_name(self):
        """Half (a) as teaching: the sentence states the ONE accepted form and names
        the wrong one it refuses, so the operator does not have to find this file."""
        with pytest.raises(ValueError) as got:
            _validate_command_structure(["/usr/bin/sort", "<", f"{CONTAINER_SECRET_DIR}/deploy_key"], frozenset())
        reason = str(got.value)
        assert f"{CONTAINER_SECRET_DIR}/<N>" in reason, reason
        assert "decimal database primary key" in reason, reason
        assert "not its key name" in reason, reason

    def test_a_target_that_must_be_refused_is_still_refused(self):
        """Mandatory pair to the edits above: re-wording the sentence must not widen
        the gate. Every non-decimal or unbound target still raises."""
        for target in (
            "/etc/passwd",
            f"{CONTAINER_SECRET_DIR}/deploy_key",
            f"{CONTAINER_SECRET_DIR}/4x",
            f"{CONTAINER_SECRET_DIR}/../4",
            f"{CONTAINER_SECRET_DIR}/",
            f"{CONTAINER_SECRET_DIR}/-4",
        ):
            with pytest.raises(ValueError, match="SESSION-BOUND"):
                _validate_command_structure(
                    ["/usr/bin/cat", "x", "<", target],
                    frozenset({f"{CONTAINER_SECRET_DIR}/4"}),
                )

    def test_a_decimal_bound_target_still_validates(self):
        """The corrected shape is not merely readable — it ACCEPTS. This is the cell
        that proves the docs fix teaches a target the guard validates."""
        bound = f"{CONTAINER_SECRET_DIR}/4"
        assert _validate_command_structure(["/usr/bin/cat", "<", bound], frozenset({bound})) == [
            "/usr/bin/cat",
            "<",
            bound,
        ]

    def test_refusal_echoes_no_element_value_and_stays_one_line(self):
        """No-echo bar (#713 AC3 / R-2631) carried onto this arm: the sentence names
        indexes and a count, never the rejected argument, and it stays one line so a
        forged extra journal/audit row is impossible."""
        with pytest.raises(ValueError) as got:
            _validate_command_structure(
                ["/usr/bin/sort", "<", f"{CONTAINER_SECRET_DIR}/sup3rsecret\nforged"],
                frozenset({f"{CONTAINER_SECRET_DIR}/1"}),
            )
        reason = str(got.value)
        assert "sup3rsecret" not in reason, "the refusal echoed the rejected target"
        assert "\n" not in reason and "\r" not in reason, "the refusal is not a single line"

    def test_ac6_of_713_is_preserved_the_fused_arm_is_unchanged(self):
        """STOP-condition guard (#713 AC6): the fused-`<` raise is a different arm and
        must keep its own sentence — names the index, names the SHAPE, carries no class
        word. This leg changed the unbound-TARGET arm only."""
        from executor.executor import METACHAR_CLASSES

        with pytest.raises(ValueError) as got:
            _validate_command_structure(["a<b"])
        reason = str(got.value)
        assert "Argument 0" in reason, reason
        assert "fused" in reason.lower(), reason
        for name, _chars in METACHAR_CLASSES:
            assert name not in reason, f"the fused-`<` sentence carried the class word {name!r}"


class TestDocsTeachTheValidatingShape:
    """Half (b) — the shipped teaching must not bless a target that can never validate.

    Predicate: the final component of a `/run/secrets/venya/...` path in documentation
    is either decimal digits, or an explicit placeholder for them. A placeholder naming
    the secret's KEY (`<secret-id>`, `<secret_id>`, `<name>`) or a literal key name
    (`deploy_key`) is the defect this row files.
    """

    #: Documentation read by an operator or an agent — the surfaces the ticket named.
    DOC_GLOBS = ("README.md", "docs/**/*.md")

    #: Placeholders that name the DECIMAL primary key, as opposed to the secret's key
    #: name. `<pk>`/`<SECRET_PK>` are legal here because the page that uses them defines
    #: them in the same sentence (full-lifecycle-test.md: "`pk` = the integer DB primary
    #: key, not the key name"); `<decimal-id>` is the corrected canon.
    DECIMAL_PLACEHOLDERS = frozenset({"<decimal-id>", "<pk>", "<SECRET_PK>", "<SECRET_ID>"})

    def test_no_documentation_teaches_a_name_shaped_target(self):
        seen = []
        for glob in self.DOC_GLOBS:
            for path in sorted(REPO_ROOT.glob(glob)):
                for n, line in enumerate(path.read_text().splitlines(), 1):
                    for m in re.finditer(r"/run/secrets/venya/([^\s`\"',)\]}]+)", line):
                        tok = m.group(1)
                        if tok.isdigit() or tok in self.DECIMAL_PLACEHOLDERS:
                            continue
                        seen.append(f"{path.relative_to(REPO_ROOT)}:{n}: {tok}")
        assert not seen, "documentation teaches a redirect target that can never validate:\n" + "\n".join(seen)

    def test_the_canonical_placeholder_is_declared_decimal(self):
        """Positive control for the cell above: the replacement text is present, so an
        empty `seen` list means the docs teach the shape — not that the filter found
        nothing to look at."""
        hits = sum(
            p.read_text().count(f"{CONTAINER_SECRET_DIR}/<decimal-id>")
            for glob in self.DOC_GLOBS
            for p in REPO_ROOT.glob(glob)
        )
        assert hits > 0, "no corrected documentation was found at all — the screen is blind"
