# Copyright (c) 2026 Tabith LLC.
# Use of this source code is governed by the Business Source License 1.1
# included in the LICENSE file at the root of this repository. As of the
# Change Date listed there, the work is available under MPL 2.0.
# SPDX-License-Identifier: BUSL-1.1

"""#689 — the relay CN column comment the ORM declares and the one migration 042
builds are the SAME string, and neither names a development site.

A `Column(comment=)` is shipped DDL on PostgreSQL: the chain writes it for other
columns in `012_add_executor_token_admin_identity.py` (3x) and
`024_add_executor_model.py` (1x). So when #689 scrubbed the example CN out of
`CoreRelayCredential.common_name`, the change had two halves that can drift
apart independently — `models.py` and `042_…`. Nothing in the tree compared
them, and a comment that lives only in the ORM is precisely the drift this leg
found: `alembic check` against a fresh `upgrade head` chain reports 29
`modify_comment` operations at this tip, because migrations 040/041 created
those columns with no comment while `models.py` declares one for each.

Three halves, all directions:

1. The migration's `COLUMN_COMMENT` equals the model's declared comment — so a
   future edit to either alone goes red rather than shipping a schema that
   disagrees with the code that documents it.
2. The comment carries no private literal, judged by the SAME patterns the
   tree-wide guard uses — read from the guard module, not restated here. This
   is the house idiom for a cross-package helper (`test_pg_door_preflight_650.py
   loads `scripts/pg_door_preflight.py` the same way), and it is not a courtesy:
   the first draft of this file copied the private-literal vocabulary into a
   second regex, and the widened guard immediately reddened THIS file for it. A
   restated vocabulary is a second source of truth that drifts, and the guard
   catching its own duplier is the proof that duplication is the defect.
3. The guard is loadable and its pattern table is non-empty, so half 2 cannot
   pass because the imported vocabulary quietly went missing.
"""

import importlib.util
from pathlib import Path

from core.iam.models import CoreRelayCredential

_CORE_DIR = Path(__file__).resolve().parents[1]
_MIGRATION_PATH = _CORE_DIR / "alembic" / "versions" / "042_scrub_relay_cn_comment.py"
#: The tree-wide private-literal guard. Its patterns are the single authority
#: for what counts as private, so this file must not invent its own list.
_GUARD_PATH = _CORE_DIR.parent / "executor" / "tests" / "test_installer_no_private_literals.py"


def _load(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    # Registered before exec: the guard module is a package-adjacent test file
    # and resolving its own module identity needs sys.modules present.
    import sys

    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


def _load_migration():
    return _load("m042_relay_cn_comment", _MIGRATION_PATH)


def _private_classes() -> dict:
    return _load("private_literal_guard_for_042", _GUARD_PATH).PRIVATE_CLASSES


def test_migration_042_comment_matches_the_model_column():
    """The two halves of the ruled change are one string, not two that agree today."""
    migration = _load_migration()
    model_comment = CoreRelayCredential.__table__.columns["common_name"].comment
    assert migration.COLUMN_COMMENT == model_comment, (
        "models.py and 042_scrub_relay_cn_comment.py declare different comments for "
        f"core_relay_credentials.common_name: ORM {model_comment!r} vs DDL "
        f"{migration.COLUMN_COMMENT!r} — the schema and the code that documents it "
        "have drifted, so a fresh install and a read of models.py disagree"
    )


def test_migration_042_chains_onto_041():
    migration = _load_migration()
    assert migration.revision == "042"
    assert migration.down_revision == "041", "042 must chain onto the #684 admin registry"


def test_guard_vocabulary_is_loaded_before_anything_is_judged_green():
    """Paired negative for half 3: an empty or missing pattern table would let
    the cleanliness cell below pass on nothing."""
    classes = _private_classes()
    assert len(classes) >= 4, f"the tree-wide guard's pattern table is thin: {sorted(classes)}"


def test_relay_cn_comment_carries_no_private_literal():
    """Both copies clean — the model is what a reader sees, the migration is
    what the customer's schema actually holds, and either could reopen #689."""
    comment = CoreRelayCredential.__table__.columns["common_name"].comment
    assert comment is not None
    classes = _private_classes()
    for text, label in ((comment, "models.py"), (_load_migration().COLUMN_COMMENT, "migration 042")):
        found = sorted(cls for cls, pattern in classes.items() if pattern.search(text))
        assert not found, f"{label} names a development site or operator in a shipped comment: {found}"
