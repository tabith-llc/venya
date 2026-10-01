# Copyright (c) 2026 Tabith LLC.
# Use of this source code is governed by the Business Source License 1.1
# included in the LICENSE file at the root of this repository. As of the
# Change Date listed there, the work is available under MPL 2.0.
# SPDX-License-Identifier: BUSL-1.1

"""Regression pin: AuditEvent.user_id must carry NO foreign key.

Migration 022 dropped audit_events.user_id -> users.user_id on purpose
(mTLS admin identities have no users row; the column stores the auth
principal verbatim regardless of mechanism). The model previously still
declared the FK — model-vs-migration drift that would make a future
autogenerate/migration diff hallucinate re-adding a dropped-by-ruling FK.
This pin inspects the model at import time so the drift class cannot
re-widen.
"""

from core.iam.models import AuditEvent


def test_audit_user_id_has_no_fk_per_migration_022():
    col = AuditEvent.__table__.columns["user_id"]
    assert len(col.foreign_keys) == 0
