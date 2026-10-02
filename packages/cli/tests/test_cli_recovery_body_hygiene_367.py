# Copyright (c) 2026 Tabith LLC.
# Use of this source code is governed by the Business Source License 1.1
# included in the LICENSE file at the root of this repository. As of the
# Change Date listed there, the work is available under MPL 2.0.
# SPDX-License-Identifier: BUSL-1.1

"""#367 wire hygiene — recovery posts only the declared RecoveryRequest fields.

force/confirm were LOCAL CLI flags that RecoveryRequest never declared (servers
silently dropped them via extra="ignore"); shipping extra="forbid" would have 422'd
the break-glass path — so the body must not carry them. The flags themselves retired
with #377. Paired positive: the declared fields still cross.
"""

from types import SimpleNamespace
from unittest.mock import MagicMock

from venya_cli.commands import cmd_recovery


def test_recovery_body_declared_fields_only():
    client = MagicMock()
    cmd_recovery(client, SimpleNamespace(code="RECOVERYCODE", new_user_id="newadmin", force=True, confirm=True))
    body = client.post.call_args.kwargs["json"]
    assert "force" not in body
    assert "confirm" not in body
    assert set(body) == {"code", "new_user_id"}  # paired: declared fields intact


def test_recovery_path_unchanged():
    client = MagicMock()
    cmd_recovery(client, SimpleNamespace(code="c", new_user_id="u", force=False, confirm=False))
    assert client.post.call_args[0][0] == "/api/v1/recovery"
