# Copyright (c) 2026 Tabith LLC.
# Use of this source code is governed by the Business Source License 1.1
# included in the LICENSE file at the root of this repository. As of the
# Change Date listed there, the work is available under MPL 2.0.
# SPDX-License-Identifier: BUSL-1.1

"""Regression for ticket kv-revoke-missing-version-id.

`venya admin key-version revoke` shipped dead on arrival: the handler
(commands.py) requires args.version_id but the parser declared zero
arguments, so every invocation printed "Error: version_id required" and
returned 1 — while the server route /admin/key-versions/{id}/revoke exists.

Args are built from the SHIPPED parser (never hand-shaped mocks — the
lying-mock defect class), the client is a MagicMock asserting the exact
route the handler must POST.
"""

from unittest.mock import MagicMock

from venya_cli.cli import create_parser
from venya_cli.commands import cmd_admin


def test_kv_revoke_posts_version_route():
    args = create_parser().parse_args(["admin", "key-version", "revoke", "3"])
    assert args.version_id == "3"  # parser declares the positional (was missing)
    client = MagicMock()
    client.post.return_value = {}
    rc = cmd_admin(client, args)
    assert rc == 0
    client.post.assert_called_once_with("/api/v1/admin/key-versions/3/revoke")


def test_kv_revoke_requires_version_id():
    """Negative half: omitted id is an argparse usage error (exit 2)."""
    import pytest

    with pytest.raises(SystemExit) as exc:
        create_parser().parse_args(["admin", "key-version", "revoke"])
    assert exc.value.code == 2
