# Copyright (c) 2026 Tabith LLC.
# Use of this source code is governed by the Business Source License 1.1
# included in the LICENSE file at the root of this repository. As of the
# Change Date listed there, the work is available under MPL 2.0.
# SPDX-License-Identifier: BUSL-1.1

"""#377 retirement — recovery --force/--confirm are gone from the surface.

The flags were dead local no-ops after #367; nothing read them. Paired cells:
each retired flag is now REJECTED as an unknown option (SystemExit 2), and the
happy-path recovery flow parses and posts the same body as before (positive
control, reusing the cmd_recovery fixture idiom from test_cli_recovery_body_hygiene_367).
"""

from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest
from venya_cli.cli import create_parser
from venya_cli.commands import cmd_recovery


@pytest.mark.parametrize("flag", ["--force", "--confirm"])
def test_retired_flag_rejected_as_unknown(flag: str):
    with pytest.raises(SystemExit) as excinfo:
        create_parser().parse_args(["recovery", "CODE", "newadmin", flag])
    assert excinfo.value.code == 2


def test_happy_path_parses_unchanged():
    args = create_parser().parse_args(["recovery", "RECOVERYCODE", "newadmin"])
    assert args.code == "RECOVERYCODE"
    assert args.new_user_id == "newadmin"


def test_happy_path_body_unchanged():
    client = MagicMock()
    cmd_recovery(client, SimpleNamespace(code="RECOVERYCODE", new_user_id="newadmin"))
    body = client.post.call_args.kwargs["json"]
    assert set(body) == {"code", "new_user_id"}
