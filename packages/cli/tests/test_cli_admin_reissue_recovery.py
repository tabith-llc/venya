# Copyright (c) 2026 Tabith LLC.
# Use of this source code is governed by the Business Source License 1.1
# included in the LICENSE file at the root of this repository. As of the
# Change Date listed there, the work is available under MPL 2.0.
# SPDX-License-Identifier: BUSL-1.1

"""venya admin reissue-recovery-code (ticket recovery-code-reissue #296).

Ceremony wiring pinned at the command level: elevation FIRST (the operator
touches their key), then the mTLS admin POST carrying X-Elevation-Token,
then the code printed EXACTLY once with the custody warning. Mock style
follows test_cli_admin_admin_ca.py (direct cmd_ calls, MagicMock client).
"""

from types import SimpleNamespace
from unittest.mock import MagicMock, patch

from venya_cli.api_client import APIClientError
from venya_cli.commands import cmd_admin, cmd_admin_reissue_recovery_code

CODE = "ABCDEF-abcdef-012345-ABCDEF-abcdef-012345-ABCDEF-abcdef"


def _client():
    client = MagicMock()
    client.post.return_value = {"user_id": "admin-user", "recovery_code": CODE}
    return client


class TestAdminReissueRecoveryCode:
    def test_p1_ceremony_order_path_and_print_once(self, capsys):
        client = _client()
        with patch("venya_cli.commands._elevate", return_value="elev-tok") as elevate:
            rc = cmd_admin_reissue_recovery_code(client, SimpleNamespace())
        assert rc == 0
        elevate.assert_called_once_with(client)
        client.post.assert_called_once_with(
            "/api/v1/admin/recovery-code/reissue",
            json={},
            extra_headers={"X-Elevation-Token": "elev-tok"},
        )
        out = capsys.readouterr().out
        assert out.count(CODE) == 1, "code must print EXACTLY once"
        assert "shown ONCE" in out
        assert "off-site backup set" in out

    def test_n1_api_failure_rc1_no_code_leak(self, capsys):
        client = MagicMock()
        client.post.side_effect = APIClientError("403 Admin role membership required")
        with patch("venya_cli.commands._elevate", return_value="elev-tok"):
            rc = cmd_admin_reissue_recovery_code(client, SimpleNamespace())
        assert rc == 1
        captured = capsys.readouterr()
        assert CODE not in captured.out + captured.err
        assert "Recovery-code reissue failed" in captured.err

    def test_n2_elevation_failure_stops_before_post(self, capsys):
        client = MagicMock()
        with patch("venya_cli.commands._elevate", side_effect=APIClientError("elevation denied")):
            rc = cmd_admin_reissue_recovery_code(client, SimpleNamespace())
        assert rc == 1
        client.post.assert_not_called()

    def test_p2_dispatch_routes_to_verb(self):
        client = _client()
        args = SimpleNamespace(admin_command="reissue-recovery-code")
        with patch("venya_cli.commands.cmd_admin_reissue_recovery_code", return_value=0) as handler:
            rc = cmd_admin(client, args)
        assert rc == 0
        handler.assert_called_once_with(client, args)

    def test_n3_parser_accepts_verb_takes_no_args(self):
        from venya_cli.cli import create_parser

        ns = create_parser().parse_args(["admin", "reissue-recovery-code"])
        assert ns.admin_command == "reissue-recovery-code"
