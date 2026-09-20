# Copyright (c) 2026 Tabith LLC.
# Use of this source code is governed by the Business Source License 1.1
# included in the LICENSE file at the root of this repository. As of the
# Change Date listed there, the work is available under MPL 2.0.
# SPDX-License-Identifier: BUSL-1.1

"""`venya secret get` unmask elevation (ticket
sec-secret-caller-param-plaintext-bypass): the server now answers a tokenless
`?unmask=true` with 403, so `--unmask` must elevate first (WebAuthn re-auth,
same ceremony as credential add) and send the one-shot elevation token.
"""

from unittest.mock import MagicMock, patch

from venya_cli.api_client import APIClientError
from venya_cli.commands import cmd_get


def _args(key="db/password", unmask=False):
    args = MagicMock()
    args.key = key
    args.unmask = unmask
    return args


class TestSecretGetUnmaskElevation:
    def test_unmask_elevates_and_passes_token(self):
        """Positive: --unmask re-authenticates and sends the token."""
        client = MagicMock()
        client.get.return_value = {"value": "plaintext-secret"}
        with patch("venya_cli.commands._elevate", return_value="elev_token_xyz") as mock_elev:
            rc = cmd_get(client, _args(unmask=True))
        assert rc == 0
        mock_elev.assert_called_once_with(client)
        client.get.assert_called_once_with(
            "/api/v1/secrets/db/password",
            params={"unmask": True, "elevation_token": "elev_token_xyz"},
        )

    def test_no_unmask_no_elevation(self):
        """Paired negative: masked get never touches the security key."""
        client = MagicMock()
        client.get.return_value = {"value": "\u2022" * 8}
        with patch("venya_cli.commands._elevate") as mock_elev:
            rc = cmd_get(client, _args(unmask=False))
        assert rc == 0
        mock_elev.assert_not_called()
        client.get.assert_called_once_with(
            "/api/v1/secrets/db/password",
            params={"unmask": False},
        )

    def test_unmask_elevation_failure_returns_1(self):
        """Elevation refusal (no key, timeout, 401) → rc 1, no secret fetch."""
        client = MagicMock()
        with patch(
            "venya_cli.commands._elevate",
            side_effect=APIClientError("Elevation challenge failed"),
        ):
            rc = cmd_get(client, _args(unmask=True))
        assert rc == 1
        client.get.assert_not_called()
