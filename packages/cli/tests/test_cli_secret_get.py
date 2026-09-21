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
        """Positive: --unmask re-authenticates and sends the token via the
        X-Elevation-Token HEADER — never the query string.

        REWRITTEN (ticket cli-elevation-token-query-param-transport): this
        cell formerly PINNED `params={"unmask": True, "elevation_token": …}`
        as desired — the 5th instance of a test institutionalizing a bypass
        the server had already removed (`9732ee7` header-only transport).
        The pinned query param physically 403'd AND leaked the single-use
        token into the server access log (results-2026-09-21-0400 D2).
        """
        client = MagicMock()
        client.get.return_value = {"value": "plaintext-secret"}
        with patch("venya_cli.commands._elevate", return_value="elev_token_xyz") as mock_elev:
            rc = cmd_get(client, _args(unmask=True))
        assert rc == 0
        mock_elev.assert_called_once_with(client)
        client.get.assert_called_once_with(
            "/api/v1/secrets/db/password",
            params={"unmask": True},
            extra_headers={"X-Elevation-Token": "elev_token_xyz"},
        )
        # Token must never ride the query string (access-log leak).
        assert "elevation_token" not in client.get.call_args.kwargs["params"]

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

    def test_get_forwards_extra_headers_to_request(self):
        """Wire shape: APIClient.get() must forward extra_headers to _request
        (the cmd_get fix depends on it; post() already had this parameter)."""
        from venya_cli.api_client import APIClient

        client = APIClient.__new__(APIClient)  # no __init__ (no config/HTTP needed)
        with patch.object(APIClient, "_request", return_value={}) as mock_req:
            client.get("/p", params={"a": 1}, extra_headers={"X-Elevation-Token": "t"})
        mock_req.assert_called_once_with("GET", "/p", params={"a": 1}, extra_headers={"X-Elevation-Token": "t"})
