# Copyright (c) 2026 Tabith LLC.
# Use of this source code is governed by the Business Source License 1.1
# included in the LICENSE file at the root of this repository. As of the
# Change Date listed there, the work is available under MPL 2.0.
# SPDX-License-Identifier: BUSL-1.1

"""Truth table for the run_command admin-mTLS headless auth gate.

Ticket cli-admin-mtls-headless-gate: the CLI forced interactive FIDO2 for
`venya admin ...` even when VENYA_ADMIN_CERT/KEY were configured, making the
installer banner's headless `sudo -u venya ... venya admin executor-enroll`
instruction impossible on a headless core. The server already authorizes
cert-only admin callers (require_admin shortcut, dependencies.py:324), so the
fix is a CLI-side exemption: when command == "admin" AND the client has admin
mTLS configured, skip authenticate() and let the server be the authority.

The load-bearing negative: the exemption must NOT fire for non-admin commands
even when the cert env is set -- role-gated routes (list/store/audit/...) still
require FIDO2/token, and the server 401s cert-only callers on those routes.
"""

from types import SimpleNamespace
from unittest.mock import MagicMock, patch

from venya_cli.commands import run_command


def _gate(command, *, access_token=None, has_admin_mtls=False):
    """Drive run_command's auth gate; return (authenticate_called, rc)."""
    client = MagicMock()
    client.config.access_token = access_token
    client.has_admin_mtls = has_admin_mtls
    args = SimpleNamespace(command=command, server_url=None, user_id=None)
    # Patch each dispatch target exercised so the test isolates the gate.
    with (
        patch("venya_cli.commands.APIClient", return_value=client),
        patch("venya_cli.commands.cmd_admin", return_value=0),
        patch("venya_cli.commands.cmd_list", return_value=0),
        patch("venya_cli.commands.cmd_init", return_value=0),
    ):
        rc = run_command(args)
    return client.authenticate.called, rc


class TestAdminMtlsGate:
    def test_admin_with_cert_skips_fido2(self):
        """THE FIX: admin + cert configured -> no interactive authenticate()."""
        called, rc = _gate("admin", has_admin_mtls=True)
        assert called is False
        assert rc == 0

    def test_admin_without_cert_still_prompts(self):
        """admin + no cert -> gate fires (FIDO2), unchanged."""
        called, _ = _gate("admin", has_admin_mtls=False)
        assert called is True

    def test_nonadmin_with_cert_still_prompts(self):
        """LOAD-BEARING NEGATIVE: cert env must NOT exempt role-gated commands.

        `venya list` with VENYA_ADMIN_CERT/KEY set still requires FIDO2/token --
        the exemption is scoped to command == 'admin' only.
        """
        called, _ = _gate("list", has_admin_mtls=True)
        assert called is True

    def test_nonadmin_without_cert_still_prompts(self):
        """list + no cert -> gate fires, unchanged."""
        called, _ = _gate("list", has_admin_mtls=False)
        assert called is True

    def test_admin_with_token_skips_fido2(self):
        """admin + existing access_token -> no authenticate() (pre-existing path)."""
        called, _ = _gate("admin", access_token="tok", has_admin_mtls=False)
        assert called is False

    def test_public_command_never_prompts(self):
        """init is public -> never authenticates, cert or not."""
        called, _ = _gate("init", has_admin_mtls=False)
        assert called is False
