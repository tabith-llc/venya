# Copyright (c) 2026 Tabith LLC.
# Use of this source code is governed by the Business Source License 1.1
# included in the LICENSE file at the root of this repository. As of the
# Change Date listed there, the work is available under MPL 2.0.
# SPDX-License-Identifier: BUSL-1.1

"""#590 — admin LOCAL commands must not demand a FIDO2 ceremony they never use.

`run_command` decided authentication BEFORE dispatch on credential posture alone
(admin_mtls_exempt at commands.py, `has_admin_mtls`), so with
VENYA_ADMIN_CERT/KEY unset — the natural state of a recovery operator and of a
never-initialised core — the ceremony gate fired for admin commands that issue
NO HTTP request (they read local CA files and prompt a passphrase). With no
config.json the URL resolves to the default http://localhost:8000 and the FIDO2
transport refuses non-https at construction (#521/#545), so run_command
returned 1 and the command body was never reached: the disaster-recovery path
unreachable on exactly the machine that needs it.

Truth table, per the house rule (this IS a permission gate — both halves):
* POSITIVE: the six body-verified local admin commands reach their handler
  with no cert pair, no bearer token, no config.json.
* NEGATIVE: every ceremony-requiring admin command (and every role command)
  with no pair and no token STILL demands the ceremony and fails closed.
  Including `admin revoke-executor`, whose handler takes `client` and
  delegates to a POST — local-by-signature-trap, gated on purpose.
* THIRD HALF: `admin cert renew` remains gated (RF-8b unchanged).
* Preserved raises: cert-without-key, key-without-cert and a nonexistent
  cert path still raise at APIClient construction even for a local command
  (the fix skips ONLY the ceremony, never the client construction).

No network, no VM, no ceremony hardware: the client is stubbed at the
constructor seam for the gate cells, and the real-body cell exercises
`export-ca-key` end-to-end down to its own local file check.
"""

from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import pytest
from venya_cli.api_client import APIClientAuthenticationError, APIClientError
from venya_cli.commands import _ADMIN_LOCAL_NO_REQUEST, run_command

_LOCAL_COMMANDS = [
    ("export-ca-cert", "cmd_admin_export_ca_cert"),
    ("export-ca-key", "cmd_admin_export_ca_key"),
    ("split-ca-key", "cmd_admin_split_ca_key"),
    ("restore-ca-key", "cmd_admin_restore_ca_key"),
    ("init-admin-ca", "cmd_admin_init_admin_ca"),
    ("generate-admin-cert", "cmd_admin_generate_admin_cert"),
]

# Admin subcommands that DO issue a request — the negative half must prove
# each still gets the ceremony. revoke-executor is here because its body
# delegates to executor_cert_revoke(), which posts (name alone would have
# mis-classified the family).
_REMOTE_ADMIN_COMMANDS = [
    "list",
    "create-user",
    "re-enroll",
    "revoke-executor",
    "revoke-admin-cert",
    "reissue-recovery-code",
]


def _ns(admin_command: object = None, **overrides: object) -> SimpleNamespace:
    base: dict[str, object] = {
        "command": "admin",
        "admin_command": admin_command,
        "server_url": None,
        "user_id": None,
    }
    base.update(overrides)
    return SimpleNamespace(**base)


@pytest.fixture(autouse=True)
def _clean_env(tmp_path: Path, monkeypatch):
    """Recovery posture: no admin pair, no server URL, no config.json."""
    for var in ("VENYA_ADMIN_CERT", "VENYA_ADMIN_KEY", "VENYA_SERVER_URL", "SSL_CERT_FILE"):
        monkeypatch.delenv(var, raising=False)
    monkeypatch.setenv("VENYA_CONFIG", str(tmp_path / "absent-config.json"))
    yield


def _stub_client(*, has_mtls: bool = False, token: str | None = None):
    """Patch run_command's APIClient seam: constructed client with the given
    credential posture, and a ceremony that FAILS CLOSED when invoked."""
    patcher = patch("venya_cli.commands.APIClient")
    client_cls = patcher.start()
    inst = client_cls.return_value
    inst.has_admin_mtls = has_mtls
    inst.config.access_token = token
    inst.authenticate.side_effect = APIClientAuthenticationError("stub: ceremony refused (no key)")
    return patcher, inst


class TestPositiveHalfLocalReachBody:
    @pytest.mark.parametrize("admin_command,handler", _LOCAL_COMMANDS)
    def test_local_command_reaches_handler_without_ceremony(self, admin_command, handler):
        """No pair, no token: the six local commands dispatch to their bodies;
        authenticate is NEVER called."""
        patcher, inst = _stub_client()
        try:
            with (
                patch("venya_cli.commands.version_advisory"),
                patch(f"venya_cli.commands.{handler}", return_value=0) as dispatched,
            ):
                rc = run_command(_ns(admin_command))
            assert rc == 0
            dispatched.assert_called_once()
            inst.authenticate.assert_not_called()
        finally:
            patcher.stop()

    def test_export_ca_key_real_body_reached_in_recovery_posture(self, tmp_path, capsys):
        """The #588-adjacent headline, at unit level: REAL client construction
        (no mocks on the gate path), default http URL, no config.json, no pair
        — `export-ca-key` arrives at its OWN body (the CA-file check on the
        recovery operator's empty ca_dir) instead of a ceremony error. The
        passphrase/unwrap prompts live downstream of this same check."""
        ca_dir = tmp_path / "empty-ca"
        ca_dir.mkdir()
        patcher = patch("venya_cli.commands.version_advisory")
        try:
            with patcher:
                rc = run_command(_ns("export-ca-key", ca_dir=str(ca_dir), output=str(tmp_path / "export.enc")))
        finally:
            patcher.stop()
        out = capsys.readouterr()
        assert rc == 1  # body's own file check, not the gate
        assert "CA key not found" in out.err
        assert "Authenticating with security key" not in out.out
        assert "Authentication failed" not in out.err


class TestNegativeHalfRemoteStaysGated:
    @pytest.mark.parametrize("admin_command", _REMOTE_ADMIN_COMMANDS)
    def test_remote_admin_command_still_demands_ceremony_and_fails_closed(self, admin_command):
        """No pair, no token: every request-issuing admin command STILL runs
        the ceremony and returns 1 when it fails. Nothing remote slips through."""
        patcher, inst = _stub_client()
        try:
            with (
                patch("venya_cli.commands.version_advisory"),
                patch("venya_cli.commands.cmd_admin") as never_dispatch,
            ):
                rc = run_command(_ns(admin_command))
            assert rc == 1
            inst.authenticate.assert_called_once_with(user_id=None)
            never_dispatch.assert_not_called()
        finally:
            patcher.stop()

    def test_role_command_outside_admin_still_gated(self):
        """Paired negative at the other class the exemption must not touch: a
        non-admin role command (`store`) keeps the ceremony."""
        patcher, inst = _stub_client()
        try:
            with (
                patch("venya_cli.commands.version_advisory"),
                patch("venya_cli.commands.cmd_store") as never_dispatch,
            ):
                rc = run_command(SimpleNamespace(command="store", server_url=None, user_id=None))
            assert rc == 1
            inst.authenticate.assert_called_once()
            never_dispatch.assert_not_called()
        finally:
            patcher.stop()


class TestThirdHalfRenewStaysGated:
    def test_cert_renew_demands_ceremony_without_pair(self):
        """RF-8b half preserved for the no-pair posture: `admin cert renew`
        needs the transport and the human session bearer, so it keeps the
        ceremony even though it lives under the `cert` family."""
        patcher, inst = _stub_client()
        try:
            with (
                patch("venya_cli.commands.version_advisory"),
                patch("venya_cli.commands.cmd_admin_cert") as never_dispatch,
            ):
                rc = run_command(
                    _ns(
                        "cert",
                        admin_cert_command="renew",
                        cert_path=str(Path("n.crt")),
                        key_path=str(Path("n.key")),
                    )
                )
            assert rc == 1
            inst.authenticate.assert_called_once_with(user_id=None)
            never_dispatch.assert_not_called()
        finally:
            patcher.stop()

    def test_bare_admin_without_subcommand_still_gated(self):
        """The predicate keys on a SET MEMBERSHIP, not a prefix: no
        admin_command at all is not local."""
        patcher, inst = _stub_client()
        try:
            with (
                patch("venya_cli.commands.version_advisory"),
                patch("venya_cli.commands.cmd_admin") as never_dispatch,
            ):
                rc = run_command(_ns(None))
            assert rc == 1
            inst.authenticate.assert_called_once()
            never_dispatch.assert_not_called()
        finally:
            patcher.stop()


class TestConstructionRaisesPreserved:
    """The fix skips ONLY the ceremony. Client construction still runs first,
    so the pairing and file-existence raises are untouched — proven here on a
    LOCAL command, the class the exemption now waves through."""

    def test_cert_without_key_still_raises_on_local_command(self, tmp_path, monkeypatch):
        cert = tmp_path / "admin.crt"
        cert.write_bytes(b"not really a cert")
        monkeypatch.setenv("VENYA_ADMIN_CERT", str(cert))
        with pytest.raises(APIClientError, match="VENYA_ADMIN_KEY is not"):
            run_command(_ns("export-ca-key"))

    def test_key_without_cert_still_raises_on_local_command(self, tmp_path, monkeypatch):
        key = tmp_path / "admin.key"
        key.write_bytes(b"not really a key")
        monkeypatch.setenv("VENYA_ADMIN_KEY", str(key))
        with pytest.raises(APIClientError, match="VENYA_ADMIN_CERT is not"):
            run_command(_ns("export-ca-key"))

    def test_nonexistent_cert_path_still_raises_on_local_command(self, tmp_path, monkeypatch):
        monkeypatch.setenv("VENYA_ADMIN_CERT", str(tmp_path / "gone.crt"))
        monkeypatch.setenv("VENYA_ADMIN_KEY", str(tmp_path / "gone.key"))
        with pytest.raises(APIClientError, match="does not exist"):
            run_command(_ns("export-ca-key"))


class TestLocalSetIsClosed:
    def test_local_set_is_exactly_the_body_verified_six(self):
        """Guard against silent widening: membership was established by reading
        each handler body (module docstring of the fix in commands.py); any new
        entry must earn its place the same way. `renew` and `revoke-executor`
        are the pinned non-members."""
        assert _ADMIN_LOCAL_NO_REQUEST == frozenset(name for name, _ in _LOCAL_COMMANDS)
        assert "cert" not in _ADMIN_LOCAL_NO_REQUEST
        assert "revoke-executor" not in _ADMIN_LOCAL_NO_REQUEST

    def test_cert_status_exempt_by_construction_not_by_this_set(self):
        """RF-8a already dispatches `admin cert status` BEFORE the APIClient
        exists; it must NOT also ride the #590 predicate (double exemption =
        drift bait)."""
        assert "cert" not in _ADMIN_LOCAL_NO_REQUEST
