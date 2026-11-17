# Copyright (c) 2026 Tabith LLC.
# Use of this source code is governed by the Business Source License 1.1
# included in the LICENSE file at the root of this repository. As of the
# Change Date listed there, the work is available under MPL 2.0.
# SPDX-License-Identifier: BUSL-1.1

"""#810 route A, narrowed to the login path: a login that dialled a core persists that core.

The shipped shape: `venya login --server-url https://core` — or the `VENYA_SERVER_URL` form the
product itself prints as headless guidance — dials the named core for that one command (#398),
and #423 keeps that transient value out of the saved data. But the same login DOES save its
token, so the session file ends up holding a token and naming no core: a fresh MCP start over
that file dials its built-in `https://localhost` default with the bearer, while the CLI refuses
the same file. The fix folds the dialled core into the SAME save the token write already
performs, at the login verb only (`cmd_login` → `Config.merge_transient_core_for_login`).

Which cells can fail, and which are pins — stated as the review law asks:

- (a) flag login and (b) env login: RED at base. At base the file is exactly
  `{"access_token": ...}` with no core; at the tip it names both, written by ONE save.
- (d) the narrowing itself: non-login consumers that receive a transient core keep writing
  exactly what they wrote before — GREEN at both faces BY DESIGN. They go red only if this
  fix widens (#398/#423 stay closed); the store arm drives the mid-command ceremony that
  shares `authenticate()` with login, and the refresh arm drives the other shipped token-save
  site. `exec register` stays covered by the landed #398 cell, uncolored.
- (e) the https guard mirrored at persistence: a login that dialled a plaintext core makes
  it durable NEVER — pin, GREEN both faces.
- (f) a login that never completes writes nothing: the merge does not save, so a refused
  ceremony leaves no file at all — GREEN both faces, and it is the trust-boundary negative.

Cell (c), the read side, lives in packages/mcp/tests (capability isolation bars a cross-package
drive here); its fixture is the verbatim output of cell (a), pasted into both reports.
"""

import json
import os
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

from venya_cli.api_client import APIClient, Config
from venya_cli.commands import cmd_login, run_command

CORE = "https://core.example"
TOKEN = "tok-810"


def _login_args(**over):
    fields = {"command": "login", "user_id": "ada", "server_url": None}
    fields.update(over)
    return SimpleNamespace(**fields)


def _fido_ok(fido_cls):
    inst = MagicMock()
    inst.authenticate.return_value = {"session_token": TOKEN, "user_id": "ada"}
    fido_cls.return_value = inst
    return inst


class TestLoginPersistsDialledCore:
    """(a)/(b): RED at base — the shipped writer left the file naming no core."""

    def _drive(self, tmp_path, env, args):
        cfg = tmp_path / "config.json"
        saves = []
        original_save = Config.save

        def counted(self):
            saves.append(1)
            return original_save(self)

        environ = {"VENYA_CONFIG": str(cfg), **env}
        with (
            patch.dict(os.environ, environ, clear=True),
            patch("venya_cli.commands.version_advisory"),
            patch("venya_cli.fido2_client.Fido2Auth") as fido,
            patch.object(Config, "save", counted),
        ):
            _fido_ok(fido)
            rc = run_command(args)
        assert rc == 0
        return cfg, saves

    def test_a_flag_login_names_the_dialled_core_in_the_saved_file(self, tmp_path):
        cfg, saves = self._drive(tmp_path, {}, _login_args(server_url=CORE))
        data = json.loads(cfg.read_text())
        assert data == {"server_url": CORE, "access_token": TOKEN}
        # the same save the token write performs carries the core: one call, one document.
        assert len(saves) == 1

    def test_b_env_login_names_the_dialled_core(self, tmp_path):
        """The headless form the product PRINTS as guidance (`VENYA_SERVER_URL=... venya login`)."""
        cfg, _ = self._drive(tmp_path, {"VENYA_SERVER_URL": CORE}, _login_args())
        data = json.loads(cfg.read_text())
        assert data == {"server_url": CORE, "access_token": TOKEN}


class TestNarrowingNegatives:
    """(d): every non-login consumer answers exactly as #398/#423 describe today."""

    def test_store_auto_auth_saves_the_token_but_no_core(self, tmp_path):
        """The arm a wide fix would leak through: a NO-token `store --server-url …` runs the
        same `authenticate()` as login, via run_command's mid-command ceremony. It keeps
        writing the token-only file it writes today — persistence stays login's alone."""
        cfg = tmp_path / "config.json"
        args = SimpleNamespace(command="store", server_url=CORE, user_id=None)
        with (
            patch.dict(os.environ, {"VENYA_CONFIG": str(cfg)}, clear=True),
            patch("venya_cli.commands.version_advisory"),
            patch("venya_cli.commands.cmd_store", return_value=0),
            patch("venya_cli.fido2_client.Fido2Auth") as fido,
        ):
            _fido_ok(fido)
            rc = run_command(args)
        assert rc == 0
        data = json.loads(cfg.read_text())
        assert data == {"access_token": TOKEN}  # the #423 shape, unchanged
        assert "server_url" not in data

    def test_refresh_save_keeps_the_transient_in_memory(self, tmp_path):
        """The other shipped token-save site: refresh writes the new token and never the
        one-shot core, exactly as today (the landed #423 cell drives the plain setter; this
        drives the second writer named in the survey)."""
        cfg = tmp_path / "config.json"
        client = APIClient(server_url="https://oneshot.example", config_file=cfg)
        try:
            client.config.access_token = "tok-before"
            with patch.object(client, "_post_raw", return_value={"access_token": "tok-after"}):
                assert client.refresh_token() == "tok-after"
            data = json.loads(cfg.read_text())
            assert data == {"access_token": "tok-after"}
            assert "server_url" not in data
        finally:
            client.close()

    def test_login_without_transient_changes_only_the_token(self, tmp_path):
        """A plain login over a file that already names a core rewrites the token and leaves
        the core line exactly as it stood — no reformatting, no reordering surprises beyond
        the one key the ceremony owns."""
        cfg = tmp_path / "config.json"
        cfg.write_text(json.dumps({"server_url": "https://already.set.example"}))
        with (
            patch.dict(os.environ, {"VENYA_CONFIG": str(cfg)}, clear=True),
            patch("venya_cli.commands.version_advisory"),
            patch("venya_cli.fido2_client.Fido2Auth") as fido,
        ):
            _fido_ok(fido)
            assert run_command(_login_args()) == 0
        data = json.loads(cfg.read_text())
        assert data == {"server_url": "https://already.set.example", "access_token": TOKEN}


class TestHttpsGuardAtPersistence:
    """(e): the shipped https rule is mirrored where the core becomes durable."""

    def test_plaintext_core_is_never_made_durable_by_login(self, tmp_path):
        cfg = tmp_path / "config.json"
        with (
            patch.dict(os.environ, {"VENYA_CONFIG": str(cfg)}, clear=True),
            patch("venya_cli.commands.version_advisory"),
            patch("venya_cli.fido2_client.Fido2Auth") as fido,
        ):
            _fido_ok(fido)
            assert run_command(_login_args(server_url="http://clear.example")) == 0
        data = json.loads(cfg.read_text())
        assert data == {"access_token": TOKEN}
        assert "server_url" not in data


class TestMergeSavesNothingAlone:
    """(f): the merge does not write, so a ceremony that fails writes nothing."""

    def test_failed_login_leaves_no_file(self, tmp_path):
        from venya_cli.fido2_client import Fido2NotFoundError

        cfg = tmp_path / "config.json"
        client = APIClient(server_url=CORE, config_file=cfg)
        try:
            with patch("venya_cli.fido2_client.Fido2Auth") as fido:
                fido.return_value = MagicMock(authenticate=MagicMock(side_effect=Fido2NotFoundError("no key")))
                rc = cmd_login(client, SimpleNamespace(user_id="ada"))
            assert rc == 1
            assert not cfg.exists()
        finally:
            client.close()
