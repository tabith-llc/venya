# Copyright (c) 2026 Tabith LLC.
# Use of this source code is governed by the Business Source License 1.1
# included in the LICENSE file at the root of this repository. As of the
# Change Date listed there, the work is available under MPL 2.0.
# SPDX-License-Identifier: BUSL-1.1

"""Finding 247 — a mis-pointed ``VENYA_CONFIG`` is named back, not silently outvoted.

The face this was measured on: ``config show`` answered the built-in ``http://localhost:8000``
with rc 0 for a path that had yielded nothing; ``list`` printed ``Authenticating with security
key...`` and then blamed the FIDO2 transport for a URL nobody typed; and with
``VENYA_CONFIG=/nope.json`` the directory-mode advisory audited ``/`` and told the operator to
secure the filesystem root by hand. Every branch sent the operator further from the one input
that was wrong, and the natural remedy — re-run the ceremony — costs a key touch and a
single-use enrollment token.

Cells, in the order the finding states them:

* AC1 — ``config show`` names the resolved path and never lets a default speak as configuration.
* AC2 — a role command whose named path yielded nothing stops before the banner, the prompt,
  the ceremony and any request.
* AC3 — the mode advisory runs on the directory of a config file that exists, and on nothing else.
* AC4 — ``venya --help`` names ``VENYA_CONFIG`` with its resolution rule, and the doubled
  ``Error: Error:`` prefix is folded to one.

Paired negatives ride each AC: the correct-path control stays byte-for-byte, a well-formed
unreachable URL still reaches the dial, an explicit ``--server-url`` is never second-guessed, a
0600 file at a valid path earns no new warning, and a path the PROGRAM supplied is never
reported as an operator error. No cell touches a real authenticator and none dials a server:
the ceremony seam is patched where a cell would otherwise reach it.
"""

import contextlib
import os
import sys
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import pytest
from venya_cli import api_client
from venya_cli.api_client import APIClient, Config, config_source_problem
from venya_cli.cli import _install_stderr_tee, _operator_error_line, create_parser, main
from venya_cli.commands import _https_refusal, cmd_config_show, run_command

CONFIGURED_URL = "https://core.example.test"
ROLE_ARGS = SimpleNamespace(command="list", server_url=None, user_id=None)


@contextlib.contextmanager
def _stderr_tee():
    """Install the process stderr tee, then hand sys.stderr back.

    The tee writes through to whatever stream pytest installed, so the capture still
    sees every line — this only keeps one cell from leaving the suite teed.
    """
    original = sys.stderr
    try:
        yield _install_stderr_tee()
    finally:
        sys.stderr = original


def _isolate_home(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """A scratch HOME, and no VENYA_SERVER_URL, so no cell reads this box's own config."""
    home = tmp_path / "home"
    home.mkdir(parents=True, exist_ok=True)
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.delenv("VENYA_SERVER_URL", raising=False)
    return home


def _role_dir(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, *, body: str | None = None) -> Path:
    """A role dir holding a config file, per the #365 isolation standard, 0600 inside 0700."""
    _isolate_home(tmp_path, monkeypatch)
    role = tmp_path / "role"
    role.mkdir(mode=0o700)
    cfg = role / "config.json"
    cfg.write_text(body if body is not None else '{"server_url": "' + CONFIGURED_URL + '"}')
    cfg.chmod(0o600)
    monkeypatch.setenv("VENYA_CONFIG", str(cfg))
    return role


# ---------------------------------------------------------------------------
# AC1 — config show names the path it resolved, and marks a default as a default
# ---------------------------------------------------------------------------


class TestConfigShowNamesItsInput:
    def test_correct_path_control_is_byte_identical(self, tmp_path, monkeypatch, capsys):
        """The control the finding ran on: a real file is reported exactly as before —
        same rc, same value line naming the configured URL, plus the path line."""
        role = _role_dir(tmp_path, monkeypatch)
        client = APIClient()
        assert cmd_config_show(client) == 0
        out = capsys.readouterr().out
        assert f"  Server URL: {CONFIGURED_URL}" in out
        assert "built-in default" not in out
        assert f"  Config File: {role / 'config.json'}" in out

    def test_directory_path_fails_closed_naming_it(self, tmp_path, monkeypatch, capsys):
        """AC1's shape, measured: the variable is named, the path is named, rc is non-zero,
        and NO server URL is printed at all — the invented value never reaches the screen."""
        role = _role_dir(tmp_path, monkeypatch)
        monkeypatch.setenv("VENYA_CONFIG", str(role))
        client = APIClient()
        assert cmd_config_show(client) == 1
        cap = capsys.readouterr()
        assert f"VENYA_CONFIG is set to '{role}'" in cap.err
        assert "is not a regular file" in cap.err
        assert "did you mean" in cap.err and str(role / "config.json") in cap.err
        assert "Server URL" not in cap.out
        assert f"Config File: {role}" in cap.out

    def test_missing_path_fails_closed_naming_it(self, tmp_path, monkeypatch, capsys):
        """AC2's other row: a path that does not exist is answered with the path and the
        cause, not with a URL and not with an audit of its ancestors."""
        _isolate_home(tmp_path, monkeypatch)
        missing = tmp_path / "nope.json"
        monkeypatch.setenv("VENYA_CONFIG", str(missing))
        client = APIClient()
        assert cmd_config_show(client) == 1
        cap = capsys.readouterr()
        assert f"VENYA_CONFIG is set to '{missing}'" in cap.err
        assert "does not exist" in cap.err
        assert "Server URL" not in cap.out
        assert "http://localhost:8000" not in cap.out

    def test_unreadable_file_names_the_cause(self, tmp_path, monkeypatch, capsys):
        _role_dir(tmp_path, monkeypatch, body="not json at all")
        client = APIClient()
        assert cmd_config_show(client) == 1
        assert "is not valid JSON" in capsys.readouterr().err

    def test_config_file_without_a_server_url_marks_the_default_differently(self, tmp_path, monkeypatch, capsys):
        """A file that WAS read but sets no URL is a different sentence from a file that
        was never read — both are defaults, only one is a config problem."""
        _role_dir(tmp_path, monkeypatch, body="{}")
        client = APIClient()
        assert cmd_config_show(client) == 0
        out = capsys.readouterr().out
        assert "  Server URL: http://localhost:8000 (built-in default — the config file sets no server URL)" in out
        assert "VENYA_CONFIG is set to" not in out

    def test_unset_variable_keeps_today_behavior_for_a_fresh_home(self, tmp_path, monkeypatch, capsys):
        """AC4's other half, stated exactly: with the variable unset there is no INPUT
        error to report, so rc stays 0 and resolution is untouched — only the default
        marker is new text on the value line."""
        _isolate_home(tmp_path, monkeypatch)
        monkeypatch.delenv("VENYA_CONFIG", raising=False)
        client = APIClient()
        assert cmd_config_show(client) == 0
        cap = capsys.readouterr()
        assert "built-in default — no config file read" in cap.out
        assert "Error" not in cap.err

    def test_unset_variable_with_a_default_config_file_is_byte_identical(self, tmp_path, monkeypatch, capsys):
        """AC4, the row the finding ran as its control: the variable absent and the file
        present at the default path — resolution and every printed line are unchanged.

        `DEFAULT_CONFIG_FILE` is a module constant frozen at import from the real HOME, so
        the cell patches the face the test is about rather than trusting HOME alone: this
        is also why no cell here may read this box's own `~/.config/venya`.
        """
        home = _isolate_home(tmp_path, monkeypatch)
        monkeypatch.delenv("VENYA_CONFIG", raising=False)
        cfg_dir = home / ".config" / "venya"
        cfg_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
        cfg = cfg_dir / "config.json"
        cfg.write_text('{"server_url": "' + CONFIGURED_URL + '"}')
        monkeypatch.setattr(api_client, "DEFAULT_CONFIG_FILE", cfg)
        client = APIClient()
        assert cmd_config_show(client) == 0
        cap = capsys.readouterr()
        assert f"  Server URL: {CONFIGURED_URL}\n" in cap.out
        assert "built-in default" not in cap.out
        assert f"  Config File: {cfg}" in cap.out
        assert cap.err == ""

    def test_program_supplied_path_is_never_an_operator_error(self, tmp_path, monkeypatch, capsys):
        """The gate is keyed on the operator's own variable, not on the Config having a
        path: `Config(config_file=...)` is the program choosing, so it stays silent."""
        _isolate_home(tmp_path, monkeypatch)
        monkeypatch.delenv("VENYA_CONFIG", raising=False)
        config = Config(config_file=tmp_path / "absent.json")
        assert config.source_error is None
        assert config.read is False


# ---------------------------------------------------------------------------
# AC2 — no mistyped path may cost a key touch
# ---------------------------------------------------------------------------


def _run_role_command_with_ceremony_seam_patched(args):
    """Drive the REAL dispatch and the REAL Config; patch only the ceremony method and the
    command body, so `authenticate.assert_not_called()` means no transport and no prompt was
    reached, and nothing that follows the ceremony dials a server."""
    with (
        patch.object(APIClient, "authenticate") as ceremony,
        patch.object(APIClient, "close"),
        patch("venya_cli.commands.version_advisory"),
        patch("venya_cli.commands.cmd_list", return_value=0),
    ):
        rc = run_command(args)
    return rc, ceremony


class TestCeremonyRefusedBeforeTheKey:
    def test_missing_named_path_stops_before_the_banner(self, tmp_path, monkeypatch, capsys):
        _isolate_home(tmp_path, monkeypatch)
        missing = tmp_path / "nope.json"
        monkeypatch.setenv("VENYA_CONFIG", str(missing))
        rc, ceremony = _run_role_command_with_ceremony_seam_patched(ROLE_ARGS)
        cap = capsys.readouterr()
        assert rc == 1
        ceremony.assert_not_called()
        assert "Authenticating with security key" not in cap.out
        assert f"VENYA_CONFIG is set to '{missing}'" in cap.err
        assert "Nothing was sent and no security key was touched." in cap.err
        # the invented URL is never the story the operator is told
        assert "http://localhost:8000" not in cap.err

    def test_directory_named_path_stops_before_the_banner(self, tmp_path, monkeypatch, capsys):
        role = _role_dir(tmp_path, monkeypatch)
        monkeypatch.setenv("VENYA_CONFIG", str(role))
        rc, ceremony = _run_role_command_with_ceremony_seam_patched(ROLE_ARGS)
        cap = capsys.readouterr()
        assert rc == 1
        ceremony.assert_not_called()
        assert "FIDO2" not in cap.err
        assert f"VENYA_CONFIG is set to '{role}'" in cap.err

    def test_well_formed_unreachable_url_still_reaches_the_dial(self, tmp_path, monkeypatch, capsys):
        """Paired negative, stated in the spec: this fix names inputs, it does not block
        network attempts. A configured URL that cannot resolve is still dialed."""
        _role_dir(tmp_path, monkeypatch, body='{"server_url": "https://nowhere.invalid"}')
        rc, ceremony = _run_role_command_with_ceremony_seam_patched(ROLE_ARGS)
        cap = capsys.readouterr()
        assert rc == 0  # the command body ran, on the URL the operator configured
        ceremony.assert_called_once_with(user_id=None)
        assert "VENYA_CONFIG is set to" not in cap.err

    def test_explicit_server_url_is_never_second_guessed(self, tmp_path, monkeypatch, capsys):
        """Paired negative: with `--server-url` the operator supplied the value being
        dialed, so a broken config path does not stop that command."""
        _isolate_home(tmp_path, monkeypatch)
        monkeypatch.setenv("VENYA_CONFIG", str(tmp_path / "nope.json"))
        args = SimpleNamespace(command="list", server_url="https://core.example.test", user_id=None)
        rc, ceremony = _run_role_command_with_ceremony_seam_patched(args)
        cap = capsys.readouterr()
        assert rc == 0  # the supplied URL is dialed; the broken path is not this command's blocker
        ceremony.assert_called_once_with(user_id=None)
        assert "VENYA_CONFIG is set to" not in cap.err

    def test_local_admin_command_is_not_stopped(self, tmp_path, monkeypatch, capsys):
        """Paired negative across #590's boundary: `admin cert status` reads no server URL
        at all, so a config path that yielded nothing is not its business."""
        _isolate_home(tmp_path, monkeypatch)
        monkeypatch.setenv("VENYA_CONFIG", str(tmp_path / "nope.json"))
        monkeypatch.delenv("VENYA_ADMIN_CERT", raising=False)
        monkeypatch.delenv("VENYA_ADMIN_KEY", raising=False)
        args = SimpleNamespace(
            command="admin",
            admin_command="cert",
            admin_cert_command="status",
            server_url=None,
            user_id=None,
            cert_path=None,
        )
        rc = run_command(args)
        cap = capsys.readouterr()
        assert "VENYA_CONFIG is set to" not in cap.err
        assert rc != 0  # the body's own missing-cert refusal, unchanged by this leg

    def test_source_error_sentence_names_the_path_first_and_the_default_second(self):
        """The wording is one sentence at every call site (installer idiom:
        `VENYA_HOSTS_FILE is set to '…', which is not an existing, writable regular file.`)."""
        line = config_source_problem(Path("/nope.json"))
        assert line is not None
        assert line.startswith("VENYA_CONFIG is set to '/nope.json', which does not exist")
        assert "must name the config FILE" in line
        assert config_source_problem(Path(__file__).resolve()) is not None  # a real file, unreadable as JSON


# ---------------------------------------------------------------------------
# AC3 — the mode advisory audits the directory that actually holds a secret
# ---------------------------------------------------------------------------


class TestModeAdvisoryScope:
    def test_missing_named_file_audits_nothing(self, tmp_path, monkeypatch, capsys):
        """The measured row: `VENYA_CONFIG=/nope.json` audited `/` and told the operator to
        `chmod` the filesystem root. The path is named instead, and nothing is audited."""
        _isolate_home(tmp_path, monkeypatch)
        monkeypatch.setenv("VENYA_CONFIG", "/nope-247-config.json")
        assert os.path.isdir("/")  # the object the old line audited, for the record
        with _stderr_tee():
            pass
        err = capsys.readouterr().err
        assert "looser than 0700" not in err
        assert "secure it manually" not in err

    def test_loose_dir_holding_a_real_config_is_still_tightened(self, tmp_path, monkeypatch, capsys):
        """Paired negative — the check was scoped, not weakened: a directory the CLI really
        writes secrets into still goes through the tightening ladder."""
        _isolate_home(tmp_path, monkeypatch)
        role = tmp_path / "role"
        role.mkdir(mode=0o755)
        cfg = role / "config.json"
        cfg.write_text('{"server_url": "https://core.example.test"}')
        cfg.chmod(0o600)
        monkeypatch.setenv("VENYA_CONFIG", str(cfg))
        with _stderr_tee():
            pass
        assert (role.stat().st_mode & 0o777) == 0o700

    def test_valid_0600_file_earns_no_new_warning(self, tmp_path, monkeypatch, capsys):
        role = _role_dir(tmp_path, monkeypatch)
        with _stderr_tee():
            pass
        err = capsys.readouterr().err
        assert "WARNING" not in err
        assert (role / "config.json").stat().st_mode & 0o777 == 0o600


# ---------------------------------------------------------------------------
# AC4 — --help names the variable, and one Error: is enough
# ---------------------------------------------------------------------------


class TestHelpAndPrefix:
    def test_help_names_venya_config_with_its_resolution_rule(self):
        text = " ".join(create_parser().format_help().split())  # argparse re-wraps; judge the words
        assert "VENYA_CONFIG" in text
        assert "names the config FILE" in text
        assert "built-in default" in text

    def test_generated_reference_names_the_variable_too(self):
        """AC6 has two faces: `--help` and `docs/cli-reference.md`. The document is
        GENERATED, so this cell reads the committed artifact — the drift interlock in
        test_cli_reference_doc.py is what proves it equals the generator's output."""
        doc = Path(__file__).resolve().parents[3] / "docs" / "cli-reference.md"
        assert "VENYA_CONFIG" in doc.read_text()

    def test_doubled_prefix_is_folded_at_the_catch_all(self):
        """The raise sites reuse the printed refusal verbatim, so the catch-all must not
        wrap a string that already opens with its own prefix."""
        refusal = _https_refusal(
            "http://localhost:8000",
            site="the FIDO2 ceremony transport",
            ticket="cli-dial-sites-missing-https-guard",
        )
        line = _operator_error_line(ValueError(refusal), SimpleNamespace(command="list"), None)
        assert line == refusal
        assert not line.startswith("Error: Error:")

    def test_unprefixed_message_still_gets_exactly_one_prefix(self):
        """Paired negative (#595 AC2): command bodies own their wording."""
        line = _operator_error_line(ValueError("CA key not found"), SimpleNamespace(command="admin"), None)
        assert line == "Error: CA key not found"

    def test_the_dial_refusal_reaches_the_operator_with_one_prefix(self, tmp_path, monkeypatch, capsys):
        """The other face of the doubling, on the measured verb: a config that really does
        hold a plaintext URL raises the shared refusal (which carries the printed `Error: `
        because `_require_https_server_url` prints it verbatim), and the catch-all wraps it
        exactly once. `Error: Error:` is what the finding recorded; this pins it away."""
        from venya_cli.fido2_client import Fido2ClientError

        _role_dir(tmp_path, monkeypatch, body='{"server_url": "http://localhost:8000"}')
        refusal = _https_refusal(
            "http://localhost:8000",
            site="the FIDO2 ceremony transport",
            ticket="cli-dial-sites-missing-https-guard",
        )
        monkeypatch.setattr(sys, "argv", ["venya", "list"])
        with (
            patch.object(APIClient, "authenticate", side_effect=Fido2ClientError(refusal)),
            patch.object(APIClient, "close"),
            patch("venya_cli.commands.version_advisory"),
        ):
            assert main() == 1
        err = capsys.readouterr().err
        assert "Error: Error:" not in err
        assert "Authentication failed: Error:" not in err
        assert "server URL must be https://" in err


class TestMainFaceEndToEnd:
    """The two verbs the operator actually ran, through `main()` — no network, no key."""

    def test_list_with_the_directory_mistake_names_the_input_not_the_transport(self, tmp_path, monkeypatch, capsys):
        role = _role_dir(tmp_path, monkeypatch)
        monkeypatch.setenv("VENYA_CONFIG", str(role))
        monkeypatch.setattr(sys, "argv", ["venya", "list"])
        assert main() == 1
        cap = capsys.readouterr()
        assert "Authenticating with security key" not in cap.out
        assert "FIDO2" not in cap.err
        assert f"VENYA_CONFIG is set to '{role}'" in cap.err

    def test_config_show_with_the_directory_mistake_exits_one_and_names_the_path(self, tmp_path, monkeypatch, capsys):
        role = _role_dir(tmp_path, monkeypatch)
        monkeypatch.setenv("VENYA_CONFIG", str(role))
        monkeypatch.setattr(sys, "argv", ["venya", "config", "show"])
        assert main() == 1
        cap = capsys.readouterr()
        assert f"  Config File: {role}" in cap.out
        assert f"VENYA_CONFIG is set to '{role}'" in cap.err
        assert "Server URL" not in cap.out

    def test_correct_path_control_through_main_is_unchanged(self, tmp_path, monkeypatch, capsys):
        role = _role_dir(tmp_path, monkeypatch)
        monkeypatch.setattr(sys, "argv", ["venya", "config", "show"])
        assert main() == 0
        cap = capsys.readouterr()
        assert f"  Server URL: {CONFIGURED_URL}" in cap.out
        assert f"  Config File: {role / 'config.json'}" in cap.out
        assert "WARNING" not in cap.err
        assert "VENYA_CONFIG is set to" not in cap.err
