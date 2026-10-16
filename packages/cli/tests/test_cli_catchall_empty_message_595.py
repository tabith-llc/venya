# Copyright (c) 2026 Tabith LLC.
# Use of this source code is governed by the Business Source License 1.1
# included in the LICENSE file at the root of this repository. As of the
# Change Date listed there, the work is available under MPL 2.0.
# SPDX-License-Identifier: BUSL-1.1

"""#595 — the process-wide CLI catch-all must not blank an empty-message exception.

`main()` used to print `f"Error: {e}"`, so any exception whose `str()` is empty reached the
operator as a bare `Error:` with the cause only in the tee'd log. These cells pin both
halves of the truth table: the blank case now names the type, the command and the next
step; the case that HAS a message prints exactly what it printed before.

Truth table (per AC2/AC3/AC4/AC6/AC8):
  empty-str exception -> named line, rc=1, log pointer still correct
  non-empty exception -> byte-identical `Error: <message>` (paired negative)
  --verbose           -> still re-raises, empty case included (developer gets the traceback)
  second/third/fourth empty classes (not getpass' EOFError) -> same named line
  the six getpass sites -> prompt failure leaves ZERO bytes behind (AC4)
  argv carrying a secret -> the new line never echoes a value (AC8)
AC5 (a real operator at a real terminal pressing Ctrl-D on a served core) is NOT RUN here:
it needs an owner-present fleet lane.
"""

import queue
import sys
from concurrent.futures import TimeoutError as FutureTimeoutError
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest
from venya_cli.at_rest_key import resolve_ca_key_path, rewrap_at_rest
from venya_cli.cli import _command_path, _operator_error_line, create_parser, main
from venya_cli.commands import (
    cmd_admin_export_ca_key,
    cmd_admin_restore_ca_key,
    cmd_store,
)

SERVER_PW = "srv-pw-595"  # pragma: allowlist secret — TEST passphrase, never real


def _real_key_pem() -> bytes:
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import ec

    return ec.generate_private_key(ec.SECP256R1()).private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )


def _encrypted_ca(tmp_path: Path) -> tuple[Path, bytes]:
    """AT-REST-ENCRYPTED fixture — the shape that reaches acquire_server_passphrase."""
    ca_dir = tmp_path / "ca"
    ca_dir.mkdir(parents=True, exist_ok=True)
    key = _real_key_pem()
    (ca_dir / "ca.key").write_bytes(rewrap_at_rest(key, SERVER_PW))
    return ca_dir, key


def _plaintext_ca(tmp_path: Path) -> Path:
    ca_dir = tmp_path / "ca"
    ca_dir.mkdir(parents=True, exist_ok=True)
    (ca_dir / "ca.key").write_bytes(_real_key_pem())
    return ca_dir


def _run_main(monkeypatch, tmp_path, exc, argv, *, role_dir: Path | None = None):
    """Drive the real `main()` with a command body that raises `exc`.

    HOME (and optionally VENYA_CONFIG) are pointed at tmp_path so the stderr tee is a real
    file under the role dir, exactly as the shipped isolation standard (#365) puts it.
    """
    monkeypatch.setenv("HOME", str(tmp_path / "home"))
    (tmp_path / "home").mkdir(parents=True, exist_ok=True)
    if role_dir is not None:
        role_dir.mkdir(parents=True, exist_ok=True)
        monkeypatch.setenv("VENYA_CONFIG", str(role_dir / "config.json"))
    else:
        monkeypatch.delenv("VENYA_CONFIG", raising=False)
    monkeypatch.setattr(sys, "argv", ["venya", *argv])
    with patch("venya_cli.commands.run_command", side_effect=exc):
        return main()


class TestOperatorErrorLineUnit:
    """The renderer itself, off the argparse path (fast half of AC1/AC2)."""

    def test_empty_message_line_names_type_and_next_step(self):
        args = SimpleNamespace(command="admin", admin_command="cert")
        line = _operator_error_line(EOFError(), args, Path("/role/venya.log"))
        assert "EOFError" in line, line
        assert "admin cert" in line, line
        assert "--verbose" in line, line
        assert "/role/venya.log" in line, line
        assert line.strip() != "Error:", "the blank render is the defect this row filed"

    def test_non_empty_message_is_byte_identical_to_the_old_print(self):
        """AC2 paired negative — command bodies own their wording; nothing is reformatted."""
        exc = ValueError("CA key not found at /var/lib/venya/ca")
        assert _operator_error_line(exc, SimpleNamespace(command="admin"), None) == f"Error: {exc}"
        assert str(exc)  # the guard below only fires for an EMPTY str()

    def test_whitespace_only_message_is_not_treated_as_blank(self):
        """Documented boundary: the contract is `str(e)` being empty, not looking blank."""
        exc = ValueError("   ")
        assert _operator_error_line(exc, SimpleNamespace(command="list"), None) == "Error:    "

    def test_missing_log_path_says_so_instead_of_pointing_at_nothing(self):
        line = _operator_error_line(queue.Empty(), SimpleNamespace(command="get"), None)
        assert "no error log could be written" in line, line
        assert "queue" not in line  # type name is Empty; the module is not interpolated

    def test_command_path_rebuilds_nested_and_top_level(self):
        parser = create_parser()
        assert _command_path(parser.parse_args(["admin", "cert", "renew"])) == "admin cert renew"
        assert _command_path(parser.parse_args(["login", "u"])) == "login"

    def test_command_path_carries_no_argument_values(self):
        """AC8 at the helper level: dests holding operator VALUES are never in the path."""
        args = create_parser().parse_args(["store", "my-key", "sup3r-s3cret-value", "--roles", "admin"])
        path = _command_path(args)
        assert path == "store", path
        assert "sup3r-s3cret-value" not in path and "my-key" not in path


class TestCatchAllEndToEnd:
    """The shipped `main()` path — an empty-message exception reaching an operator."""

    def test_empty_message_exception_prints_a_named_line(self, monkeypatch, capsys, tmp_path):
        """AC1 — type + command + next step + where the detail lives, rc=1."""
        rc = _run_main(monkeypatch, tmp_path, EOFError(), ["admin", "export-ca-key", "-o", "out.enc"])
        err = capsys.readouterr().err
        assert rc == 1
        assert "Error:" in err
        assert "EOFError" in err, err
        assert "admin export-ca-key" in err, err
        assert "--verbose" in err, err
        assert "carried no message" in err, err

    @pytest.mark.parametrize(
        "exc",
        [
            queue.Empty(),
            ValueError(),
            FutureTimeoutError(),
        ],
        ids=["queue.Empty", "bare ValueError", "futures TimeoutError"],
    )
    def test_second_third_fourth_empty_str_classes_are_named(self, monkeypatch, capsys, tmp_path, exc):
        """AC3 — the fix is not tuned to getpass' EOFError: str(exc) is empty, and each
        still gets a non-blank operator line naming its own type."""
        assert str(exc) == "", "fixture honesty: this class really does render empty"
        rc = _run_main(monkeypatch, tmp_path, exc, ["list"])
        err = capsys.readouterr().err
        assert rc == 1
        assert err.strip() != "Error:", err
        assert type(exc).__name__ in err, err

    def test_non_empty_exception_line_is_unchanged(self, monkeypatch, capsys, tmp_path):
        """AC2 paired negative through main(): byte-identical to the pre-fix print."""
        message = "CA key not found at /var/lib/venya/ca"
        rc = _run_main(monkeypatch, tmp_path, ValueError(message), ["admin", "cert", "status"])
        err = capsys.readouterr().err
        assert rc == 1
        assert f"Error: {message}\n" in err, err
        assert "carried no message" not in err, err

    def test_verbose_still_raises_for_the_empty_case(self, monkeypatch, tmp_path):
        """AC2 — the `if args.verbose: raise` arm is untouched for blank messages too."""
        with pytest.raises(EOFError):
            _run_main(monkeypatch, tmp_path, EOFError(), ["--verbose", "list"])

    def test_verbose_still_raises_for_a_message_exception(self, monkeypatch, tmp_path):
        with pytest.raises(ValueError):
            _run_main(monkeypatch, tmp_path, ValueError("boom"), ["--verbose", "list"])

    def test_log_pointer_line_still_printed_and_correct_under_role_isolation(self, monkeypatch, capsys, tmp_path):
        """AC6 — the named line and the shipped pointer line agree, and both name the
        VENYA_CONFIG role-dir log, not the personal default (#365 standard)."""
        role_dir = tmp_path / "role"
        rc = _run_main(monkeypatch, tmp_path, EOFError(), ["list"], role_dir=role_dir)
        err = capsys.readouterr().err
        log_file = role_dir / "venya.log"
        assert rc == 1
        assert f"error details logged to {log_file}" in err, err
        assert str(log_file) in err, err
        assert "EOFError" in log_file.read_text(), "the named line is tee'd into the log it points at"
        assert not (tmp_path / "home" / ".config" / "venya" / "venya.log").exists()

    def test_no_secret_value_appears_in_the_operator_line(self, monkeypatch, capsys, tmp_path):
        """AC8 — argv positionals can carry a secret; the command path never does."""
        rc = _run_main(
            monkeypatch,
            tmp_path,
            EOFError(),
            ["store", "my-key-name", "sup3r-s3cret-value", "--roles", "admin"],
        )
        err = capsys.readouterr().err
        assert rc == 1
        assert "sup3r-s3cret-value" not in err, err
        assert "my-key-name" not in err, err
        assert "EOFError" in err, err


class TestGetpassSitesLeaveNothingBehind:
    """AC4 — zero partial writes asserted at each of the six getpass sites, not assumed.

    Sites re-derived at base 664f267: commands.py cmd_store (:447), cmd_admin_export_ca_key
    (:4199, :4200), cmd_admin_restore_ca_key (:4412), at_rest_key.acquire_server_passphrase
    (:128), at_rest_key.restore_at_rest_bytes (:161). None of them has an enclosing Try (AST
    pass, this lane), so an EOF at any of them reaches the catch-all whole.
    """

    @staticmethod
    def _tty_stdin():
        return MagicMock(isatty=MagicMock(return_value=True))

    def test_site1_store_prompt_makes_no_request(self, monkeypatch, tmp_path):
        client, config_file = MagicMock(), tmp_path / "config.json"
        config_file.write_text("{}")
        client.close = MagicMock()
        client._http = MagicMock()
        monkeypatch.setattr(sys, "stdin", self._tty_stdin())
        args = SimpleNamespace(
            key="mykey",
            value=None,
            roles=["admin"],
            metadata=None,
            key_version="v1",
            shape=None,
            usage=None,
        )
        with patch("getpass.getpass", side_effect=EOFError), pytest.raises(EOFError):
            cmd_store(client, args)
        assert client._http.request.call_count == 0, "a failed prompt must not POST"

    def test_site2_export_first_prompt_writes_nothing(self, tmp_path):
        ca_dir = _plaintext_ca(tmp_path)
        out = tmp_path / "export" / "ca.key.enc"
        args = SimpleNamespace(output=str(out), ca_dir=str(ca_dir))
        with patch("getpass.getpass", side_effect=EOFError), pytest.raises(EOFError):
            cmd_admin_export_ca_key(args)
        assert not out.exists()
        assert not out.parent.exists(), "the staged directory is created only after both prompts"

    def test_site3_export_confirm_prompt_writes_nothing_and_leaves_no_temp(self, tmp_path):
        ca_dir = _plaintext_ca(tmp_path)
        out = tmp_path / "o.enc"
        args = SimpleNamespace(output=str(out), ca_dir=str(ca_dir))
        with patch("getpass.getpass", side_effect=["a-long-enough-phrase-595", EOFError]), pytest.raises(EOFError):
            cmd_admin_export_ca_key(args)
        assert not out.exists()
        assert not list(Path(tmp_path).glob(".venya-cabackup-*")), "no orphaned staged temp"

    def test_site4_restore_prompt_leaves_the_incumbent_key_untouched(self, tmp_path):
        ca_dir, _ = _encrypted_ca(tmp_path)
        key_path = resolve_ca_key_path(ca_dir)
        before = key_path.read_bytes()
        backup = tmp_path / "backup.enc"
        backup.write_bytes(b"not a real VENYACA1 blob")
        args = SimpleNamespace(mode="backup", backup_file=str(backup), shares=None, ca_dir=str(ca_dir))
        with patch("getpass.getpass", side_effect=EOFError), pytest.raises(EOFError):
            cmd_admin_restore_ca_key(args)
        assert key_path.read_bytes() == before, "the at-rest key keeps its bytes"
        assert not list(ca_dir.glob(".venya-*.tmp*")), "no staged write left behind"

    def test_site5_server_passphrase_prompt_writes_no_export(self, monkeypatch, tmp_path):
        """acquire_server_passphrase (:128) — reached through the export door, so the
        assertion is about the door's output, not just the helper's return."""
        ca_dir, _ = _encrypted_ca(tmp_path)
        monkeypatch.delenv("VENYA_CA_KEY_PASSPHRASE", raising=False)
        monkeypatch.setattr(sys, "stdin", self._tty_stdin())
        out = tmp_path / "o.enc"
        args = SimpleNamespace(output=str(out), ca_dir=str(ca_dir))
        with patch("getpass.getpass", side_effect=EOFError), pytest.raises(EOFError):
            cmd_admin_export_ca_key(args)
        assert not out.exists()
        assert ca_dir.is_dir()

    def test_site6_restore_bytes_prompt_on_absent_target_writes_nothing(self, monkeypatch, tmp_path):
        """restore_at_rest_bytes (:161) — absent target + tty prompt; the key path the
        caller would write stays absent and the function returns no bytes."""
        from venya_cli.at_rest_key import restore_at_rest_bytes

        key_path = tmp_path / "ca" / "ca.key"
        key_path.parent.mkdir(parents=True, exist_ok=True)
        monkeypatch.delenv("VENYA_CA_KEY_PASSPHRASE", raising=False)
        monkeypatch.setattr(sys, "stdin", self._tty_stdin())
        with patch("getpass.getpass", side_effect=EOFError), pytest.raises(EOFError):
            restore_at_rest_bytes(key_path, _real_key_pem())
        assert not key_path.exists()


class TestBoundaryHolds:
    """#593 owns the six getpass sites; this row owns the catch-all. Pinned as a guard."""

    def test_getpass_sites_themselves_are_unchanged_by_this_leg(self):
        """No site gained a try/except or a different prompt — the fix landed at one print.

        If this fails, the leg widened into #593's surface.
        """
        import inspect

        from venya_cli import at_rest_key, commands

        src = inspect.getsource(commands.cmd_admin_export_ca_key) + inspect.getsource(commands.cmd_admin_restore_ca_key)
        src += inspect.getsource(commands.cmd_store) + inspect.getsource(at_rest_key.acquire_server_passphrase)
        src += inspect.getsource(at_rest_key.restore_at_rest_bytes)
        assert "EOFError" not in src, "#593's door-level handling does not belong in this leg"
        assert src.count("getpass.getpass") == 6, "all six shipped prompts are still the ones that shipped"
