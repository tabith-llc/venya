# Copyright (c) 2026 Tabith LLC.
# Use of this source code is governed by the Business Source License 1.1
# included in the LICENSE file at the root of this repository. As of the
# Change Date listed there, the work is available under MPL 2.0.
# SPDX-License-Identifier: BUSL-1.1

"""Leg 1426 §C: `exec audit` / `exec list` / `exec availability` can be told which core.

The bug (a seat's own cell 22, face `31c0ccc7`): these three verbs dial the core through the
shared `APIClient`, but none of their parsers carried the exec-family URL flag pair and
the `run_command` chokepoint stopped reading the precedence chain after `config.json`. An
operator holding no usable config.json got the plaintext default and this refusal:

    Error: server URL must be https:// — got 'http://localhost:8000'. ...

which named no flag and no env, while `exec register` and `exec heartbeat` had carried
`--core-url` / `--server-url` (dest=core_url) since #387.

Cells, and the paired negatives the law requires:

* the flag pair exists on all three verbs and reaches the client;
* the documented chain is honored IN FULL — flag > VENYA_SERVER_URL > config.json >
  executor.toml — including the fourth link these verbs skipped;
* a config.json the operator configured still beats executor.toml (the extension is a
  last link, not a re-ordering);
* no flag, no env, no config, no toml still refuses, with text that names the flag and
  the env;
* commands OUTSIDE the three verbs never gain an executor.toml read;
* `exec list`'s admin client-certificate requirement is untouched: the flag names which
  core to dial, never how it is authenticated.
"""

from __future__ import annotations

import os
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest
from venya_cli.api_client import DEFAULT_SERVER_URL, APIClient, APIClientError
from venya_cli.cli import create_parser
from venya_cli.commands import _EXEC_URL_TOML_VERBS, _exec_url_from_host_config, run_command

DIAL_VERBS = ("audit", "list", "availability")


def _parse(argv: list[str]):
    return create_parser().parse_args(argv)


class TestFlagPairOnTheThreeVerbs:
    """§C requirement 1: the same flag pair the rest of the family has."""

    @pytest.mark.parametrize("verb", DIAL_VERBS)
    def test_core_url_flag_parses_to_dest_core_url(self, verb):
        args = _parse(["exec", verb, "--core-url", "https://core.example"])
        assert args.command == "exec"
        assert args.exec_command == verb
        assert args.core_url == "https://core.example"

    @pytest.mark.parametrize("verb", DIAL_VERBS)
    def test_server_url_alias_is_the_same_dest(self, verb):
        args = _parse(["exec", verb, "--server-url", "https://core.example"])
        assert args.core_url == "https://core.example"

    @pytest.mark.parametrize("verb", DIAL_VERBS)
    def test_flag_defaults_to_none(self, verb):
        assert _parse(["exec", verb]).core_url is None

    @pytest.mark.parametrize("verb", DIAL_VERBS)
    def test_flag_reaches_the_shared_client(self, verb):
        """THE BUG: the typed URL must be the URL the verb dials."""
        client = MagicMock()
        client.config.access_token = "tok"
        client.has_admin_mtls = False
        args = _parse(["exec", verb, "--core-url", "https://flag.example"])
        with (
            patch("venya_cli.commands.APIClient", return_value=client) as mock_client,
            patch("venya_cli.commands.cmd_exec_group", return_value=0),
            patch.dict(os.environ, {}, clear=True),
        ):
            assert run_command(args) == 0
        assert mock_client.call_args.kwargs.get("server_url") == "https://flag.example"

    def test_flag_beats_env(self):
        """LOAD-BEARING NEGATIVE: an explicit flag is never overridden by the env."""
        client = MagicMock()
        client.config.access_token = "tok"
        client.has_admin_mtls = False
        args = _parse(["exec", "list", "--core-url", "https://flag.example"])
        with (
            patch("venya_cli.commands.APIClient", return_value=client) as mock_client,
            patch("venya_cli.commands.cmd_exec_group", return_value=0),
            patch.dict(os.environ, {"VENYA_SERVER_URL": "https://env.example"}, clear=True),
        ):
            run_command(args)
        assert mock_client.call_args.kwargs.get("server_url") == "https://flag.example"

    def test_empty_env_is_unset(self):
        client = MagicMock()
        client.config.access_token = "tok"
        client.has_admin_mtls = False
        args = _parse(["exec", "audit"])
        with (
            patch("venya_cli.commands.APIClient", return_value=client) as mock_client,
            patch("venya_cli.commands.cmd_exec_group", return_value=0),
            patch("venya_cli.commands.EXECUTOR_TOML_PATH", "/nonexistent/executor.toml"),
            patch.dict(os.environ, {"VENYA_SERVER_URL": ""}, clear=True),
        ):
            run_command(args)
        assert mock_client.call_args.kwargs.get("server_url") is None


class TestHostConfigLink:
    """§C requirement 2: the precedence chain these verbs document includes executor.toml."""

    def _toml(self, tmp_path: Path, url: str) -> Path:
        toml = tmp_path / "executor.toml"
        toml.write_text(f'server_url = "{url}"\n')
        return toml

    def test_toml_is_used_when_nothing_above_it_answered(self, tmp_path: Path):
        toml = self._toml(tmp_path, "https://toml.example")
        args = SimpleNamespace(command="exec", exec_command="list")
        cfg = tmp_path / "absent.json"
        with (
            patch("venya_cli.commands.EXECUTOR_TOML_PATH", str(toml)),
            patch.dict(os.environ, {"VENYA_CONFIG": str(cfg)}, clear=True),
        ):
            assert _exec_url_from_host_config(args) == "https://toml.example"

    def test_configured_config_json_beats_toml(self, tmp_path: Path):
        """The fourth link stays fourth: a config.json the operator wrote wins."""
        cfg = tmp_path / "config.json"
        cfg.write_text('{"server_url": "https://config.example"}')
        toml = self._toml(tmp_path, "https://toml.example")
        args = SimpleNamespace(command="exec", exec_command="list")
        with (
            patch("venya_cli.commands.EXECUTOR_TOML_PATH", str(toml)),
            patch.dict(os.environ, {"VENYA_CONFIG": str(cfg)}, clear=True),
        ):
            assert _exec_url_from_host_config(args) is None

    def test_default_config_json_falls_through_to_toml(self, tmp_path: Path):
        cfg = tmp_path / "config.json"
        cfg.write_text(f'{{"server_url": "{DEFAULT_SERVER_URL}"}}')
        toml = self._toml(tmp_path, "https://toml.example")
        args = SimpleNamespace(command="exec", exec_command="availability")
        with (
            patch("venya_cli.commands.EXECUTOR_TOML_PATH", str(toml)),
            patch.dict(os.environ, {"VENYA_CONFIG": str(cfg)}, clear=True),
        ):
            assert _exec_url_from_host_config(args) == "https://toml.example"

    def test_env_suppresses_the_toml_read(self, tmp_path: Path):
        toml = self._toml(tmp_path, "https://toml.example")
        args = SimpleNamespace(command="exec", exec_command="list")
        with (
            patch("venya_cli.commands.EXECUTOR_TOML_PATH", str(toml)),
            patch.dict(os.environ, {"VENYA_SERVER_URL": "https://env.example"}, clear=True),
        ):
            assert _exec_url_from_host_config(args) is None

    def test_missing_toml_yields_nothing(self, tmp_path: Path):
        args = SimpleNamespace(command="exec", exec_command="list")
        with (
            patch("venya_cli.commands.EXECUTOR_TOML_PATH", str(tmp_path / "absent.toml")),
            patch.dict(os.environ, {"VENYA_CONFIG": str(tmp_path / "absent.json")}, clear=True),
        ):
            assert _exec_url_from_host_config(args) is None

    def test_unreadable_toml_yields_nothing_and_does_not_raise(self, tmp_path: Path):
        """A malformed host config is 'nothing configured', never a crashed verb."""
        toml = tmp_path / "executor.toml"
        toml.write_text("this is not = = toml\n")
        args = SimpleNamespace(command="exec", exec_command="list")
        with (
            patch("venya_cli.commands.EXECUTOR_TOML_PATH", str(toml)),
            patch.dict(os.environ, {"VENYA_CONFIG": str(tmp_path / "absent.json")}, clear=True),
        ):
            assert _exec_url_from_host_config(args) is None


class TestScopedToThreeVerbs:
    """§C blast radius: nothing outside the three verbs gains an executor.toml read."""

    @pytest.mark.parametrize(
        ("command", "sub"),
        [
            ("admin", None),
            ("exec", "register"),
            ("exec", "heartbeat"),
            ("exec", "cert"),
            ("exec", "status"),
            ("run", None),
            ("get", None),
        ],
    )
    def test_other_commands_return_none(self, command, sub, tmp_path: Path):
        toml = tmp_path / "executor.toml"
        toml.write_text('server_url = "https://toml.example"\n')
        args = SimpleNamespace(command=command, exec_command=sub)
        with (
            patch("venya_cli.commands.EXECUTOR_TOML_PATH", str(toml)),
            patch.dict(os.environ, {"VENYA_CONFIG": str(tmp_path / "absent.json")}, clear=True),
        ):
            assert _exec_url_from_host_config(args) is None

    def test_verb_set_is_exactly_the_three(self):
        assert _EXEC_URL_TOML_VERBS == frozenset(DIAL_VERBS)


class TestRefusalTextNamesTheRepair:
    """§C requirement 3: a refusal that implies a config write when a flag exists."""

    def test_dial_seam_refusal_names_the_flag_and_the_env(self, tmp_path: Path):
        ca = tmp_path / "ca.crt"
        ca.write_bytes(_selfsigned_ca())
        client = APIClient(
            server_url="http://localhost:8000",
            config_file=tmp_path / "config.json",
        )
        try:
            with patch.dict(os.environ, {"SSL_CERT_FILE": str(ca)}, clear=True):
                # The anchor resolves (so the guard under test is the scheme check, not
                # the #530 anchor refusal), and the build branch runs: an http base_url
                # must die before any transport exists.
                with pytest.raises(APIClientError) as excinfo:
                    _ = client._http  # the property IS the dial branch: it must raise
        finally:
            client.close()
        text = str(excinfo.value)
        assert text.startswith("Error: server URL must be https:// — got 'http://localhost:8000'.")
        assert "--core-url" in text
        assert "VENYA_SERVER_URL" in text

    def test_the_sentence_is_still_built_in_one_place(self):
        """AC1 of #521: no site may hand-copy the refusal sentence."""
        from venya_cli import commands as commands_mod

        pkg = Path(commands_mod.__file__).parent
        needles = ("Plaintext http is ", "not supported for {site}")
        hits = sorted(f.name for f in pkg.glob("*.py") if all(n in f.read_text() for n in needles))
        assert hits == ["commands.py"]
        assert (pkg / "commands.py").read_text().count('f"Error: server URL must be https://') == 1


class TestCertRequirementUnchanged:
    """§C requirement 4: the flag names WHICH core, never how `exec list` authenticates."""

    def test_admin_pair_missing_still_refuses_at_construction(self, tmp_path: Path):
        cert = tmp_path / "admin.crt"
        cert.write_text("not a real cert\n")
        with patch.dict(
            os.environ,
            {"VENYA_ADMIN_CERT": str(cert), "VENYA_ADMIN_KEY": str(tmp_path / "absent.key")},
            clear=True,
        ):
            with pytest.raises(APIClientError, match="does not exist"):
                APIClient(server_url="https://core.example", config_file=tmp_path / "config.json")

    def test_half_set_pair_still_refuses(self, tmp_path: Path):
        with patch.dict(os.environ, {"VENYA_ADMIN_CERT": str(tmp_path / "admin.crt")}, clear=True):
            with pytest.raises(APIClientError, match="Both are required for admin mTLS."):
                APIClient(server_url="https://core.example", config_file=tmp_path / "config.json")

    def test_no_flag_no_env_no_config_resolves_to_nothing(self, tmp_path: Path):
        """THE paired negative the spec asks for: nothing is INVENTED.

        With no flag, no env, no config.json and no executor.toml, the fourth link
        yields nothing, so the client keeps its documented fallback and the plaintext
        refusal still fires at the dial seam (proved by
        `test_dial_seam_refusal_names_the_flag_and_the_env`) — now with text that names
        the flag and the env. The fix improves the remedy; it does not soften the gate.
        """
        args = SimpleNamespace(command="exec", exec_command="list")
        with (
            patch("venya_cli.commands.EXECUTOR_TOML_PATH", str(tmp_path / "absent.toml")),
            patch.dict(os.environ, {"VENYA_CONFIG": str(tmp_path / "absent.json")}, clear=True),
        ):
            assert _exec_url_from_host_config(args) is None

    def test_unknown_url_is_not_handed_to_the_client(self, tmp_path: Path):
        """`_get_server_url`'s last resort is the string "unknown" — never a dial target."""
        args = SimpleNamespace(command="exec", exec_command="audit")
        with (
            patch("venya_cli.commands.EXECUTOR_TOML_PATH", str(tmp_path / "absent.toml")),
            patch.dict(os.environ, {"VENYA_CONFIG": str(tmp_path / "absent.json")}, clear=True),
        ):
            assert _exec_url_from_host_config(args) is None


def _selfsigned_ca() -> bytes:
    import datetime

    from cryptography import x509
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import ed25519
    from cryptography.x509.oid import NameOID

    key = ed25519.Ed25519PrivateKey.generate()
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "t1426-ca")])
    now = datetime.datetime.now(datetime.UTC)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=1))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(key, None)
    )
    return cert.public_bytes(serialization.Encoding.PEM)
