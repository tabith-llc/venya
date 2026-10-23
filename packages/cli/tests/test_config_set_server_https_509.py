# Copyright (c) 2026 Tabith LLC.
# Use of this source code is governed by the Business Source License 1.1
# included in the LICENSE file at the root of this repository. As of the
# Change Date listed there, the work is available under MPL 2.0.
# SPDX-License-Identifier: BUSL-1.1

"""#509 pins — ``venya config set-server`` must refuse a plaintext URL at the counter.

This is the PERSIST half of the owner's plaintext ruling (sec-sweep-low-informational
#17, 2026-09-21: REJECTED, not downgraded; re-affirmed on #509, note 3971355156:
"refuse at the counter"). ``config set-server`` writes ``server_url`` into
config.json, and that stored value becomes the ``base_url`` of every later API
call (login, refresh, secrets, audit, admin), so an accepted ``http://`` here
puts bearer tokens and secret payloads on the wire in the clear — no later
per-command guard can un-store it.

The guard is the SHARED ``_require_https_server_url`` helper (#521 lineage), not a
fifth hand-copied check (AC4). The refusal happens BEFORE assignment, so on refusal
nothing is written — the paired negative here is file-content equality, not just
a return code. No ``--force`` escape and no dev opt-out were added (AC3); the
``VENYA_TLS_VERIFY`` knob means "distrust this certificate over https", never
"no TLS", and is not consulted here.

Bare hostnames still normalize to ``https://`` and persist (AC2) — the form the
help text and the setup flow teach. An explicit scheme is NEVER rewritten: like
the register site (#508), normalization only fills a MISSING scheme, so an
uppercase ``HTTP://`` reaches the guard's case-sensitive https whitelist verbatim
and fails closed (at HEAD it was massaged into ``https://HTTP://...`` and written).
"""

import inspect
import json
from pathlib import Path
from types import SimpleNamespace

import pytest
from venya_cli.api_client import APIClient
from venya_cli.commands import _https_refusal, cmd_config_set_server

TICKET = "config-set-server-accepts-plaintext-url"


def _client(tmp_path: Path) -> APIClient:
    """A real APIClient over a real Config file — the persistence half must be
    tested on the file, not on a mock setter."""
    return APIClient(config_file=tmp_path / "config.json")


class TestRefusalAtTheCounter:
    """AC1: explicit http:// returns non-zero, names the https requirement, writes nothing."""

    def test_plaintext_url_returns_nonzero(self, tmp_path):
        client = _client(tmp_path)
        rc = cmd_config_set_server(client, SimpleNamespace(url="http://core.example.com"))
        assert rc == 1

    def test_plaintext_url_names_the_https_requirement(self, tmp_path, capsys):
        client = _client(tmp_path)
        cmd_config_set_server(client, SimpleNamespace(url="http://core.example.com"))
        err = capsys.readouterr().err
        assert "must be https://" in err
        assert TICKET in err
        # the ONE shared wording, not a variant (AC4)
        assert (
            err.strip()
            == _https_refusal(
                "http://core.example.com",
                site="venya config set-server",
                ticket=TICKET,
                detail="every later API call dials the value this command writes",
            ).strip()
        )

    def test_plaintext_url_writes_nothing_when_no_file_exists(self, tmp_path):
        cfg = tmp_path / "config.json"
        client = APIClient(config_file=cfg)
        cmd_config_set_server(client, SimpleNamespace(url="http://core.example.com"))
        assert not cfg.exists()

    def test_plaintext_url_leaves_an_existing_config_untouched(self, tmp_path):
        cfg = tmp_path / "config.json"
        cfg.write_text(json.dumps({"server_url": "https://good.example.com"}))
        before = cfg.read_text()
        client = APIClient(config_file=cfg)
        rc = cmd_config_set_server(client, SimpleNamespace(url="http://core.example.com"))
        assert rc == 1
        assert cfg.read_text() == before
        assert client.config.server_url == "https://good.example.com"

    def test_uppercase_plaintext_scheme_also_refused(self, tmp_path, capsys):
        """Normalization fills a MISSING scheme only — an explicit one is never
        rewritten, so HTTP:// fails the case-sensitive https whitelist."""
        cfg = tmp_path / "config.json"
        client = APIClient(config_file=cfg)
        rc = cmd_config_set_server(client, SimpleNamespace(url="HTTP://core.example.com"))
        assert rc == 1
        assert not cfg.exists()

    def test_venya_tls_verify_false_does_not_re_open_plaintext(self, tmp_path, monkeypatch):
        """The sanctioned knob is a distrust-cert escape, not a no-TLS escape."""
        monkeypatch.setenv("VENYA_TLS_VERIFY", "false")
        cfg = tmp_path / "config.json"
        client = APIClient(config_file=cfg)
        rc = cmd_config_set_server(client, SimpleNamespace(url="http://core.example.com"))
        assert rc == 1
        assert not cfg.exists()


class TestGoodPathsPreserved:
    """AC2: bare hostname normalizes to https:// and persists; https persists."""

    def test_bare_hostname_normalizes_and_persists(self, tmp_path, capsys):
        cfg = tmp_path / "config.json"
        client = APIClient(config_file=cfg)
        rc = cmd_config_set_server(client, SimpleNamespace(url="venya-core-1"))
        assert rc == 0
        assert "Server URL set to: https://venya-core-1" in capsys.readouterr().out
        assert json.loads(cfg.read_text())["server_url"] == "https://venya-core-1"

    def test_explicit_https_persists(self, tmp_path, capsys):
        cfg = tmp_path / "config.json"
        client = APIClient(config_file=cfg)
        rc = cmd_config_set_server(client, SimpleNamespace(url="https://core.example.com"))
        assert rc == 0
        assert json.loads(cfg.read_text())["server_url"] == "https://core.example.com"

    def test_trailing_slash_still_stripped(self, tmp_path):
        cfg = tmp_path / "config.json"
        client = APIClient(config_file=cfg)
        rc = cmd_config_set_server(client, SimpleNamespace(url="https://core.example.com/"))
        assert rc == 0
        assert json.loads(cfg.read_text())["server_url"] == "https://core.example.com"


class TestNoEscapeHatch:
    """AC3 paired negative: refusal only — no --force, no opt-out, shared guard."""

    def test_guard_is_the_shared_helper_not_a_fifth_copy(self):
        """AC4 wiring half: the command body calls the ONE helper."""
        body = inspect.getsource(cmd_config_set_server)
        assert "_require_https_server_url(" in body

    def test_no_force_or_opt_out_in_the_command(self):
        """The code (not the docstring — it NAMES the ruled-out hatch) gained no
        escape hatch: strip the docstring via ast, then ban the hatch vocabulary."""
        import ast

        tree = ast.parse(inspect.getsource(cmd_config_set_server))
        fn = tree.body[0]
        assert isinstance(fn, ast.FunctionDef)
        fn.body.pop(0)  # the module-style docstring Expr
        code = ast.unparse(fn)
        for banned in ("force", "insecure", "opt_out", "allow_http", "skip", "warn"):
            assert banned not in code

    def test_cli_parser_gained_no_escape_flag(self):
        """AC3 negative half at the CLI boundary: ``--force`` is not a recognized
        option of ``config set-server`` — argparse refuses it outright."""
        from venya_cli import cli

        parser = cli.create_parser()
        args = parser.parse_args(["config", "set-server", "https://core.example.com"])
        assert not [name for name in vars(args) if "force" in name or "insecure" in name]
        with pytest.raises(SystemExit):
            parser.parse_args(["config", "set-server", "--force", "http://core.example.com"])

    def test_refusal_precedes_the_assignment(self):
        """The write cannot happen on refusal: in the function body the guard
        block appears BEFORE the ``client.config.server_url`` assignment."""
        body = inspect.getsource(cmd_config_set_server)
        assert body.index("_require_https_server_url(") < body.index("client.config.server_url = url")
