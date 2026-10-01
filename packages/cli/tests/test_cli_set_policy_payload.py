# Copyright (c) 2026 Tabith LLC.
# Use of this source code is governed by the Business Source License 1.1
# included in the LICENSE file at the root of this repository. As of the
# Change Date listed there, the work is available under MPL 2.0.
# SPDX-License-Identifier: BUSL-1.1

"""#289 — set-command-policy payload contract + CLI↔API-model drift guard.

Class killed: knob-inertness / dead-payload-key. The CLI POSTed
{"preset": ..., "custom": <PATH STRING>} while AdminSetCommandPolicyRequest
has no ``custom`` field — pydantic's default-ignore silently dropped the key
and the CLI printed success anyway (the file was never even opened).

Owner rulings cited (see #289 A1 note): Q1/Q5 remove the inert --custom and
add explicit --custom-allowed / --custom-dangerous (repeatable + comma-split,
#293 flatten idiom), each list REPLACES its stored counterpart; Q4 server
extra="forbid" (the 422 cell lives in packages/server/tests/test_admin.py);
Q8 this file's drift guard: every key the CLI can post to this route must be
a real model field — cross-import precedent test_executor_id_parity.py:23.
"""

import json
import tempfile
from pathlib import Path
from unittest.mock import MagicMock

import httpx2
import pytest
from server.routes.admin import AdminSetCommandPolicyRequest
from venya_cli.api_client import APIClient
from venya_cli.cli import create_parser
from venya_cli.commands import cmd_admin_set_policy


def _make_mock_response(status_code=200, json_data=None):
    mock = MagicMock(spec=httpx2.Response)
    mock.status_code = status_code
    if json_data is not None:
        mock.json.return_value = json_data
        mock.content = json.dumps(json_data).encode()
    else:
        mock.content = b""
        mock.json.return_value = {}
    mock.raise_for_status.return_value = None
    return mock


def _mock_client(response):
    """APIClient whose HTTP layer returns `response`; returns (client, captured)."""
    with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as f:
        f.write(b"{}")
        config_file = Path(f.name)
    client = APIClient(config_file=config_file)
    http = MagicMock()
    http.request.return_value = response
    client._http = http
    return client


def _post_body(client):
    """The json= body of the single captured POST."""
    call = client._http.request.call_args
    assert call[0][0] == "POST"
    assert call[0][1] == "/api/v1/admin/command-policy"
    return call[1]["json"]


class TestSetPolicyPayloadRealFields:
    """T1: flags map to the REAL API fields; the dead 'custom' key is gone."""

    def test_flags_map_to_real_fields(self, capsys):
        client = _mock_client(
            _make_mock_response(200, {"policy_name": "default", "preset": "balanced", "updated": True})
        )
        args = create_parser().parse_args(
            [
                "admin",
                "set-command-policy",
                "balanced",
                "--custom-allowed",
                "/usr/bin/ssh",
                "/bin/ls",
                "--custom-dangerous",
                "rm -rf",
                "dd",
            ]
        )
        assert cmd_admin_set_policy(client, args) == 0
        body = _post_body(client)
        assert body == {
            "preset": "balanced",
            "custom_allowed_commands": ["/usr/bin/ssh", "/bin/ls"],
            "custom_dangerous_patterns": ["rm -rf", "dd"],
        }
        assert "custom" not in body
        assert "Command policy set to 'balanced'." in capsys.readouterr().out

    def test_preset_only_touches_no_custom_keys(self, capsys):
        """N1: preset-only request posts exactly {"preset"} — zero custom keys."""
        client = _mock_client(_make_mock_response(200, {"policy_name": "default", "preset": "strict", "updated": True}))
        args = create_parser().parse_args(["admin", "set-command-policy", "strict"])
        assert cmd_admin_set_policy(client, args) == 0
        assert _post_body(client) == {"preset": "strict"}

    def test_success_print_suppressed_on_error(self, capsys):
        """H: non-2xx (raise_for_status) -> rc 1, stderr text, NO success print."""
        response = _make_mock_response(400, {"detail": "Command policy update failed"})
        response.raise_for_status.side_effect = httpx2.HTTPStatusError("400", request=MagicMock(), response=response)
        response.json.return_value = {"detail": "Command policy update failed"}
        client = _mock_client(response)
        args = create_parser().parse_args(["admin", "set-command-policy", "permissive"])
        assert cmd_admin_set_policy(client, args) == 1
        captured = capsys.readouterr()
        assert "Set policy failed" in captured.err
        assert "Command policy set" not in captured.out


class TestCustomFlagRemoved:
    """T2: the inert --custom is REMOVED (inert-surface doctrine, Q1/Q5)."""

    def test_custom_flag_rejected(self):
        with pytest.raises(SystemExit) as excinfo:
            create_parser().parse_args(["admin", "set-command-policy", "balanced", "--custom", "policy.toml"])
        assert excinfo.value.code == 2


class TestCsvRepeatableFlatten:
    """T5: comma- and space-separated tokens flatten + strip (Q5, #293 idiom)."""

    @pytest.mark.parametrize(
        "argv_tokens, expected",
        [
            (["a,b"], ["a", "b"]),
            (["a , b "], ["a", "b"]),
            (["a", "b,c"], ["a", "b", "c"]),
            (["single"], ["single"]),
        ],
    )
    def test_allowed_flatten(self, argv_tokens, expected):
        client = _mock_client(
            _make_mock_response(200, {"policy_name": "default", "preset": "balanced", "updated": True})
        )
        args = create_parser().parse_args(["admin", "set-command-policy", "balanced", "--custom-allowed", *argv_tokens])
        assert cmd_admin_set_policy(client, args) == 0
        assert _post_body(client)["custom_allowed_commands"] == expected

    def test_dangerous_flatten_independent(self):
        """Q3: each flag sets ITS list independently — omitted flag omits the key."""
        client = _mock_client(
            _make_mock_response(200, {"policy_name": "default", "preset": "permissive", "updated": True})
        )
        args = create_parser().parse_args(
            ["admin", "set-command-policy", "permissive", "--custom-dangerous", "sudo, su "]
        )
        assert cmd_admin_set_policy(client, args) == 0
        body = _post_body(client)
        assert body == {"preset": "permissive", "custom_dangerous_patterns": ["sudo", "su"]}
        assert "custom_allowed_commands" not in body


class TestPayloadKeyDriftGuard:
    """T6 (Q8): every key the CLI can post is a real AdminSetCommandPolicyRequest field.

    The class-killer: pydantic's default-ignore turns a CLI-side key rename
    into a silent no-op server-side. This pin makes any future invented key
    RED here before it can ship. Cross-import of the server model is the
    point (precedent: test_executor_id_parity.py:23) — do not replace with a
    hand-copied list.
    """

    @pytest.mark.parametrize(
        "argv",
        [
            ["admin", "set-command-policy", "strict"],
            ["admin", "set-command-policy", "balanced", "--custom-allowed", "/bin/ls"],
            ["admin", "set-command-policy", "permissive", "--custom-dangerous", "sudo"],
            [
                "admin",
                "set-command-policy",
                "balanced",
                "--custom-allowed",
                "/bin/ls,/usr/bin/ssh",
                "--custom-dangerous",
                "rm -rf",
            ],
        ],
    )
    def test_posted_keys_are_model_fields(self, argv):
        client = _mock_client(
            _make_mock_response(200, {"policy_name": "default", "preset": "balanced", "updated": True})
        )
        args = create_parser().parse_args(argv)
        assert cmd_admin_set_policy(client, args) == 0
        posted = set(_post_body(client))
        assert posted <= set(AdminSetCommandPolicyRequest.model_fields), (
            f"CLI posts keys {posted - set(AdminSetCommandPolicyRequest.model_fields)} "
            "that AdminSetCommandPolicyRequest does not define — pydantic would "
            "silently DROP them (the #289 dead-key class)."
        )
