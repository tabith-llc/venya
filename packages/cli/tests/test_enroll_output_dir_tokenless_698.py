# Copyright (c) 2026 Tabith LLC.
# Use of this source code is governed by the Business Source License 1.1
# included in the LICENSE file at the root of this repository. As of the
# Change Date listed there, the work is available under MPL 2.0.
# SPDX-License-Identifier: BUSL-1.1

"""#698 AC3 / gap 4 — `executor-enroll` must never report success on a zero-byte token.

`result.get("enrollment_token", "")` (`commands.py`, the `executor-enroll` body at the base of this
branch) accepts a response with **no token in it**, and the code carries on: it writes a **zero-byte**
`token`, prints the "Generated enrollment bundle" block, prints a SHA256 fingerprint of the
CA-only bundle, and returns 0. The operator gets a directory that looks complete and nothing to copy
to the executor.

**The bug is narrower than the ticket reads, and that matters.** `_request` calls
`response.raise_for_status()` and converts every 4xx/5xx into `APIClientAuthenticationError` (401) or
`APIClientError`, so a server error *cannot* reach the token line — the CLI does not mint on a 500.
What reaches it is a **2xx that carries no usable token**: an empty body (`_request` returns `{}` when
`response.content` is falsy), a 2xx JSON without the field, the field empty, the field whitespace, a
non-dict body, and — found while reading this file — **the 401-refresh retry path, which returns `{}`
for an empty retried response** on its own line, separate from the main one.

AC3's wording is the rule these cells hold: *"`--output-dir` must either write a token or fail loudly
… No branch of this may end in silence."*

Truth table (both halves are here, per the project's standing requirement):

| response | expected |
|---|---|
| well-formed token | rc 0, token at 0600, bundle block printed |
| field absent | rc != 0, "Nothing was minted." on stderr, no bundle block, **no token file** |
| field empty string | same |
| field whitespace-only | same — a whitespace token cannot authenticate, and `strip()` is applied before the emptiness test |
| body is `None` / a list | same, and no traceback reaches the operator |
| POST raises (4xx/5xx/connect) | unchanged: rc 1, and `--output-dir` still created (that is #616's ordering, not this leg) |

Plus `TestOrderingIsPinned`, which fails if anyone "tidies" the mkdir or the stale-token `unlink` to
sit after the POST — both are deliberate and both are commented in place.
"""

import json
import os
import stat
from unittest.mock import MagicMock

import httpx2
import pytest
from venya_cli.api_client import APIClient
from venya_cli.commands import cmd_admin_executor_enroll

GOOD_TOKEN = "enrl_exec_698_TEST"
BUNDLE_SENTINEL = "Generated enrollment bundle"
REFUSAL = "Nothing was minted."

CONFIG = {"server_url": "https://test-core.example"}


def _response(json_data, *, content: bytes | None = None):
    """A 2xx httpx response shape, as `_request` consumes it."""
    mock = MagicMock(spec=httpx2.Response)
    mock.status_code = 200
    mock.json.return_value = json_data
    # `content` None mirrors "the server answered 2xx with no body at all"
    mock.content = content if content is not None else (b"" if json_data is None else json.dumps(json_data).encode())
    mock.raise_for_status.return_value = None
    return mock


def _client():
    return APIClient(config_file=None)


def _args(output_dir=None):
    args = MagicMock()
    args.executor_id = "venya-exec-9"
    args.output_dir = str(output_dir) if output_dir is not None else None
    return args


@pytest.fixture
def no_cas(monkeypatch, tmp_path):
    """The CA copies are bundle decoration, not the token path — keep them absent and named so a
    missing-CA warning cannot be mistaken for this leg's refusal."""
    monkeypatch.setattr("venya_cli.commands._BUNDLE_CORE_CA", tmp_path / "absent.crt")
    monkeypatch.setattr("venya_cli.commands._BUNDLE_ADMIN_CA", tmp_path / "absent-admin.crt")


def _run(client, args):
    return cmd_admin_executor_enroll(client, args)


class TestPositiveDoesNotRegress:
    def test_good_token_writes_bundle_and_returns_zero(self, tmp_path, capsys, no_cas):
        client = _client()
        try:
            client._http = MagicMock()
            client._http.request.return_value = _response({"enrollment_token": GOOD_TOKEN, "expires_in_seconds": 900})
            bundle = tmp_path / "bundle"

            old = os.umask(0o022)
            try:
                rc = _run(client, _args(bundle))
            finally:
                os.umask(old)

            assert rc == 0
            out = capsys.readouterr().out
            assert BUNDLE_SENTINEL in out
            assert (bundle / "token").read_text() == GOOD_TOKEN
            assert stat.S_IMODE((bundle / "token").stat().st_mode) == 0o600
        finally:
            client.close()

    def test_good_token_without_output_dir_prints_the_token(self, capsys, no_cas):
        """The stdout-only branch is a success path too; a good token must still reach the operator."""
        client = _client()
        try:
            client._http = MagicMock()
            client._http.request.return_value = _response({"enrollment_token": GOOD_TOKEN})
            assert _run(client, _args(None)) == 0
            assert GOOD_TOKEN in capsys.readouterr().out
        finally:
            client.close()


class TestTokenlessResponseRefuses:
    """AC3's negative half, four shapes. Each asserts the SAME three things: non-zero rc, the named
    refusal on stderr with the executor id and the path, and no success text or token file left behind."""

    @pytest.mark.parametrize(
        "payload",
        [
            pytest.param({}, id="empty-dict-from-empty-body"),
            pytest.param({"expires_in_seconds": 900}, id="field-absent"),
            pytest.param({"enrollment_token": ""}, id="field-empty-string"),
            pytest.param({"enrollment_token": "   "}, id="field-whitespace-only"),
            pytest.param({"enrollment_token": None}, id="field-null"),
        ],
    )
    def test_output_dir_refuses_loudly(self, tmp_path, capsys, no_cas, payload):
        client = _client()
        try:
            bundle = tmp_path / "bundle"
            client._http = MagicMock()
            client._http.request.return_value = _response(payload)

            rc = _run(client, _args(bundle))
            captured = capsys.readouterr()

            assert rc != 0, f"a tokenless response returned success ({rc}) for {payload!r}"
            assert REFUSAL in captured.err, f"no named refusal on stderr for {payload!r}: {captured.err!r}"
            assert "venya-exec-9" in captured.err, "the refusal must carry the executor id"
            assert str(bundle) in captured.err, "the refusal must carry the path"
            assert BUNDLE_SENTINEL not in captured.out, f"a success block printed on {payload!r}"
            assert "SHA256" not in captured.out, f"a fingerprint printed for a bundle with no token: {payload!r}"
            assert not (bundle / "token").exists(), f"a zero-byte token was left behind on {payload!r}"
            # #616 stays honored: the directory itself IS created before the mint.
            assert bundle.is_dir()
        finally:
            client.close()

    @pytest.mark.parametrize(
        "payload",
        [
            pytest.param(None, id="body-null"),
            pytest.param([], id="body-list"),
            pytest.param("a string", id="body-string"),
        ],
    )
    def test_non_dict_body_refuses_without_a_traceback(self, tmp_path, capsys, no_cas, payload):
        """A non-dict 2xx body must not surface `AttributeError: 'list' object has no attribute 'get'`.

        At the base this shape raised through the generic `except Exception` and printed an
        attribute-error sentence — an accidental refusal, worded like a crash, with no path and no
        "Nothing was minted." This cell demands the named refusal instead.
        """
        client = _client()
        try:
            bundle = tmp_path / "bundle"
            client._http = MagicMock()
            client._http.request.return_value = _response(payload)

            rc = _run(client, _args(bundle))
            captured = capsys.readouterr()

            assert rc != 0
            assert REFUSAL in captured.err, captured.err
            assert BUNDLE_SENTINEL not in captured.out
            assert not (bundle / "token").exists()
            for leak in ("Traceback", "AttributeError", "object has no attribute"):
                assert leak not in captured.err, f"internal error text reached the operator: {captured.err!r}"
        finally:
            client.close()

    def test_stdout_only_branch_also_refuses(self, tmp_path, capsys, no_cas):
        """The no-`--output-dir` path printed `Token: ` with nothing after it and returned 0.

        Same defect, other branch — and the branch an operator without a bundle directory lands on.
        """
        client = _client()
        try:
            client._http = MagicMock()
            client._http.request.return_value = _response({"expires_in_seconds": 900})

            rc = _run(client, _args(None))
            captured = capsys.readouterr()

            assert rc != 0
            assert REFUSAL in captured.err, captured.err
            assert "Token:" not in captured.out, f"a blank token line printed as success: {captured.out!r}"
        finally:
            client.close()

    def test_empty_body_with_no_content_bytes(self, tmp_path, capsys, no_cas):
        """The exact reachable route `_request` documents: 2xx, `content` falsy -> `{}`.

        Pinned separately from `field-absent` because it is the route the brief names, and it is the
        one a mock with a JSON body would never exercise: `.json()` must not even be consulted.
        """
        client = _client()
        try:
            bundle = tmp_path / "bundle"
            client._http = MagicMock()
            client._http.request.return_value = _response(None, content=b"")

            rc = _run(client, _args(bundle))
            captured = capsys.readouterr()

            assert rc != 0
            assert REFUSAL in captured.err
            assert not (bundle / "token").exists()
        finally:
            client.close()


class TestOrderingIsPinned:
    """Both orderings are deliberate, both are commented in place, and a future cleanup will "tidy"
    them back into the bug. This is the cell that says no.

    The probe inspects the filesystem FROM INSIDE the POST call, which is the only way to pin
    "happened before the round trip" without reading the source as text.
    """

    def test_mkdir_and_stale_unlink_happen_before_the_post(self, tmp_path, no_cas):
        client = _client()
        try:
            bundle = tmp_path / "bundle"
            bundle.mkdir()
            stale = bundle / "token"
            stale.write_text("enrl_exec_STALE_DEAD_TOKEN")

            seen = {}

            def probe(*_a, **_kw):
                # observed at the moment the POST is issued, i.e. strictly before it returns
                seen["dir_exists"] = bundle.is_dir()
                seen["dir_mode"] = stat.S_IMODE(bundle.stat().st_mode) if bundle.is_dir() else None
                seen["stale_gone"] = not stale.exists()
                return _response({"enrollment_token": GOOD_TOKEN})

            client._http = MagicMock()
            client._http.request.side_effect = probe

            old = os.umask(0o022)
            try:
                rc = _run(client, _args(bundle))
            finally:
                os.umask(old)

            assert rc == 0
            assert seen, "the probe never ran — the command is not POSTing through _http"
            assert seen["dir_exists"] is True, "--output-dir must be created BEFORE the mint (#616)"
            assert seen["dir_mode"] == 0o700
            assert seen["stale_gone"] is True, "the stale token must be unlinked BEFORE the mint"
            assert (bundle / "token").read_text() == GOOD_TOKEN
        finally:
            client.close()

    def test_refusal_does_not_create_a_token_file_at_all(self, tmp_path, no_cas):
        """The failure branch must not create-then-delete; it must simply never create.

        Asserted by listing the directory, not by a `not exists` on the one name, so a stray temp file
        (`.venya-token-*`) left behind by a reordered write also fails here.
        """
        client = _client()
        try:
            bundle = tmp_path / "bundle"
            client._http = MagicMock()
            client._http.request.return_value = _response({})

            rc = _run(client, _args(bundle))

            assert rc != 0
            assert list(bundle.iterdir()) == [], f"the refusal left artifacts behind: {list(bundle.iterdir())}"
        finally:
            client.close()
