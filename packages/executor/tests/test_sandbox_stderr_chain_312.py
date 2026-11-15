# Copyright (c) 2026 Tabith LLC.
# Use of this source code is governed by the Business Source License 1.1
# included in the LICENSE file at the root of this repository. As of the
# Change Date listed there, the work is available under MPL 2.0.
# SPDX-License-Identifier: BUSL-1.1

"""Leg 1360 instrument: where do a sandboxed command's stderr bytes actually go?

The estate finding (`O1146` set, ticket #312 / #791) says a ``venya run
--executor-id`` failure printed only its exit line while the executor's own
journal recorded a non-empty stderr, and placed the loss at the Stage-2 filter
hop. This cell tests THAT claim with the shipped route, not a reconstruction of
it: the executor's real ``_send_to_stage2`` dials a starlette ``TestClient``
mounted with the real ``routes/filter`` app, so the request model, the decode,
the bindings walk and the response model are production code.

This cell drives ONE run through the real code at each hop and prints the byte
length at hops 1, 3, 4 and 6. The transports (executor->core mTLS POST,
client->core HTTPS POST) are the only parts substituted, because a guest is not
available to a unit run; every field-carrying statement is the shipped one:

  hop 1  executor sandbox capture        ``Executor._filter_and_build_result``
  hop 2  Stage-1 local masking           ``executor.filter.filter_and_redact``
  hop 3  relay encode                    ``RelayResponse(...)`` as relay_listener.py builds it
  hop 4  core validate + re-emit         ``RelayResponse(**result)`` as routes/executors.py does
  hop 5  FastAPI response_model face     ``jsonable_encoder``
  hop 6  operator's stderr               ``venya_cli.commands.cmd_run``

The Stage-2 dial is answered by the server's real ``filter_output`` masking
function over the real ``FilterRequest``/``FilterResponse`` models, so a drop
inside that round-trip shows up here rather than being assumed.
"""

import importlib.util
import json
import sys
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest
from fastapi import FastAPI
from fastapi.encoders import jsonable_encoder
from server.routes import filter as filter_routes
from starlette.testclient import TestClient
from venya_contract.relay import RelayResponse

from executor.executor import Executor

# The shipped relay-listener fixtures, loaded by path rather than imported: the
# tests directory is not an installed package, and copying its PKI harness would
# be a second copy that can drift from the first.
_spec = importlib.util.spec_from_file_location("_rl_harness", str(Path(__file__).with_name("test_relay_listener.py")))
_rl = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_rl)

pk = _rl.pk

STDERR_BYTES = b"podman: no such file or directory: /usr/local/bin/tve\n"  # 53 bytes, the logged class
STDOUT_BYTES = b""


def _real_filter_route_client(session_id: str) -> TestClient:
    """The SHIPPED Stage-2 route as the executor's http_client face.

    ``_send_to_stage2`` calls ``http_client.post(url, json=..., timeout=...)``;
    TestClient answers that signature, so the executor's own encoder, the real
    ``FilterRequest`` decode, the no-bindings walk and the real
    ``FilterResponse`` model all run.
    """
    from unittest.mock import MagicMock

    app = FastAPI()
    app.include_router(filter_routes.router, prefix="/api/v1")

    exec_session = MagicMock()
    exec_session.executor_id = "exec-1360"
    exec_session.revoked_at = None
    db = MagicMock()
    q = MagicMock()
    q.filter.return_value.first.return_value = exec_session
    q.filter.return_value.all.return_value = []  # zero bindings — the estate case
    db.query.return_value = q
    backend = MagicMock()
    app.state.config = SimplePayload()

    def _get_db():
        return db

    def _get_backend():
        return backend

    app.dependency_overrides[filter_routes.get_db] = _get_db
    app.dependency_overrides[filter_routes.get_backend] = _get_backend
    return TestClient(app, raise_server_exceptions=False)


class SimplePayload(SimpleNamespace):
    pass


class _BaseURLClient:
    """TestClient plus the base URL the executor's dial assumes.

    The executor posts a PATH (``/api/v1/sessions/<id>/filter``), so the borrowed
    route face needs to resolve it the way the real core client does.
    """

    def __init__(self, inner: TestClient, session_id: str):
        self._inner = inner
        self.session_id = session_id
        self.calls: list[str] = []

    def post(self, url, json=None, timeout=None):
        self.calls.append(url)
        return self._inner.post(url, json=json)


def test_stderr_bytes_survive_the_whole_chain(capsys):
    """One run, four lengths printed: hops 1, 3, 4 and 6 — Stage-2 is the real route."""
    stage2 = _BaseURLClient(_real_filter_route_client("sess-1360"), "sess-1360")

    executor = Executor.__new__(Executor)
    executor.http_client = stage2
    executor.session_id = "sess-1360"
    executor.config = None

    # hops 1-2: the real post-capture path through the real Stage-2 dial, entered
    # with the bytes the journal said existed (rc non-zero, stdout empty, stderr
    # non-empty).
    result = executor._filter_and_build_result(
        command="/usr/local/bin/tve status",
        exit_code=127,
        stdout=STDOUT_BYTES,
        stderr=STDERR_BYTES,
        injections=[],
    )
    assert stage2.calls, "the Stage-2 route was never dialed — this cell proves nothing"
    print(f"hop1-2 executor CommandResult.stderr = {len(result.stderr)} bytes", file=sys.stderr)
    assert len(result.stderr) == len(STDERR_BYTES), f"lost at hops 1-2: {len(result.stderr)} != {len(STDERR_BYTES)}"

    # hop 3: exactly what relay_listener.py builds and puts on the wire
    relay_body = RelayResponse(
        exit_code=result.exit_code,
        stdout=result.stdout.decode("utf-8", "replace"),
        stderr=result.stderr.decode("utf-8", "replace"),
        masked_count=len(result.masked_secret_ids),
    ).model_dump()
    wire = json.dumps(relay_body)
    print(f"hop3 relay wire stderr = {len(relay_body['stderr'])} bytes (json {len(wire)})", file=sys.stderr)
    assert len(relay_body["stderr"]) == len(STDERR_BYTES), "lost at hop 3 (relay encode)"

    # hop 4: exactly what routes/executors.py does to that body
    validated = RelayResponse(**json.loads(wire)).model_dump()
    print(f"hop4 core validated stderr = {len(validated['stderr'])} bytes", file=sys.stderr)
    assert len(validated["stderr"]) == len(STDERR_BYTES), "lost at hop 4 (contract validate)"

    # hop 5: the FastAPI response_model face the client actually receives
    served = jsonable_encoder(RelayResponse(**validated))
    print(f"hop5 served body stderr = {len(served['stderr'])} bytes", file=sys.stderr)
    assert len(served["stderr"]) == len(STDERR_BYTES), "lost at hop 5 (response_model)"

    # hop 6: the real CLI print site, fed the served body
    client = MagicMock()
    client.post.side_effect = [
        {"session_id": "sess-1360"},
        served,
    ]
    args = SimpleNamespace(command_args=["/usr/local/bin/tve", "status"], executor_id="tve", secrets=None)
    with patch("venya_cli.commands.EXECUTOR_TOML_PATH", "/nonexistent/executor.toml"):
        from venya_cli.commands import cmd_run

        rc = cmd_run(client, args)
    captured = capsys.readouterr()
    print(f"hop6 operator stderr = {len(captured.err)} bytes (rc={rc})", file=sys.stderr)
    print(f"hop6 operator stderr text: {captured.err!r}", file=sys.stderr)

    assert rc == 127
    assert (
        STDERR_BYTES.decode() in captured.err
    ), f"stderr never reached the operator; hops 1-5 carried it, hop 6 printed: {captured.err!r}"

    # The split that explains the estate symptom: the command's stderr goes to
    # fd 2 and the exit line goes to fd 1. A capture that keeps only stdout
    # reads EXACTLY the reported symptom — the bare exit line, no stderr — with
    # nothing lost by the product. Pinned here so a later reader cannot mistake
    # the two streams for one.
    assert "Command exited with code: 127" in captured.out, captured.out
    assert "Command exited with code" not in captured.err, captured.err


def test_stderr_crosses_the_real_relay_socket(pk):
    """Hop 3 over the ACTUAL mTLS socket, not a reconstruction of it.

    The shipped canned result in ``test_relay_listener.py`` hardcodes
    ``stderr=b""``, so no existing cell ever put a non-empty stderr on that
    socket. This one does: it borrows that module's PKI fixture, engine stub and
    listener launcher, answers with the byte class the estate journal reported,
    and reads the JSON the listener really wrote.
    """
    from executor.executor import CommandResult

    listener = _rl._start(
        pk.config,
        _rl._factory(
            _rl._FakeExec(
                result=CommandResult(
                    command="/usr/local/bin/tve status",
                    exit_code=127,
                    stdout=b"",
                    stderr=STDERR_BYTES,
                )
            ),
            [],
        ),
        [_rl.ALLOWED],
    )
    try:
        with _rl._client(pk.ca_a, pk.c_ok) as client:
            resp = client.post(
                _rl._url(listener),
                json={"session_id": "s1", "command": ["/usr/local/bin/tve", "status"], "secrets": []},
            )
    finally:
        listener.stop()

    assert resp.status_code == 200
    body = resp.json()
    print(f"hop3 REAL socket stderr = {len(body['stderr'])} bytes", file=sys.stderr)
    assert body["stderr"] == STDERR_BYTES.decode(), f"lost on the real socket: {body!r}"


def test_negative_control_the_assertion_is_load_bearing(capsys):
    """Prove the instrument COULD have returned the opposite answer.

    If stderr is stripped from the served body, hop 6 prints only the exit line
    and the byte assertion must fail. A guard that passes on a stripped body is
    worth nothing, so this cell asserts the failure it exists to catch.
    """
    stripped = {
        "exit_code": 127,
        "stdout": "",
        "stderr": "",
        "masked_count": 0,
    }
    client = MagicMock()
    client.post.side_effect = [{"session_id": "sess-1360"}, stripped]
    args = SimpleNamespace(command_args=["/usr/local/bin/tve", "status"], executor_id="tve", secrets=None)
    with patch("venya_cli.commands.EXECUTOR_TOML_PATH", "/nonexistent/executor.toml"):
        from venya_cli.commands import cmd_run

        rc = cmd_run(client, args)
    captured = capsys.readouterr()

    assert rc == 127
    # The symptom as reported: an exit line on stdout and silence on fd 2.
    assert "Command exited with code: 127" in captured.out
    assert STDERR_BYTES.decode() not in captured.err


if __name__ == "__main__":
    sys.exit(pytest.main([__file__, "-s", "-p", "no:cacheprovider"]))
