# Copyright (c) 2026 Tabith LLC.
# Use of this source code is governed by the Business Source License 1.1
# included in the LICENSE file at the root of this repository. As of the
# Change Date listed there, the work is available under MPL 2.0.
# SPDX-License-Identifier: BUSL-1.1

"""RED-first contract tests for venya-contract.

Three disjoint failure modes, per the refactor-2 acceptance:

1. IDENTITY — both consumers import THE SAME model objects. This is the strongest
   check: it catches a local re-declaration on either side (the drift this package
   exists to kill), which neither ``extra="forbid"`` nor mypy catches. A one-sided
   re-declaration breaks the ``is`` even when the field set looks identical.
2. EXTRA=FORBID — an unknown/renamed field is a loud ``ValidationError``, not a
   silent drop. This is the negative half: it proves the ``masked_count``
   silent-data-loss class (pydantic ignoring an extra key, defaulted field silently
   zeroed) is gone.
3. ROUND-TRIP — the wire shape serializes and parses symmetrically, so the server's
   ``model_dump()`` payload is exactly what the executor's ``RelayRequest(**body)``
   accepts.
"""

import pytest
from pydantic import ValidationError
from venya_contract import ASKPASS_HELPER_PATH, RelayEnvVar, RelayRequest, RelayResponse, RelaySecret


def test_identity_server_and_executor_share_the_same_model_objects():
    """Server and executor must import THE SAME objects, not local copies."""
    import executor.relay_listener as rl
    import server.routes.executors as srv

    # Server side: constructs all three (RelaySecret in the secrets comprehension).
    assert srv.RelayResponse is RelayResponse
    assert srv.RelayRequest is RelayRequest
    assert srv.RelaySecret is RelaySecret
    # Executor side: parses RelayRequest (which nests RelaySecret) and builds RelayResponse.
    assert rl.RelayResponse is RelayResponse
    assert rl.RelayRequest is RelayRequest


def test_response_forbids_extra_field():
    """A one-sided rename of a DEFAULTED field is a loud error, not a silent drop.

    Pre-contract, renaming masked_count->redacted_count on the server only meant the
    executor's still-sent ``masked_count`` was silently ignored and ``redacted_count``
    defaulted to 0 — data loss with no error. extra=forbid makes it a ValidationError.
    """
    with pytest.raises(ValidationError):
        RelayResponse(exit_code=0, stdout="ok", stderr="", masked_count=1, redacted_count=1)


def test_response_forbids_renamed_required_field():
    """A one-sided rename of a REQUIRED field is rejected, not silently accepted."""
    with pytest.raises(ValidationError):
        RelayResponse(exit_code=0, output="ok", stderr="")  # type: ignore[call-arg]


def test_request_forbids_extra_field():
    with pytest.raises(ValidationError):
        RelayRequest(session_id="s", command="echo hi", bogus="x")


def test_secret_forbids_extra_field():
    with pytest.raises(ValidationError):
        RelaySecret(secret_id=1, wrapped_value="v", extra="x")


def test_secret_rejects_non_integer_id():
    """secret_id is the Integer secrets PK — a str id is a wire-type error."""
    with pytest.raises(ValidationError):
        RelaySecret(secret_id="sec1", wrapped_value="v")  # type: ignore[arg-type]


def test_response_round_trip():
    r = RelayResponse(exit_code=0, stdout="ok", stderr="", masked_count=2)
    assert RelayResponse(**r.model_dump()) == r


def test_request_round_trip_with_secrets():
    req = RelayRequest(
        session_id="s1",
        command="echo hi",
        secrets=[RelaySecret(secret_id=1, wrapped_value="wrapped")],
    )
    parsed = RelayRequest(**req.model_dump())
    assert parsed == req
    assert parsed.secrets[0].wrapped_value == "wrapped"


def test_request_secrets_default_empty():
    req = RelayRequest(session_id="s1", command="echo hi")
    assert req.secrets == []


def test_response_masked_count_defaults_zero():
    r = RelayResponse(exit_code=0, stdout="ok", stderr="")
    assert r.masked_count == 0


# --- env/askpass additions (ticket secret-shape-env-injection) --------------
# Coordinated contract change: both directions of the compatibility matrix are
# pinned (ca-key-export cross-compat precedent).


def test_old_wire_payload_parses_with_env_defaults():
    """Compat direction 1: an OLD server's payload (exactly the three pre-env
    keys) parses on the NEW model with inert defaults."""
    old_payload = {"session_id": "s1", "command": "echo hi", "secrets": []}
    req = RelayRequest(**old_payload)
    assert req.env == []
    assert req.askpass_helper is False


def test_env_var_requires_exactly_one_source():
    with pytest.raises(ValidationError):
        RelayEnvVar(var_name="A")  # neither source
    with pytest.raises(ValidationError):
        RelayEnvVar(var_name="A", secret_id=1, literal_value="x")  # both


def test_env_var_name_pattern_pinned():
    """A crafted var_name must never be able to forge env-file lines."""
    for bad in ("BAD NAME", "1LEADING", "A\nB", "A=B", ""):
        with pytest.raises(ValidationError):
            RelayEnvVar(var_name=bad, literal_value="x")
    for good in ("GOOD_1", "_x", "AWS_SECRET_ACCESS_KEY"):
        RelayEnvVar(var_name=good, literal_value="x")


def test_env_var_forbids_extra_field():
    with pytest.raises(ValidationError):
        RelayEnvVar(var_name="A", literal_value="x", surprise=1)


def test_request_round_trip_with_env():
    req = RelayRequest(
        session_id="s1",
        command="printenv TOKEN",
        secrets=[RelaySecret(secret_id=7, wrapped_value="w")],
        env=[
            RelayEnvVar(var_name="TOKEN", secret_id=7),
            RelayEnvVar(var_name="GIT_ASKPASS", literal_value=ASKPASS_HELPER_PATH),
        ],
        askpass_helper=True,
    )
    parsed = RelayRequest(**req.model_dump())
    assert parsed == req
    assert parsed.env[0].secret_id == 7
    assert parsed.env[1].literal_value == ASKPASS_HELPER_PATH
    assert parsed.askpass_helper is True
