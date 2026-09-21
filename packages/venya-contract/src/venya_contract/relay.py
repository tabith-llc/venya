# Copyright (c) 2026 Tabith LLC.
# Use of this source code is governed by the Business Source License 1.1
# included in the LICENSE file at the root of this repository. As of the
# Change Date listed there, the work is available under MPL 2.0.
# SPDX-License-Identifier: BUSL-1.1

"""Relay wire models for the server<->executor ``POST /execute`` hop.

See the package ``__init__`` docstring for the freeze policy. These models are the
frozen spec: both ends import them, neither re-declares them, and ``extra="forbid"``
makes any one-sided field change a loud ``ValidationError`` instead of a silent drop.
"""

from pydantic import BaseModel, ConfigDict, Field


class RelaySecret(BaseModel):
    """One wrapped secret as it crosses the relay wire.

    ``secret_id`` is the integer primary key of the ``secrets`` table
    (``core.iam.models.Secret.id`` / ``SessionSecret.secret_id``, both
    ``Column(Integer)``) — the server relays it as a JSON number, so it is typed
    ``int`` here, not ``str``. ``wrapped_value`` is the sentinel-wrapped string
    ``[VENYA:<hash8>]base64(plaintext)[/VENYA]`` (``SessionSecret.wrapped_value``,
    ``Column(Text)``). HONESTY NOTE (ticket sec-secret-redaction-log-leaks #10 —
    the former docstring claimed "ciphertext ... never plaintext", which was
    FALSE): base64 is PLAINTEXT-EQUIVALENT, not encryption. Confidentiality at
    rest and on this hop rests on the surrounding controls — the mTLS-only
    relay transport, the 10-minute TTL purge of ``execution_session_secrets``,
    and host disk protections — NEVER on the encoding. Never logged (see the
    Stage-2 sign-off invariant). The executor encodes it to bytes for the
    engine's ``strip_sentinel()`` — that str->bytes mapping is an
    executor-internal concern, not part of the wire shape.
    """

    model_config = ConfigDict(extra="forbid")

    secret_id: int
    wrapped_value: str


class RelayRequest(BaseModel):
    """Server -> executor relay request body for ``POST /execute``.

    ``secrets`` defaults to empty so a command with no injected secrets is valid;
    the server always sends the key (possibly an empty list).
    """

    model_config = ConfigDict(extra="forbid")

    session_id: str
    command: str
    secrets: list[RelaySecret] = Field(default_factory=list)


class RelayResponse(BaseModel):
    """Executor -> server relay response body for ``POST /execute``.

    Also reused as the server -> client FastAPI ``response_model`` for the
    ``/executors/{id}/execute`` endpoint: the field set is identical, so the server
    does not re-declare a local copy (the previous ``ExecuteResponse`` was exactly
    such a copy and is removed).
    """

    model_config = ConfigDict(extra="forbid")

    exit_code: int
    stdout: str
    stderr: str
    masked_count: int = Field(default=0, description="Number of [REDACTED:...] markers in output")
