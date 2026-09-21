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

from pydantic import BaseModel, ConfigDict, Field, model_validator

# Sandbox path of the askpass helper script (ticket secret-shape-askpass-helpers).
# The executor writes it when ``askpass_helper`` is set; the server references it
# in literal env entries (GIT_ASKPASS/SSH_ASKPASS). Shared constant so both ends
# of the wire agree on the path without a stringly-typed duplicate.
ASKPASS_HELPER_PATH = "/run/secrets/venya/.venya-askpass"


class RelayEnvVar(BaseModel):
    """One environment variable to set inside the sandbox (env/askpass shapes).

    Exactly ONE source:

    - ``secret_id``: the value is the unwrapped plaintext of that secret, which
      MUST also appear in ``secrets`` — env never replaces the file injection,
      it references it (the output filter's fingerprints come from the secrets
      list; an env-only secret would be unmasked).
    - ``literal_value``: a non-secret constant (helper paths, sandbox file
      paths, usernames).

    Transport (ticket secret-shape-env-injection, spike-ruled option ii):
    the executor writes ``KEY=VALUE`` lines to a 0600 file in the session
    tmpfs and passes ``sbx exec --env-file`` — values NEVER ride host argv
    (``-e K=V`` would expose them in ``/proc/<pid>/cmdline``). The env-file
    format is line-based: values containing CR/LF are rejected loudly by both
    ends. ``var_name`` is pinned to a shell identifier so a crafted name can
    never forge extra env-file lines.
    """

    model_config = ConfigDict(extra="forbid")

    var_name: str = Field(pattern=r"^[A-Za-z_][A-Za-z0-9_]*$")
    secret_id: int | None = None
    literal_value: str | None = None

    @model_validator(mode="after")
    def _exactly_one_source(self) -> RelayEnvVar:
        if (self.secret_id is None) == (self.literal_value is None):
            raise ValueError("set exactly one of secret_id or literal_value")
        return self


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

    ``env`` / ``askpass_helper`` (ticket secret-shape-env-injection /
    secret-shape-askpass-helpers) are OPTIONAL additions: a payload without
    them is byte-identical to the pre-env wire shape, and new executors parse
    both forms. A server MUST NOT send a non-empty ``env`` (or
    ``askpass_helper=true``) to an executor older than 0.1.0a13 — old daemons
    run ``extra="forbid"`` and would reject the field; the server version-gates
    on the heartbeat-reported ``executors.version`` before dialing.
    """

    model_config = ConfigDict(extra="forbid")

    session_id: str
    command: str
    secrets: list[RelaySecret] = Field(default_factory=list)
    env: list[RelayEnvVar] = Field(default_factory=list)
    askpass_helper: bool = False


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
