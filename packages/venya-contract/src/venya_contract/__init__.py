# Copyright (c) 2026 Tabith LLC.
# Use of this source code is governed by the Business Source License 1.1
# included in the LICENSE file at the root of this repository. As of the
# Change Date listed there, the work is available under MPL 2.0.
# SPDX-License-Identifier: BUSL-1.1

"""Venya relay wire contract — the frozen spec for the server<->executor ``/execute`` hop.

This package is the SINGLE SOURCE OF TRUTH for the relay wire shape. Both ends
import these models; neither declares its own copy. Any future Rust port of
either end MUST satisfy these models byte-for-byte on the wire — this package is
the artifact that port is measured against (per REFACTOR.md / refactor-5: no Rust
conversion of this component before this contract exists).

Freeze policy — what counts as a breaking change
------------------------------------------------
Every model here uses ``extra="forbid"``. That is the load-bearing choice: it
turns a one-sided field rename from a SILENT drop (pydantic's default ignores
unknown keys, so a renamed defaulted field would silently default and lose data)
into a loud ``ValidationError`` at the boundary. Consequences:

* Renaming, removing, or retyping any field is BREAKING. It changes the wire and
  requires a coordinated two-sided deploy (server AND executor, plus any port).
  Never do it one-sided.
* ADDING a field is ALSO breaking under ``extra="forbid"``: the receiving side
  rejects unknown keys, so a new field on the wire without both sides agreeing
  fails at the boundary. Additive changes are therefore coordinated two-sided
  deploys, NOT tolerate-then-add rollouts. This is the correct trade for an
  internal relay whose installs are versioned and under our control — but it is a
  real operational constraint, so it is stated here rather than discovered in
  production.
* Relaxing ``extra="forbid"`` to permissive is BREAKING — it re-opens the
  silent-field-drop class this contract exists to eliminate.

Do not "just add a field" here without a coordinated deploy of both consumers.

What is NOT in this package
---------------------------
* The client->server FastAPI inbound model (``ExecuteRequest`` in
  ``server.routes.executors``) is a DIFFERENT contract (client<->server, not the
  relay wire) and stays local to the server. Only the relay hop is frozen here.
* The executor's internal ``CommandResult`` dataclass and the engine-facing
  secrets list are internal types, not wire shapes; ``relay_listener`` maps
  between them and these models.
"""

from venya_contract.relay import ASKPASS_HELPER_PATH, RelayEnvVar, RelayRequest, RelayResponse, RelaySecret

__all__ = ["ASKPASS_HELPER_PATH", "RelayEnvVar", "RelayRequest", "RelayResponse", "RelaySecret"]
