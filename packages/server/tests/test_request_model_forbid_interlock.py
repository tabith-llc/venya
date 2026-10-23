# Copyright (c) 2026 Tabith LLC.
# Use of this source code is governed by the Business Source License 1.1
# included in the LICENSE file at the root of this repository. As of the
# Change Date listed there, the work is available under MPL 2.0.
# SPDX-License-Identifier: BUSL-1.1

"""Interlock pin for the repo-wide extra='forbid' sweep (ticket
request-models-extra-forbid-sweep #357, ruled 2026-10-02):

    every request model either forbids extras OR is listed exempt.

The sweep collected 38 request-body models (ruling-input inventory at tip:
admin 11, auth_browser 6, executors 4, roles 3, secrets 3, auth 2,
credentials 2, enroll 2, init 2, filter 1, recovery 1, auth_elevation 1;
already-forbid = 2 after #355). This pin walks the LIVE route surface —
every endpoint parameter annotated as a pydantic body model, plus the
transitive closure of nested BaseModel field types — so a new route model
added WITHOUT forbid (or with a name that dodges a *Request grep) fails
loudly here.

NAMED EXEMPTIONS (ruled — no self-granting; new candidates STOP-and-report):
  * SecretMetadata (secrets.py, extra='allow'): deliberate operator-context
    pass-through store, DELIBERATE per the wave-3B inventory note.
  * FilterRequest (filter.py, extra='ignore'): legacy-tolerant filter wire —
    the 2026-09-20 plaintext-signoff compat ruling STANDS (lead call
    forwarded on #357); old daemons send the dead `secrets` key, must keep
    getting 200 (cell: test_legacy_payload_with_secrets_field_tolerated_and_dropped).
    (RecoveryRequest was the third exemption; the #367 client fix discharged
    its condition and the #371 leg re-swept it — forbidden count is now 37 of
    the 38 defined, exemptions 2.)

ORPHAN FLAG (listed, NOT deleted — separate-surface policy per ruling-inputs):
  * BrowserLogoutRequest (auth_browser.py): defined, zero consumers.

Raw-dict site (outside model scope, listed for completeness): the rate-limit
dashboard consumes a plain dict (rate_limit.py) — keying-only, no model.
"""

import importlib
import inspect
import pkgutil
import typing
from pathlib import Path

import pytest
import server.routes
from pydantic import BaseModel, ValidationError

EXEMPT = {
    # Policy prose below — no credentials (detect-secrets keyword false positives).
    "SecretMetadata": "deliberate pass-through store (ruled #357; wave-3B note)",  # pragma: allowlist secret
    "FilterRequest": "legacy-tolerant filter wire (ruled #357: 2026-09-20 compat ruling stands; old daemons send the dead `secrets` key and must keep getting 200)",  # pragma: allowlist secret
}
ORPHANS = {
    "BrowserLogoutRequest": "defined, zero consumers (listed per ruling-inputs; deletion is separate-surface policy)",
}

# Ruling-input inventory at the sweep tip: 38 defined *Request models in
# server.routes (admin 11, auth_browser 6, executors 4, roles 3, secrets 3,
# auth 2, credentials 2, enroll 2, init 2, filter 1, recovery 1,
# auth_elevation 1). Drift in EITHER direction trips this pin before the
# behavior pins can silently absorb it. (#597 adds a thirteenth module,
# core_relay_certs, carrying 2 of these.)
# RF-7 chunk 2 (refs RF-6 §2.7) added ONE model to the surface:
# AdminIssueCertRequest (routes/admin_certs.py), shipped with extra="forbid"
# because the §2.6 no-self-described-identity rule IS that field's absence.
# 38 -> 39 defined, 37 -> 38 forbidden; the 2 ruled exemptions are unchanged.
# #597 added TWO, both shipped forbid (routes/core_relay_certs.py:
# CoreRelayCertRevokeRequest + CoreRelayCertRegisterRequest) — a typo'd flag on a
# revocation verb must die at the schema, not be silently dropped and leave the
# caller believing they revoked something. 39 -> 41 defined, 38 -> 40 forbidden.
# #684 added ONE more, also shipped forbid (routes/admin_certs.py:
# AdminRegisterCertRequest). Its extra=forbid is not decoration — that verb's whole
# purpose is to enroll a credential by PRESENTING it, so a body carrying a bare
# ``serial`` must die at the schema instead of enrolling a serial no certificate holds,
# which is the precise failure #684 exists to stop. 41 -> 42 defined, 40 -> 41 forbidden;
# the 2 ruled exemptions are unchanged.
EXPECTED_DEFINED_REQUEST_MODELS = 42


def _route_modules():
    pkg = server.routes
    for info in pkgutil.iter_modules([str(Path(pkg.__file__).parent)]):
        yield importlib.import_module(f"server.routes.{info.name}")


def _is_model(cls) -> bool:
    return inspect.isclass(cls) and issubclass(cls, BaseModel)


def _defined_request_models():
    """The sweep inventory: every *Request BaseModel DEFINED in a routes
    module (the same basis the ruling's 38-count was taken on)."""
    found = {}
    for mod in _route_modules():
        for name, obj in vars(mod).items():
            if _is_model(obj) and name.endswith("Request") and obj.__module__ == mod.__name__:
                found[name] = obj
    return found


def _walk_model_closure(model: type[BaseModel], seen: set[type[BaseModel]]) -> None:
    if model in seen:
        return
    seen.add(model)
    for field in model.model_fields.values():
        args = typing.get_args(field.annotation) or (field.annotation,)
        stack = list(args)
        while stack:
            item = stack.pop()
            if _is_model(item):
                _walk_model_closure(item, seen)
            else:
                stack.extend(typing.get_args(item))


def _bound_body_models():
    """Second net: every pydantic model actually BOUND as a route body
    (catches bodies named without the *Request suffix) and their nested
    closure."""
    bound = {}
    for mod in _route_modules():
        for route in getattr(getattr(mod, "router", None), "routes", []):
            endpoint = getattr(route, "endpoint", None)
            if endpoint is None:
                continue
            for param in inspect.signature(endpoint).parameters.values():
                for cand in typing.get_args(param.annotation) or (param.annotation,):
                    if _is_model(cand) and cand.__module__.startswith("server."):
                        bound[cand.__name__] = cand
    closure: set[type[BaseModel]] = set()
    for model in bound.values():
        _walk_model_closure(model, closure)
    for model in closure:
        bound.setdefault(model.__name__, model)
    return bound


def _checked_models() -> dict[str, type[BaseModel]]:
    pool = dict(_defined_request_models())
    for name, model in _bound_body_models().items():
        pool.setdefault(name, model)
    return pool


def test_every_request_model_forbids_or_is_exempt():
    offenders = []
    for name, model in _checked_models().items():
        if name in EXEMPT:
            continue
        if model.model_config.get("extra") != "forbid":
            offenders.append(f"{model.__module__}.{name}")
    assert not offenders, "request models missing extra='forbid' and not ruled exempt: " + ", ".join(offenders)


def test_exemption_list_is_still_true_and_tight():
    """Paired negative for the pin itself: every named exemption must still
    exist, still be a non-forbidding model — an exemption that rots into a
    forbid (or vanishes) fails here, keeping the list honest."""
    pool = _checked_models()
    for exempt in EXEMPT:
        assert exempt in pool, f"exempt model {exempt} no longer reachable from the route surface"
        assert (
            pool[exempt].model_config.get("extra") != "forbid"
        ), f"{exempt} now forbids — remove it from the exemption list"


def test_inventory_count_pin():
    """Non-vacuity: the definition walk must find the ruled 39 *Request
    models — a broken walk (import failure, module renamed) must not pass
    silently."""
    defined = _defined_request_models()
    assert len(defined) == EXPECTED_DEFINED_REQUEST_MODELS
    # #371 re-sweep pinned the split at 37 of 38; RF-7 chunk 2 added one
    # forbid-shipped model, so 38 of 39; #597 added two more, so 40 of 41. The
    # ruled exemptions stay exactly SecretMetadata + FilterRequest (2).
    assert len(EXEMPT) == 2, "exemption list grew/shrank — new candidates are STOP-and-report, not list edits"
    forbidden = [n for n, m in defined.items() if m.model_config.get("extra") == "forbid"]
    assert len(forbidden) == 41, f"forbidden defined models: {len(forbidden)} != 41 (post-#684)"


def test_orphan_flag_still_listed():
    """BrowserLogoutRequest is LISTED, not deleted (ruled). If it is ever
    bound to a route or removed, the flag is revisited deliberately."""
    defined = _defined_request_models()
    bound = _bound_body_models()
    for orphan in ORPHANS:
        assert orphan in defined, f"{orphan} vanished — deletion happened elsewhere; update the flag"
        assert orphan not in bound, f"{orphan} is now bound to a route — revisit the ORPHANS list"


def test_sanity_check_forbid_meaning_not_vacuous():
    """The pin asserts config VALUES; prove the mechanism means something:
    a fresh model WITHOUT config silently ignores an unknown key, while the
    swept surface rejects it — the two halves of the dead-key class."""

    class _NoConfig(BaseModel):
        x: int = 1

    assert _NoConfig.model_validate({"x": 1, "typo_key": 2}).model_dump() == {"x": 1}

    from server.routes.credentials import CredentialAddStartRequest

    with pytest.raises(ValidationError):
        CredentialAddStartRequest.model_validate({"label": "ok", "typo_key": 2})
