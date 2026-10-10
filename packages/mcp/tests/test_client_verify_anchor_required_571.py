# Copyright (c) 2026 Tabith LLC.
# Use of this source code is governed by the Business Source License 1.1
# included in the LICENSE file at the root of this repository. As of the
# Change Date listed there, the work is available under MPL 2.0.
# SPDX-License-Identifier: BUSL-1.1

"""#571 — the VenyaClient constructor requires an anchored CA; the host store is not a default.

``VenyaClient.__init__`` used to ship ``verify: bool | str = True``, and in httpx2 ``True`` is the
HOST trust store, not our CA. The venue quote from this repo's own installed transport,
``httpx2/_config.py`` (``create_ssl_context``, httpx2 2.12.0 as installed in this venue), is what
makes the close honest:

    if verify is True:
        ...
        else:
            # Default case: rely on the system trust store via `truststore`.
            ctx = truststore.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    elif verify is False:
        ...
    elif isinstance(verify, str):
        ...
        return ssl.create_default_context(cafile=verify)

So a caller that took the old default — or takes it again after a re-widening — trusts whatever the
machine trusts, silently, and a core served by our CA either fails to verify or (worse) verifies
against a public CA issued cert for the same hostname. The posture now is anchored-or-refuse at the
constructor seam, the same close #530/#533/#536 landed on the CLI bearer dial and the FIDO2
ceremony dial: no trust default, and a refusal that names ``VENYA_CA_CERT`` before any transport
exists.

#540's ruled alpha debug escape (``VENYA_TLS_VERIFY=false`` → ``False``, with its warning) is a
DIFFERENT posture and stays exactly as it ships: this file asserts that ``False`` still passes
through unchanged, it does not touch the escape.
"""

from __future__ import annotations

import inspect
import json
import os
import ssl
import warnings
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
from venya_mcp.client import (
    ANCHORED_ONLY_REFUSAL,
    VenyaClient,
    _bootstrap_tls_verify,
)
from venya_mcp.config import MCPConfig


def _config(tmp_path: Path) -> MCPConfig:
    config_file = tmp_path / "config.json"
    config_file.write_text(
        json.dumps({"server_url": "https://venya-core-1", "access_token": "test-token"}),
        encoding="utf-8",
    )
    return MCPConfig(config_file)


def _ca_bundle(tmp_path: Path) -> Path:
    ca = tmp_path / "ca-bundle.crt"
    ca.write_text("fake-ca-material", encoding="utf-8")
    return ca


def _spy_transport() -> MagicMock:
    """A stand-in ``httpx2.AsyncClient`` so we can see what the seam handed the transport."""
    return MagicMock(name="AsyncClient")


# --- positive halves: the anchored value reaches the transport ---


def test_ca_path_reaches_the_transport(tmp_path: Path) -> None:
    """A CA bundle path is handed straight to the transport — anchored, as intended."""
    ca = _ca_bundle(tmp_path)
    spy = _spy_transport()

    with patch("venya_mcp.client.httpx2.AsyncClient", spy):
        VenyaClient(_config(tmp_path), verify=str(ca))

    assert spy.call_count == 1, "the constructor built the transport a different number of times"
    assert spy.call_args.kwargs["verify"] == str(ca), (
        f"the transport was handed verify={spy.call_args.kwargs['verify']!r}, not the CA bundle "
        f"{str(ca)!r} the caller named"
    )


def test_alpha_debug_escape_still_passes_through_false(tmp_path: Path) -> None:
    """#540's posture is UNCHANGED: exactly ``False`` still reaches the transport.

    The ruled alpha debug escape is a caller naming the escape, not a silent default — so this
    cell asserts the close left it alone (no refusal, no rewrite), and that the startup resolver
    still returns ``False`` with its warning.
    """
    spy = _spy_transport()
    with patch("venya_mcp.client.httpx2.AsyncClient", spy):
        VenyaClient(_config(tmp_path), verify=False)

    assert spy.call_count == 1, "verify=False stopped constructing the transport — #540 moved"
    assert (
        spy.call_args.kwargs["verify"] is False
    ), f"the escape now reaches the transport as {spy.call_args.kwargs['verify']!r}, not False"

    with patch.dict(os.environ, {"VENYA_TLS_VERIFY": "false"}, clear=True):
        with warnings.catch_warnings(record=True) as caught:
            warnings.simplefilter("always")
            resolved = _bootstrap_tls_verify()
    assert resolved is False, f"the startup escape returned {resolved!r}, not False"
    assert any(
        "TLS verification is disabled" in str(w.message) for w in caught
    ), "the escape's warning path changed — #540's posture is hands-off and must still warn"


# --- negative halves: a host-store-shaped value is refused, and nothing dials ---


def test_true_is_refused_before_any_transport_exists(tmp_path: Path) -> None:
    """``verify=True`` — the old default — is the host store, so the seam refuses it."""
    spy = _spy_transport()

    with patch("venya_mcp.client.httpx2.AsyncClient", spy):
        with pytest.raises(RuntimeError) as excinfo:
            VenyaClient(_config(tmp_path), verify=True)

    assert spy.call_count == 0, (
        f"a refused client still constructed a transport ({spy.call_count} call(s)) — the "
        "refusal must land BEFORE httpx2.AsyncClient exists"
    )
    message = str(excinfo.value)
    assert "VENYA_CA_CERT" in message, f"the refusal must name the CA env var, got: {message}"
    assert ANCHORED_ONLY_REFUSAL in message, f"the refusal drifted from the shipped anchored-only wording: {message}"


def test_omitted_verify_is_refused_before_any_transport_exists(tmp_path: Path) -> None:
    """The second shape: nothing passed at all — the sentinel, not a Python TypeError.

    Omission is the case a future caller reaches by accident, so it carries the same CA-naming
    refusal rather than a bare ``TypeError``: an operator reading the traceback learns the repair.
    """
    spy = _spy_transport()

    with patch("venya_mcp.client.httpx2.AsyncClient", spy):
        with pytest.raises(RuntimeError) as excinfo:
            VenyaClient(_config(tmp_path))

    assert spy.call_count == 0, "an omitted verify still built a transport — the seam is not first"
    message = str(excinfo.value)
    assert "VENYA_CA_CERT" in message, f"the refusal must name the CA env var, got: {message}"
    assert ANCHORED_ONLY_REFUSAL in message, f"the refusal drifted from the shipped anchored-only wording: {message}"


# --- the seam itself, pinned (the #568 discipline: a check whose failure mode is silence) ---


def test_constructor_carries_no_trust_default() -> None:
    """No re-widening: ``verify`` must never default to a value the transport can read as trust.

    Derived from the live signature AND from the shipped source line, so the two cannot drift
    apart. ``= True`` coming back is exactly what turns this cell red — and the suite does not go
    silent when it does.
    """
    param = inspect.signature(VenyaClient.__init__).parameters["verify"]
    assert param.default in (None, inspect.Parameter.empty), (
        f"VenyaClient.__init__ defaults verify to {param.default!r}; the seam takes no trust "
        "default (a host-store-shaped value must be refused, never assumed) — #571"
    )

    source_lines = Path(inspect.getfile(VenyaClient)).read_text(encoding="utf-8").splitlines()
    widened = [
        line.strip()
        for line in source_lines
        if line.strip().startswith("verify:") and "= True" in line.replace("=True", "= True")
    ]
    assert not widened, f"the shipped signature widened back to a trust default: {widened}"


def test_a_hand_built_ssl_context_is_refused_too(tmp_path: Path) -> None:
    """Third negative shape: an ``ssl.SSLContext`` is not the seam's contract.

    The narrow surface this leg ships is "name the Venya CA bundle, or the ruled ``False``". A
    context object would be anchored only if its caller loaded the right CA, and nothing at this
    seam can see that — so it is refused rather than trusted by shape. No shipped site passes one
    (``build_client`` passes the ``bool | str`` from ``_bootstrap_tls_verify``), so this is a wall,
    not a regression.
    """
    spy = _spy_transport()
    with patch("venya_mcp.client.httpx2.AsyncClient", spy):
        with pytest.raises(RuntimeError) as excinfo:
            VenyaClient(_config(tmp_path), verify=ssl.create_default_context())

    assert spy.call_count == 0, "a refused value still built a transport"
    assert "VENYA_CA_CERT" in str(excinfo.value), f"refusal must name the CA var: {excinfo.value}"


def test_refusal_wording_is_the_anchored_only_one_the_tree_already_ships(tmp_path: Path) -> None:
    """Derive-both-sides on the operator text (#553's lesson, sibling of the #568 interlock).

    Two seams — the constructor and the startup resolver — tell an operator the same thing. The
    resolver's own RAISED text is captured by running it, and the constant the seam refuses with
    must be contained in it; nothing here re-types a third copy of the sentence to compare.
    """
    with patch.dict(os.environ, {}, clear=True):
        with pytest.raises(RuntimeError) as resolver_error:
            _bootstrap_tls_verify()
    shipped = str(resolver_error.value)
    assert ANCHORED_ONLY_REFUSAL in shipped, (
        f"the seam's constant is no longer the startup resolver's own wording — two seams teach "
        f"two repairs now. resolver says: {shipped}"
    )

    with pytest.raises(RuntimeError) as seam_error:
        VenyaClient(_config(tmp_path), verify=True)
    assert ANCHORED_ONLY_REFUSAL in str(
        seam_error.value
    ), "the constructor refusal no longer carries the shipped anchored-only sentences"
