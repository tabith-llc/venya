# Copyright (c) 2026 Tabith LLC.
# Use of this source code is governed by the Business Source License 1.1
# included in the LICENSE file at the root of this repository. As of the
# Change Date listed there, the work is available under MPL 2.0.
# SPDX-License-Identifier: BUSL-1.1

"""Inner-mTLS uvicorn kwargs builder (end-to-end-mtls-header-trust-removal #314).

Pins the fail-closed startup guard and — the ruled Q7 drift pin — the EXPLICIT
``ssl_cert_reqs=CERT_REQUIRED``: uvicorn 0.52.1 defaults ``ssl_cert_reqs`` to
``CERT_NONE``, so passing ``ssl_ca_certs`` alone would leave the inner
listener accepting connections with NO client cert (silently defeating the
ingress seal). If a future uvicorn changes that signature/default, these
cells fail instead of shipping a weakened listener.
"""

import ssl

import pytest
from server.app import build_uvicorn_kwargs
from server.config import InnerTLSConfig, ServerConfig


def _config(**inner_kwargs) -> ServerConfig:
    return ServerConfig(
        recovery_code_pepper="test-pepper",
        inner_mtls=InnerTLSConfig(**inner_kwargs),
    )


_FULL = {
    "enabled": True,
    "cert_file": "/etc/venya/tls/inner.crt",
    "key_file": "/etc/venya/tls/inner.key",
    "client_ca_file": "/var/lib/venya/ca/ca.crt",
}


def test_disabled_yields_plaintext_kwargs():
    kwargs = build_uvicorn_kwargs(object(), _config())
    assert "ssl_certfile" not in kwargs
    assert "ssl_cert_reqs" not in kwargs
    assert kwargs["proxy_headers"] is True


def test_enabled_sets_cert_required_explicitly():
    """The Q7 drift pin: CERT_REQUIRED is passed EXPLICITLY (uvicorn's own
    default is CERT_NONE — ssl_ca_certs alone would verify nothing)."""
    kwargs = build_uvicorn_kwargs(object(), _config(**_FULL))
    assert kwargs["ssl_certfile"] == "/etc/venya/tls/inner.crt"
    assert kwargs["ssl_keyfile"] == "/etc/venya/tls/inner.key"
    assert kwargs["ssl_ca_certs"] == "/var/lib/venya/ca/ca.crt"
    assert kwargs["ssl_cert_reqs"] == ssl.CERT_REQUIRED
    assert int(kwargs["ssl_cert_reqs"]) == int(ssl.VerifyMode.CERT_REQUIRED)


@pytest.mark.parametrize(
    "missing",
    ["cert_file", "key_file", "client_ca_file"],
)
def test_half_wired_inner_mtls_refuses_startup(missing):
    """Fail-closed guard: enabled + ANY material path missing raises — the
    app never serves with a half-wired inner channel. (The old cert_path_prefix
    case is gone: content transport has no filesystem path to wire.)"""
    kwargs = dict(_FULL)
    kwargs[missing] = None
    with pytest.raises(RuntimeError, match="refusing to start"):
        build_uvicorn_kwargs(object(), _config(**kwargs))


def test_inner_mtls_requires_loopback_bind():
    config = ServerConfig(
        recovery_code_pepper="test-pepper",
        host="0.0.0.0",
        inner_mtls=InnerTLSConfig(**_FULL),
    )
    with pytest.raises(RuntimeError, match="loopback"):
        build_uvicorn_kwargs(object(), config)


def test_legacy_ssl_cert_still_maps_when_inner_disabled():
    config = ServerConfig(
        recovery_code_pepper="test-pepper",
        ssl_cert="/legacy.crt",
        ssl_key="/legacy.key",
    )
    kwargs = build_uvicorn_kwargs(object(), config)
    assert kwargs["ssl_certfile"] == "/legacy.crt"
    assert kwargs["ssl_keyfile"] == "/legacy.key"
    assert "ssl_cert_reqs" not in kwargs
