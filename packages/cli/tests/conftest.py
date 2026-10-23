# Copyright (c) 2026 Tabith LLC.
# Use of this source code is governed by the Business Source License 1.1
# included in the LICENSE file at the root of this repository. As of the
# Change Date listed there, the work is available under MPL 2.0.
# SPDX-License-Identifier: BUSL-1.1

"""Shared fixtures for the venya-cli test suite."""

import ssl

import pytest


@pytest.fixture(autouse=True)
def _hermetic_venya_env(monkeypatch):
    """Keep ambient VENYA_* resolution envs out of every test.

    The CLI reads VENYA_SERVER_URL (run_command chokepoint, _get_server_url)
    and VENYA_EXECUTOR_ENROLLMENT_TOKEN (executor_register) from os.environ.
    An export on a dev/CI machine must not silently drive resolution chains —
    tests that exercise these set them explicitly (patch.dict / monkeypatch).
    """
    monkeypatch.delenv("VENYA_SERVER_URL", raising=False)
    monkeypatch.delenv("VENYA_EXECUTOR_ENROLLMENT_TOKEN", raising=False)


#: TEST-only passphrase for the executor key plane (#565). Declared here so the
#: one number is in one place; cells that assert the refusal delete it.
TEST_EXECUTOR_KEY_PASSPHRASE = "test-executor-key-passphrase"  # pragma: allowlist secret — TEST value, never real


@pytest.fixture(autouse=True)
def _executor_key_passphrase_env(monkeypatch):
    """Supply the executor-key passphrase for the writer cells (#565).

    ``venya exec register`` and ``venya exec cert renew`` now refuse to write a
    plaintext key, so every cell that expects one of them to SUCCEED must carry a
    passphrase in the environment — which is exactly what a deployed executor
    host gets from the installer's EnvironmentFile. Autouse rather than per-cell
    because the requirement is unconditional on this plane; the refusal cells
    call `no_executor_key_passphrase` and say so out loud. #573's floor applies
    here too, so this value is 28 code points.
    """
    monkeypatch.setenv("VENYA_EXECUTOR_KEY_PASSPHRASE", TEST_EXECUTOR_KEY_PASSPHRASE)


@pytest.fixture
def no_executor_key_passphrase(monkeypatch):
    """Opt-in for the refusal cells: this host has NO passphrase configured."""
    monkeypatch.delenv("VENYA_EXECUTOR_KEY_PASSPHRASE", raising=False)


@pytest.fixture
def executor_key_passphrase() -> str:
    """The TEST passphrase the env fixture sets — for cells that read a key back."""
    return TEST_EXECUTOR_KEY_PASSPHRASE


@pytest.fixture
def venya_tls_anchor_536(tmp_path, monkeypatch):
    """A Venya TLS trust anchor for THIS cell only — a self-signed CA under
    ``tmp_path`` named by ``monkeypatch.setenv("SSL_CERT_FILE", ...)``.

    Why it exists (#536): ``APIClient.register_executor()`` used to answer "no
    bundle handed to me" with the bare bool ``verify=True``, which is httpx asking
    OpenSSL for the workstation host store. The dial now resolves the same anchor
    as the bearer (#530) and ceremony (#533) dials and REFUSES when there is
    none — so any cell that expects the registration POST to actually dial must
    run on a host that HAS an anchor. This is the one place that supplies it.

    The mechanism is the point: ``setenv`` OVERWRITES whatever the operator's
    shell happens to export and pytest reverts it per cell, so no cell here can
    pass because of ambient state (and none can pass because of an absent anchor,
    which is now the refused case). Cells that want the refusal delete it.
    """
    import datetime

    from cryptography import x509
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import ed25519
    from cryptography.x509.oid import NameOID

    key = ed25519.Ed25519PrivateKey.generate()
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "venya-test-anchor-536")])
    now = datetime.datetime.now(datetime.UTC)
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=1))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(key, None)
    )
    ca = tmp_path / "anchor-ca.crt"
    ca.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    monkeypatch.setenv("SSL_CERT_FILE", str(ca))
    monkeypatch.delenv("VENYA_TLS_VERIFY", raising=False)

    def cns(ctx: ssl.SSLContext) -> set[str]:
        """Common names actually loaded into ``ctx`` — the anchor-set proof.

        Same helper shape the #530/#533 suites use. A count assertion would be a
        lie here: a host-store context reports zero loaded certs while the store
        is live, so the proof is WHICH names the dial trusts, not how many.
        """
        names: set[str] = set()
        for issued in ctx.get_ca_certs():
            for rdn in issued["subject"]:
                for attr, value in rdn:
                    if attr == "commonName":
                        names.add(value)
        return names

    from types import SimpleNamespace

    def without_anchor(server_url: str = "https://core.example.com"):
        """A client on a host that has NO anchor at all — the refusal half.

        The env value is removed and the config lives in this cell's private tmp
        dir (so no ``ca.crt`` can sit beside it), never an ambient path: the
        refusal assert cannot be satisfied or defeated by what happens to exist
        in ``/tmp`` on the machine running the suite.
        """
        import json

        from venya_cli.api_client import APIClient

        monkeypatch.delenv("SSL_CERT_FILE", raising=False)
        # Its OWN directory: a cell that just completed a successful registration
        # has a response-written ca.crt sitting in tmp_path (that is what
        # `exec register` does), which would make this client legitimately ANCHORED
        # and the refusal half a lie. Private dir, nothing beside it, ever.
        anchorless_dir = tmp_path / "no-anchor-host"
        anchorless_dir.mkdir(exist_ok=True)
        cfg = anchorless_dir / "config.json"
        cfg.write_text(json.dumps({"server_url": server_url}))
        return APIClient(config_file=cfg)

    return SimpleNamespace(path=ca, cn="venya-test-anchor-536", cns=cns, without_anchor=without_anchor)
