# Copyright (c) 2026 Tabith LLC.
# Use of this source code is governed by the Business Source License 1.1
# included in the LICENSE file at the root of this repository. As of the
# Change Date listed there, the work is available under MPL 2.0.
# SPDX-License-Identifier: BUSL-1.1

"""#507 pins — renew / heartbeat must resolve the Venya CA, never guess it.

Both commands used to do this:

    ca_cert_path = str(Path(cert_path).parent / "ca.crt")
    ssl_ctx = ssl.create_default_context()          # <-- system store loaded
    if Path(ca_cert_path).exists():
        ssl_ctx.load_verify_locations(ca_cert_path) # <-- silent skip when it does not

Two defects in four lines: the anchor location is GUESSED as a sibling of the
leaf, and a miss is SILENT — `create_default_context()` has already loaded the
host store, so verification continues against public CAs with no message. The
installer puts the trust anchor at
`/usr/local/share/ca-certificates/venya-local-ca.crt` / `executor.toml`
`ca_bundle`, not beside the leaf, so the miss is the common case.

The fix reuses the register-path rule (`_resolve_register_verify_cafile`, #395):
config-dir CA → bundle (flag or executor.toml) → certificate sibling → FAIL
LOUD, with no system-store and no no-verify fallback. The context is built by
`_build_ssl_context(cafile=...)`, which loads ONLY that anchor — so a
publicly-signed certificate cannot be accepted even when the host store would.
"""

import datetime
import tomllib
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_ca(tmp_path: Path, cn: str, name: str) -> Path:
    """A real self-signed CA PEM written under a unique name."""
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])
    now = datetime.datetime.now(datetime.UTC)
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=30))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(key, hashes.SHA256())
    )
    path = tmp_path / name
    path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    return path


def _make_executor_pair(tmp_path: Path, executor_id: str = "test-exec") -> tuple[Path, Path]:
    """executor.crt + executor.key (the leaf/key pair the mTLS client presents)."""
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, executor_id)])
    now = datetime.datetime.now(datetime.UTC)
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=30))
        .sign(key, hashes.SHA256())
    )
    cert_path = tmp_path / "executor.crt"
    cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    key_path = tmp_path / "executor.key"
    key_path.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
    )
    key_path.chmod(0o600)
    return cert_path, key_path


def _ctx_anchor_cns(verify) -> set[str]:
    """CNs among the trust anchors of the SSLContext handed to httpx2."""
    names: set[str] = set()
    for cert in verify.get_ca_certs():
        for rdn in cert["subject"]:
            for attr, value in rdn:
                if attr == "commonName":
                    names.add(value)
    return names


def _mock_httpx_client(response_payload: dict | None = None):
    """A patched httpx2.Client that succeeds; the call asserts we never reached it."""
    import httpx2

    payload = response_payload if response_payload is not None else {"revoked": False, "new_cert_required": False}
    resp = MagicMock()
    resp.status_code = 200
    resp.content = b"{}"
    resp.json.return_value = payload
    resp.raise_for_status.return_value = None
    client = MagicMock()
    client.post = MagicMock(return_value=resp)
    client.get = MagicMock(return_value=resp)
    client.__enter__ = MagicMock(return_value=client)
    client.__exit__ = MagicMock(return_value=False)
    http2 = httpx2  # keep the import used (mirrors the sibling suites)
    assert http2 is not None
    return client


def _renew_response(cert_path: Path, anchor: Path):
    """A renewal response carrying REAL PEMs — renew re-reads the leaf it just
    wrote for the auth-verification call, so garbage text breaks that second
    client build at HEAD as well as here (the cell must not hinge on that)."""
    now = datetime.datetime.now(datetime.UTC)
    return {
        "executor_id": "test-exec",
        "cert_pem": cert_path.read_text(),
        "ca_cert_pem": anchor.read_text(),
        "serial_number": "AB:CD",
        "not_after": (now + datetime.timedelta(days=365)).isoformat(),
    }


def _renew_args(cert_path: Path, **extra) -> MagicMock:
    args = MagicMock()
    args.cert_path = str(cert_path)
    args.key_path = None
    args.core_url = "https://venya-core"
    args.ca_bundle = extra.get("ca_bundle")
    return args


def _heartbeat_args(cert_path: Path, **extra) -> MagicMock:
    args = MagicMock()
    args.cert_path = str(cert_path)
    args.key_path = None
    args.core_url = "https://venya-core"
    args.ca_bundle = extra.get("ca_bundle")
    return args


def _isolate_config(tmp_path: Path, monkeypatch) -> Path:
    """Point VENYA_CONFIG at a scratch dir whose ca.crt is ABSENT unless a test
    writes it — no cell may depend on the developer's own ~/.config/venya."""
    cfg_dir = tmp_path / "cfg"
    cfg_dir.mkdir(parents=True, exist_ok=True)
    monkeypatch.setenv("VENYA_CONFIG", str(cfg_dir / "config.json"))
    return cfg_dir


# ---------------------------------------------------------------------------
# AC1 — no anchor anywhere: loud failure, never the system store
# ---------------------------------------------------------------------------


class TestNoAnchorFailsLoud:
    def test_renew_without_anchor_refuses_before_any_transport(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture
    ):
        """RED at HEAD: no config-dir CA, no bundle, no sibling ca.crt. HEAD built
        a system-store context and POSTed; the fix refuses and constructs NOTHING."""
        from venya_cli.commands import executor_cert_renew

        cert_path, _key_path = _make_executor_pair(tmp_path)
        _isolate_config(tmp_path, monkeypatch)
        assert not (tmp_path / "ca.crt").exists()

        with patch("venya_cli.commands.httpx2.Client", return_value=_mock_httpx_client()) as mock_ctor:
            result = executor_cert_renew(_renew_args(cert_path))

        assert result == 1
        mock_ctor.assert_not_called()
        err = capsys.readouterr().err
        assert "--ca-bundle" in err
        assert "ca.crt" in err

    def test_heartbeat_without_anchor_refuses_before_any_transport(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture
    ):
        """RED at HEAD, same shape on the heartbeat (it POSTs executor-identifying
        state over the same guessed anchor)."""
        from venya_cli.commands import executor_heartbeat

        cert_path, _key_path = _make_executor_pair(tmp_path)
        _isolate_config(tmp_path, monkeypatch)

        with patch("venya_cli.commands.httpx2.Client", return_value=_mock_httpx_client()) as mock_ctor:
            result = executor_heartbeat(_heartbeat_args(cert_path))

        assert result == 1
        mock_ctor.assert_not_called()
        err = capsys.readouterr().err
        assert "--ca-bundle" in err
        assert "ca.crt" in err

    def test_error_names_the_heartbeat_its_own_site(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture
    ):
        """Diagnosability half: the refusal says WHICH command failed, so an
        operator on a fleet host is not told to re-run the other one."""
        from venya_cli.commands import executor_heartbeat

        cert_path, _key_path = _make_executor_pair(tmp_path)
        _isolate_config(tmp_path, monkeypatch)

        with patch("venya_cli.commands.httpx2.Client", return_value=_mock_httpx_client()):
            executor_heartbeat(_heartbeat_args(cert_path))

        assert "heartbeat" in capsys.readouterr().err


# ---------------------------------------------------------------------------
# AC2 — every configured trust source is honoured, in the register order
# ---------------------------------------------------------------------------


class TestConfiguredAnchorHonoured:
    def test_renew_uses_ca_bundle_flag(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
        """`--ca-bundle` reaches the context: the anchors are exactly that bundle."""
        from venya_cli.commands import executor_cert_renew

        cert_path, _key_path = _make_executor_pair(tmp_path)
        cfg_dir = _isolate_config(tmp_path, monkeypatch)
        bundle = _make_ca(tmp_path, "venya-bundle-ca", "bundle-ca.crt")
        assert not (cfg_dir / "ca.crt").exists()

        with patch(
            "venya_cli.commands.httpx2.Client", return_value=_mock_httpx_client(_renew_response(cert_path, bundle))
        ) as ctor:
            result = executor_cert_renew(_renew_args(cert_path, ca_bundle=str(bundle)))

        assert result == 0
        assert _ctx_anchor_cns(ctor.call_args.kwargs["verify"]) == {"venya-bundle-ca"}

    def test_renew_uses_executor_toml_ca_bundle(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture
    ):
        """`ca_bundle` in executor.toml is a configured source too (the installer
        records it there), with no flag given."""
        from venya_cli.commands import executor_cert_renew

        cert_path, _key_path = _make_executor_pair(tmp_path)
        _isolate_config(tmp_path, monkeypatch)
        bundle = _make_ca(tmp_path, "venya-toml-ca", "toml-ca.crt")
        toml_path = tmp_path / "executor.toml"
        toml_path.write_text(f'ca_bundle = "{bundle}"\n')

        with patch("venya_cli.commands.EXECUTOR_TOML_PATH", str(toml_path)):
            with patch(
                "venya_cli.commands.httpx2.Client", return_value=_mock_httpx_client(_renew_response(cert_path, bundle))
            ) as ctor:
                result = executor_cert_renew(_renew_args(cert_path))

        assert result == 0, capsys.readouterr().err
        assert _ctx_anchor_cns(ctor.call_args.kwargs["verify"]) == {"venya-toml-ca"}

    def test_renew_uses_config_dir_ca_first(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
        """Precedence unchanged from #395: the config-dir CA (`venya setup`) wins
        over the bundle — the incumbent client trust path is not displaced."""
        from venya_cli.commands import executor_cert_renew

        cert_path, _key_path = _make_executor_pair(tmp_path)
        cfg_dir = _isolate_config(tmp_path, monkeypatch)
        _make_ca(cfg_dir, "venya-config-ca", "ca.crt")
        bundle = _make_ca(tmp_path, "venya-bundle-ca", "bundle-ca.crt")

        with patch(
            "venya_cli.commands.httpx2.Client", return_value=_mock_httpx_client(_renew_response(cert_path, bundle))
        ) as ctor:
            result = executor_cert_renew(_renew_args(cert_path, ca_bundle=str(bundle)))

        assert result == 0
        assert _ctx_anchor_cns(ctor.call_args.kwargs["verify"]) == {"venya-config-ca"}

    def test_heartbeat_uses_ca_bundle_flag(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
        from venya_cli.commands import executor_heartbeat

        cert_path, _key_path = _make_executor_pair(tmp_path)
        _isolate_config(tmp_path, monkeypatch)
        bundle = _make_ca(tmp_path, "venya-bundle-ca", "bundle-ca.crt")

        with patch("venya_cli.commands.httpx2.Client", return_value=_mock_httpx_client()) as ctor:
            result = executor_heartbeat(_heartbeat_args(cert_path, ca_bundle=str(bundle)))

        assert result == 0
        assert _ctx_anchor_cns(ctor.call_args.kwargs["verify"]) == {"venya-bundle-ca"}


# ---------------------------------------------------------------------------
# AC3 — paired negatives: the sibling habit survives, the host store does not
# ---------------------------------------------------------------------------


class TestSiblingStillWorksAndStoreIsOut:
    def test_renew_sibling_ca_still_works(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
        """Operator habit preserved: a ca.crt beside the leaf is STILL accepted
        (as the last candidate), so hosts that only have the register-written
        bundle keep renewing."""
        from venya_cli.commands import executor_cert_renew

        cert_path, _key_path = _make_executor_pair(tmp_path)
        _isolate_config(tmp_path, monkeypatch)
        sibling = _make_ca(tmp_path, "venya-sibling-ca", "ca.crt")

        with patch(
            "venya_cli.commands.httpx2.Client", return_value=_mock_httpx_client(_renew_response(cert_path, sibling))
        ) as ctor:
            result = executor_cert_renew(_renew_args(cert_path))

        assert result == 0
        assert _ctx_anchor_cns(ctor.call_args.kwargs["verify"]) == {"venya-sibling-ca"}

    def test_heartbeat_sibling_ca_still_works(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
        from venya_cli.commands import executor_heartbeat

        cert_path, _key_path = _make_executor_pair(tmp_path)
        _isolate_config(tmp_path, monkeypatch)
        _make_ca(tmp_path, "venya-sibling-ca", "ca.crt")

        with patch("venya_cli.commands.httpx2.Client", return_value=_mock_httpx_client()) as ctor:
            result = executor_heartbeat(_heartbeat_args(cert_path))

        assert result == 0
        assert _ctx_anchor_cns(ctor.call_args.kwargs["verify"]) == {"venya-sibling-ca"}

    def test_host_trust_store_is_never_loaded(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
        """THE mechanism cell for "a public CA is rejected even when the host store
        would accept it": the code path must never LOAD the host store. HEAD did
        ``ssl.create_default_context()`` first (system anchors in, always) and only
        then added the Venya CA on top — so the Venya anchor made the trust set
        BIGGER instead of pinning it, and a publicly-signed certificate verified.

        Probed by forbidding the two entry points to the host store, not by counting
        anchors: this venue's CPython 3.14 reports ``create_default_context()`` with
        0 readable anchors (its OpenSSL default paths differ from the system bundle),
        so an anchor count here would prove nothing either way.
        """
        import ssl

        from venya_cli.commands import executor_heartbeat

        def _forbidden(*_a, **_k):
            raise AssertionError("the host trust store must never be a trust source")

        monkeypatch.setattr(ssl, "create_default_context", _forbidden)
        monkeypatch.setattr(ssl.SSLContext, "load_default_certs", _forbidden)

        cert_path, _key_path = _make_executor_pair(tmp_path)
        _isolate_config(tmp_path, monkeypatch)
        bundle = _make_ca(tmp_path, "venya-only-ca", "bundle-ca.crt")

        with patch("venya_cli.commands.httpx2.Client", return_value=_mock_httpx_client()) as ctor:
            result = executor_heartbeat(_heartbeat_args(cert_path, ca_bundle=str(bundle)))

        assert result == 0
        ctx = ctor.call_args.kwargs["verify"]
        assert _ctx_anchor_cns(ctx) == {"venya-only-ca"}
        assert len(ctx.get_ca_certs()) == 1, "the Venya anchor must be the ONLY trust source"
        assert ctx.verify_mode == ssl.CERT_REQUIRED
        assert ctx.check_hostname is True

    def test_renew_host_trust_store_is_never_loaded(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
        """Same prohibition on the renew path — and renew builds the context TWICE
        (the renewal POST and the auth-verification GET), so both must pin the same
        anchor. Spied on the builder because renew writes a fresh keypair mid-run,
        which makes the second real handshake setup fail on its own (a key/cert
        mismatch this cell is not about)."""
        import ssl

        from venya_cli import commands as cmd
        from venya_cli.commands import executor_cert_renew

        def _forbidden(*_a, **_k):
            raise AssertionError("the host trust store must never be a trust source")

        monkeypatch.setattr(ssl, "create_default_context", _forbidden)
        monkeypatch.setattr(ssl.SSLContext, "load_default_certs", _forbidden)

        cert_path, _key_path = _make_executor_pair(tmp_path)
        _isolate_config(tmp_path, monkeypatch)
        bundle = _make_ca(tmp_path, "venya-renew-ca", "bundle-ca.crt")

        seen: list[dict] = []
        real_build = cmd._build_ssl_context

        def _spy(cafile, certfile, keyfile):
            seen.append({"cafile": cafile, "certfile": certfile, "keyfile": keyfile})
            return real_build(cafile, certfile, keyfile)

        monkeypatch.setattr(cmd, "_build_ssl_context", _spy)

        response = _mock_httpx_client(_renew_response(cert_path, bundle))
        with patch("venya_cli.commands.httpx2.Client", return_value=response):
            result = executor_cert_renew(_renew_args(cert_path, ca_bundle=str(bundle)))

        # the second build's failure is renew's own (renewed key vs. fixture cert) and
        # prints 'Certificate was renewed, but auth verification failed.' — not an anchor
        # problem, so rc is checked from the builder's view, not the command's
        assert [c["cafile"] for c in seen] == [str(bundle), str(bundle)], seen
        assert all(c["certfile"] == str(cert_path) for c in seen)
        assert result in (0, 1)

    def test_publicly_signed_anchor_bundle_still_excludes_the_host_store(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ):
        """Paired shape: even when the configured bundle happens to be the system
        CA file, the CODE PATH is anchor-only — the cell above proves the gate,
        this one proves nothing crashes on a big bundle."""
        from venya_cli.commands import executor_heartbeat

        system_bundle = Path("/etc/ssl/certs/ca-certificates.crt")
        if not system_bundle.exists():
            pytest.skip("no system CA bundle on this venue")
        cert_path, _key_path = _make_executor_pair(tmp_path)
        _isolate_config(tmp_path, monkeypatch)

        with patch("venya_cli.commands.httpx2.Client", return_value=_mock_httpx_client()) as ctor:
            result = executor_heartbeat(_heartbeat_args(cert_path, ca_bundle=str(system_bundle)))

        assert result == 0
        assert len(ctor.call_args.kwargs["verify"].get_ca_certs()) > 1


# ---------------------------------------------------------------------------
# AC4 — the sanctioned knob is untouched
# ---------------------------------------------------------------------------


class TestTlsVerifyKnobUnchanged:
    def test_renew_tls_verify_false_still_skips_verification(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture
    ):
        """VENYA_TLS_VERIFY=false keeps its ruled meaning on renew (distrust the
        certificate over https): verify=False, warning printed, NO anchor needed —
        the gate must not turn the knob path into an anchor failure."""
        from venya_cli.commands import executor_cert_renew

        cert_path, _key_path = _make_executor_pair(tmp_path)
        _isolate_config(tmp_path, monkeypatch)
        monkeypatch.setenv("VENYA_TLS_VERIFY", "false")

        # no anchor exists on this branch — the knob path needs none (AC4)
        with patch(
            "venya_cli.commands.httpx2.Client", return_value=_mock_httpx_client(_renew_response(cert_path, cert_path))
        ) as ctor:
            result = executor_cert_renew(_renew_args(cert_path))

        assert result == 0, capsys.readouterr().err
        assert ctor.call_args.kwargs["verify"] is False
        assert "TLS verification disabled" in capsys.readouterr().err

    def test_knob_does_not_reopen_the_no_anchor_case(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture
    ):
        """Companion to the #506 rule: the knob is about VERIFICATION, not scheme.
        Here the scheme is https and the knob is off, so the run proceeds — which
        is exactly why the knob cannot be the thing the anchor gate consults."""
        from venya_cli.commands import executor_heartbeat

        cert_path, _key_path = _make_executor_pair(tmp_path)
        _isolate_config(tmp_path, monkeypatch)
        monkeypatch.delenv("VENYA_TLS_VERIFY", raising=False)

        with patch("venya_cli.commands.httpx2.Client", return_value=_mock_httpx_client()) as ctor:
            result = executor_heartbeat(_heartbeat_args(cert_path))

        assert result == 1
        ctor.assert_not_called()
        assert "TLS verification disabled" not in capsys.readouterr().err


# ---------------------------------------------------------------------------
# Resolver truth table (the shared rule itself, #395 order + #507 sibling)
# ---------------------------------------------------------------------------


class TestSharedResolverTruthTable:
    def test_register_wrapper_message_still_names_the_registration(self, tmp_path: Path):
        """The #395 wrapper keeps its wording class — register cells pin it."""
        from venya_cli.api_client import APIClientError
        from venya_cli.commands import _resolve_register_verify_cafile

        client = MagicMock()
        client.config.ca_path = tmp_path / "absent-ca.crt"
        with pytest.raises(APIClientError) as excinfo:
            _resolve_register_verify_cafile(client, None)
        assert "registration" in str(excinfo.value)
        assert "--ca-bundle" in str(excinfo.value)

    def test_sibling_candidate_is_last_not_first(self, tmp_path: Path):
        """A configured bundle outranks the guessed sibling — the guess stays only
        so old layouts keep working, never so it can shadow real trust material."""
        from venya_cli.commands import _resolve_verify_cafile

        bundle = _make_ca(tmp_path, "venya-bundle", "b.crt")
        sibling = _make_ca(tmp_path, "venya-sibling", "s.crt")
        assert _resolve_verify_cafile(
            tmp_path / "nope.crt", str(bundle), purpose="the test", sibling_ca=sibling
        ) == str(bundle)

    def test_toml_read_is_loud_on_garbage(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture
    ):
        """A malformed executor.toml warns and falls through to the gate — it is
        never parse-silently treated as 'no bundle' with no trace."""
        from venya_cli.commands import executor_heartbeat

        cert_path, _key_path = _make_executor_pair(tmp_path)
        _isolate_config(tmp_path, monkeypatch)
        bad = tmp_path / "executor.toml"
        bad.write_text("this is not [[valid toml")

        with patch("venya_cli.commands.EXECUTOR_TOML_PATH", str(bad)):
            with patch("venya_cli.commands.httpx2.Client", return_value=_mock_httpx_client()) as ctor:
                result = executor_heartbeat(_heartbeat_args(cert_path))

        assert result == 1
        ctor.assert_not_called()
        err = capsys.readouterr().err
        assert "executor.toml" in err
        # proof the file really was unparseable (named type, not a blind assert)
        with pytest.raises(tomllib.TOMLDecodeError):
            tomllib.loads(bad.read_text())
