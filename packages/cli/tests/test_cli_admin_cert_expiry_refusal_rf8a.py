# Copyright (c) 2026 Tabith LLC.
# Use of this source code is governed by the Business Source License 1.1
# included in the LICENSE file at the root of this repository. As of the
# Change Date listed there, the work is available under MPL 2.0.
# SPDX-License-Identifier: BUSL-1.1

"""RF-8a CP-B — the §4.4 helpful expiry refusal, landed at the admin dial seam.

Design record: docs/design/rf6-shortcert-dossier-20261007.md §4.4 (the six ruled
properties), §4.6 (the no-automatic-ceremony boundary, stated as a testable rule)
and §5.7 (the CLI-advises / core-decides asymmetry).

The guard lives inside the lazy transport builder ``APIClient._http``, in the build
branch — the SAME seam the landed #530 anchor refusal and #521 scheme refusal use.
Why there and not in ``__init__``: ``run_command()`` constructs an APIClient for
EVERY command before it dispatches, so an eager raise would brick the very repair the
refusal names. ``TestSetupStillConstructs`` is the anti-regression pair — every cell
in it FAILS if the guard moves to construction.

Because the refusal lands before ``httpx2.Client`` is ever constructed, §4.6's
one-attempt boundary is directly observable: a transport factory that explodes on
construction proves nothing left the machine, and the guard is consulted exactly once
per attempt — no ceremony, no retry loop.
"""

import datetime
import sys
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import httpx2
import pytest
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.x509.oid import NameOID
from venya_cli.api_client import APIClient, APIClientError
from venya_cli.commands import admin_cert_expiry_refusal, cmd_admin_cert_status

UTC = datetime.UTC


def _cert_pair(now: datetime.datetime, before: datetime.timedelta, after: datetime.timedelta):
    """Build a real admin cert + key with an EXPLICIT validity window."""
    key = ed25519.Ed25519PrivateKey.generate()
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "admin-bot@workstation")])
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(key.public_key())
        .serial_number(0x1234_ABCD)
        .not_valid_before(now + before)
        .not_valid_after(now + after)
        .sign(key, None)
    )
    return cert, key


def _pair(
    tmp_path: Path,
    before: datetime.timedelta,
    after: datetime.timedelta,
    subdir: str = "expired",
):
    """Write an admin cert/key pair to disk with the requested window. Returns (cert, key) paths."""
    now = datetime.datetime.now(UTC)
    cert, key = _cert_pair(now, before, after)
    room = tmp_path / subdir
    room.mkdir(exist_ok=True)
    cert_path = room / "admin.crt"
    cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    key_path = room / "admin.key"
    key_path.write_bytes(
        key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
    )
    # 0600 like a real admin key: the constructor's loose-mode warning is a separate
    # rule (tested in test_admin_key_mode_warn.py) and must not pollute these cells.
    key_path.chmod(0o600)
    return cert_path, key_path


def _anchor(tmp_path: Path) -> Path:
    """A self-signed CA PEM planted as SSL_CERT_FILE.

    The expiry guard runs AFTER the #530 anchor check and the #521 scheme check, so a
    cell that wants to observe the expiry refusal needs an anchor and an https URL to
    exist first — otherwise what it sees is a different rule.
    """
    key = ed25519.Ed25519PrivateKey.generate()
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "rf8a-anchor")])
    now = datetime.datetime.now(UTC)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(0x99)
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=1))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(key, None)
    )
    path = tmp_path / "anchor-ca.crt"
    path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    return path


def _client(tmp_path: Path, monkeypatch, cert_path: Path, key_path: Path) -> APIClient:
    """An APIClient with a real anchor, an https URL and the admin pair under test.

    Every admin-relevant env var is set EXPLICITLY (delenv first) so an ambient
    VENYA_ADMIN_CERT on the runner cannot leak into a hermetic cell.
    """
    for var in ("VENYA_ADMIN_CERT", "VENYA_ADMIN_KEY", "SSL_CERT_FILE", "VENYA_TLS_VERIFY"):
        monkeypatch.delenv(var, raising=False)
    monkeypatch.setenv("SSL_CERT_FILE", str(_anchor(tmp_path)))
    monkeypatch.setenv("VENYA_ADMIN_CERT", str(cert_path))
    monkeypatch.setenv("VENYA_ADMIN_KEY", str(key_path))
    return APIClient(server_url="https://core.invalid", config_file=tmp_path / "config.json")


def _no_build_transport():
    """A transport factory that explodes if ANY client is constructed."""
    return MagicMock(side_effect=AssertionError("httpx2.Client was constructed — the expiry guard must land first"))


def _seam_text(client: APIClient) -> str:
    """Dial the seam with no transport available; return the refusal text it raised."""
    with patch("venya_cli.api_client.httpx2.Client", side_effect=AssertionError("transport built")):
        with pytest.raises(APIClientError) as excinfo:
            _ = client._http
    return str(excinfo.value)


class TestExpiredRefusalAtTheSeam:
    """RED at base: an expired admin cert used to reach TLS/the core and die inscrutably."""

    def test_expired_pair_refuses_before_any_transport(self, tmp_path, monkeypatch):
        cert_path, key_path = _pair(tmp_path, datetime.timedelta(days=-1), datetime.timedelta(minutes=-15))
        client = _client(tmp_path, monkeypatch, cert_path, key_path)
        try:
            factory = _no_build_transport()
            with patch("venya_cli.api_client.httpx2.Client", factory):
                with pytest.raises(APIClientError, match="EXPIRED"):
                    _ = client._http
            assert factory.call_count == 0  # nothing was ever constructed
        finally:
            client.close()

    def test_request_path_refuses_and_is_not_reworded(self, tmp_path, monkeypatch):
        """The `_request` half: `http = self._http` resolves OUTSIDE the try (#530 shape),
        so the refusal is never swallowed into 'Connection failed:' by the httpx handlers."""
        cert_path, key_path = _pair(tmp_path, datetime.timedelta(days=-1), datetime.timedelta(minutes=-15))
        client = _client(tmp_path, monkeypatch, cert_path, key_path)
        try:
            with patch("venya_cli.api_client.httpx2.Client", side_effect=AssertionError("transport built")):
                with pytest.raises(APIClientError, match="EXPIRED") as excinfo:
                    client.get("/api/v1/secrets")
            assert "Connection failed" not in str(excinfo.value)
        finally:
            client.close()


class TestSixProperties:
    """§4.4 properties 1-3, 5-6, read straight off the string the seam raises."""

    @pytest.fixture()
    def expired_text(self, tmp_path, monkeypatch) -> str:
        cert_path, key_path = _pair(tmp_path, datetime.timedelta(days=-1), datetime.timedelta(minutes=-42))
        client = _client(tmp_path, monkeypatch, cert_path, key_path)
        try:
            return _seam_text(client)
        finally:
            client.close()

    def test_property_1_names_the_exact_command(self, expired_text):
        assert "`venya admin cert renew`" in expired_text

    def test_property_2_names_file_instant_with_offset_and_age(self, expired_text):
        assert "admin.crt" in expired_text
        assert "+00:00" in expired_text
        assert "42 minutes ago" in expired_text
        assert "this workstation's clock" in expired_text

    def test_property_3_expired_is_not_reported_as_not_yet_valid(self, expired_text):
        assert "EXPIRED" in expired_text
        assert "NOT YET VALID" not in expired_text

    def test_property_3_not_yet_valid_is_its_own_sentence(self, tmp_path, monkeypatch):
        cert_path, key_path = _pair(
            tmp_path, datetime.timedelta(minutes=30), datetime.timedelta(minutes=90), subdir="future"
        )
        client = _client(tmp_path, monkeypatch, cert_path, key_path)
        try:
            text = _seam_text(client)
        finally:
            client.close()
        assert "NOT YET VALID" in text
        assert "EXPIRED" not in text
        assert "CLOCK SKEW" in text
        assert "fix the clock" in text
        # §5.4 property 4: the repair ORDER — time sync first, renew only if the cert is wrong.
        assert text.index("fix the clock") < text.index("`venya admin cert renew`")

    def test_property_5_stdout_clean_and_nonzero(self, tmp_path, capsys):
        cert_path, _key = _pair(tmp_path, datetime.timedelta(days=-1), datetime.timedelta(minutes=-3))
        rc = cmd_admin_cert_status(SimpleNamespace(cert_path=str(cert_path), within=None))
        captured = capsys.readouterr()
        assert rc == 1
        assert captured.out == ""
        assert captured.err.startswith("Error:")

    def test_property_6_refusal_not_prompt(self, expired_text):
        assert "?" not in expired_text
        assert "[Y/n]" not in expired_text
        assert "touch" not in expired_text.lower()


class TestOneAttemptBoundary:
    """§4.6 — the boundary stated as a testable rule: one attempt, no ceremony, no retry."""

    def test_guard_is_consulted_exactly_once_per_attempt(self, tmp_path, monkeypatch):
        cert_path, key_path = _pair(tmp_path, datetime.timedelta(days=-1), datetime.timedelta(minutes=-2))
        client = _client(tmp_path, monkeypatch, cert_path, key_path)
        calls = []
        real = admin_cert_expiry_refusal

        def spy(path, *, site):
            calls.append((path, site))
            return real(path, site=site)

        try:
            with (
                patch("venya_cli.commands.admin_cert_expiry_refusal", side_effect=spy),
                patch("venya_cli.api_client.httpx2.Client", side_effect=AssertionError("transport built")),
            ):
                with pytest.raises(APIClientError, match="EXPIRED"):
                    client.get("/api/v1/secrets")
        finally:
            client.close()
        assert len(calls) == 1, f"expected exactly one guard consultation, got {calls}"
        assert calls[0][0] == str(cert_path)

    def test_no_ceremony_and_no_token_refresh_from_the_refusal(self, tmp_path, monkeypatch):
        """The load-bearing negative half of §4.6: a refusal never reaches for a key,
        and it never tries the bearer refresh path the admin cert must not copy."""
        cert_path, key_path = _pair(tmp_path, datetime.timedelta(days=-1), datetime.timedelta(minutes=-2))
        client = _client(tmp_path, monkeypatch, cert_path, key_path)
        try:
            with (
                patch("venya_cli.api_client.httpx2.Client", side_effect=AssertionError("transport built")),
                patch.object(APIClient, "authenticate") as auth,
                patch.object(APIClient, "refresh_token") as refresh,
            ):
                with pytest.raises(APIClientError, match="EXPIRED"):
                    client.get("/api/v1/secrets")
        finally:
            client.close()
        auth.assert_not_called()
        refresh.assert_not_called()

    def test_second_attempt_refuses_again_without_building_a_client(self, tmp_path, monkeypatch):
        """No client is cached by a refusal: every attempt is refused the same way, and
        the transport factory is still never called (no hidden retry)."""
        cert_path, key_path = _pair(tmp_path, datetime.timedelta(days=-1), datetime.timedelta(minutes=-2))
        client = _client(tmp_path, monkeypatch, cert_path, key_path)
        factory = _no_build_transport()
        try:
            with patch("venya_cli.api_client.httpx2.Client", factory):
                for _ in range(3):
                    with pytest.raises(APIClientError, match="EXPIRED"):
                        client.get("/api/v1/secrets")
        finally:
            client.close()
        assert factory.call_count == 0


class TestHealthyPairProceeds:
    """Paired negative: a certificate inside its window is NOT touched by the guard."""

    def test_healthy_pair_dials_untouched(self, tmp_path, monkeypatch):
        cert_path, key_path = _pair(
            tmp_path, datetime.timedelta(minutes=-5), datetime.timedelta(minutes=45), subdir="healthy"
        )
        client = _client(tmp_path, monkeypatch, cert_path, key_path)
        stub = MagicMock()
        stub.request.return_value.content = b"{}"
        stub.request.return_value.json.return_value = {"ok": True}
        try:
            client._http = stub  # sanctioned test seam: the setter bypasses the real build
            assert client.get("/api/v1/anything") == {"ok": True}
            assert stub.request.call_count == 1
        finally:
            client.close()

    def test_healthy_pair_builds_a_real_transport(self, tmp_path, monkeypatch):
        """Without the setter seam: the guard returns None and the client constructs."""
        cert_path, key_path = _pair(
            tmp_path, datetime.timedelta(minutes=-5), datetime.timedelta(minutes=45), subdir="healthy2"
        )
        client = _client(tmp_path, monkeypatch, cert_path, key_path)
        factory = MagicMock(name="httpx2.Client")
        try:
            with patch("venya_cli.api_client.httpx2.Client", factory):
                _ = client._http
        finally:
            client.close()
        assert factory.call_count == 1

    def test_guard_is_silent_for_a_healthy_cert(self, tmp_path):
        cert_path, _key = _pair(
            tmp_path, datetime.timedelta(minutes=-5), datetime.timedelta(minutes=45), subdir="healthy3"
        )
        assert admin_cert_expiry_refusal(str(cert_path), site="this admin request") is None

    def test_unreadable_cert_is_not_invented_as_expired(self, tmp_path):
        """Wrap-never-invent: a file that is not a certificate is the TLS load path's
        problem (it already refuses loudly, naming file + cause + repair). This guard
        must not claim an expiry it cannot see."""
        junk = tmp_path / "garbage.crt"
        junk.write_text("-----BEGIN CERTIFICATE-----\nnope\n-----END CERTIFICATE-----\n", encoding="utf-8")
        assert admin_cert_expiry_refusal(str(junk), site="this admin request") is None

    def test_missing_cert_is_not_invented_as_expired(self, tmp_path):
        assert admin_cert_expiry_refusal(str(tmp_path / "absent.crt"), site="this admin request") is None


class TestServerDetailPassthrough:
    """§4.4 property 4: when the dial DID happen, the server's detail still arrives verbatim."""

    def test_403_detail_reaches_the_operator_unchanged(self, tmp_path, monkeypatch):
        cert_path, key_path = _pair(
            tmp_path, datetime.timedelta(minutes=-1), datetime.timedelta(minutes=45), subdir="live"
        )
        client = _client(tmp_path, monkeypatch, cert_path, key_path)
        response = httpx2.Response(
            status_code=403,
            json={"detail": "Admin certificate is expired according to this core's clock"},
            request=httpx2.Request("GET", "https://core.invalid/api/v1/secrets"),
        )
        stub = MagicMock()
        stub.request.return_value = response
        try:
            client._http = stub
            with pytest.raises(APIClientError) as excinfo:
                client.get("/api/v1/secrets")
        finally:
            client.close()
        assert "expired according to this core's clock" in str(excinfo.value)

    def test_bearer_only_dial_is_not_expiry_guarded(self, tmp_path, monkeypatch):
        """Load-bearing negative: with NO admin pair, there is no admin cert to police.

        Refusing a bearer dial over an absent file would be a NEW failure mode invented
        by this leg, not a ruled rule — so the guard stays inert and the transport builds.
        """
        monkeypatch.delenv("VENYA_ADMIN_CERT", raising=False)
        monkeypatch.delenv("VENYA_ADMIN_KEY", raising=False)
        monkeypatch.delenv("VENYA_TLS_VERIFY", raising=False)
        monkeypatch.setenv("SSL_CERT_FILE", str(_anchor(tmp_path)))
        client = APIClient(server_url="https://core.invalid", config_file=tmp_path / "config.json")
        assert client._admin_certfile is None
        factory = MagicMock(name="httpx2.Client")
        try:
            with patch("venya_cli.api_client.httpx2.Client", factory):
                _ = client._http
        finally:
            client.close()
        assert factory.call_count == 1


class TestSetupStillConstructs:
    """Anti-regression pair: every cell here FAILS if the guard moves to construction."""

    def test_client_with_expired_pair_still_constructs(self, tmp_path, monkeypatch):
        """`venya setup` — the repair path — must stay constructible on a dead-cert host."""
        cert_path, key_path = _pair(tmp_path, datetime.timedelta(days=-1), datetime.timedelta(minutes=-1))
        client = _client(tmp_path, monkeypatch, cert_path, key_path)
        # Construction is silent: no raise until something actually dials.
        assert client._admin_certfile == str(cert_path)
        client.close()

    def test_injected_stub_bypasses_the_guard(self, tmp_path, monkeypatch):
        """The setter seam stays usable (the #521 requirement): an injected transport
        never consults the expiry guard, so stub-driven tests keep working."""
        cert_path, key_path = _pair(tmp_path, datetime.timedelta(days=-1), datetime.timedelta(minutes=-1))
        client = _client(tmp_path, monkeypatch, cert_path, key_path)
        stub = MagicMock()
        stub.request.return_value.content = b"{}"
        stub.request.return_value.json.return_value = {"stubbed": True}
        try:
            client._http = stub
            with patch("venya_cli.commands.admin_cert_expiry_refusal") as guard:
                assert client.get("/api/v1/x") == {"stubbed": True}
            guard.assert_not_called()
        finally:
            client.close()


class TestWindowsCarrierLine:
    """§6 carrier: one honest line about the interactive-desktop ceremony limitation."""

    def test_expired_refusal_carries_the_windows_line(self, tmp_path, monkeypatch):
        cert_path, key_path = _pair(tmp_path, datetime.timedelta(days=-1), datetime.timedelta(minutes=-4))
        client = _client(tmp_path, monkeypatch, cert_path, key_path)
        try:
            text = _seam_text(client)
        finally:
            client.close()
        assert "interactive desktop session" in text


class TestSharedWording:
    """One wording, reused not copied: the status readout and the seam agree verbatim."""

    def test_status_and_seam_print_the_same_sentence(self, tmp_path, monkeypatch):
        cert_path, key_path = _pair(tmp_path, datetime.timedelta(days=-1), datetime.timedelta(minutes=-9))
        client = _client(tmp_path, monkeypatch, cert_path, key_path)
        try:
            seam_text = _seam_text(client)
        finally:
            client.close()

        captured: list[str] = []

        def sink(text: str) -> int:
            captured.append(text)
            return len(text)

        with patch.object(sys.stderr, "write", side_effect=sink):
            rc = cmd_admin_cert_status(SimpleNamespace(cert_path=str(cert_path), within=None))
        assert rc == 1
        status_text = "".join(captured).strip()
        # ONE wording, two site labels: the seam speaks "this admin request", the
        # readout speaks "the certificate readout". Everything else is byte-identical,
        # which is the whole point of reusing the function instead of copying the text.
        assert status_text.replace("the certificate readout", "this admin request") == seam_text.strip()
        assert admin_cert_expiry_refusal(str(cert_path), site="the certificate readout").strip() == status_text
