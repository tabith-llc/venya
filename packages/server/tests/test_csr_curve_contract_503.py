# Copyright (c) 2026 Tabith LLC.
# Use of this source code is governed by the Business Source License 1.1
# included in the LICENSE file at the root of this repository. As of the
# Change Date listed there, the work is available under MPL 2.0.
# SPDX-License-Identifier: BUSL-1.1

"""#503 option A — the CSR signer honours every curve the surface advertises.

`routes/executors.validate_csr_key_strength` advertises secp256r1 / secp384r1 /
secp521r1 and maps ValueError to a 400. At HEAD the signer in
`CAManager.sign_csr` disagreed: it asserted P-256 only and raised **TypeError**,
which the registration route never catches (its `try` around `sign_csr` catches
RuntimeError → 503 only), so a perfectly-validated P-384/P-521 CSR died as a 500.
A broken CSR self-signature raised ValueError from the same block and escaped the
same way — also a 500.

This suite pins the ruled contract from both sides:

* GREEN  — P-256, P-384 and P-521 all sign, with the leaf extension set unchanged.
* RED    — an off-list curve, an RSA key and a broken self-signature are 400s,
           never 500s; unusable CA material is STILL a 503 (the RuntimeError path
           was not loosened).
* DRIFT  — the advertised list and the enforced list are one object: retargeting
           `ca.ACCEPTED_CSR_CURVE_LABELS` moves the validator and the signer
           together. If either side keeps its own literal list, that cell fails.
"""

from unittest.mock import MagicMock

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, ExtensionOID, NameOID
from fastapi import FastAPI
from server import ca as ca_module
from server.ca import CAManager
from server.routes import executors as executors_routes
from starlette.testclient import TestClient

# ---------------------------------------------------------------------------
# Fixtures and helpers
# ---------------------------------------------------------------------------

ADVERTISED_CURVES: tuple[type[ec.EllipticCurve], ...] = (ec.SECP256R1, ec.SECP384R1, ec.SECP521R1)
# Curves the surface never advertises — both halves of the gate must refuse them.
OFF_LIST_CURVES: tuple[type[ec.EllipticCurve], ...] = (ec.SECP192R1, ec.SECP224R1)
OFF_LIST_IDS = ["secp192r1", "secp224r1"]


@pytest.fixture
def ca_dir(tmp_path):
    """Create a temporary CA directory."""
    d = tmp_path / "ca"
    d.mkdir()
    return str(d)


@pytest.fixture
def ca_manager(ca_dir):
    """Create and initialize a CAManager (P-256 CA — the root stays P-256)."""
    manager = CAManager(ca_dir)
    manager.initialize()
    return manager


def _csr(private_key, common_name: str = "csr-curve-check") -> x509.CertificateSigningRequest:
    """A self-signed CSR carrying the supplied key."""
    subject = x509.Name(
        [
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Venya"),
            x509.NameAttribute(NameOID.COMMON_NAME, common_name),
        ]
    )
    return x509.CertificateSigningRequestBuilder().subject_name(subject).sign(private_key, hashes.SHA256())


def _ec_csr(curve_type: type[ec.EllipticCurve]) -> x509.CertificateSigningRequest:
    return _csr(ec.generate_private_key(curve_type()))


def _tampered_csr(csr: x509.CertificateSigningRequest) -> x509.CertificateSigningRequest:
    """Same CSR with a broken self-signature (one bit of the signature flipped).

    Parses fine and still advertises its curve — only `is_signature_valid` sees
    it, which is exactly why the key-strength validator cannot catch it.
    """
    der = bytearray(csr.public_bytes(serialization.Encoding.DER))
    der[-1] ^= 0x01
    broken = x509.load_der_x509_csr(bytes(der))
    assert broken.is_signature_valid is False, "fixture must produce an unverifiable CSR"
    return broken


def _mock_db() -> MagicMock:
    """Minimal session double: no existing rows, all writes accepted."""
    db = MagicMock()
    db.add = MagicMock()
    db.flush = MagicMock()
    db.commit = MagicMock()

    def query(model):
        m = MagicMock()
        m.filter = lambda *a, **k: m
        m.first = lambda: None
        m.all = list
        return m

    db.query.side_effect = query
    return db


def _register_client(ca_manager_obj: CAManager, db: MagicMock) -> TestClient:
    app = FastAPI()
    app.state.backend = MagicMock()
    app.state.backend.get_session.return_value = db
    app.state.ca_manager = ca_manager_obj
    app.include_router(executors_routes.router, prefix="/api/v1")
    # raise_server_exceptions=False: an escaping defect must land as a 500 status
    # we can assert on, not as an exception out of the client.
    return TestClient(app, raise_server_exceptions=False)


def _post_register(client: TestClient, csr: x509.CertificateSigningRequest, executor_id: str = "curve-exec"):
    csr_pem = csr.public_bytes(serialization.Encoding.PEM).decode()
    return client.post("/api/v1/executors/register", json={"executor_id": executor_id, "csr_pem": csr_pem})


def _ext_set(cert: x509.Certificate) -> list[tuple[object, bool]]:
    """(oid, critical) for every extension — the shape the leaf must keep."""
    return [(e.oid, e.critical) for e in cert.extensions]


# ---------------------------------------------------------------------------
# GREEN — the signer honours all three advertised curves
# ---------------------------------------------------------------------------


class TestSignerAcceptsAdvertisedCurves:
    """sign_csr accepts every curve the registration surface advertises."""

    @pytest.mark.parametrize("curve_type", ADVERTISED_CURVES, ids=lambda c: c().name)
    def test_sign_csr_accepts_curve(self, ca_manager, curve_type):
        cert = ca_manager.sign_csr(_ec_csr(curve_type), "curve-exec")

        cn = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
        assert [a.value for a in cn] == ["curve-exec"], "CN must be the executor id, not the CSR's"

    @pytest.mark.parametrize("curve_type", ADVERTISED_CURVES, ids=lambda c: c().name)
    def test_leaf_extension_set_matches_the_p256_baseline(self, ca_manager, curve_type):
        """Widening the signer changed nothing but the accepted key — the leaf
        extension set is byte-for-byte the same SHAPE a P-256 leaf gets."""
        baseline = ca_manager.sign_csr(_ec_csr(ec.SECP256R1), "base-exec")
        cert = ca_manager.sign_csr(_ec_csr(curve_type), "wide-exec")

        assert _ext_set(cert) == _ext_set(baseline)

        bc = cert.extensions.get_extension_for_oid(ExtensionOID.BASIC_CONSTRAINTS)
        assert bc.critical is True and bc.value.ca is False

        ku = cert.extensions.get_extension_for_oid(ExtensionOID.KEY_USAGE)
        assert ku.critical is True
        assert ku.value.digital_signature is True
        assert ku.value.key_cert_sign is False and ku.value.crl_sign is False

        eku = cert.extensions.get_extension_for_oid(ExtensionOID.EXTENDED_KEY_USAGE)
        assert set(eku.value) == {ExtendedKeyUsageOID.SERVER_AUTH, ExtendedKeyUsageOID.CLIENT_AUTH}

        san = cert.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
        assert san.value.get_values_for_type(x509.DNSName) == ["wide-exec"]

        # SKI keys off the leaf's own (possibly wider) public key; AKI off the CA's.
        ca_cert, _ = ca_manager.load_ca()
        ski = cert.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_KEY_IDENTIFIER)
        assert (
            ski.value.digest == x509.SubjectKeyIdentifier.from_public_key(cert.public_key()).digest
        ), "SKI must describe THIS leaf key"
        aki = cert.extensions.get_extension_for_oid(ExtensionOID.AUTHORITY_KEY_IDENTIFIER)
        assert (
            aki.value.key_identifier
            == x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_cert.public_key()).key_identifier
        )

    @pytest.mark.parametrize("curve_type", ADVERTISED_CURVES, ids=lambda c: c().name)
    def test_leaf_chains_to_the_p256_ca(self, ca_manager, curve_type):
        """The CA key (P-256, SHA-256) signs the leaf, so the signing hash does
        NOT follow the CSR curve — a P-521 leaf is still CA-signed with SHA-256."""
        ca_cert, ca_key = ca_manager.load_ca()
        cert = ca_manager.sign_csr(_ec_csr(curve_type), "chain-exec")

        assert isinstance(cert.public_key().curve, curve_type)
        assert isinstance(ca_key.curve, ec.SECP256R1), "the CA root stays P-256 (#503 does not re-root)"
        assert cert.signature_hash_algorithm.name == "sha256"
        # Raises on a bad signature; the leaf must verify under the CA's key.
        ca_cert.public_key().verify(cert.signature, cert.tbs_certificate_bytes, ec.ECDSA(hashes.SHA256()))

    def test_endpoint_registers_a_p384_executor(self, ca_manager, _executor_ids_resolvable):
        """The 500 at HEAD becomes a 201: a P-384 CSR passes the validator AND signs."""
        client = _register_client(ca_manager, _mock_db())
        resp = _post_register(client, _ec_csr(ec.SECP384R1), "curve-exec")

        assert resp.status_code == 201, resp.text
        cert = x509.load_pem_x509_certificate(resp.json()["cert_pem"].encode())
        assert isinstance(cert.public_key().curve, ec.SECP384R1)
        assert [a.value for a in cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)] == ["curve-exec"]

    def test_endpoint_registers_a_p521_executor(self, ca_manager, _executor_ids_resolvable):
        client = _register_client(ca_manager, _mock_db())
        resp = _post_register(client, _ec_csr(ec.SECP521R1), "curve-exec")

        assert resp.status_code == 201, resp.text
        cert = x509.load_pem_x509_certificate(resp.json()["cert_pem"].encode())
        assert isinstance(cert.public_key().curve, ec.SECP521R1)


# ---------------------------------------------------------------------------
# RED — refusals are clean 400s, never 500s
# ---------------------------------------------------------------------------


class TestRefusalsAreClientErrors:
    """Off-list curves, RSA keys and broken self-signatures: 400, not 500."""

    @pytest.mark.parametrize("curve_type", OFF_LIST_CURVES, ids=OFF_LIST_IDS)
    def test_signer_rejects_off_list_curve_as_valueerror(self, ca_manager, curve_type):
        with pytest.raises(ValueError, match="Unsupported curve"):
            ca_manager.sign_csr(_ec_csr(curve_type), "curve-exec")

    def test_signer_rejects_rsa_csr_as_valueerror(self, ca_manager):
        rsa_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        with pytest.raises(ValueError, match="Unsupported CSR key type"):
            ca_manager.sign_csr(_csr(rsa_key), "curve-exec")

    def test_signer_rejects_broken_self_signature(self, ca_manager):
        with pytest.raises(ValueError, match="CSR signature verification failed"):
            ca_manager.sign_csr(_tampered_csr(_ec_csr(ec.SECP256R1)), "curve-exec")

    @pytest.mark.parametrize("curve_type", OFF_LIST_CURVES, ids=OFF_LIST_IDS)
    def test_endpoint_off_list_curve_is_400_not_500(self, ca_manager, _executor_ids_resolvable, curve_type):
        client = _register_client(ca_manager, _mock_db())
        resp = _post_register(client, _ec_csr(curve_type), "curve-exec")

        assert resp.status_code == 400, resp.text
        assert "curve" in resp.json()["detail"].lower()

    def test_endpoint_rsa_csr_is_400_not_500(self, ca_manager, _executor_ids_resolvable):
        rsa_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        client = _register_client(ca_manager, _mock_db())
        resp = _post_register(client, _csr(rsa_key), "curve-exec")

        assert resp.status_code == 400, resp.text

    def test_endpoint_broken_self_signature_is_400_not_500(self, ca_manager, _executor_ids_resolvable):
        """The half the validator cannot cover: the CSR advertises P-256, so it
        clears key strength and only the signer sees the broken signature. At HEAD
        that ValueError escaped the sign block (RuntimeError→503 only) as a 500."""
        client = _register_client(ca_manager, _mock_db())
        resp = _post_register(client, _tampered_csr(_ec_csr(ec.SECP256R1)), "curve-exec")

        assert resp.status_code == 400, resp.text
        assert "signature" in resp.json()["detail"].lower()

    def test_unusable_ca_material_is_still_503(self, ca_dir, _executor_ids_resolvable):
        """Paired negative for the new 400 path: a CA that cannot be loaded is a
        SERVICE fault. The RuntimeError→503 mapping is untouched by #503."""
        empty_manager = CAManager(ca_dir)  # never initialize()d — no ca.key on disk
        client = _register_client(empty_manager, _mock_db())
        resp = _post_register(client, _ec_csr(ec.SECP256R1), "curve-exec")

        assert resp.status_code == 503, resp.text
        assert resp.json()["detail"] == "Certificate signing unavailable"


# ---------------------------------------------------------------------------
# DRIFT — one list, two readers (AC5)
# ---------------------------------------------------------------------------


class TestAdvertisedAndEnforcedListsAgree:
    """The promise and the vault read the SAME list."""

    def test_every_advertised_curve_passes_both_readers(self, ca_manager):
        for curve_type in ADVERTISED_CURVES:
            csr = _ec_csr(curve_type)
            executors_routes.validate_csr_key_strength(csr)  # no raise
            ca_manager.sign_csr(csr, "curve-exec")

    @pytest.mark.parametrize("curve_type", OFF_LIST_CURVES, ids=OFF_LIST_IDS)
    def test_off_list_curve_is_refused_by_both_readers(self, ca_manager, curve_type):
        csr = _ec_csr(curve_type)
        with pytest.raises(ValueError):
            executors_routes.validate_csr_key_strength(csr)
        with pytest.raises(ValueError):
            ca_manager.sign_csr(csr, "curve-exec")

    def test_hint_text_names_exactly_the_enforced_curves(self):
        """The actionable text and the enforced set cannot disagree."""
        hint = ca_module.csr_curve_hint()
        for name, label in ca_module.ACCEPTED_CSR_CURVE_LABELS.items():
            assert name in hint
            assert label in hint
        assert "secp224r1" not in hint
        assert "secp192r1" not in hint

    def test_single_list_moves_both_readers_together(self, ca_manager, monkeypatch):
        """AC5 drift cell. Dropping P-521 from the ONE shared dict must make BOTH
        the validator and the signer refuse a P-521 CSR; if either side kept its
        own literal curve list, that side would still accept it and this fails."""
        monkeypatch.setattr(
            ca_module,
            "ACCEPTED_CSR_CURVE_LABELS",
            {"secp256r1": "P-256", "secp384r1": "P-384"},
        )
        csr_521 = _ec_csr(ec.SECP521R1)

        with pytest.raises(ValueError, match="Weak or unsupported curve"):
            executors_routes.validate_csr_key_strength(csr_521)
        with pytest.raises(ValueError, match="Unsupported curve"):
            ca_manager.sign_csr(csr_521, "curve-exec")

        # And the 400 text the endpoint would emit follows the retargeted list.
        assert "secp521r1" not in ca_module.csr_curve_hint()
        assert "secp384r1" in ca_module.csr_curve_hint()

    def test_endpoint_400_detail_advertises_the_enforced_set(self, ca_manager, _executor_ids_resolvable):
        """A rejected curve gets a message naming the curves that WOULD work."""
        client = _register_client(ca_manager, _mock_db())
        resp = _post_register(client, _ec_csr(ec.SECP224R1), "curve-exec")

        assert resp.status_code == 400, resp.text
        detail = resp.json()["detail"]
        for name in ca_module.ACCEPTED_CSR_CURVE_LABELS:
            assert name in detail
