# Copyright (c) 2026 Tabith LLC.
# Use of this source code is governed by the Business Source License 1.1
# included in the LICENSE file at the root of this repository. As of the
# Change Date listed there, the work is available under MPL 2.0.
# SPDX-License-Identifier: BUSL-1.1

"""#565 site 1 — what ``AdminCAManager.sign_admin_cert`` does and does not own.

Ruling (R7-Q1, ledger ``cdcde4e``): ruling 4d survives, so the core-side admin
key keeps its ruled resting posture and the plaintext return at this site is not
changed by this row. What the ruling did NOT release is the DELIVERY path —
"remains a defect and stays in the fix set" — and the three obligations that
make up that fix (role-dir destination, enforced file modes, a stated
backup-exclusion requirement) are RF-10's, owned in ``install-venya-core.sh``.

So the useful product-side work at site 1 is to pin the boundary the RF-10 leg
has to land on, in re-runnable cells rather than prose:

* the mint hands back bytes and touches NO filesystem itself — it picks no
  destination and sets no mode, which is exactly why the delivery obligations
  cannot be discharged anywhere in ``packages/``;
* the delivered leaf is plaintext while the CA key beside it is encrypted, both
  under the same configured passphrase — the distinction RF-10 must preserve;
* the destination and the modes appear in the installer's bootstrap block and
  NOWHERE in shipped server source;
* every test file the site's own docstring cites actually exists (the cite this
  changeset repaired had named a file that never existed, so a lane following it
  would have hunted for a cell that was not there).

Paired negatives are stated per cell: each "absent" claim is shown against a
live instance of the same pattern, so no cell passes because its detector is
broken.
"""

import re
import stat
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from server.ca import AdminCAManager
from server.config import CASecurityConfig

_ADMIN_ENV = "VENYA_ADMIN_CA_KEY_PASSPHRASE"

#: Over the #573 15-code-point floor; names the site it belongs to.
_MINT_PASSPHRASE = "site1-seam-passphrase-565"

_IDENTITY = "admin@core-1.internal"

#: The delivered-leaf filenames. They are the installer's business, never the
#: server's — asserted both ways below.
_LEAF_NAMES = ("admin.key", "admin.crt", "venya-admin.key", "venya-admin.crt")

_PKG_SERVER = Path(__file__).resolve().parents[1]
_SRC_ROOT = _PKG_SERVER / "src" / "server"
_REPO_ROOT = _PKG_SERVER.parents[1]
_INSTALLER = _REPO_ROOT / "install-venya-core.sh"


@pytest.fixture(autouse=True)
def _passphrase_env(monkeypatch):
    monkeypatch.setenv(_ADMIN_ENV, _MINT_PASSPHRASE)


@pytest.fixture
def manager(tmp_path: Path) -> AdminCAManager:
    m = AdminCAManager(tmp_path / "admin-ca", CASecurityConfig(key_passphrase_env=_ADMIN_ENV))
    m.initialize()
    return m


def _tree(root: Path) -> dict[str, tuple[int, int]]:
    """relpath -> (mode, size) for every entry under ``root`` (root itself too)."""
    entries = {".": (stat.S_IMODE(root.stat().st_mode), 0)}
    for path in sorted(root.rglob("*")):
        info = path.stat()
        entries[str(path.relative_to(root))] = (stat.S_IMODE(info.st_mode), info.st_size)
    return entries


def _server_source() -> list[tuple[str, str]]:
    return [(str(p.relative_to(_SRC_ROOT)), p.read_text(encoding="utf-8")) for p in sorted(_SRC_ROOT.rglob("*.py"))]


def _leaf_offenders(text: str) -> list[str]:
    """The delivered-leaf names present in ``text`` — the single predicate the
    destination cells share, so its positive and negative halves cannot drift
    apart into two different greps."""
    return [leaf for leaf in _LEAF_NAMES if leaf in text]


class TestMintTouchesNoFilesystem:
    """The seam's server side: bytes out, nothing written."""

    def test_ac_boundary_mint_creates_no_file_and_changes_no_mode(self, manager, tmp_path):
        """The mint owns no destination and sets no modes, so the delivery
        obligations have nothing to attach to in ``packages/`` — that is why the
        #565 site-1 remedy is RF-10's installer edit and cannot be shipped
        server-side. Checked by tree snapshot: same paths, same modes, same sizes."""
        before = _tree(tmp_path)

        _cert, key_pem, cert_pem = manager.sign_admin_cert(_IDENTITY)

        assert _tree(tmp_path) == before, "sign_admin_cert wrote to disk; the destination is not the caller's alone"
        # The bytes still arrived — the cell pins "no writes", not "no output".
        assert key_pem and cert_pem

    def test_ac_boundary_snapshot_detects_a_write(self, manager, tmp_path):
        """Paired negative for the cell above: prove the snapshot is not
        vacuously green — a new file and a mode change MUST each be caught by it.
        Each half is measured against the snapshot immediately before it, so the
        mode change is not proven by the write that preceded it."""
        before = _tree(tmp_path)

        decoy = tmp_path / "admin.key"
        decoy.write_bytes(b"decoy")
        after_write = _tree(tmp_path)
        assert after_write != before, "the snapshot missed a new file; the cell above proves nothing"

        decoy.chmod(0o600)
        assert _tree(tmp_path) != after_write, "the snapshot missed a mode change; the cell above proves nothing"
        # And the mode it caught is the exact one, not merely "different".
        assert _tree(tmp_path)["admin.key"][0] == 0o600


class TestDeliveredLeafVsCAKey:
    """The distinction RF-10 must preserve: plaintext leaf, encrypted CA, one passphrase."""

    def test_leaf_return_is_plaintext_by_ruling(self, manager):
        """Ruling 4d (affirmed by R7-Q1): the returned leaf PEM is plaintext.
        Pinned so a lane cannot quietly change the delivered shape here — that
        change is RF-10's, in the installer, with its own gate. The passphrase
        this run carries is the admin CA's, and it does not reach the return.

        Mechanism, stated because the byte-grep alone would not prove it: a
        passwordless parse reaching an EC P-256 key is what "delivered
        unencrypted" means, and the encrypted-PEM armor being absent is its
        paired negative (the same call on an encrypted body raises TypeError,
        which the cell below shows on the CA key). #537's suite uses that shape
        for the opposite claim, deliberately mirrored here.
        """
        _cert, key_pem, _cert_pem = manager.sign_admin_cert(_IDENTITY)

        leaf = serialization.load_pem_private_key(key_pem, password=None)
        assert isinstance(leaf, ec.EllipticCurvePrivateKey), "the delivered leaf must parse without a passphrase"
        assert isinstance(leaf.curve, ec.SECP256R1)
        assert b"ENCRYPTED" not in key_pem, "the leaf return must keep the ruled posture until RF-10 retires it"

    def test_ca_key_on_disk_stays_encrypted_under_the_same_passphrase(self, manager):
        """Paired negative: the passphrase in play protects the CA key at rest,
        so "plaintext" here is the leaf's ruled shape and not a lost encryption
        setting. The same manager loads its CA key fine (the env opens it) and
        refuses a passwordless read of the bytes — the exact pair #541/#537
        shipped, re-checked here because RF-10 must not disturb it."""
        ca_bytes = manager.ca_key_path.read_bytes()

        assert manager._key_passphrase_env == _ADMIN_ENV, "the manager must read the admin CA variable"
        assert manager._load_ca_key() is not None, "the configured passphrase must open the CA key"
        assert b"ENCRYPTED" in ca_bytes, "the admin CA key must be encrypted at rest (#537)"
        with pytest.raises(TypeError):
            serialization.load_pem_private_key(ca_bytes, password=None)


class TestDestinationAndModesLiveInTheInstaller:
    """The seam's other side, located rather than assumed."""

    def test_shipped_server_source_names_no_leaf_destination(self):
        """No file under ``packages/server/src`` names the delivered-leaf paths:
        destination and modes are not expressible from the server at all."""
        offenders = [name for name, text in _server_source() if _leaf_offenders(text)]

        assert offenders == [], (
            f"server source now names a leaf destination: {offenders} — the destination/mode obligations "
            "belong to the installer's bootstrap block (RF-10), not to packages/"
        )
        # Non-vacuity, in the same breath: the population really is scanned.
        assert len(list(_server_source())) > 40, "the scan walked almost nothing; the cell above proves nothing"

    def test_the_leaf_predicate_flags_a_written_destination_when_one_exists(self):
        """Paired negative for the cell above: the shared predicate must actually
        catch a leaf destination, so "no offenders" is a finding and not a blind
        grep. Fed the installer's own bootstrap line as the live instance."""
        decoy_source = 'Path("$2/admin.key").write_bytes(key_pem)\nPath("$2/admin.crt").chmod(0o644)'

        assert _leaf_offenders(decoy_source) == [
            "admin.key",
            "admin.crt",
        ], "the predicate missed a leaf destination it is supposed to detect"

    def test_installer_bootstrap_block_is_where_destination_and_modes_are_set(self):
        """Paired positive: the same pattern DOES find the names, in the
        installer's ``sign_admin_cert`` unpack — the single place the #565
        delivery obligations are discharged today, and the place RF-10 edits.
        Read-only: this leg holds no installer ok and changes nothing here."""
        installer = _INSTALLER.read_text(encoding="utf-8")
        # The bootstrap block is a quoted heredoc-in-quotes, so the leaf paths
        # reach the file backslash-escaped. Compare the unescaped form: the cell
        # is about the destination and the mode, not about shell quoting.
        plain = installer.replace('\\"', '"')

        assert "sign_admin_cert" in plain, "the bootstrap call site moved; the seam moved with it"
        assert _leaf_offenders(plain)[:2] == [
            "admin.key",
            "admin.crt",
        ], "the leaf destinations are no longer written where this row says they are"
        assert 'Path("$2/admin.key").chmod(0o600)' in plain, (
            "the delivered key's enforced 0600 mode is not where this row says it is — re-derive the seam "
            "before editing it (RF-10: role-dir destination, enforced modes, stated backup exclusion)"
        )
        assert 'install -d -m 0700 -o venya -g venya "$ADMIN_CERT_DIR"' in plain, (
            "the delivered-leaf directory (role dir, 0700 venya:venya — #610: was 0770) "
            "moved — RF-10's destination "
            "obligation has to be measured against the real line, not a remembered one"
        )


class TestSiteDocstringCitesRealCells:
    """Anti-drift: the contract text points at cells that exist."""

    def test_every_tests_cite_in_the_mint_docstring_resolves(self):
        doc = AdminCAManager.sign_admin_cert.__doc__ or ""
        cites = re.findall(r"tests/(\w+\.py)", doc)

        assert cites, "the site's contract must name the cells that hold it"
        for cite in cites:
            path = _PKG_SERVER / "tests" / cite
            assert path.exists(), (
                f"sign_admin_cert cites tests/{cite}, which does not exist — " "correct the cite or restore the cell"
            )

    def test_the_rotted_cite_this_changeset_repaired_is_gone(self):
        """Negative half: the name that never had a file behind it may not come back."""
        stale = "test_rf7_bootstrap_mint_interlock.py"

        assert not any(stale in text for _, text in _server_source()), f"stale cite {stale!r} is back in server source"
