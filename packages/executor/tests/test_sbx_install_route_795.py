"""iid 795: the `sbx` boot refusal must name an install route that exists on THIS host.

The shipped sentence (base `fc6b8abe`) tells every operator
`sudo apt-get install docker-sbx`, and leg 1373 measured that **no Debian publication face
carries `docker-sbx` at all**, while `noble` and `resolute` do. `README.md`'s own platform
statement says Debian 13 is a Workstation CLI platform, so the sentence routed a CLI-only
platform's operator to an apt package its family never publishes.

The fix classifies. These cells are the four shapes that classification owes, and each has a
counterpart proving the check can answer the other way:

* an apt face that publishes the package still gets the apt route (the Ubuntu server/executor
  target must keep working — this is not a removal of a true instruction);
* a face that does not publish it is never told to `apt-get install docker-sbx`;
* the KVM requirement is stated as a host-privilege requirement with the place it is granted,
  not as a bare `usermod -aG kvm $USER` typed at a refusal;
* **the classifier's own negative** — a face the product cannot identify falls to the safe
  wording, never to the Ubuntu one. Guessing "probably Ubuntu" is how this defect gets worse.

No cell here reads the host's real `/etc/os-release`: the mapping is passed in, so a suite run
on any box tests the classifier, not the box it happens to run on.
"""

from __future__ import annotations

from unittest.mock import patch

import pytest

from executor.strategies import sbx_strategy as sbx

# Faces as leg 1373 measured them: stanzas of `docker-sbx` on
# download.docker.com/linux/<dist>/<codename>. Noble 35, resolute 34, everything else zero.
UBUNTU_NOBLE = {"ID": "ubuntu", "VERSION_CODENAME": "noble"}
UBUNTU_RESOLUTE = {"ID": "ubuntu", "VERSION_CODENAME": "resolute"}
UBUNTU_JAMMY = {"ID": "ubuntu", "VERSION_CODENAME": "jammy"}
UBUNTU_STONKING = {"ID": "ubuntu", "VERSION_CODENAME": "stonking"}
DEBIAN_TRIXIE = {"ID": "debian", "VERSION_CODENAME": "trixie"}
DEBIAN_BOOKWORM = {"ID": "debian", "VERSION_CODENAME": "bookworm"}
UNIDENTIFIED_IDS = (
    {"ID": "tux", "VERSION_CODENAME": "sloth"},
    {"ID": "ubuntu"},  # family known, release not measured either way
    {},  # nothing readable
)

VENDOR_ASSET_MARK = "docker/sbx-releases"


def refusal_text(os_release: dict[str, str]) -> str:
    """The verbatim operator text `validate()` raises for one platform face."""
    with patch("shutil.which", return_value=None), patch.object(sbx, "read_os_release", return_value=os_release):
        with pytest.raises(RuntimeError) as exc:
            sbx.SbxStrategy().validate()
    return str(exc.value)


class TestRouteClassification:
    def test_apt_publishing_face_still_names_the_apt_route(self):
        """The true instruction survives: noble publishes `docker-sbx` (35 stanzas)."""
        text = refusal_text(UBUNTU_NOBLE)
        assert "apt-get install docker-sbx" in text

    @pytest.mark.parametrize("face", [UBUNTU_RESOLUTE])
    def test_the_other_publishing_face_names_it_too(self, face):
        assert "apt-get install docker-sbx" in refusal_text(face)

    @pytest.mark.parametrize(
        "face",
        [DEBIAN_TRIXIE, DEBIAN_BOOKWORM, UBUNTU_JAMMY, UBUNTU_STONKING],
        ids=["debian-trixie", "debian-bookworm", "ubuntu-jammy", "ubuntu-stonking"],
    )
    def test_non_publishing_face_is_never_told_to_apt_install(self, face):
        """RED at base: one sentence served every face, and it was the Ubuntu one."""
        text = refusal_text(face)
        assert "apt-get install docker-sbx" not in text
        assert VENDOR_ASSET_MARK in text

    @pytest.mark.parametrize("face", UNIDENTIFIED_IDS, ids=["foreign-id", "ubuntu-no-codename", "unreadable"])
    def test_unidentified_face_falls_to_safe_wording_not_the_ubuntu_one(self, face):
        """The classifier's own negative — it may not guess."""
        text = refusal_text(face)
        assert "apt-get install docker-sbx" not in text
        assert VENDOR_ASSET_MARK in text

    def test_the_classes_are_distinct_so_the_classifier_cannot_be_a_constant(self):
        """Paired negative for the whole feature: the wording actually differs by face."""
        assert "apt-get install docker-sbx" in refusal_text(UBUNTU_NOBLE)
        assert "apt-get install docker-sbx" not in refusal_text(DEBIAN_TRIXIE)


class TestKvmRequirementIsStatedNotOrdered:
    def test_no_bare_group_edit_is_ordered_at_a_refusal(self):
        for face in (UBUNTU_NOBLE, DEBIAN_TRIXIE, {}):
            assert "usermod -aG kvm $USER" not in refusal_text(face)

    def test_the_requirement_names_the_account_it_is_granted_to_and_the_check(self):
        """iid 384/383 prove kvm is a real installer concern: say what it is and where it lives."""
        text = refusal_text(UBUNTU_NOBLE).lower()
        assert "kvm" in text
        assert "getent group kvm" in text
        assert "installer" in text


class TestRefusalStaysActionable:
    def test_the_head_of_the_sentence_is_unchanged(self):
        """`test_sbx_strategy.py` pins `sbx CLI not found`; the fix must not move the headline."""
        assert refusal_text(DEBIAN_TRIXIE).startswith("sbx CLI not found")

    def test_no_face_gets_a_bare_see_the_docs(self):
        for face in (UBUNTU_NOBLE, DEBIAN_TRIXIE, {}):
            text = refusal_text(face).lower()
            assert "see the docs" not in text
            assert "see documentation" not in text
            assert "curl" in text or VENDOR_ASSET_MARK in text or "apt-get" in text, text


class TestClassifierNormalisation:
    def test_family_match_is_case_and_quote_insensitive(self):
        """os-release allows quoting; a classifier that only reads the exact lowercase string
        silently falls to the safe route on a face that legitimately publishes."""
        assert sbx.sbx_install_route({"ID": '"Ubuntu"', "VERSION_CODENAME": '"Noble"'}) == sbx.ROUTE_APT

    def test_the_measured_absence_is_a_different_route_from_no_measurement(self):
        """jammy was READ as zero stanzas; an Ubuntu release nobody read has no claim at all.
        Collapsing the two is how a measured fact turns back into a guess."""
        assert sbx.sbx_install_route(UBUNTU_JAMMY) == sbx.ROUTE_ASSET
        assert sbx.sbx_install_route({"ID": "ubuntu", "VERSION_CODENAME": "somename"}) == sbx.ROUTE_UNIDENTIFIED


class TestDebianIsRecognisedNotUnknown:
    """The ticket's own subject: a Debian host is a known family with no apt route, and telling
    its operator the distribution was 'not recognised' is a second, different wrong."""

    @pytest.mark.parametrize("face", [DEBIAN_TRIXIE, DEBIAN_BOOKWORM], ids=["trixie", "bookworm"])
    def test_debian_routes_to_the_asset_and_names_the_family(self, face):
        assert sbx.sbx_install_route(face) == sbx.ROUTE_ASSET
        text = refusal_text(face)
        assert "not recognised" not in text
        assert "debian" in text.casefold()

    def test_a_measured_absence_is_phrased_as_a_measurement_not_a_permanent_claim(self):
        """'Docker's debian publication carries no package' is true today and falsifiable at the
        reader's own face; 'will never publish' would age into the same defect this ticket files."""
        assert "never publishes" not in refusal_text(DEBIAN_TRIXIE).lower()


class TestReaderCanFalsifyTheSentence:
    def test_every_non_apt_face_hands_over_the_check_command(self):
        """The staleness guard: a measurement baked into a release must ship the instrument that
        disproves it, or the fix rots into the same lie the next time the vendor publishes.

        Leg 1389 re-aims this, it does not weaken it: the hand-over stays on every face where an
        apt route is genuinely plausible (debian and known-ubuntu families, both asset arms), and
        comes OFF the unidentified face — where the same arm's own first sentence says no package
        manager is named, so naming `apt-cache` made the sentence false on all five unidentified
        shapes (`{}` plus the four in UNIDENTIFIED_IDS). The paired negative below now pins the
        other direction."""
        for face in (DEBIAN_TRIXIE, UBUNTU_JAMMY):
            assert sbx.APT_CHECK in refusal_text(face)

    def test_the_unidentified_face_names_no_package_manager(self):
        """Paired negative, the shape `test_the_apt_face_does_not_need_it` extends: on a face the
        product cannot identify, the refusal names NO package manager — not the apt command, not
        any other — because the sentence that opens the arm claims exactly that. Red at
        `54356e6f`, where the arm pasted `APT_CHECK` into its own last clause."""
        managers = ("apt", "dnf", "yum", "zypper", "pacman", "apk", "emerge", "xbps-install")
        for face in (*UNIDENTIFIED_IDS, {"ID": "rhel"}, {"ID": "suse", "VERSION_CODENAME": ""}):
            text = refusal_text(face)
            assert sbx.APT_CHECK not in text
            lowered = text.casefold()
            named = [m for m in managers if m in lowered]
            assert not named, f"unidentified face {face} names {named}"
            assert "no package manager is named" in lowered  # the claim the arm must keep

    def test_the_apt_face_does_not_need_it(self):
        """Paired negative — the check is not pasted onto a face whose route is the package."""
        assert sbx.APT_CHECK not in refusal_text(UBUNTU_NOBLE)


class TestClassifierIsPure:
    def test_the_class_fn_answers_every_face_without_touching_a_host_file(self):
        assert sbx.sbx_install_route(UBUNTU_NOBLE) == sbx.ROUTE_APT
        assert sbx.sbx_install_route(DEBIAN_TRIXIE) == sbx.ROUTE_ASSET
        assert sbx.sbx_install_route({"ID": "suse"}) == sbx.ROUTE_UNIDENTIFIED

    def test_read_os_release_unquotes_and_survives_a_missing_file(self):
        assert sbx.read_os_release("/nonexistent/f2-795/os-release") == {}
