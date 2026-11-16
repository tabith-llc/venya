# Copyright (c) 2026 Tabith LLC.
# Use of this source code is governed by the Business Source License 1.1
# included in the LICENSE file at the root of this repository. As of the
# Change Date listed there, the work is available under MPL 2.0.
# SPDX-License-Identifier: BUSL-1.1

"""The release version line (ruling O1199, leg 1444): three faces must say the same two facts.

After any release, ``README.md`` carries the released version and the date it was released as the
first line below the title, and the product site says the same version and the same date. This gate
compares the three faces that would hold those facts:

* the **declared version** — the seven plates (root ``pyproject.toml`` plus ``cli`` ``core``
  ``executor`` ``mcp`` ``server`` ``venya-contract``), the same denominator
  ``test_version_rendering_1196.py:34`` reads;
* the **README top line** — the first non-blank line after the H1 title;
* the **site version claim** — a version token sitting beside a claim word in the page's visible
  text, the marker rule ``test_root_docs_version_claim_640.py`` already uses, so a number quoted in
  a dated historical note is not read as a claim.

The **date face is UTC**. This box runs local time while tags, the ledger and the room run UTC, so a
date written off the workstation clock can land a day off — ``v0.1.0beta1`` is tagged
``2026-10-23T01:40:31-06:00``, and a same-instant stamp at ``18:11`` would be ``2026-10-30`` in UTC.
Dates are therefore compared against the tag that carries the version, read as an offset-aware
timestamp and converted: naive timestamps are refused, never assumed to be somebody's local time.

**Red today, by design.** This tree declares ``0.1.0beta3``; ``README.md`` carries no version line;
the ``venya.ai`` page still says ``Version 0.1.0alpha15`` with no date. A check that read green
against that face would be manufacturing a release act nobody performed. The lines that carry the
version land in the follow-up legs of that ruling, so this gate is meant to be red until then and to go green when they
merge — not to be softened now.

What this gate deliberately does not do:

* It does not require a tag. The version line is written before the tag is cut, so an untagged
  declared version simply has no date to compare against; the README and the site still have to
  agree with the plates, and with each other on the version.
* It does not reach the network. A test that fetches ``venya.ai`` goes red on any air-gapped
  install, and the promise guarded here is a source-tree promise. The page is read from
  ``$VENYA_SITE_SOURCE`` when set, else ``/projects/tabith-websites/venya.ai/live/index.html`` when
  it exists; when neither is present the site cell SKIPS and names the face left unproven. A skip is
  not a pass — ``pytest -rs`` prints it by name, and the fleet gate host has the path.
"""

from __future__ import annotations

import os
import re
import shutil
import subprocess  # nosec B404 — the cross-check runs `git` beside the tree, same seam as core/version.py
import tomllib
from datetime import UTC, datetime
from pathlib import Path

import pytest
from core.version import _git  # the repo's own bounded git reader: fixed argv, answers None, never raises

_ROOT = Path(__file__).resolve().parents[3]
_UTC = UTC

#: relpath of each version-declaring plate, keyed by what it is called in the release record.
_PLATES = {
    "root": "pyproject.toml",
    "core": "packages/core/pyproject.toml",
    "server": "packages/server/pyproject.toml",
    "executor": "packages/executor/pyproject.toml",
    "venya-cli": "packages/cli/pyproject.toml",
    "venya-mcp": "packages/mcp/pyproject.toml",
    "venya-contract": "packages/venya-contract/pyproject.toml",
}

#: Set this to compare a page whose source is not on this host.
SITE_SOURCE_ENV = "VENYA_SITE_SOURCE"
SITE_SOURCE_DEFAULT = Path("/projects/tabith-websites/venya.ai/live/index.html")

#: A version, with or without a leading ``v``, prerelease spelled or PEP 440 letters.
VERSION = re.compile(r"\b[vV]?(\d+\.\d+\.\d+(?:[-.]?(?:alpha|beta|rc|dev)\d*)?)\b")
#: The one date form the rule allows — a calendar date, no time, no clock suffix.
UTC_DATE = re.compile(r"\b(\d{4}-\d{2}-\d{2})\b")
#: A version token is a CLAIM only beside one of these words (the #640 rule, for the #640 reason).
CLAIM_WORD = re.compile(r"\b(version|releas\w*)\b", re.IGNORECASE)


# --------------------------------------------------------------------------- the readers


def read_plate(path: Path) -> str:
    """The version one plate declares. A plate that stopped declaring raises; it never answers None."""
    return tomllib.loads(path.read_text(encoding="utf-8"))["project"]["version"]


def plate_versions(root: Path) -> dict[str, str]:
    """The version each of the seven plates declares, read now."""
    return {name: read_plate(root / rel) for name, rel in _PLATES.items()}


def declared_version(root: Path) -> str | None:
    """The one declared version, or None when the plates disagree.

    Plate agreement is 1196's invariant; this gate does not get to pick a favourite out of a
    denominator that contradicts itself, so a disagreement is reported as its own problem.
    """
    found = set(plate_versions(root).values())
    return found.pop() if len(found) == 1 else None


def utc_date(iso: str) -> str:
    """One offset-aware timestamp, rendered as its UTC calendar date.

    The conversion is the whole clock rule: the same instant read off two clocks is two strings, and
    only the UTC one is comparable across a README, a tag and a page. A naive timestamp is refused
    rather than assumed — an assumption here would silently pick this host's timezone.
    """
    moment = datetime.fromisoformat(iso)
    if moment.tzinfo is None:
        raise ValueError(f"{iso!r} carries no offset; a date face has to say which clock it was read from")
    return moment.astimezone(_UTC).strftime("%Y-%m-%d")


def release_date_utc(root: Path, version: str) -> str | None:
    """The UTC calendar date of the tag naming ``version``, or None while nothing is tagged.

    Both spellings are tried because the two products tag differently: venya prefixes ``v``, and the
    root record's nameplate guard reads the prefixed form.
    """
    for name in (f"v{version}", version):
        iso = _git(root, "log", "-1", "--format=%cI", name)
        if iso:
            return utc_date(iso)
    return None


def top_line(readme_text: str) -> str | None:
    """The first non-blank line after the H1 title — the line the rule names, and only that line."""
    lines = readme_text.splitlines()
    try:
        title = next(i for i, line in enumerate(lines) if line.startswith("# "))
    except StopIteration:
        return None
    for line in lines[title + 1 :]:
        if line.strip():
            return line.strip()
    return None


def facts(text: str) -> tuple[str | None, str | None]:
    """The version and the date a line states; None for a field that is not in it."""
    version = VERSION.search(text)
    date = UTC_DATE.search(text)
    return (version.group(1) if version else None, date.group(1) if date else None)


def visible_text(html: str) -> list[str]:
    """The page as a reader sees it, one entry per source line: script and style bodies and every
    tag gone, line structure kept so a claim is judged as the line it occupies."""
    hidden = re.sub(
        r"<(script|style)\b.*?</\1>",
        lambda m: "\n" * m.group(0).count("\n"),
        html,
        flags=re.DOTALL | re.IGNORECASE,
    )
    return [re.sub(r"<[^>]+>", " ", line) for line in hidden.splitlines()]


def site_claims(html: str) -> list[str]:
    """Every visible line that states a version claim. History without a claim word is not a claim."""
    return [line for line in visible_text(html) if CLAIM_WORD.search(line) and VERSION.search(line)]


def site_source_path() -> Path | None:
    """The page this tree is compared against, or None when no copy of it is reachable from here."""
    env = (os.environ.get(SITE_SOURCE_ENV) or "").strip()
    if env:
        return Path(env)
    return SITE_SOURCE_DEFAULT if SITE_SOURCE_DEFAULT.is_file() else None


# --------------------------------------------------------------------------- the comparison


def readme_problems(declared: str | None, line: str | None, release_date: str | None) -> list[str]:
    """Every way the README top line disagrees with the declared version and the tag's UTC date."""
    if declared is None:
        return ["the seven plates do not declare one version, so no line can state it"]
    if line is None:
        return [f"README.md carries no line below the title; it must state {declared} and its release date"]
    problems: list[str] = []
    version, date = facts(line)
    if version is None:
        problems.append(f"README top line states no version: {line!r}")
    elif version != declared:
        problems.append(f"README top line says {version!r}, the plates declare {declared!r}")
    if date is None:
        problems.append(f"README top line carries no release date: {line!r}")
    elif release_date is not None and date != release_date:
        problems.append(
            f"README top line dates {date!r} but the tag for {declared} is {release_date!r} in UTC "
            "— dates are compared in UTC only"
        )
    return problems


def site_problems(
    declared: str | None, claims: list[str], release_date: str | None, readme_date: str | None = None
) -> list[str]:
    """Every way the page's version claims disagree with the plates, the tag, or the README."""
    if declared is None:
        return []  # no single denominator; the README cell already names that problem
    if not claims:
        return ["the site states no version claim at all"]
    problems: list[str] = []
    for claim in claims:
        version, date = facts(claim)
        shown = claim.strip()
        if version != declared:
            problems.append(f"site claim says {version!r}, the plates declare {declared!r}: {shown!r}")
        if date is None:
            problems.append(f"site claim carries no release date: {shown!r}")
        elif release_date is not None and date != release_date:
            problems.append(
                f"site claim dates {date!r} but the tag for {declared} is {release_date!r} in UTC: {shown!r}"
            )
        elif readme_date is not None and date != readme_date:
            problems.append(f"site claim dates {date!r} where the README says {readme_date!r}: {shown!r}")
    return problems


# --------------------------------------------------------------------------- the real tree


class TestRealTree:
    """These cells read this repository as it stands, and they are red today.

    That is the point of the leg: the rule is standing, the artifacts do not yet carry the line, and
    the gate says so in the suite every lane runs. The fix is the follow-up legs of that ruling writing the lines, not
    this check giving way.
    """

    def test_readme_top_line_states_the_declared_version_and_a_utc_date(self):
        declared = declared_version(_ROOT)
        line = top_line((_ROOT / "README.md").read_text(encoding="utf-8"))
        release = release_date_utc(_ROOT, declared) if declared else None
        print(f"\ndeclared={declared!r} readme_top_line={line!r} tag_utc_date={release!r}")
        assert not readme_problems(declared, line, release), "README and the declared version disagree"

    def test_the_site_states_the_same_version_and_the_same_date(self):
        site = site_source_path()
        if site is None:
            pytest.skip(
                f"no copy of the product page reachable: set ${SITE_SOURCE_ENV} or have "
                f"{SITE_SOURCE_DEFAULT} present — until then the site face is UNPROVEN, not passed"
            )
        declared = declared_version(_ROOT)
        release = release_date_utc(_ROOT, declared) if declared else None
        line = top_line((_ROOT / "README.md").read_text(encoding="utf-8"))
        readme_date = facts(line)[1] if line else None
        claims = site_claims(site.read_text(encoding="utf-8", errors="replace"))
        print(f"\nsite={site} claims={claims}")
        assert not site_problems(declared, claims, release, readme_date), "the site and the declared version disagree"


class TestReleaseDateReader:
    """The clock instrument itself, cross-checked against a second mechanism on real tags."""

    def test_every_tag_here_dates_the_same_way_under_two_instruments(self):
        """`utc_date()` converting %cI, and `git --date=format:%Y-%m-%d` with TZ=UTC, on the same tags.

        Two instruments, one answer: the conversion is not trusted because it is tidy. The cell reads
        the tags that exist and refuses to pass on an empty list, so a face with no tags cannot make
        it green by looking trivially satisfied.
        """
        tags = sorted((_git(_ROOT, "tag", "-l") or "").split())
        assert tags, "no tags in this venue — the instrument comparison did not happen"
        env = {**os.environ, "TZ": "UTC"}
        for tag in tags:
            iso = _git(_ROOT, "log", "-1", "--format=%cI", tag)
            assert iso, f"{tag}: no committer timestamp"
            out = subprocess.run(  # nosec B603 B607 — fixed argv, shell disabled, the tree is this repo
                ["git", "log", "-1", "--format=%ad", "--date=format:%Y-%m-%d", tag],
                cwd=_ROOT,
                capture_output=True,
                text=True,
                timeout=10,
                check=False,
                env=env,
            )
            assert utc_date(iso) == out.stdout.strip(), f"{tag}: {utc_date(iso)} vs {out.stdout.strip()}"

    def test_the_untagged_version_has_no_date_to_compare(self):
        """The face tonight: ``0.1.0beta3`` is declared and tagged by nobody, so nothing is released.

        The reader answers None — it does not invent a date out of the working tree's HEAD.
        """
        assert declared_version(_ROOT) == "0.1.0beta3", "the declared plate moved; re-derive this cell"
        assert release_date_utc(_ROOT, "0.1.0beta3") is None


# --------------------------------------------------------------------------- the paired negatives


class TestPlantedDefects:
    """Each red state planted once, on an explicit denominator, with the good face beside it.

    A check that only ever fires is indistinguishable from one that cannot read, so every red here is
    paired with the same input corrected.
    """

    DECLARED = "0.1.0beta3"
    TAG_UTC = "2026-11-17"
    GOOD = "Current release: 0.1.0beta3, released 2026-11-17"

    def test_the_good_face_is_green(self):
        assert readme_problems(self.DECLARED, self.GOOD, self.TAG_UTC) == []
        assert site_problems(self.DECLARED, ["Version 0.1.0beta3 released 2026-11-17"], self.TAG_UTC) == []

    def test_a_missing_readme_line_is_red(self):
        """The case the ruling names: an empty face is refused, never read as agreement."""
        print(readme_problems(self.DECLARED, None, self.TAG_UTC))
        assert readme_problems(self.DECLARED, None, self.TAG_UTC)

    def test_a_readme_version_that_disagrees_is_red(self):
        problems = readme_problems(self.DECLARED, "Current release: 0.1.0beta2, released 2026-11-17", self.TAG_UTC)
        print(problems)
        assert any("beta2" in p and "beta3" in p for p in problems)

    def test_a_readme_with_no_version_at_all_is_red(self):
        problems = readme_problems(self.DECLARED, "Released 2026-11-17 — see the changelog", self.TAG_UTC)
        print(problems)
        assert any("states no version" in p for p in problems)

    def test_a_readme_date_that_is_missing_is_red(self):
        problems = readme_problems(self.DECLARED, "Current release: 0.1.0beta3", self.TAG_UTC)
        print(problems)
        assert any("no release date" in p for p in problems)

    def test_a_date_from_the_wrong_clock_is_red(self):
        """The same instant, read two ways: ``2026-11-16T20:30:00-07:00`` is ``2026-11-17`` in UTC."""
        iso = "2026-11-16T20:30:00-07:00"
        assert utc_date(iso) == "2026-11-17"
        local = "Current release: 0.1.0beta3, released 2026-11-16"
        problems = readme_problems(self.DECLARED, local, utc_date(iso))
        print(problems)
        assert any("in UTC" in p for p in problems), "a local-clock date must not read green"
        assert readme_problems(self.DECLARED, self.GOOD, utc_date(iso)) == []

    def test_a_naive_timestamp_is_refused_not_assumed(self):
        """A timestamp with no offset is somebody's wall clock; guessing here is the defect itself."""
        with pytest.raises(ValueError):
            utc_date("2026-11-17T09:00:00")

    def test_disagreeing_plates_are_red_on_their_own(self):
        problems = readme_problems(None, self.GOOD, self.TAG_UTC)
        print(problems)
        assert any("plates do not declare one version" in p for p in problems)

    def test_a_site_that_says_nothing_is_red(self):
        print(site_problems(self.DECLARED, [], self.TAG_UTC))
        assert site_problems(self.DECLARED, [], self.TAG_UTC)

    def test_a_site_version_that_disagrees_is_red(self):
        """The live shape today: the page names an older release than the tree declares."""
        problems = site_problems(self.DECLARED, ["Version 0.1.0alpha15 released 2026-11-17"], self.TAG_UTC)
        print(problems)
        assert any("alpha15" in p for p in problems)

    def test_a_site_date_that_is_missing_is_red(self):
        problems = site_problems(self.DECLARED, ["Version 0.1.0beta3"], self.TAG_UTC)
        print(problems)
        assert any("no release date" in p for p in problems)

    def test_a_site_date_that_disagrees_with_the_readme_is_red(self):
        """No tag to appeal to, and the two faces still cannot both be right about the day."""
        problems = site_problems(
            self.DECLARED, ["Version 0.1.0beta3, released 2026-11-18"], None, readme_date="2026-11-17"
        )
        print(problems)
        assert any("where the README says" in p for p in problems)

    def test_a_historical_number_on_the_page_is_not_a_claim(self):
        """The negative of the negative: a version in prose with no claim word is not checked, which
        is the one thing that keeps a gate like this from being deleted inside a week."""
        html = "<p>History</p><p>Validated on 0.1.0alpha16, 2026-09-30.</p>"
        assert site_claims(html) == []

    def test_a_version_line_buried_below_the_title_is_not_accepted(self):
        """The rule says FIRST line below the title. Three sections down is not that line."""
        readme = "# Venya\n\n> Start at docs/agents.md\n\n## Install\n\nVersion 0.1.0beta3 (2026-11-17)\n"
        assert top_line(readme) == "> Start at docs/agents.md"
        assert readme_problems(self.DECLARED, top_line(readme), self.TAG_UTC)


class TestParsersAreHonest:
    """The instruments, so a green run cannot come from a reader that saw nothing."""

    def test_visible_text_keeps_a_claim_and_drops_the_markup(self):
        html = "<div class='tm'>\n  Version 0.1.0beta3 released 2026-11-17\n</div>"
        claims = site_claims(html)
        assert len(claims) == 1, claims
        assert "Version 0.1.0beta3 released 2026-11-17" in claims[0]

    def test_script_and_style_bodies_are_not_visible_text(self):
        html = "<style>a{content:'Version 9.9.9'}</style>\n<p>Version 0.1.0beta3 released 2026-11-17</p>"
        claims = site_claims(html)
        assert len(claims) == 1, claims
        assert "9.9.9" not in claims[0]

    def test_a_version_split_across_inline_tags_is_one_claim(self):
        html = "<p>Version <b>0.1.0beta3</b>, released <span>2026-11-17</span></p>"
        assert facts(site_claims(html)[0]) == ("0.1.0beta3", "2026-11-17")

    def test_top_line_survives_a_blank_line_after_the_title(self):
        assert (
            top_line("# Venya\n\n  Current release: 0.1.0beta3 (2026-11-17)\n")
            == "Current release: 0.1.0beta3 (2026-11-17)"
        )

    def test_a_file_with_no_title_has_no_top_line(self):
        assert top_line("just prose\n") is None

    def test_the_denominator_is_seven_plates(self):
        """Printed, so an empty answer from this check can be proved to have looked."""
        found = plate_versions(_ROOT)
        assert len(found) == 7, found
        assert all(v for v in found.values()), found

    def test_a_plate_that_stops_declaring_raises_rather_than_answering_none(self, tmp_path):
        """Paired negative of the reader: a silent plate cannot quietly become an empty agreement."""
        plate = tmp_path / "pyproject.toml"
        plate.write_text('[project]\nname = "core"\n', encoding="utf-8")
        with pytest.raises(KeyError):
            read_plate(plate)


class TestScratchTree:
    """The whole check end to end against a tree assembled in a scratch directory.

    Nothing here touches this repository: the plates are copied, then one face is moved at a time, so
    a green agreement is shown to be reachable and every moved face is shown to be refused.
    """

    def _tree(self, tmp_path: Path, readme: str, site_html: str | None = None) -> Path:
        for rel in _PLATES.values():
            dest = tmp_path / rel
            dest.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(_ROOT / rel, dest)
        (tmp_path / "README.md").write_text(readme, encoding="utf-8")
        if site_html is not None:
            (tmp_path / "site.html").write_text(site_html, encoding="utf-8")
        return tmp_path

    def test_three_agreeing_faces_are_green(self, tmp_path):
        declared = declared_version(_ROOT)
        tree = self._tree(tmp_path, f"# Venya\n\nCurrent release: {declared}, released 2026-11-17\n", None)
        line = top_line((tree / "README.md").read_text(encoding="utf-8"))
        # a scratch tree has no tags, so there is no date face to compare against there.
        assert readme_problems(declared, line, None) == [], line
        site = f"<p>Version {declared}, released 2026-11-17</p>"
        assert site_problems(declared, site_claims(site), None, readme_date=facts(line)[1]) == []

    def test_a_moved_site_line_against_a_good_readme_is_red(self, tmp_path):
        declared = declared_version(_ROOT)
        tree = self._tree(tmp_path, f"# Venya\n\nCurrent release: {declared}, released 2026-11-17\n", None)
        line = top_line((tree / "README.md").read_text(encoding="utf-8"))
        stale = "<p>Version 0.1.0alpha15, released 2026-11-17</p>"
        problems = site_problems(declared, site_claims(stale), None, readme_date=facts(line)[1])
        print(problems)
        assert problems

    def test_a_moved_readme_line_against_a_good_site_is_red(self, tmp_path):
        declared = declared_version(_ROOT)
        tree = self._tree(tmp_path, "# Venya\n\nCurrent release: 0.1.0beta9, released 2026-11-17\n", None)
        line = top_line((tree / "README.md").read_text(encoding="utf-8"))
        problems = readme_problems(declared, line, None)
        print(problems)
        assert any("beta9" in p for p in problems)

    def test_a_tree_with_no_readme_line_is_red_whatever_the_site_says(self, tmp_path):
        declared = declared_version(_ROOT)
        tree = self._tree(tmp_path, "# Venya\n\n> Start at docs/agents.md\n", None)
        line = top_line((tree / "README.md").read_text(encoding="utf-8"))
        assert readme_problems(declared, line, None)
