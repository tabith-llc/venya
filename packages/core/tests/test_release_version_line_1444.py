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
date written off the workstation clock can land a day off. The crossing shape is the one that matters:
``2026-09-17T20:30:00-07:00`` is ``2026-09-18T03:30:00Z`` — the UTC calendar day is the one AFTER the day
the offset spells. Both instruments in ``TestReleaseDateReader`` therefore have to read the same **field**
(the committer stamp) in the same **clock** (UTC); ``v0.1.0beta1`` and ``v0.1.0beta2`` are stamped
``-06:00`` and do not cross, which is why a venue holding only those two tags cannot see a clock bug at all.
Dates are compared against the tag that carries the version, read as an offset-aware
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
* It does not reach the network, and it does not guess which page you meant. A test that fetches
  ``venya.ai`` goes red on any air-gapped install, and the promise guarded here is a promise about a source
  tree. The page comes from ``$VENYA_SITE_SOURCE`` and from nowhere else: a working copy of another
  repository's capture slot can be weeks behind its own authority face and behind the bytes actually being
  served, and reading such a file silently is how a check ends up stating something false about a
  customer-facing page. When the variable is unset the site cell SKIPS and names the face left unproven.
  A skip is not a pass — ``pytest -rs`` prints it by name.
"""

from __future__ import annotations

import os
import re
import shutil
import subprocess  # nosec B404 — the cross-check runs `git` beside the tree, same seam as core/version.py
import tomllib
from datetime import UTC, date, datetime
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

#: The page to compare is named, never assumed. Set this to a capture you believe in.
SITE_SOURCE_ENV = "VENYA_SITE_SOURCE"
#: No default path. A working copy of another repository's capture slot can be weeks behind both its own
#: authority face and the bytes being served, and reading it silently produces a confident false statement
#: about a customer-facing page. Measured at this pen: the local `venya.ai/live/index.html` is 30,576 bytes
#: claiming `Version 0.1.0alpha15`, while the site serves 57,155 bytes and says `v0.1.0beta2 is current as
#: of 30 October 2026` — and those 57,155 bytes are what the sites repo's own authority face holds. So the
#: site half compares `$VENYA_SITE_SOURCE` when it names a readable file, and otherwise SKIPS and says so.
SITE_SOURCE_DEFAULT = None

#: A version, with or without a leading ``v``, prerelease spelled or PEP 440 letters.
VERSION = re.compile(r"\b[vV]?(\d+\.\d+\.\d+(?:[-.]?(?:alpha|beta|rc|dev)\d*)?)\b")
#: The date forms the rule allows — a calendar date, no time, no clock suffix.
UTC_DATE = re.compile(r"\b(\d{4}-\d{2}-\d{2})\b")
#: The two word orders a human date is actually written in, named rather than guessed at: the product page
#: uses `30 October 2026`, a README would use `October 30, 2026`. Anything else ("October 2026", "last
#: month") matches nothing here and stays a refusal, which is the reason to list forms instead of parsing prose.
_MONTHS = "January|February|March|April|May|June|July|August|September|October|November|December"
#: Month names resolved here, not through `%B`, so the answer does not depend on the locale of the seat that
#: runs the suite — and a release day is a **calendar date**, not a datetime, which is the form this repo's
#: own rule asks for.
_MONTH_NUMBER = {name.lower(): number for number, name in enumerate(_MONTHS.split("|"), start=1)}
LONG_DATE = re.compile(r"\b(" + _MONTHS + r")\s+(\d{1,2}),\s*(\d{4})", re.IGNORECASE)
LONG_DATE_DAY_FIRST = re.compile(r"\b(\d{1,2})\s+(" + _MONTHS + r"),?\s*(\d{4})", re.IGNORECASE)
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


# --------------------------------------------------------------------------- the date instruments

#: The calendar form both instruments render. A date, no time, no clock suffix.
_DATE_FORM = "%Y-%m-%d"


def _git_env(hermetic: bool = False, **extra: str) -> dict[str, str]:
    """The environment an instrument reading runs under: always ``TZ=UTC``.

    ``hermetic=True`` also points ``GIT_CONFIG_GLOBAL`` / ``GIT_CONFIG_SYSTEM`` at ``os.devnull``, for the
    throwaway fixture repo only: a fixture must not inherit this host's global git settings — including the
    fleet's armed commit hooks, which are a venue rule and must never decide a test verdict. A reading of a
    real venue stays on the box's own config, because that is where ``safe.directory`` lives and an instrument
    that cannot open the repository it is measuring is not measuring anything.
    """
    env = {**os.environ, "TZ": "UTC", **extra}
    if hermetic:
        env["GIT_CONFIG_GLOBAL"] = os.devnull
        env["GIT_CONFIG_SYSTEM"] = os.devnull
    return env


def _run_git(root: Path, *args: str, hermetic: bool = False) -> str:
    """A git reading that must succeed: fixed argv, shell disabled, bounded by timeout, rc is the check."""
    out = subprocess.run(  # nosec B603 B607 — fixed argv, shell disabled, constant "git" on PATH
        ["git", *args],
        cwd=root,
        capture_output=True,
        text=True,
        timeout=10,
        check=False,
        env=_git_env(hermetic=hermetic),
    )
    assert out.returncode == 0, f"git {' '.join(args)} at {root} rc {out.returncode}: {out.stderr.strip()[:200]}"
    return out.stdout.strip()


def committer_date_utc(root: Path, name: str, hermetic: bool = False) -> str:
    """Instrument two: the tag's committer stamp rendered as a UTC calendar date, by git itself.

    ``format-local:`` is the variant that honours ``TZ``. ``%cd`` is the committer stamp, the same field
    ``release_date_utc()`` reads through ``%cI`` — two instruments have to be pointed at one field before
    their agreement means anything, and ``%ad`` (author) against ``%cI`` (committer) was the second way this
    cell could compare two different instants.
    """
    return _run_git(root, "log", "-1", "--format=%cd", f"--date=format-local:{_DATE_FORM}", name, hermetic=hermetic)


def committer_date_at_stored_offset(root: Path, name: str, hermetic: bool = False) -> str:
    """The reading this cell used to make, kept on purpose as the control that can still fire.

    ``--date=format:`` renders in the commit's OWN stored offset and ignores ``TZ``, so ``TZ=UTC`` beside it
    is a statement the instrument does not obey. On the planted tag below it answers a day earlier than the
    UTC reading, which is what makes the agreement in ``committer_date_utc`` a measurement rather than a tautology.
    """
    return _run_git(root, "log", "-1", "--format=%cd", f"--date=format:{_DATE_FORM}", name, hermetic=hermetic)


def release_tag_names(root: Path) -> list[str]:
    """The tags the cross-check runs over, by a predicate: ``git tag -l``, kept where ``VERSION`` matches.

    ``VERSION`` is this file's own version pattern — the one that decides what counts as a release claim on a
    page — so the denominator of the tag check is the same grammar as the claim it guards, and not "whatever
    refs this venue happens to hold". Measured on this box: the authority remote carries TWO tags
    (``git ls-remote --tags <authority-remote>``), while one lane's venue held 52 refs including ``tmp928``,
    ``ghprobe--alpha.8`` and an ``archive/tickets-50ceec0`` ref-tag. A guard whose verdict moves with that
    accumulation is not a guard. A mirror whose NAME carries the version grammar stays in: it points at a
    release commit, and the instrument comparison is valid over it.
    """
    return sorted(t for t in (_git(root, "tag", "-l") or "").split() if VERSION.search(t))


#: A stamp written twenty-three minutes before that offset's own midnight: the UTC day is the day AFTER the
#: one the offset spells. This is the shape that split the two instruments.
CROSSING_STAMP = "2026-09-17T20:30:00-07:00"
CROSSING_UTC_DAY = "2026-09-18"
CROSSING_OFFSET_DAY = "2026-09-17"
CROSSING_TAG = "v0.0.0-crossing"
#: The other shape a real venue carries: a stamp whose offset and UTC day are the same number — `v0.0.0beta1`'s
#: own committer stamp. A venue holding only tags like this one cannot see a clock defect at all.
NONCROSSING_STAMP = "2026-10-23T01:40:31-06:00"
SCRATCH_REF = "tmp928"


def planted_venue(repo: Path, tags: dict[str, str]) -> Path:
    """A throwaway repo carrying ``tags`` (name -> committer stamp): a venue whose contents you control.

    Why plant a venue instead of reading this one: the case at issue is a tag whose stored offset lands it on a
    different UTC day, and no venue is obliged to hold one. This lane's venue holds two tags, neither of which
    crosses, and passed the old instrument happily — so that cell could not see the defect it later went red
    about. A planted venue makes the comparison fire on every host, empty venue or full, and lets the
    denominator be tested against a named scratch ref instead of trusting which tags a lane left behind.
    """
    repo.mkdir(parents=True, exist_ok=True)

    def run(stamp: str, *args: str) -> None:
        out = subprocess.run(  # nosec B603 B607 — fixed argv, shell disabled, constant "git" on PATH
            ["git", *args],
            cwd=repo,
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
            env=_git_env(hermetic=True, GIT_AUTHOR_DATE=stamp, GIT_COMMITTER_DATE=stamp),
        )
        assert out.returncode == 0, f"fixture git {args[0]!r} rc {out.returncode}: {out.stderr.strip()[:200]}"

    run(NONCROSSING_STAMP, "init", "-q", ".")
    for name, stamp in tags.items():
        run(
            stamp,
            "-c",
            "user.name=Release Date Fixture",
            "-c",
            "user.email=fixture@invalid",
            "commit",
            "-q",
            "--allow-empty",
            "-m",
            f"planted {name}",
        )
        run(stamp, "tag", name)
    return repo


def planted_crossing_tag(repo: Path) -> Path:
    """A venue carrying exactly one release-shaped tag, stamped across a UTC day boundary."""
    return planted_venue(repo, {CROSSING_TAG: CROSSING_STAMP})


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


def iso_of_prose(text: str) -> str | None:
    """A human-written calendar date rendered as ISO, or None. `October 30, 2026` -> `2026-10-30`.

    The rule states a date and a clock, not a typography, so the comparison is by value: a README may carry
    the ISO form while the page carries words for the same day. An impossible or partial date answers None and
    is refused as missing, never coerced into a value it did not state.
    """
    for pattern, order in ((LONG_DATE, "mdy"), (LONG_DATE_DAY_FIRST, "dmy")):
        match = pattern.search(text)
        if not match:
            continue
        if order == "mdy":
            month_name, day, year = match.group(1), match.group(2), match.group(3)
        else:
            day, month_name, year = match.group(1), match.group(2), match.group(3)
        month = _MONTH_NUMBER.get(month_name.lower())
        if month is None:
            continue
        try:
            return date(int(year), month, int(day)).isoformat()
        except ValueError:
            continue
    return None


def facts(text: str) -> tuple[str | None, str | None]:
    """The version and the date a line states, the date in ISO form; None for a field that is not in it."""
    version = VERSION.search(text)
    iso = UTC_DATE.search(text)
    date = iso.group(1) if iso else iso_of_prose(text)
    return (version.group(1) if version else None, date)


def untagged_note(declared: str | None, line_date: str | None, release_date: str | None) -> str:
    """The sentence a date carries when no tag exists to check it against — never a failure of its own.

    A version line is drafted before the tag is stamped, so its day is a statement about the future until the
    tag exists. Saying so is the honest face; the note disappears the moment a tag answers it, at which point
    a disagreement turns the real-tree cell red. So the grace cannot outlive the release it covers.
    """
    if declared is None or release_date is not None or line_date is None:
        return ""
    return (
        f"NOTE  the README dates {declared} as {line_date!r} and no tag names that version, so the date is "
        "UNVERIFIED — a tag on a different UTC day turns this line red, which is the point of the rule"
    )


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
    """The page named by $VENYA_SITE_SOURCE, or None. None is a named SKIP, never a pass."""
    env = (os.environ.get(SITE_SOURCE_ENV) or "").strip()
    if env and Path(env).is_file():
        return Path(env)
    return None


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
        problems = readme_problems(declared, line, release)
        note = untagged_note(declared, facts(line)[1] if line else None, release)
        if note:
            print(note)
        assert not problems, "README and the declared version disagree"

    def test_the_site_states_the_same_version_and_the_same_date(self):
        site = site_source_path()
        if site is None:
            pytest.skip(
                f"no page named: set ${SITE_SOURCE_ENV} to a capture of the product page you mean to compare — "
                "there is no default path, because a capture that has not been refetched describes the past, "
                "and a site face left unnamed is UNPROVEN, not passed"
            )
        declared = declared_version(_ROOT)
        release = release_date_utc(_ROOT, declared) if declared else None
        line = top_line((_ROOT / "README.md").read_text(encoding="utf-8"))
        readme_date = facts(line)[1] if line else None
        claims = site_claims(site.read_text(encoding="utf-8", errors="replace"))
        print(f"\nsite={site} claims={claims}")
        assert not site_problems(declared, claims, release, readme_date), "the site and the declared version disagree"


class TestReleaseDateReader:
    """The clock instrument itself, cross-checked against a second mechanism on a denominator that does not move.

    Both instruments read ONE field (the committer stamp) in ONE clock (UTC), and the comparison is anchored
    by a planted tag that straddles a UTC day, so it fires on any host — not only on a venue that happens to
    hold a crossing tag, which is how this cell came to be green in one lane's clone and red in another's on
    identical bytes.
    """

    def test_the_instruments_agree_on_a_planted_tag_that_crosses_a_utc_day(self, tmp_path):
        """The case the old reading got wrong: `2026-09-17T20:30:00-07:00` is `2026-09-18` in UTC."""
        repo = planted_crossing_tag(tmp_path / "crossing")
        iso = _run_git(repo, "log", "-1", "--format=%cI", CROSSING_TAG, hermetic=True)
        assert iso, "the planted tag has no committer timestamp — the fixture did not build"
        assert utc_date(iso) == CROSSING_UTC_DAY, f"python reader: {utc_date(iso)}"
        assert committer_date_utc(repo, CROSSING_TAG, hermetic=True) == CROSSING_UTC_DAY

    def test_the_paired_negative_the_stored_offset_reading_disagrees_on_that_same_tag(self, tmp_path):
        """The comparison can fire: the form this cell used to run prints the OTHER day on the same tag.

        Two instruments agreeing is worth nothing until you have seen them capable of disagreeing. Here the
        same commit, with `TZ=UTC` set for both, answers `2026-09-17` under `--date=format:` and `2026-09-18`
        under `--date=format-local:`. Revert the instrument and the cell above goes red; that is the proof
        this file asked for and did not have.
        """
        repo = planted_crossing_tag(tmp_path / "negative")
        assert committer_date_at_stored_offset(repo, CROSSING_TAG, hermetic=True) == CROSSING_OFFSET_DAY
        assert committer_date_utc(repo, CROSSING_TAG, hermetic=True) == CROSSING_UTC_DAY

    def test_every_release_tag_here_dates_the_same_way_under_two_instruments(self):
        """The venue half, over a named denominator: the tags here whose name carries the release grammar.

        An empty set is not a silent pass — the instrument is already proved on the planted tag, which every
        host carries by construction. What this loop adds is the real tags, and it prints how many it read so
        a count in a report can be re-derived instead of trusted.
        """
        names = release_tag_names(_ROOT)
        print(f"\ndenominator: {len(names)} release tag(s) at {_ROOT}: {names}")
        for tag in names:
            iso = _git(_ROOT, "log", "-1", "--format=%cI", tag)
            assert iso, f"{tag}: no committer timestamp"
            git_day = committer_date_utc(_ROOT, tag)
            assert utc_date(iso) == git_day, f"{tag}: {utc_date(iso)} vs {git_day}"

    def test_the_denominator_is_a_predicate_and_not_an_accident(self):
        """Both directions of the filter, on the names actually measured in a lane venue.

        The dropped list is that venue's scratch — a probe tag, a scratch dated tag, an archive ref-tag — so
        the predicate is checked against the shape that made this cell's verdict move, not a convenient list.
        """
        kept = ["v0.1.0beta1", "v0.1.0beta2", "v0.1.0alpha12", "v0.1.0-alpha12", "github-v0.1.0-alpha12", CROSSING_TAG]
        dropped = ["tmp928", "ghprobe--alpha.8", "archive/tickets-50ceec0", "HEAD"]
        assert [n for n in kept if VERSION.search(n)] == kept, "the predicate dropped a release name"
        assert [n for n in dropped if VERSION.search(n)] == [], "the predicate kept a ref naming no version"

    def test_the_loop_fires_on_a_planted_venue_holding_a_crossing_tag(self, tmp_path):
        """The venue loop, on data this host controls: two release names (one crossing) and one scratch ref.

        This closes the hole the two instrument cells cannot: nothing but the venue's own tag set exercised the
        loop body, and on a venue of non-crossing tags the loop passed under the wrong instrument too. Here the
        scratch ref is planted beside the release names, so the denominator is seen to drop it by name while
        the comparison still runs over both tags that count — including the one that crosses.
        """
        repo = planted_venue(
            tmp_path / "venue",
            {CROSSING_TAG: CROSSING_STAMP, "v0.0.0-plain": NONCROSSING_STAMP, SCRATCH_REF: CROSSING_STAMP},
        )
        names = release_tag_names(repo)
        assert set(names) == {CROSSING_TAG, "v0.0.0-plain"}, f"denominator moved: {names}"
        assert SCRATCH_REF not in names
        for tag in names:
            iso = _run_git(repo, "log", "-1", "--format=%cI", tag, hermetic=True)
            git_day = committer_date_utc(repo, tag, hermetic=True)
            assert utc_date(iso) == git_day, f"{tag}: {utc_date(iso)} vs {git_day}"
        assert utc_date(_run_git(repo, "log", "-1", "--format=%cI", CROSSING_TAG, hermetic=True)) == CROSSING_UTC_DAY

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

    def test_a_human_date_is_read_as_the_same_value_as_the_iso_form(self):
        """Both word orders the artifacts actually use, and only those."""
        assert facts("Version 0.1.0beta3, released October 30, 2026")[1] == "2026-10-30"
        assert facts("v0.1.0beta3 is current as of 30 October 2026")[1] == "2026-10-30"
        assert facts("Version 0.1.0beta3, released 2026-10-30")[1] == "2026-10-30"

    def test_a_human_date_that_disagrees_in_value_is_red(self):
        problems = readme_problems(
            self.DECLARED, "Current release: 0.1.0beta3, released October 30, 2026", self.TAG_UTC
        )
        print(problems)
        assert any("in UTC" in p for p in problems), "a prose date on the wrong day must not read green"

    def test_a_partial_or_impossible_human_date_is_refused_as_missing(self):
        """`October 2026` names no day and `February 30` names no date — neither coerces into a pass."""
        assert facts("Current release: 0.1.0beta3, released October 2026")[1] is None
        assert iso_of_prose("released February 30, 2026") is None
        assert readme_problems(self.DECLARED, "Current release: 0.1.0beta3, released October 2026", self.TAG_UTC)

    def test_an_untagged_date_is_reported_and_not_refused(self):
        """The draft state the rule names: a version line written before its tag.

        The note is the disclosure, and it is empty the moment a tag answers the date — so a drafted day
        cannot sit inside a green suite forever, and a tag on another UTC day turns the real-tree cell red.
        """
        assert untagged_note(self.DECLARED, "2026-11-16", None).startswith("NOTE")
        assert untagged_note(self.DECLARED, "2026-11-16", self.TAG_UTC) == ""
        assert untagged_note(self.DECLARED, None, None) == ""

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
