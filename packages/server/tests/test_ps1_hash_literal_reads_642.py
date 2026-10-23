# Copyright (c) 2026 Tabith LLC.
# Use of this source code is governed by the Business Source License 1.1
# included in the LICENSE file at the root of this repository. As of the
# Change Date listed there, the work is available under MPL 2.0.
# SPDX-License-Identifier: BUSL-1.1

"""#642 static cells: the integrity READS bind ``-LiteralPath``, and the net now names the verbs it casts.

Why this file exists. #628/#629 landed a sweep that enumerates ``Test-Path`` call sites and asserts each
binds ``-LiteralPath``. That sweep is correct and it is blind: **a regex that asks "is every Test-Path
literal" cannot answer "is every hash read literal."** Three integrity reads on the anti-tamper path — the
``uv.exe`` hash gate, the tarball hash gate, and the sidecar read — bind ``-LiteralPath`` and carried no
pin at all. The code is right; nothing guarded it staying right. That is the class this board booked four
times the same night (566, 614/630, 634, 640): a check whose scope quietly omits its subject passes by
construction.

So the cells below name the verbs they enumerate (``COVERED_VERBS``) instead of inheriting a verb from
whichever defect was found last. Adding a ``-LiteralPath``-capable verb to the integrity path is a change
to this file's scope, in the open, not a silent miss.

**These are STATIC SOURCE CELLS — the Linux limit, stated where it cannot be missed.** No ``pwsh`` runs
here and no ``.ps1`` is executed by this file; a green read establishes only that the shipped TEXT binds the
literal form. Behavioural proof needs the shipping platform (``win11``), which is an owner-present window.
A prior worker lane's caveat, carried on the row and not in a footnote: **a Linux-green pin proves source, never a
``.ps1`` acceptance criterion.**

Truth table, in the #628 idiom. POSITIVE: every covered-verb call site binds ``-LiteralPath``, and each of
the three named integrity sites is asserted separately so a single revert fails at its own door. NEGATIVE: a
hand-written reverted form of each site goes through the same detector and must be reported, and its literal
form must read clean; additionally ``Test-Path``-shaped detection is fed a hash site and must MISS it — the
blind spot, measured.

EXEMPTIONS, pinned as decisions rather than left as gaps:
* whole-line ``#`` comments are prose, not calls (the installer carries one naming ``Get-FileHash``);
* ``uninstall-venya-cli.ps1``'s printed advice line ``Warn '  Get-ChildItem C:\\Users\\*\\…'`` — the ``*``
  is INTENTIONAL (it means every user profile). It is text inside another command's quoted argument, the
  detector must not count it, and the line must not be "corrected";
* the four ``New-Item -ItemType Directory -Force -Path`` sites are **unconvertible** — ``New-Item`` has no
  ``-LiteralPath`` parameter. A prior worker lane's measurement, not PowerShell folklore: pinned as count and form,
  with the fake conversion refused, so nobody buys a green by writing a parameter that does not exist.

No product byte moves. This file reads two ``.ps1`` texts and asserts. The exemption comment AC6 permits was
deliberately NOT added to the installers: the statement belongs where enforcement lives, and a test-only leg
has no business editing a shipped installer script.
"""

import re
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[3]

#: The two tracked PowerShell installers, named here so a third file in this plane is a visible omission
#: rather than an invisible one.
PS1_FILES = ("install-venya-cli.ps1", "uninstall-venya-cli.ps1")
PS1_TEXT = {name: (REPO_ROOT / name).read_text(encoding="utf-8") for name in PS1_FILES}

#: The verbs this net casts. Each is a PowerShell command that accepts ``-LiteralPath`` and takes a
#: wildcard-resolving ``-Path`` by default, so a positional call on any of them is the #628 door wearing
#: different clothes. Write verbs (``Set-Content``/``Add-Content``) are out of scope by decision: none
#: appears in this plane, and this row is about the READS that stand between a swapped file on disk and an
#: install that reports success.
COVERED_VERBS = ("Get-FileHash", "Get-Content", "Get-ChildItem")

#: Tokens after which a verb is the command being invoked. Note the ABSENCE of an empty string:
#: ``anything.endswith("")`` is True for every line, and the first version of this constant carried one,
#: which made the sweep report the ``Warn`` advice line as a call site. The paired cell
#: ``test_the_advice_wildcard_stays_a_wildcard`` is what caught it, so the bug is pinned rather than merely
#: gone — a verb after a quote or after a command name is text inside someone else's argument.
_CALL_PREFIXES = ("=", "(", "|", "{", ",", "&")
_CALL_PREFIX_WORDS = frozenset({"if", "elseif", "while", "return", "not", "-not", "|", "{"})

#: The three integrity reads the row names, each in the form the shipped text carries. Asserted one by one
#: because a count-only pin cannot say WHICH door a revert re-opened.
INTEGRITY_SITES = (
    ("uv.exe download hash gate", r"Get-FileHash -LiteralPath \$uvZip -Algorithm SHA256"),
    ("tarball sidecar read", r"Get-Content -LiteralPath \$sidecarFile -TotalCount 1"),
    ("tarball hash gate", r"Get-FileHash -LiteralPath \$tarballFile -Algorithm SHA256"),
)

#: Floor on enumerated call sites: the three integrity reads plus #493's ACL enumeration, both in the
#: installer. A check that "goes green" by deleting a call lowers this number, and that is a behaviour
#: change, not a cleanup.
MIN_CALL_SITES = 4

#: The deliberate wildcard in printed advice, kept as an EXACT literal line rather than a pattern. A regex
#: over backslashes is how a pin ends up asserting about its own escaping instead of about the file — the
#: first version of this constant was a pattern and failed for exactly that reason, caught by running it.
ADVICE_WILDCARD_LINE = (
    r"Warn '  Get-ChildItem C:\Users\*\AppData\Roaming\venya\config.json -ErrorAction SilentlyContinue'"
)

#: The unconvertible sites, counted not converted.
NEW_ITEM_RE = re.compile(r"New-Item -ItemType Directory -Force -Path\b")


def _verb_pattern(verb: str) -> re.Pattern[str]:
    """One verb as a call. Group ``args`` populates ONLY when the next token is not ``-LiteralPath``."""
    return re.compile(rf"(?<![A-Za-z-]){verb}(?P<args>\s+(?!-LiteralPath)[^\s|)])?")


def _is_call_position(before: str) -> bool:
    """True when the token ending ``before`` puts a verb in command position."""
    if not before:
        return True
    if before.endswith(_CALL_PREFIXES):
        return True
    words = before.split()
    return bool(words) and words[-1] in _CALL_PREFIX_WORDS


def _call_lines(text: str) -> list[tuple[int, str]]:
    """Covered-verb CALL lines as ``(lineno, text)``, with comment and in-string prose excluded."""
    out: list[tuple[int, str]] = []
    for lineno, line in enumerate(text.splitlines(), start=1):
        if line.strip().startswith("#"):
            continue
        for verb in COVERED_VERBS:
            for match in _verb_pattern(verb).finditer(line):
                if _is_call_position(line[: match.start()].rstrip()):
                    out.append((lineno, line.strip()))
                    break
    return out


def _offenders(text: str) -> list[str]:
    """Every covered-verb call in ``text`` that binds a wildcard, with its line.

    This is the sweep #628's shape could not express: the same question, asked of more verbs.
    """
    hits: list[str] = []
    for lineno, line in _call_lines(text):
        for verb in COVERED_VERBS:
            for match in _verb_pattern(verb).finditer(line):
                if match.group("args") is not None:
                    hits.append(f":{lineno} {line}"[:160])
                    break
    return hits


# ------------------------------------------------------------------ the 628-shaped detector, mirrored
# Mirrored locally for the reason test_pip_audit_feed_interlock.py gives: the shipped reader is written
# for ITS verb, and importing a sibling test module couples two rows that share only a technique. The
# mirror exists to demonstrate the miss, so it stays textually faithful to the CALL pattern in
# packages/server/tests/test_ps1_testpath_literal_628.py.

TESTPATH_CALL = re.compile(r"Test-Path(?P<args>\s+(?!-LiteralPath)\S[^\n]*)?")


def _testpath_offenders(text: str) -> list[str]:
    """#628's detector, applied to arbitrary text — used to show what it cannot see."""
    hits = []
    for lineno, line in enumerate(text.splitlines(), start=1):
        if line.strip().startswith("#") or "Test-Path" not in line:
            continue
        if any(m.group("args") is not None for m in TESTPATH_CALL.finditer(line)):
            hits.append(f":{lineno} {line.strip()}")
    return hits


class TestPs1HashLiteralReads642:
    """#642 — the hash and sidecar reads stay literal, and the net states its own scope."""

    def test_no_wildcard_binding_covered_verb_sites(self) -> None:
        """The sweep: zero positional calls of any verb in COVERED_VERBS, in either installer."""
        offenders = [hit for name in PS1_FILES for hit in _offenders(PS1_TEXT[name])]
        assert not offenders, (
            f"a -LiteralPath-capable read binds a wildcard again — #642: {offenders}. Covered verbs: "
            f"{COVERED_VERBS}. This is the door #628 closed, wearing a different verb."
        )

    def test_each_named_integrity_site_is_literal(self) -> None:
        """Positive half, per site: the three reads the row names are literal, one assertion each.

        Named individually so the failure text says WHICH gate lost its literal binding — the uv.exe hash
        gate, the sidecar read and the tarball hash gate are three installs failing differently.
        """
        for label, pattern in INTEGRITY_SITES:
            assert re.search(pattern, PS1_TEXT["install-venya-cli.ps1"]), (
                f"{label} no longer matches {pattern!r} — the integrity read changed shape, and the pair "
                "(this pin + its per-site mutation cell below) is what notices"
            )

    def test_covered_verb_site_floor_matches_the_sweep(self) -> None:
        """No call was deleted to make the sweep green — the #628 pairing, same reason."""
        sites = [s for name in PS1_FILES for s in _call_lines(PS1_TEXT[name])]
        assert len(sites) >= MIN_CALL_SITES, (
            f"expected at least {MIN_CALL_SITES} covered-verb call sites across {PS1_FILES}, found "
            f"{len(sites)}: {sites} — zero offenders over a shrunken site count is not this fix"
        )

    def test_detector_catches_each_reverted_site(self) -> None:
        """PAIRED NEGATIVE (AC2): each of the three sites, reverted to the wildcard form, is REPORTED.

        One fixture per named site so the leg can say which red answers which door: fixture 1 is the uv.exe
        hash gate, 2 the sidecar read, 3 the tarball hash gate. Each reverted line must yield exactly one
        offender and its literal form must read clean, so the detector is neither blind nor screaming at
        everything.
        """
        reverted = (
            (
                "uv.exe hash gate",
                "        $uvActual = (Get-FileHash $uvZip -Algorithm SHA256).Hash.ToLowerInvariant()\n",
            ),
            ("sidecar read", "        $line = Get-Content $sidecarFile -TotalCount 1\n"),
            (
                "tarball hash gate",
                "    $actual = (Get-FileHash $tarballFile -Algorithm SHA256).Hash.ToLowerInvariant()\n",
            ),
        )
        for label, fixture in reverted:
            hits = _offenders(fixture)
            assert len(hits) == 1, f"{label}: detector missed the reverted site ({fixture!r} -> {hits})"
            literal = re.sub(r"(Get-FileHash|Get-Content) \$", r"\1 -LiteralPath $", fixture)
            assert _offenders(literal) == [], f"{label}: detector over-reports the literal form {literal!r}"

    def test_the_testpath_shaped_net_misses_these_sites(self) -> None:
        """The row's actual defect, measured: #628's detector cannot see a hash read.

        Fed a reverted ``Get-FileHash`` line, the shipped ``Test-Path``-shaped sweep returns ZERO offenders
        while this file's sweep returns one. That asymmetry is why three correct lines sat unguarded, and it
        is the evidence that widening the verb set — not trusting the last verb anyone needed — was the fix.
        """
        sample = "    $actual = (Get-FileHash $tarballFile -Algorithm SHA256).Hash.ToLowerInvariant()\n"
        assert _testpath_offenders(sample) == [], (
            "the #628-shaped detector now sees hash reads, so this row's premise moved: widen the purpose "
            "stated in COVERED_VERBS rather than leaving two detectors making different claims about one line"
        )
        assert len(_offenders(sample)) == 1, "this file's detector does not see its own subject"

    def test_the_advice_wildcard_stays_a_wildcard(self) -> None:
        """The printed ``Get-ChildItem C:\\Users\\*\\…`` advice is prose, and it is still there.

        Two halves, both load-bearing: the line exists verbatim with its ``*`` (so literalizing the advert
        goes red), and the call-site detector reports ZERO sites for it (so the net cannot be satisfied by
        flagging, then deleting, the one hit a naive sweep would have found).
        """
        lines = PS1_TEXT["uninstall-venya-cli.ps1"].splitlines()
        assert ADVICE_WILDCARD_LINE in lines, (
            "the operator-facing advice line in uninstall-venya-cli.ps1 is not present verbatim — its * is "
            "DELIBERATE (every user profile). If it was literalized, undo that; if it moved, this pin and "
            "the message move together on purpose, not by accident"
        )
        advice = next(ln for ln in lines if ln.startswith("Warn '  Get-ChildItem"))
        assert _offenders(advice + "\n") == [], (
            f"the net counted printed advice as a call site: {advice!r} — a sweep that flags this line "
            "teaches the next reader to distrust sweeps"
        )

    def test_comment_prose_is_not_a_call_site(self) -> None:
        """The comment skip rule, exercised: the installer carries a ``Get-FileHash`` comment."""
        prose = "    # Get-FileHash emits uppercase and the sidecar is lowercase; normalise both.\n"
        assert _offenders(prose) == [], "comment prose counted as a call site"
        assert any(
            "Get-FileHash" in ln for ln in PS1_TEXT["install-venya-cli.ps1"].splitlines() if ln.strip().startswith("#")
        ), "the installer no longer carries a Get-FileHash comment, so this skip rule is untested here"

    def test_new_item_sites_are_counted_not_converted(self) -> None:
        """``New-Item`` has no ``-LiteralPath``, so its ``-Path`` sites are stated, not 'fixed'.

        The four sites are pinned as COUNT and FORM, and a fake conversion is refused: rewriting
        ``New-Item -Path`` to ``-LiteralPath`` is a runtime parameter error on the shipping platform, so this
        cell makes it a red test on Linux instead of a broken installer on ``win11``.
        """
        installer = PS1_TEXT["install-venya-cli.ps1"]
        sites = [ln for ln in installer.splitlines() if NEW_ITEM_RE.search(ln)]
        assert len(sites) == 4, (
            f"expected the 4 measured New-Item -Path directory sites, found {len(sites)}: {sites} — the "
            "count moving means someone converted or added one, and conversion is not available"
        )
        assert "New-Item -LiteralPath" not in installer, (
            "someone wrote New-Item -LiteralPath, which is not a parameter of New-Item — the fake coverage "
            "the row names, and it breaks the installer where installs actually happen"
        )

    def test_the_uninstaller_carries_no_integrity_read_yet(self) -> None:
        """Scope, measured rather than assumed.

        ``uninstall-venya-cli.ps1`` has zero ``Get-FileHash``/``Get-Content`` calls, so the three sites this
        row names are all installer-side even though its component line spans both files. If a leg later
        adds a hash read there, the sweep already covers the verb and this cell says out loud that the site
        list must grow with it.
        """
        reads = [
            (lineno, line.strip())
            for lineno, line in enumerate(PS1_TEXT["uninstall-venya-cli.ps1"].splitlines(), start=1)
            if re.search(r"Get-FileHash|Get-Content", line) and not line.strip().startswith("#")
        ]
        assert reads == [], (
            f"uninstall-venya-cli.ps1 now carries integrity reads: {reads} — add each as a NAMED site in "
            "INTEGRITY_SITES in the same change, and re-check this cell; a silent extra read is how #642 "
            "happened the first time"
        )
