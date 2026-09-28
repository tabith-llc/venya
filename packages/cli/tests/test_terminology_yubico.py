# Copyright (c) 2026 Tabith LLC.
# Use of this source code is governed by the Business Source License 1.1
# included in the LICENSE file at the root of this repository. As of the
# Change Date listed there, the work is available under MPL 2.0.
# SPDX-License-Identifier: BUSL-1.1

"""Interlock: YubiKey/Yubico trademark discipline (ticket yubico-terminology-audit).

Three pins, owner-ruled 2026-09-26:
1. ZERO misspelling variants of YubiKey across user-facing surfaces. Scope
   note: all-lowercase `yubikey` is OUT of scope BY DESIGN — legitimate
   shapes are tool names (`yubikey-manager`) and user credential-label
   examples (`yubikey-office`); the scanned variants are the case-mangled
   and spaced/hyphenated forms only.
2. The README carries the owner-approved recommendation line + the Yubico AB
   trademark notice (C1/C2).
3. ZERO partnership/endorsement claims anywhere (D3/F standing gate — these
   may only appear after formal Yubico partner approval, and then via a
   commit that cites the approval).
"""

import re
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[3]
SELF = Path(__file__).resolve()

SCAN_GLOBS = (
    "README.md",
    "THIRD-PARTY-NOTICES.md",
    "docs/**/*.md",
    "packages/*/src/**/*.py",
    "packages/*/scripts/**/*.py",
    "packages/server/src/server/static/**/*.html",
    "packages/server/src/server/static/**/*.js",
)

# Case-mangled / spaced / hyphenated variants (the checklist's wrong-form
# families), CASE-SENSITIVE by design — that is the whole point (`Yubikey` vs
# `YubiKey`). The correct "YubiKey" and the legitimate all-lowercase one-word
# shapes (`yubikey-manager`, `yubikey-office`) are NOT matched.
MISSPELLINGS = re.compile(r"Yubikey|YUBIKEY|YUBI[ -]KEY|[Yy]ubi[ -][Kk]ey")

ENDORSEMENT = re.compile(
    r"endorsed by yubico|approved by yubico|official partner|yubico partner|certified by yubico",
    re.IGNORECASE,
)

RECOMMENDATION = "Tabith LLC recommends YubiKey\u00ae security keys for Venya."
NOTICE = "registered trademarks of Yubico AB"


def _scanned_files():
    for glob in SCAN_GLOBS:
        for path in REPO_ROOT.glob(glob):
            if path.is_file() and path.resolve() != SELF:
                yield path


def test_no_yubikey_misspellings_in_user_facing_surfaces():
    offenders = []
    for path in _scanned_files():
        text = path.read_text(encoding="utf-8", errors="replace")
        for m in MISSPELLINGS.finditer(text):
            line = text.count("\n", 0, m.start()) + 1
            offenders.append(f"{path.relative_to(REPO_ROOT)}:{line}: {m.group(0)!r}")
    assert offenders == [], "YubiKey misspelling variants found:\n" + "\n".join(offenders)


def test_readme_carries_recommendation_and_trademark_notice():
    readme = (REPO_ROOT / "README.md").read_text(encoding="utf-8")
    assert RECOMMENDATION in readme
    assert NOTICE in readme


def test_no_yubico_endorsement_or_partner_claims():
    offenders = []
    for path in _scanned_files():
        text = path.read_text(encoding="utf-8", errors="replace")
        for m in ENDORSEMENT.finditer(text):
            line = text.count("\n", 0, m.start()) + 1
            offenders.append(f"{path.relative_to(REPO_ROOT)}:{line}: {m.group(0)!r}")
    assert offenders == [], "Partnership/endorsement claims require Yubico approval (D3/F):\n" + "\n".join(offenders)
