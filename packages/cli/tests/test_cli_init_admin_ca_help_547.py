# Copyright (c) 2026 Tabith LLC.
# Use of this source code is governed by the Business Source License 1.1
# included in the LICENSE file at the root of this repository. As of the
# Change Date listed there, the work is available under MPL 2.0.
# SPDX-License-Identifier: BUSL-1.1

"""#547 follow-up — the ``admin init-admin-ca`` help line names the variable the
command now requires.

After #547 landed, ``venya admin init-admin-ca`` refuses when
``VENYA_ADMIN_CA_KEY_PASSPHRASE`` is unset or empty. The help line still read
"Initialize the admin CA (create key/cert pair)", so an operator who followed another
path's advice to "just run init-admin-ca" hit a refusal the help never mentioned — the
same dead-end class RF-8a/RF-8b closes. The help now names the requirement.

Mechanism of verification: the strings are read off the LIVE parser built by
``create_parser()`` (the same object the arg-surface pin and the doc generator walk),
never re-typed from the source file. The paired negative runs the pre-#547 help line
through the same predicate so the positive cell cannot pass on an always-true check.

Scope is the help TEXT only — no new argument, no flag, no behavior change — so the
last cell pins the option list to prove the arg surface did not move.
"""

import pytest
from venya_cli.cli import create_parser

PASSPHRASE_ENV = "VENYA_ADMIN_CA_KEY_PASSPHRASE"
COMMAND = "init-admin-ca"

# The pre-#547 help line, kept ONLY as the negative half below.
_OLD_HELP = "Initialize the admin CA (create key/cert pair)"


def _admin_subparsers():
    """(admin parser, {name: subparser}) for the `admin` group, off the live tree."""
    admin = next(a for a in create_parser()._actions if a.__class__.__name__ == "_SubParsersAction").choices["admin"]
    targets = next(a for a in admin._actions if a.__class__.__name__ == "_SubParsersAction")
    return admin, targets.choices


def _subcommand_help(name: str) -> str:
    """The help line a subcommand advertises, read off the live parser.

    argparse stores it on the pseudo-action the subparsers action registers for the
    name (``_SubParsersAction._get_subactions()``), NOT on the child ArgumentParser —
    so this is the string ``--help`` prints and the string the doc generator renders.
    """
    admin, _ = _admin_subparsers()
    subparsers_action = next(a for a in admin._actions if a.__class__.__name__ == "_SubParsersAction")
    entry = next(a for a in subparsers_action._get_subactions() if a.dest == name)
    return entry.help


class TestInitAdminCaHelpNamesTheRequirement:

    def test_help_names_the_variable_the_command_requires(self):
        help_text = _subcommand_help(COMMAND)
        assert help_text is not None
        assert PASSPHRASE_ENV in help_text, f"help does not name {PASSPHRASE_ENV}: {help_text!r}"

    def test_help_still_describes_the_command(self):
        """The requirement is ADDED; the subject line is not replaced."""
        help_text = _subcommand_help(COMMAND)
        assert "Initialize the admin CA" in help_text
        assert "key/cert pair" in help_text

    def test_negative_pre_change_help_is_rejected(self):
        """The same predicate the positive cell uses fails on the old wording, so the
        cell is not an always-true check."""
        assert PASSPHRASE_ENV not in _OLD_HELP
        assert _OLD_HELP == _subcommand_help(COMMAND).replace(f"; requires {PASSPHRASE_ENV}", "")

    def test_generate_admin_cert_help_is_untouched(self):
        """Only the one help string moved — the sibling admin command keeps its text."""
        assert _subcommand_help("generate-admin-cert") == "Sign an admin client certificate"


class TestNoArgSurfaceMovement:
    """This leg adds no argument, so the per-command option list — the surface the
    arg-surface pin walks and the doc generator renders — is unchanged."""

    def test_init_admin_ca_options_are_unchanged(self):
        init_parser = _admin_subparsers()[1][COMMAND]
        flags = sorted(f for a in init_parser._actions if a.option_strings for f in a.option_strings)
        assert flags == ["--help", "--output-dir", "-h"]

    def test_output_dir_is_still_required(self):
        init_parser = _admin_subparsers()[1][COMMAND]
        action = next(a for a in init_parser._actions if "--output-dir" in a.option_strings)
        assert action.required is True

    @pytest.mark.parametrize("name", ["init-admin-ca", "generate-admin-cert", "revoke-admin-cert"])
    def test_admin_subcommand_set_is_unchanged(self, name):
        assert name in _admin_subparsers()[1]
