"""#675 AC1 — a secret prompt states its bound BEFORE the value is read.

Source-text cells, the same instrument `test_cli_passphrase_length_floor_573.py` uses
when it asserts `read_path=True` appears in the renew gate: the guarantee lives in a
prompt string, so the cell reads the prompt string. It carries its own negative, because
a substring test that cannot fail is a habit, not evidence.

The bound must be INTERPOLATED from the module constants, not typed into the string —
that is what keeps a future change of the floor from leaving an operator reading a stale
number. So the cell asserts the constant NAME appears and a bare `15` does not.
"""

from __future__ import annotations

import re
from pathlib import Path

SRC = Path(__file__).resolve().parents[1] / "src" / "venya_cli"

# (label, file, the getpass line's opening fragment)
PROMPTS = [
    (
        "executor write prompt",
        SRC / "executor_key.py",
        'f"Executor private key passphrase ({env_var}, hidden)',
    ),
    (
        "backup encrypt prompt",
        SRC / "commands.py",
        'f"Enter passphrase for encrypted key (at least "',
    ),
    (
        "backup decrypt prompt (READ door: states the rule, refuses as #573 already ruled)",
        SRC / "commands.py",
        'f"Enter passphrase to decrypt backup (a backup passphrase shorter than "',
    ),
]

_BOUND = re.compile(r"\bat least\b|shorter than", re.IGNORECASE)
_STALE_NUMBER = re.compile(r"(?:\(|\s)15 characters")


def _prompt_block(path: Path, opening: str) -> str:
    """The getpass call and the string lines that follow it, up to the closing paren."""
    source = path.read_text(encoding="utf-8")
    start = source.index(opening)
    return re.split(r"\n\s*\)", source[start : start + 600])[0]


def test_the_instrument_can_fail():
    """Negative half: an old-style prompt, with no bound in it, must read as unbounded
    to this cell. If this ever passes wrongly, every assertion below is decoration."""
    old_shape = 'getpass.getpass("Enter passphrase for encrypted key: ")'
    assert not _BOUND.search(old_shape), "the extractor reads a bound where there is none"
    assert not _STALE_NUMBER.search(old_shape)
    new_shape = 'getpass.getpass(f"Enter passphrase (at least {MIN_PASSPHRASE_CODE_POINTS} characters)")'
    assert _BOUND.search(new_shape), "the extractor cannot see a stated bound"


def test_every_secret_prompt_states_its_bound_before_the_value_is_read():
    for label, path, opening in PROMPTS:
        assert opening in path.read_text(encoding="utf-8"), f"prompt moved or renamed: {label}"
        block = _prompt_block(path, opening)
        assert _BOUND.search(block), f"{label} reads a value with no bound stated"
        assert "character" in block.lower(), f"{label} states a bound in units nobody uses"


def test_the_bound_is_interpolated_from_the_constants_not_typed_into_the_string():
    for label, path, opening in PROMPTS:
        block = _prompt_block(path, opening)
        assert "MIN_PASSPHRASE_CODE_POINTS" in block, f"{label} states a floor that the floor constant does not govern"
        assert not _STALE_NUMBER.search(block), (
            f"{label} hardcodes the floor number; a future change would desync the " "prompt from the door"
        )
