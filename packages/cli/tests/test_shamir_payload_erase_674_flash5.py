# Copyright (c) 2026 Tabith LLC.
# Use of this source code is governed by the Business Source License 1.1
# included in the LICENSE file at the root of this repository. As of the
# Change Date listed there, the work is available under MPL 2.0.
# SPDX-License-Identifier: BUSL-1.1

"""#674 AC3 — `shamir.split()` erases the plaintext payload copy it owns.

`split()` accepts a `memoryview` so a caller holding the secret in a `SecretHolder`
(#538/#674) can feed it without a fresh `bytes` copy, but it then builds
`payload = checksum + secret` — **this function's own copy of the whole secret** — and
until AC3 landed nothing ever erased it. The caller's buffer was scoped and released;
the splitter's was not. This file pins the erase.

**The claim is erasure of this buffer, not residency.** `secret_holder.py` says so in its
own words: it does not pin and it does not remove copies made by other code, and
`cryptography` allocates plaintext too. So every cell here asserts a lifetime fact this
process controls — the buffer `split()` built is zeroed before `split()` hands back — and
no cell asserts that key material escaped the process or that some byte pattern is absent
from machine memory. That would be a leak claim, and this row does not make one.

Truth table, both halves:

+--------------------------------------------------------+-----------------------------------------------+
| shape                                                  | expected                                      |
+--------------------------------------------------------+-----------------------------------------------|
| split, happy path                                      | the eraser is called, once, on a buffer that  |
|                                                        | held checksum + secret, and that buffer reads |
|                                                        | all zero once `split()` returns               |
| split, mid-loop exception (`os.urandom` fails)         | the exception propagates AND the buffer is    |
|                                                        | still zeroed — the `finally` is not decoration|
| the three refusals (`threshold < 2`, `threshold >      | raise BEFORE any copy exists, so no erase is   |
| shares`, `shares > 255`)                               | owed and none runs                            |
| every path                                             | the returned shares are not the erased buffer |
|                                                        | and still reconstruct the secret              |
+--------------------------------------------------------+-----------------------------------------------+

The paired negative is the deliverable, not an afterthought: the owner ruled this fix
"with a mutation-proven negative" (`POST-BETA.md` PB-SHAMIR). `test_erase_hook_fires…`
asserts the eraser WAS called, so deleting the `finally` call fails the cell rather than
passing on a buffer nobody can see — the toothless shape this row exists to prevent.
"""

import ast
import inspect

import pytest
from venya_cli import shamir
from venya_cli.secret_holder import _erase
from venya_cli.shamir import combine, split

PLAINTEXT = b"AC3-erase-me-literal-not-a-real-key"  # a test literal, never key material
CHECKSUM_LEN = 4


class _Eraser:
    """The REAL `_erase`, with a ledger of the buffers it was handed.

    Deliberately a pass-through wrapper and not a mock: a mock would let the cell pass on
    an erase that never zeroes anything, which is the exact failure this file is about.
    The snapshot is taken BEFORE the real eraser runs, because afterwards the buffer is
    zeros by definition and the assertion would prove nothing about which buffer was
    erased. The snapshot is a copy of a test literal, not of key material.
    """

    def __init__(self) -> None:
        self.calls: list[tuple[bytes, bytearray]] = []

    def __call__(self, data: bytearray) -> None:
        self.calls.append((bytes(data), data))
        _erase(data)

    @property
    def buffers(self) -> list[bytearray]:
        return [buf for _, buf in self.calls]


@pytest.fixture
def eraser(monkeypatch):
    """Install the recording eraser into the module under test, per cell."""
    rec = _Eraser()
    monkeypatch.setattr(shamir, "_erase", rec)
    return rec


class TestSplitErasesItsOwnCopy:
    def test_erase_hook_fires_once_on_the_payload_and_the_buffer_reads_zero(self, eraser) -> None:
        shares = split(PLAINTEXT, threshold=2, shares=3)

        assert len(eraser.calls) == 1, (
            f"split() built its plaintext copy and never handed it to the eraser — "
            f"{len(eraser.calls)} erase calls, AC3 is not in force"
        )
        snapshot, buf = eraser.calls[0]
        assert (
            snapshot == shamir._checksum(PLAINTEXT) + PLAINTEXT
        ), "the buffer that WAS erased is not the payload copy — the erase landed on the wrong buffer"
        assert all(byte == 0 for byte in buf), "the payload buffer survived split() un-erased"
        # …and the output is untouched by the erase: it is a fresh `bytes`, not this buffer.
        assert combine(shares[:2]) == PLAINTEXT

    def test_memoryview_input_is_erased_too(self, eraser) -> None:
        """The holder-fed shape the CA custody path actually uses (`commands.py`, split)."""
        owned = bytearray(PLAINTEXT)
        shares = split(memoryview(owned), threshold=2, shares=3)

        assert len(eraser.calls) == 1, "the memoryview path does not erase its payload copy"
        snapshot, buf = eraser.calls[0]
        assert snapshot == shamir._checksum(PLAINTEXT) + PLAINTEXT
        assert all(byte == 0 for byte in buf)
        assert combine(shares[:2]) == PLAINTEXT
        assert owned == bytearray(PLAINTEXT), "split() wrote through the caller's buffer"

    def test_empty_secret_still_erases_the_checksum_only_payload(self, eraser) -> None:
        shares = split(b"", threshold=2, shares=3)

        assert len(eraser.calls) == 1
        snapshot, buf = eraser.calls[0]
        assert len(snapshot) == CHECKSUM_LEN, "an empty secret must still carry the shared checksum"
        assert all(byte == 0 for byte in buf)
        assert combine(shares[:2]) == b""

    def test_mid_loop_exception_still_erases(self, eraser, monkeypatch) -> None:
        """The `finally` half: a failure between the copy and the return does not leak it."""
        calls = {"n": 0}
        real_urandom = shamir.os.urandom

        class _FlakyOs:
            """Sham only the name `shamir` reads, never the real `os` module (process-wide)."""

            @staticmethod
            def urandom(n: int) -> bytes:
                calls["n"] += 1
                if calls["n"] > 3:
                    raise OSError("simulated entropy failure mid-split")
                return real_urandom(n)

        monkeypatch.setattr(shamir, "os", _FlakyOs())
        with pytest.raises(OSError, match="simulated entropy failure"):
            split(PLAINTEXT, threshold=3, shares=5)

        assert len(eraser.calls) == 1, "the exception path skipped the erase — the payload survived"
        snapshot, buf = eraser.calls[0]
        assert snapshot.startswith(shamir._checksum(PLAINTEXT))
        assert all(byte == 0 for byte in buf)

    @pytest.mark.parametrize(
        ("threshold", "shares", "match"),
        [
            (1, 3, "Threshold must be at least 2"),
            (5, 3, "Threshold cannot exceed"),
            (2, 256, "Maximum 255 shares"),
        ],
    )
    def test_refusals_owe_no_erase_because_no_copy_was_built(self, eraser, threshold, shares, match) -> None:
        """Negative half of the refusal paths, stated honestly: these raise BEFORE the copy.

        The claim is not "the refusals erase the payload" — there is no payload yet. The
        cell pins the ORDER, so a future edit that moves the copy above the guards has to
        redden this cell rather than quietly reintroduce an un-erased buffer.
        """
        with pytest.raises(ValueError, match=match):
            split(PLAINTEXT, threshold=threshold, shares=shares)

        assert eraser.calls == [], f"{match}: a refusal built a copy it did not erase"


class TestReturnIsNotTheErasedBuffer:
    """The census boundary: erasing the payload must not reach the shares."""

    def test_shares_are_independent_of_the_erased_buffer(self, eraser) -> None:
        shares = split(PLAINTEXT, threshold=2, shares=3)
        erased_ids = {id(buf) for _, buf in eraser.calls}

        assert all(
            id(share) not in erased_ids for share in shares
        ), "a returned share IS the erased buffer — reconstructing would read zeros"
        for share in shares:
            assert isinstance(share, bytes) and not isinstance(share, bytearray)
        assert combine([shares[0], shares[2]]) == PLAINTEXT

    def test_finally_erases_the_payload_by_name_not_a_copy(self) -> None:
        """Source-shape cell — the behavioural half cannot see this mutation, so this one can.

        Measured, not assumed: with `_erase(payload)` replaced by `_erase(bytearray(payload))`
        — erasing a THROWAWAY COPY while the real buffer survives — every behavioural cell
        above still passes, because the copy it inspects really is zeroed. That is the
        silent-no-op shape `secret_holder.py` names as worse than no zeroizer at all, so the
        check here is on the CALL SHAPE: the `finally` must hand the eraser the `payload`
        name itself, as a direct argument, not an expression wrapping it.
        """
        tree = ast.parse(inspect.getsource(shamir.split))
        erases: list[ast.expr] = []
        for node in ast.walk(tree):
            if not isinstance(node, ast.Try):
                continue
            for stmt in node.finalbody:
                call = stmt.value if isinstance(stmt, ast.Expr) else None
                if isinstance(call, ast.Call) and getattr(call.func, "id", None) == "_erase":
                    erases.append(call)

        assert len(erases) == 1, f"expected exactly one `_erase(...)` in a `finally`, found {len(erases)}"
        arg = erases[0].args[0]
        assert isinstance(arg, ast.Name) and arg.id == "payload", (
            f"the finally erases {ast.unparse(arg)!r}, not the `payload` buffer itself — "
            "erasing a copy leaves the splitter's plaintext alive and no behavioural cell can see it"
        )
