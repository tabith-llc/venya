# Copyright (c) 2026 Tabith LLC.
# Use of this source code is governed by the Business Source License 1.1
# included in the LICENSE file at the root of this repository. As of the
# Change Date listed there, the work is available under MPL 2.0.
# SPDX-License-Identifier: BUSL-1.1

"""Tests for the Stage 1 filter Python wrapper layer.

Tests build_filter_entries, filter_output, and filter_and_redact
functions that wrap the Rust venya_filter extension.
"""

from typing import Any

import pytest

try:
    import venya_filter  # type: ignore  # noqa: F401
except ImportError:
    pytest.skip("venya_filter Rust extension not available", allow_module_level=True)

from executor.filter import build_filter_entries, filter_and_redact, filter_output


def _make_entries(secret_id: str, value: bytes) -> list[dict[str, Any]]:
    """Helper to create filter entries in the Rust extension wire shape."""
    return [{"secret_id": secret_id, "secret_value": value}]


# ---------------------------------------------------------------------------
# build_filter_entries
# ---------------------------------------------------------------------------


class TestBuildFilterEntries:
    """Tests for build_filter_entries()."""

    def test_build_entries_send_no_hashes(self):
        """Entries carry only secret_id + secret_value — no precomputed hashes."""
        secrets = [{"secret_id": "s1", "value": b"test-secret-value"}]
        entries = build_filter_entries(secrets)

        assert len(entries) == 1
        assert entries[0] == {"secret_id": "s1", "secret_value": b"test-secret-value"}
        assert "hashes" not in entries[0]

    def test_build_entries_ignore_legacy_hashes_key(self):
        """A legacy 'hashes' key on the input dict is dropped, not forwarded."""
        secrets = [{"secret_id": "s1", "value": b"data", "hashes": ["abc123", "def456"]}]
        entries = build_filter_entries(secrets)

        assert entries[0] == {"secret_id": "s1", "secret_value": b"data"}

    def test_build_entries_multiple_secrets(self):
        """Handles multiple secrets correctly."""
        secrets = [
            {"secret_id": "s1", "value": b"secret-one"},
            {"secret_id": "s2", "value": b"secret-two"},
            {"secret_id": "s3", "value": b"secret-three"},
        ]
        entries = build_filter_entries(secrets)

        assert len(entries) == 3
        assert entries[0]["secret_id"] == "s1"
        assert entries[1]["secret_id"] == "s2"
        assert entries[2]["secret_id"] == "s3"

    def test_build_entries_empty_list(self):
        """Empty input returns empty output."""
        entries = build_filter_entries([])
        assert entries == []

    def test_build_entries_accepts_64_byte_id(self):
        """A secret_id of exactly 64 bytes is accepted (slot boundary)."""
        secrets = [{"secret_id": "x" * 64, "value": b"v"}]
        entries = build_filter_entries(secrets)
        assert entries[0]["secret_id"] == "x" * 64

    def test_build_entries_rejects_overlong_id(self):
        """A secret_id longer than 64 bytes raises a named ValueError."""
        secrets = [{"secret_id": "x" * 65, "value": b"v"}]
        with pytest.raises(ValueError, match="secret_id must be at most 64 bytes"):
            build_filter_entries(secrets)

    def test_build_entries_rejects_non_str_id(self):
        """An int secret_id raises a named TypeError (302ab25-class diagnosis)."""
        secrets = [{"secret_id": 1234, "value": b"v"}]
        with pytest.raises(TypeError, match="secret_id must be str"):
            build_filter_entries(secrets)

    def test_build_entries_rejects_non_bytes_value(self):
        """A str value raises a named TypeError naming the entry."""
        secrets = [{"secret_id": "s1", "value": "not-bytes"}]
        with pytest.raises(TypeError, match="value must be bytes"):
            build_filter_entries(secrets)

    def test_build_entries_preserves_order(self):
        """Entry order matches input order."""
        secrets = [
            {"secret_id": "first", "value": b"1"},
            {"secret_id": "second", "value": b"2"},
            {"secret_id": "third", "value": b"3"},
        ]
        entries = build_filter_entries(secrets)
        assert [e["secret_id"] for e in entries] == ["first", "second", "third"]


# ---------------------------------------------------------------------------
# filter_output (Python wrapper)
# ---------------------------------------------------------------------------


class TestFilterOutput:
    """Tests for filter_output() Python wrapper."""

    def test_empty_entries_passthrough(self):
        """Empty entries returns data unchanged."""
        data = b"no secrets here"
        masked, masked_ids = filter_output(data, [])
        assert masked == data
        assert masked_ids == []

    def test_wraps_rust_filter_output(self):
        """Properly delegates to Rust extension."""
        secret = b"wrapper-test-secret"
        entries = _make_entries("wrapped", secret)
        data = f"Output with {secret.decode()} in it".encode()

        masked, masked_ids = filter_output(data, entries)

        assert secret not in masked
        assert "wrapped" in masked_ids

    def test_empty_data(self):
        """Empty data returns empty."""
        masked, masked_ids = filter_output(b"", [])
        assert masked == b""
        assert masked_ids == []

    def test_window_size_parameter_passthrough(self):
        """Window size parameter is accepted (even if unused)."""
        data = b"clean output"
        masked, _ = filter_output(data, [], _window_size=30)
        assert masked == data

    def test_min_match_length_parameter_passthrough(self):
        """Min match length parameter is accepted (even if unused)."""
        data = b"clean output"
        masked, _ = filter_output(data, [], _min_match_length=16)
        assert masked == data


# ---------------------------------------------------------------------------
# filter_and_redact
# ---------------------------------------------------------------------------


class TestFilterAndRedact:
    """Tests for filter_and_redact()."""

    def test_filters_both_stdout_and_stderr(self):
        """Both stdout and stderr are filtered."""
        stdout_secret = b"stdout-secret"
        stderr_secret = b"stderr-secret"
        secrets = [
            {"secret_id": "s1", "value": stdout_secret},
            {"secret_id": "s2", "value": stderr_secret},
        ]

        masked_stdout, masked_stderr, stdout_ids, stderr_ids = filter_and_redact(
            b"stdout with " + stdout_secret,
            b"stderr with " + stderr_secret,
            secrets,
        )

        assert stdout_secret not in masked_stdout
        assert stderr_secret not in masked_stderr
        assert "s1" in stdout_ids
        assert "s2" in stderr_ids

    def test_clean_output_passthrough(self):
        """Clean output passes through unchanged."""
        masked_stdout, masked_stderr, stdout_ids, stderr_ids = filter_and_redact(
            b"clean stdout",
            b"clean stderr",
            [{"secret_id": "s1", "value": b"not-in-output"}],
        )

        assert masked_stdout == b"clean stdout"
        assert masked_stderr == b"clean stderr"
        assert stdout_ids == []
        assert stderr_ids == []

    def test_empty_both_streams(self):
        """Empty streams return empty."""
        masked_stdout, masked_stderr, stdout_ids, stderr_ids = filter_and_redact(b"", b"", [])

        assert masked_stdout == b""
        assert masked_stderr == b""
        assert stdout_ids == []
        assert stderr_ids == []

    def test_only_stdout_has_secret(self):
        """Only stdout is masked when secret only appears there."""
        secret = b"only-in-stdout"
        secrets = [{"secret_id": "s1", "value": secret}]

        masked_stdout, masked_stderr, stdout_ids, stderr_ids = filter_and_redact(
            b"output " + secret,
            b"clean stderr",
            secrets,
        )

        assert secret not in masked_stdout
        assert masked_stderr == b"clean stderr"
        assert "s1" in stdout_ids
        assert stderr_ids == []

    def test_only_stderr_has_secret(self):
        """Only stderr is masked when secret only appears there."""
        secret = b"only-in-stderr"
        secrets = [{"secret_id": "s1", "value": secret}]

        masked_stdout, masked_stderr, stdout_ids, stderr_ids = filter_and_redact(
            b"clean stdout",
            b"error " + secret,
            secrets,
        )

        assert masked_stdout == b"clean stdout"
        assert secret not in masked_stderr
        assert stdout_ids == []
        assert "s1" in stderr_ids

    def test_shared_secret_both_streams(self):
        """Same secret in both streams is masked in both."""
        secret = b"shared-secret"
        secrets = [{"secret_id": "shared", "value": secret}]

        masked_stdout, masked_stderr, stdout_ids, stderr_ids = filter_and_redact(
            b"stdout " + secret,
            b"stderr " + secret,
            secrets,
        )

        assert secret not in masked_stdout
        assert secret not in masked_stderr
        assert "shared" in stdout_ids
        assert "shared" in stderr_ids

    def test_legacy_hashes_key_tolerated_end_to_end(self):
        """Secrets carrying a legacy 'hashes' key still filter from the raw value."""
        secret = b"precomputed-test"
        secrets = [{"secret_id": "s1", "value": secret, "hashes": ["stale"]}]

        masked_stdout, _, stdout_ids, _ = filter_and_redact(
            b"output " + secret,
            b"",
            secrets,
        )

        assert secret not in masked_stdout
        assert "s1" in stdout_ids

    def test_long_secret_id_returned_in_full(self):
        """Masked ids are NOT truncated to 8 chars (#20 finding 2)."""
        secret = b"long-id-secret-value"
        long_id = "unrelated-secret-identifier"
        secrets = [{"secret_id": long_id, "value": secret}]

        masked_stdout, _, stdout_ids, _ = filter_and_redact(
            b"output " + secret,
            b"clean stderr",
            secrets,
        )

        assert secret not in masked_stdout
        assert stdout_ids == [long_id]
        assert f"[REDACTED:{long_id}]".encode() in masked_stdout
        # Negative half: a distinct long id must not alias with another.
        other_id = "unrelated-other-identifier"
        masked_stdout2, _, stdout_ids2, _ = filter_and_redact(
            b"value " + secret + b" and other ",
            b"",
            secrets + [{"secret_id": other_id, "value": b"other-value"}],
        )
        assert other_id not in stdout_ids2  # other-value not in output
        assert stdout_ids2 == [long_id]
