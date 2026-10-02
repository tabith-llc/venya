# Copyright (c) 2026 Tabith LLC.
# Use of this source code is governed by the Business Source License 1.1
# included in the LICENSE file at the root of this repository. As of the
# Change Date listed there, the work is available under MPL 2.0.
# SPDX-License-Identifier: BUSL-1.1

"""#351 ruling A — argv redaction in the support-log session header.

Secret-bearing subcommands (store/enroll/recovery) log positionals that carry
secret material as <redacted>; known secret flag VALUES are masked; everything
else stays verbatim (paired negatives: non-secret commands keep forensic value).
"""

import sys

import pytest
from venya_cli.cli import _install_stderr_tee


class TestArgvRedaction:
    def _header(self, tmp_path, monkeypatch, argv):
        monkeypatch.setenv("HOME", str(tmp_path))
        monkeypatch.setattr(sys, "argv", ["venya", *argv])
        log_path = _install_stderr_tee()
        assert log_path is not None
        return log_path.read_text()

    def test_store_value_redacted_key_kept(self, tmp_path, monkeypatch):
        content = self._header(tmp_path, monkeypatch, ["store", "MYKEY", "hunter2secret"])
        assert "MYKEY" in content
        assert "hunter2secret" not in content
        assert "<redacted>" in content

    def test_enroll_token_redacted(self, tmp_path, monkeypatch):
        content = self._header(tmp_path, monkeypatch, ["enroll", "enrl_abc123XYZ"])
        assert "enrl_abc123XYZ" not in content
        assert "<redacted>" in content

    def test_recovery_code_redacted_new_user_kept(self, tmp_path, monkeypatch):
        content = self._header(tmp_path, monkeypatch, ["recovery", "BREAKGLASSCODE", "newadmin"])
        assert "BREAKGLASSCODE" not in content
        assert "newadmin" in content

    def test_secret_flag_value_redacted(self, tmp_path, monkeypatch):
        content = self._header(tmp_path, monkeypatch, ["exec", "register", "--enrollment-token", "enrl_secret_token"])
        assert "enrl_secret_token" not in content
        content2 = self._header(tmp_path, monkeypatch, ["admin", "rotate-key", "--new-key", "/root/kek-file"])
        assert "/root/kek-file" not in content2

    def test_secret_flag_equals_form_redacted(self, tmp_path, monkeypatch):
        content = self._header(tmp_path, monkeypatch, ["exec", "register", "--enrollment-token=enrl_eq_secret"])
        assert "enrl_eq_secret" not in content

    def test_nonsecret_ops_logged_verbatim(self, tmp_path, monkeypatch):
        # paired negative: the non-secret path keeps its forensic value intact
        content = self._header(tmp_path, monkeypatch, ["run", "--executor-id", "exec-1", "ls", "-la"])
        assert "['run', '--executor-id', 'exec-1', 'ls', '-la']" in content
        content2 = self._header(tmp_path, monkeypatch, ["login", "alice"])
        assert "['login', 'alice']" in content2


if __name__ == "__main__":
    sys.exit(pytest.main([__file__, "-q"]))
