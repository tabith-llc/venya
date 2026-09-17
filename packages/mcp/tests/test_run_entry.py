# Copyright (c) 2026 Tabith LLC.
# Use of this source code is governed by the Business Source License 1.1
# included in the LICENSE file at the root of this repository. As of the
# Change Date listed there, the work is available under MPL 2.0.
# SPDX-License-Identifier: BUSL-1.1

"""Console-entry startup precondition errors exit clean, no traceback.

Ticket mcp-missing-config-traceback-ux: missing/malformed config rendered the
documented actionable message as a raw FileNotFoundError traceback.
"""

import pytest
from venya_mcp.server import run


def test_missing_config_exits_clean(tmp_path, monkeypatch, capsys):
    monkeypatch.setenv("VENYA_CONFIG", str(tmp_path / "absent.json"))
    with pytest.raises(SystemExit) as exc:
        run()
    assert exc.value.code == 1
    err = capsys.readouterr().err
    assert "No Venya session token found" in err
    assert "Traceback" not in err


def test_malformed_config_exits_clean(tmp_path, monkeypatch, capsys):
    cfg = tmp_path / "config.json"
    cfg.write_text("{not json")
    monkeypatch.setenv("VENYA_CONFIG", str(cfg))
    with pytest.raises(SystemExit) as exc:
        run()
    assert exc.value.code == 1
    err = capsys.readouterr().err
    assert "not valid JSON" in err
    assert "Traceback" not in err
