"""Tests for C-11 KEK-salt startup handling in the server.

_init_core() is the lifespan's wrapper around backend.get_core(). When the
persisted KEK salt is missing while secrets exist, it must log a fatal,
operator-actionable error and re-raise. Propagation is what aborts startup
(lifespan -> uvicorn exits non-zero), so the test asserts re-raise + the
critical log.
"""

from unittest.mock import MagicMock, patch

import pytest

import server.app as app
from core.engine.backend import KekSaltMissingError


class TestInitCoreKekSalt:
    def test_kek_salt_missing_logs_critical_and_reraises(self):
        backend = MagicMock()
        backend.get_core.side_effect = KekSaltMissingError("salt missing, secrets exist")

        with patch.object(app, "logger") as mock_logger:
            with pytest.raises(KekSaltMissingError):
                app._init_core(backend, "pw")

        mock_logger.critical.assert_called_once()
        (msg,) = mock_logger.critical.call_args[0]
        assert "KEK salt" in msg
        assert "unrecoverable" in msg
        assert "backup" in msg

    def test_init_core_forwards_to_get_core(self):
        backend = MagicMock()
        sentinel = object()
        backend.get_core.return_value = sentinel

        result = app._init_core(backend, "pw")

        assert result is sentinel
        backend.get_core.assert_called_once_with("pw")

    def test_init_core_does_not_log_on_success(self):
        backend = MagicMock()
        backend.get_core.return_value = object()

        with patch.object(app, "logger") as mock_logger:
            app._init_core(backend, "pw")

        mock_logger.critical.assert_not_called()
