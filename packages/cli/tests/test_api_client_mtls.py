"""Truth-table tests for APIClient admin mTLS client-cert support."""

from pathlib import Path
from unittest.mock import patch

import pytest
from venya_cli.api_client import APIClient, APIClientError


class TestAdminMtlsClientCert:
    """VENYA_ADMIN_CERT / VENYA_ADMIN_KEY env var handling in APIClient.__init__."""

    @patch("venya_cli.api_client.httpx2.Client")
    def test_both_set_constructs_with_cert(self, mock_client_cls, tmp_path: Path, monkeypatch):
        """Both env vars set → client constructed with cert=(path, path)."""
        cert = tmp_path / "admin.crt"
        key = tmp_path / "admin.key"
        cert.write_text("dummy cert")
        key.write_text("dummy key")

        monkeypatch.setenv("VENYA_ADMIN_CERT", str(cert))
        monkeypatch.setenv("VENYA_ADMIN_KEY", str(key))

        APIClient(config_file=tmp_path / "config.json")

        mock_client_cls.assert_called_once()
        kwargs = mock_client_cls.call_args.kwargs
        assert kwargs["cert"] == (str(cert), str(key))

    @patch("venya_cli.api_client.httpx2.Client")
    def test_neither_set_no_cert_param(self, mock_client_cls, tmp_path: Path, monkeypatch):
        """Neither env var set → no cert key in Client kwargs."""
        monkeypatch.delenv("VENYA_ADMIN_CERT", raising=False)
        monkeypatch.delenv("VENYA_ADMIN_KEY", raising=False)

        APIClient(config_file=tmp_path / "config.json")

        mock_client_cls.assert_called_once()
        kwargs = mock_client_cls.call_args.kwargs
        assert "cert" not in kwargs

    @patch("venya_cli.api_client.httpx2.Client")
    def test_only_cert_set_raises_naming_key(self, mock_client_cls, tmp_path: Path, monkeypatch):
        """Only VENYA_ADMIN_CERT set → loud error naming the missing var."""
        monkeypatch.setenv("VENYA_ADMIN_CERT", str(tmp_path / "admin.crt"))
        monkeypatch.delenv("VENYA_ADMIN_KEY", raising=False)

        with pytest.raises(APIClientError, match="VENYA_ADMIN_KEY"):
            APIClient(config_file=tmp_path / "config.json")

        mock_client_cls.assert_not_called()

    @patch("venya_cli.api_client.httpx2.Client")
    def test_only_key_set_raises_naming_cert(self, mock_client_cls, tmp_path: Path, monkeypatch):
        """Only VENYA_ADMIN_KEY set → loud error naming the missing var."""
        monkeypatch.delenv("VENYA_ADMIN_CERT", raising=False)
        monkeypatch.setenv("VENYA_ADMIN_KEY", str(tmp_path / "admin.key"))

        with pytest.raises(APIClientError, match="VENYA_ADMIN_CERT"):
            APIClient(config_file=tmp_path / "config.json")

        mock_client_cls.assert_not_called()

    @patch("venya_cli.api_client.httpx2.Client")
    def test_cert_path_does_not_exist_raises(self, mock_client_cls, tmp_path: Path, monkeypatch):
        """Both set but cert file missing → actionable error."""
        key = tmp_path / "admin.key"
        key.write_text("dummy key")

        monkeypatch.setenv("VENYA_ADMIN_CERT", str(tmp_path / "nonexistent.crt"))
        monkeypatch.setenv("VENYA_ADMIN_KEY", str(key))

        with pytest.raises(APIClientError, match="does not exist"):
            APIClient(config_file=tmp_path / "config.json")

        mock_client_cls.assert_not_called()

    @patch("venya_cli.api_client.httpx2.Client")
    def test_key_path_does_not_exist_raises(self, mock_client_cls, tmp_path: Path, monkeypatch):
        """Both set but key file missing → actionable error."""
        cert = tmp_path / "admin.crt"
        cert.write_text("dummy cert")

        monkeypatch.setenv("VENYA_ADMIN_CERT", str(cert))
        monkeypatch.setenv("VENYA_ADMIN_KEY", str(tmp_path / "nonexistent.key"))

        with pytest.raises(APIClientError, match="does not exist"):
            APIClient(config_file=tmp_path / "config.json")

        mock_client_cls.assert_not_called()
