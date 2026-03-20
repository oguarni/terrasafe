"""
Unit tests for Settings — config/settings.py
"""
import pytest
from unittest.mock import Mock, patch

try:
    from botocore.exceptions import ClientError
except ImportError:
    class ClientError(Exception):  # type: ignore[no-redef]
        """Minimal stand-in for botocore.exceptions.ClientError."""
        def __init__(self, error_response: dict, operation_name: str):
            self.response = error_response
            self.operation_name = operation_name
            super().__init__(str(error_response))

VALID_HASH = "$2b$12$" + "x" * 53


@pytest.mark.unit
class TestSettingsProperties:

    def test_max_file_size_bytes_computed(self):
        from terrasafe.config.settings import Settings
        s = Settings(max_file_size_mb=5)
        assert s.max_file_size_bytes == 5 * 1024 * 1024

    def test_is_production_true(self):
        from terrasafe.config.settings import Settings
        s = Settings(environment="production")
        assert s.is_production() is True

    def test_is_production_false(self):
        from terrasafe.config.settings import Settings
        s = Settings(environment="development")
        assert s.is_production() is False

    def test_is_development_true(self):
        from terrasafe.config.settings import Settings
        s = Settings(environment="development")
        assert s.is_development() is True

    def test_is_development_false(self):
        from terrasafe.config.settings import Settings
        s = Settings(environment="production")
        assert s.is_development() is False


@pytest.mark.unit
class TestGetSecret:

    def test_get_secret_no_boto3(self):
        from terrasafe.config.settings import Settings
        s = Settings()
        with patch('terrasafe.config.settings.boto3', None):
            result = s._get_secret("terrasafe/database")
        assert result == {}

    def test_get_secret_client_error(self):
        from terrasafe.config.settings import Settings
        s = Settings()
        error_response = {'Error': {'Code': 'ResourceNotFoundException', 'Message': 'Secret not found'}}
        with patch('terrasafe.config.settings.boto3') as mock_boto3, \
             patch('terrasafe.config.settings.ClientError', ClientError, create=True):
            mock_session = Mock()
            mock_boto3.session.Session.return_value = mock_session
            mock_client = Mock()
            mock_session.client.return_value = mock_client
            mock_client.get_secret_value.side_effect = ClientError(error_response, 'GetSecretValue')
            with pytest.raises(ClientError):
                s._get_secret("terrasafe/database")

    def test_get_secret_success_with_secret_string(self):
        from terrasafe.config.settings import Settings
        s = Settings()
        with patch('terrasafe.config.settings.boto3') as mock_boto3:
            mock_session = Mock()
            mock_boto3.session.Session.return_value = mock_session
            mock_client = Mock()
            mock_session.client.return_value = mock_client
            mock_client.get_secret_value.return_value = {'SecretString': '{"key": "val"}'}
            result = s._get_secret("terrasafe/database")
        assert result == {'key': 'val'}

    def test_get_secret_success_no_secret_string(self):
        from terrasafe.config.settings import Settings
        s = Settings()
        with patch('terrasafe.config.settings.boto3') as mock_boto3:
            mock_session = Mock()
            mock_boto3.session.Session.return_value = mock_session
            mock_client = Mock()
            mock_session.client.return_value = mock_client
            mock_client.get_secret_value.return_value = {}
            result = s._get_secret("terrasafe/database")
        assert result == {}


@pytest.mark.unit
class TestDatabaseUrlResolved:

    def test_database_url_resolved_production_with_secret(self):
        from terrasafe.config.settings import Settings
        s = Settings(environment="production", database_url=None)
        secret = {
            'username': 'admin',
            'password': 'secret123',
            'host': 'db.example.com',
            'port': 5432,
            'dbname': 'terrasafe_prod',
        }
        with patch.object(s, '_get_secret', return_value=secret):
            url = s.database_url_resolved
        assert url == "postgresql+asyncpg://admin:secret123@db.example.com:5432/terrasafe_prod"

    def test_database_url_resolved_production_secret_fails(self):
        from terrasafe.config.settings import Settings
        s = Settings(environment="production", database_url=None)
        with patch.object(s, '_get_secret', side_effect=Exception("network error")):
            url = s.database_url_resolved
        assert url == ""

    def test_database_url_resolved_production_with_explicit_url(self):
        from terrasafe.config.settings import Settings
        explicit = "postgresql+asyncpg://user:pw@host:5432/db"
        s = Settings(environment="production", database_url=explicit)
        assert s.database_url_resolved == explicit

    def test_database_url_resolved_non_production(self):
        from terrasafe.config.settings import Settings
        url = "postgresql+asyncpg://user:pw@localhost:5432/terrasafe"
        s = Settings(environment="development", database_url=url)
        assert s.database_url_resolved == url

    def test_database_url_resolved_non_production_no_url(self):
        from terrasafe.config.settings import Settings
        s = Settings(environment="development", database_url=None)
        assert s.database_url_resolved == ""
