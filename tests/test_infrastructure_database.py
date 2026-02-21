"""
Integration tests for terrasafe.infrastructure.database module.

These tests verify the database infrastructure including:
- DatabaseManager initialization
- Connection and disconnection
- Session management
- Transaction handling
- Health checks
- Table creation and dropping
"""

import pytest
from unittest.mock import AsyncMock, MagicMock, patch, Mock
from contextlib import asynccontextmanager
from sqlalchemy.ext.asyncio import AsyncSession, AsyncEngine, create_async_engine
from sqlalchemy import text

from terrasafe.infrastructure.database import (
    DatabaseManager,
    Base,
    get_db_manager,
    get_session
)


def _make_mock_settings(**kwargs):
    """Create a mock settings object with common defaults."""
    mock = Mock()
    mock.database_url = kwargs.get('database_url', None)
    mock.database_pool_size = kwargs.get('database_pool_size', 10)
    mock.debug = kwargs.get('debug', False)
    mock.is_production = Mock(return_value=kwargs.get('is_production', False))
    return mock


class TestBase:
    """Test suite for Base class."""

    def test_base_class_exists(self):
        """Test that Base class is properly defined."""
        assert Base is not None
        assert hasattr(Base, 'metadata')


class TestDatabaseManager:
    """Test suite for DatabaseManager class."""

    @pytest.fixture
    def db_url(self):
        """Provide a test database URL."""
        return "postgresql+asyncpg://test:test@localhost:5432/test"

    @pytest.fixture
    def db_manager(self, db_url):
        """Create a DatabaseManager instance."""
        mock_settings = _make_mock_settings(database_url=db_url, database_pool_size=10)
        with patch('terrasafe.infrastructure.database.get_settings', return_value=mock_settings):
            return DatabaseManager(database_url=db_url, pool_size=10)

    def test_initialization_with_url(self, db_url):
        """Test initializing DatabaseManager with database URL."""
        mock_settings = _make_mock_settings(database_url=db_url, database_pool_size=20)
        with patch('terrasafe.infrastructure.database.get_settings', return_value=mock_settings):
            manager = DatabaseManager(database_url=db_url, pool_size=5)

            assert manager.database_url == db_url
            assert manager.pool_size == 5
            assert manager._engine is None
            assert manager._session_factory is None

    def test_initialization_without_url(self):
        """Test initializing DatabaseManager without database URL."""
        mock_settings = _make_mock_settings(database_url=None, database_pool_size=10)
        with patch('terrasafe.infrastructure.database.get_settings', return_value=mock_settings):
            manager = DatabaseManager()

            assert manager.database_url is None
            assert manager._engine is None
            assert manager._session_factory is None

    def test_is_connected_false(self, db_manager):
        """Test is_connected property when not connected."""
        assert db_manager.is_connected is False

    @pytest.mark.asyncio
    async def test_connect_success(self, db_manager):
        """Test successful database connection."""
        mock_engine = AsyncMock(spec=AsyncEngine)
        mock_conn = AsyncMock()
        mock_conn.execute = AsyncMock()

        @asynccontextmanager
        async def mock_begin():
            yield mock_conn

        mock_engine.begin = mock_begin

        mock_settings = _make_mock_settings(debug=False)
        with patch('terrasafe.infrastructure.database.create_async_engine', return_value=mock_engine):
            with patch('terrasafe.infrastructure.database.async_sessionmaker') as mock_sessionmaker:
                with patch('terrasafe.infrastructure.database.get_settings', return_value=mock_settings):
                    await db_manager.connect()

                    assert db_manager._engine is not None
                    assert db_manager._session_factory is not None
                    assert db_manager.is_connected is True

    @pytest.mark.asyncio
    async def test_connect_already_connected(self, db_manager):
        """Test connecting when already connected."""
        # Simulate already connected state
        db_manager._engine = AsyncMock()

        await db_manager.connect()

        # Should not create a new engine
        assert db_manager._engine is not None

    @pytest.mark.asyncio
    async def test_connect_no_url(self):
        """Test connecting without database URL."""
        mock_settings = _make_mock_settings(database_url=None, database_pool_size=10)
        with patch('terrasafe.infrastructure.database.get_settings', return_value=mock_settings):
            manager = DatabaseManager()
            await manager.connect()

            assert manager._engine is None

    @pytest.mark.asyncio
    async def test_connect_failure(self, db_manager):
        """Test connection failure handling."""
        mock_settings = _make_mock_settings(debug=False)
        with patch('terrasafe.infrastructure.database.create_async_engine', side_effect=Exception("Connection error")):
            with patch('terrasafe.infrastructure.database.get_settings', return_value=mock_settings):
                with pytest.raises(Exception) as exc_info:
                    await db_manager.connect()

                assert "Connection error" in str(exc_info.value)

    @pytest.mark.asyncio
    async def test_disconnect(self, db_manager):
        """Test disconnecting from database."""
        mock_engine = AsyncMock()
        mock_engine.dispose = AsyncMock()
        db_manager._engine = mock_engine
        db_manager._session_factory = MagicMock()

        await db_manager.disconnect()

        mock_engine.dispose.assert_called_once()
        assert db_manager._engine is None
        assert db_manager._session_factory is None

    @pytest.mark.asyncio
    async def test_disconnect_not_connected(self, db_manager):
        """Test disconnecting when not connected."""
        db_manager._engine = None

        # Should not raise an error
        await db_manager.disconnect()

        assert db_manager._engine is None

    @pytest.mark.asyncio
    async def test_session_context_manager_success(self, db_manager):
        """Test session context manager with successful transaction."""
        mock_session = AsyncMock(spec=AsyncSession)
        mock_session.commit = AsyncMock()
        mock_session.rollback = AsyncMock()
        mock_session.close = AsyncMock()

        mock_session_factory = MagicMock()

        @asynccontextmanager
        async def mock_factory():
            yield mock_session

        mock_session_factory.return_value = mock_factory()
        db_manager._session_factory = mock_session_factory

        async with db_manager.session() as session:
            assert session is not None

        mock_session.commit.assert_called_once()
        mock_session.close.assert_called_once()

    @pytest.mark.asyncio
    async def test_session_context_manager_rollback(self, db_manager):
        """Test session context manager with rollback on error."""
        mock_session = AsyncMock(spec=AsyncSession)
        mock_session.commit = AsyncMock()
        mock_session.rollback = AsyncMock()
        mock_session.close = AsyncMock()

        mock_session_factory = MagicMock()

        @asynccontextmanager
        async def mock_factory():
            yield mock_session

        mock_session_factory.return_value = mock_factory()
        db_manager._session_factory = mock_session_factory

        with pytest.raises(ValueError):
            async with db_manager.session() as session:
                raise ValueError("Test error")

        mock_session.rollback.assert_called_once()
        mock_session.close.assert_called_once()

    @pytest.mark.asyncio
    async def test_session_not_connected(self, db_manager):
        """Test session creation when not connected."""
        db_manager._session_factory = None

        with pytest.raises(RuntimeError) as exc_info:
            async with db_manager.session() as session:
                pass

        assert "not connected" in str(exc_info.value).lower()

    @pytest.mark.asyncio
    async def test_create_all_tables(self, db_manager):
        """Test creating all database tables."""
        mock_engine = AsyncMock()
        mock_conn = AsyncMock()
        mock_conn.run_sync = AsyncMock()

        @asynccontextmanager
        async def mock_begin():
            yield mock_conn

        mock_engine.begin = mock_begin
        db_manager._engine = mock_engine

        await db_manager.create_all_tables()

        mock_conn.run_sync.assert_called_once()

    @pytest.mark.asyncio
    async def test_create_all_tables_not_connected(self, db_manager):
        """Test creating tables when not connected."""
        db_manager._engine = None

        with pytest.raises(RuntimeError) as exc_info:
            await db_manager.create_all_tables()

        assert "not connected" in str(exc_info.value).lower()

    @pytest.mark.asyncio
    async def test_drop_all_tables_development(self, db_manager):
        """Test dropping all tables in development environment."""
        mock_engine = AsyncMock()
        mock_conn = AsyncMock()
        mock_conn.run_sync = AsyncMock()

        @asynccontextmanager
        async def mock_begin():
            yield mock_conn

        mock_engine.begin = mock_begin
        db_manager._engine = mock_engine

        mock_settings = _make_mock_settings(is_production=False)
        with patch('terrasafe.infrastructure.database.get_settings', return_value=mock_settings):
            await db_manager.drop_all_tables()

            mock_conn.run_sync.assert_called_once()

    @pytest.mark.asyncio
    async def test_drop_all_tables_production(self, db_manager):
        """Test that dropping tables is prevented in production."""
        mock_engine = AsyncMock()
        db_manager._engine = mock_engine

        mock_settings = _make_mock_settings(is_production=True)
        with patch('terrasafe.infrastructure.database.get_settings', return_value=mock_settings):
            with pytest.raises(RuntimeError) as exc_info:
                await db_manager.drop_all_tables()

            assert "production" in str(exc_info.value).lower()

    @pytest.mark.asyncio
    async def test_drop_all_tables_not_connected(self, db_manager):
        """Test dropping tables when not connected."""
        db_manager._engine = None

        with pytest.raises(RuntimeError) as exc_info:
            await db_manager.drop_all_tables()

        assert "not connected" in str(exc_info.value).lower()

    @pytest.mark.asyncio
    async def test_health_check_healthy(self, db_manager):
        """Test health check with healthy database."""
        mock_engine = AsyncMock()
        mock_conn = AsyncMock()
        mock_conn.execute = AsyncMock()

        @asynccontextmanager
        async def mock_begin():
            yield mock_conn

        mock_engine.begin = mock_begin
        db_manager._engine = mock_engine

        result = await db_manager.health_check()

        assert result is True
        mock_conn.execute.assert_called_once()

    @pytest.mark.asyncio
    async def test_health_check_unhealthy(self, db_manager):
        """Test health check with unhealthy database."""
        mock_engine = AsyncMock()

        @asynccontextmanager
        async def mock_begin():
            raise Exception("Connection lost")
            yield

        mock_engine.begin = mock_begin
        db_manager._engine = mock_engine

        result = await db_manager.health_check()

        assert result is False

    @pytest.mark.asyncio
    async def test_health_check_not_connected(self, db_manager):
        """Test health check when not connected."""
        db_manager._engine = None

        result = await db_manager.health_check()

        assert result is False


class TestGetDbManager:
    """Test suite for get_db_manager function."""

    def test_get_db_manager_singleton(self):
        """Test that get_db_manager returns a singleton instance."""
        mock_settings = _make_mock_settings(database_url="postgresql://test", database_pool_size=10)
        with patch('terrasafe.infrastructure.database._db_manager', None):
            with patch('terrasafe.infrastructure.database.get_settings', return_value=mock_settings):
                manager1 = get_db_manager()
                manager2 = get_db_manager()

                # Both should be the same instance
                assert manager1 is manager2

    def test_get_db_manager_creates_instance(self):
        """Test that get_db_manager creates an instance if none exists."""
        mock_settings = _make_mock_settings(database_url="postgresql://test", database_pool_size=10)
        with patch('terrasafe.infrastructure.database._db_manager', None):
            with patch('terrasafe.infrastructure.database.get_settings', return_value=mock_settings):
                manager = get_db_manager()

                assert manager is not None
                assert isinstance(manager, DatabaseManager)


class TestGetSession:
    """Test suite for get_session dependency function."""

    @pytest.mark.asyncio
    async def test_get_session_yields_session(self):
        """Test that get_session yields a database session."""
        mock_session = AsyncMock(spec=AsyncSession)
        mock_manager = MagicMock()

        @asynccontextmanager
        async def mock_session_cm():
            yield mock_session

        mock_manager.session = mock_session_cm

        with patch('terrasafe.infrastructure.database.get_db_manager', return_value=mock_manager):
            async for session in get_session():
                assert session == mock_session
                break

    @pytest.mark.asyncio
    async def test_get_session_multiple_calls(self):
        """Test that get_session can be called multiple times."""
        mock_sessions = [AsyncMock(spec=AsyncSession) for _ in range(3)]
        call_count = [0]

        @asynccontextmanager
        async def mock_session_cm():
            session = mock_sessions[call_count[0]]
            call_count[0] += 1
            yield session

        mock_manager = MagicMock()
        mock_manager.session = mock_session_cm

        with patch('terrasafe.infrastructure.database.get_db_manager', return_value=mock_manager):
            sessions_received = []

            for _ in range(3):
                async for session in get_session():
                    sessions_received.append(session)
                    break

            assert len(sessions_received) == 3
