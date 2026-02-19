"""
Database infrastructure for TerraSafe using async SQLAlchemy.
Provides connection management, session handling, and base models.
"""

from typing import AsyncGenerator, Optional
from contextlib import asynccontextmanager
from sqlalchemy.ext.asyncio import (
    AsyncSession,
    AsyncEngine,
    create_async_engine,
    async_sessionmaker
)
from sqlalchemy.orm import DeclarativeBase
from sqlalchemy.pool import AsyncAdaptedQueuePool
from sqlalchemy import text
import logging

from terrasafe.config.settings import get_settings

logger = logging.getLogger(__name__)
settings = get_settings()


class Base(DeclarativeBase):
    """Base class for all database models."""
    pass


class DatabaseManager:
    """
    Manages database connections and sessions.

    Provides async SQLAlchemy engine and session factory with proper
    connection pooling and lifecycle management.
    """

    def __init__(self, database_url: Optional[str] = None, pool_size: Optional[int] = None):
        """
        Initialize database manager.

        Args:
            database_url: Database connection URL (from settings if None)
            pool_size: Connection pool size (from settings if None)
        """
        self.database_url = database_url or settings.database_url
        self.pool_size = pool_size or settings.database_pool_size
        self._engine: Optional[AsyncEngine] = None
        self._session_factory: Optional[async_sessionmaker] = None

        if self.database_url:
            logger.info(f"DatabaseManager initialized with pool size: {self.pool_size}")
        else:
            logger.warning("No database URL configured. Database features will be disabled.")

    async def connect(self) -> None:
        """
        Create database engine and session factory.
        Should be called during application startup.
        """
        if not self.database_url:
            logger.warning("Cannot connect: No database URL configured")
            return

        if self._engine is not None:
            logger.warning("Database engine already connected")
            return

        try:
            # Create async engine
            self._engine = create_async_engine(
                self.database_url,
                echo=settings.debug,  # Log SQL in debug mode
                pool_size=self.pool_size,
                max_overflow=20,
                pool_pre_ping=True,  # Verify connections before using
                pool_recycle=3600,  # Recycle connections after 1 hour
                poolclass=AsyncAdaptedQueuePool,
            )

            # Create session factory
            self._session_factory = async_sessionmaker(
                bind=self._engine,
                class_=AsyncSession,
                expire_on_commit=False,
                autoflush=False,
                autocommit=False,
            )

            # Test connection
            async with self._engine.begin() as conn:
                await conn.execute(text("SELECT 1"))

            logger.info("Database connection established successfully")

        except Exception as e:
            logger.error(f"Failed to connect to database: {e}")
            raise

    async def disconnect(self) -> None:
        """
        Close database connections.
        Should be called during application shutdown.
        """
        if self._engine:
            await self._engine.dispose()
            self._engine = None
            self._session_factory = None
            logger.info("Database connections closed")

    @asynccontextmanager
    async def session(self) -> AsyncGenerator[AsyncSession, None]:
        """
        Provide a transactional scope for database operations.

        Yields:
            AsyncSession for database operations

        Example:
            async with db_manager.session() as session:
                result = await session.execute(query)
                await session.commit()
        """
        if not self._session_factory:
            raise RuntimeError(
                "Database not connected. Call connect() first or configure database_url."
            )

        async with self._session_factory() as session:
            try:
                yield session
                await session.commit()
            except Exception as e:
                await session.rollback()
                logger.error(f"Database session error: {e}")
                raise
            finally:
                await session.close()

    async def create_all_tables(self) -> None:
        """
        Create all database tables.
        Used for initial setup or testing.
        In production, use Alembic migrations instead.
        """
        if not self._engine:
            raise RuntimeError("Database not connected")

        async with self._engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)

        logger.info("All database tables created")

    async def drop_all_tables(self) -> None:
        """
        Drop all database tables.
        WARNING: This will delete all data!
        Only use in testing or development.
        """
        if not self._engine:
            raise RuntimeError("Database not connected")

        if settings.is_production():
            raise RuntimeError("Cannot drop tables in production environment")

        async with self._engine.begin() as conn:
            await conn.run_sync(Base.metadata.drop_all)

        logger.warning("All database tables dropped")

    @property
    def is_connected(self) -> bool:
        """Check if database is connected."""
        return self._engine is not None

    async def health_check(self) -> bool:
        """
        Perform health check on database connection.

        Returns:
            True if database is healthy, False otherwise
        """
        if not self._engine:
            return False

        try:
            async with self._engine.begin() as conn:
                await conn.execute(text("SELECT 1"))
            return True
        except Exception as e:
            logger.error(f"Database health check failed: {e}")
            return False


# Singleton instance
_db_manager: Optional[DatabaseManager] = None


def get_db_manager() -> DatabaseManager:
    """
    Get singleton DatabaseManager instance.

    Returns:
        DatabaseManager instance
    """
    global _db_manager
    if _db_manager is None:
        _db_manager = DatabaseManager()
    return _db_manager


async def get_session() -> AsyncGenerator[AsyncSession, None]:
    """
    Dependency for FastAPI to get database session.

    Yields:
        AsyncSession for database operations

    Example:
        @app.get("/scans")
        async def get_scans(session: AsyncSession = Depends(get_session)):
            result = await session.execute(select(Scan))
            return result.scalars().all()
    """
    db_manager = get_db_manager()
    async with db_manager.session() as session:
        yield session
