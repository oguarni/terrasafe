"""
Configuration management for TerraSafe using Pydantic Settings.
Provides type-safe configuration with validation and environment variable support.
"""

from functools import lru_cache
from typing import Optional
from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """
    Application settings with validation and environment variable support.

    All settings can be overridden via environment variables.
    Sensitive values (like API keys) should never have defaults in production.
    """

    # API Configuration
    api_host: str = Field(default="0.0.0.0", description="API host address")
    api_port: int = Field(default=8000, ge=1, le=65535, description="API port")
    api_key_hash: str = Field(..., description="Hashed API key (required, no default)")
    api_cors_origins: list[str] = Field(
        default=["http://localhost:3000"],
        description="Allowed CORS origins"
    )

    # Database Configuration
    database_url: Optional[str] = Field(
        default=None,
        description="Database connection URL (PostgreSQL recommended)"
    )
    database_pool_size: int = Field(default=10, ge=1, description="Database connection pool size")

    # Redis Configuration
    redis_url: str = Field(
        default="redis://localhost:6379",
        description="Redis connection URL for caching and rate limiting"
    )
    redis_max_connections: int = Field(default=50, ge=1, description="Redis connection pool size")

    # Cache Configuration
    cache_ttl_seconds: int = Field(default=3600, ge=60, description="Default cache TTL in seconds")
    cache_max_entries: int = Field(default=100, ge=1, description="Maximum cache entries")

    # ML Model Configuration
    model_confidence_threshold: float = Field(
        default=0.7,
        ge=0.0,
        le=1.0,
        description="Minimum confidence threshold for vulnerability detection"
    )
    model_version: str = Field(default="1.0.0", description="ML model version")
    model_path: str = Field(
        default="models/terrasafe_model.pkl",
        description="Path to ML model file"
    )

    # Security Configuration
    max_file_size_mb: int = Field(
        default=10,
        ge=1,
        le=100,
        description="Maximum allowed file size in megabytes"
    )
    scan_timeout_seconds: int = Field(
        default=30,
        ge=5,
        le=300,
        description="Maximum time allowed for a single scan"
    )
    rate_limit_requests: int = Field(
        default=100,
        ge=1,
        description="Number of requests allowed per time window"
    )
    rate_limit_window_seconds: int = Field(
        default=60,
        ge=1,
        description="Time window for rate limiting in seconds"
    )

    # Logging Configuration
    log_level: str = Field(default="INFO", description="Logging level")
    log_format: str = Field(default="json", description="Log format: json or text")
    log_file: Optional[str] = Field(default=None, description="Optional log file path")

    # Environment
    environment: str = Field(default="development", description="Environment: development, staging, production")
    debug: bool = Field(default=False, description="Enable debug mode")

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        env_prefix="TERRASAFE_",
        extra="ignore",
        protected_namespaces=()  # Allow model_ prefix in field names
    )

    @field_validator("log_level")
    @classmethod
    def validate_log_level(cls, v: str) -> str:
        """Validate log level is one of the standard levels."""
        valid_levels = {"DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"}
        v_upper = v.upper()
        if v_upper not in valid_levels:
            raise ValueError(f"log_level must be one of {valid_levels}")
        return v_upper

    @field_validator("log_format")
    @classmethod
    def validate_log_format(cls, v: str) -> str:
        """Validate log format."""
        valid_formats = {"json", "text"}
        v_lower = v.lower()
        if v_lower not in valid_formats:
            raise ValueError(f"log_format must be one of {valid_formats}")
        return v_lower

    @field_validator("environment")
    @classmethod
    def validate_environment(cls, v: str) -> str:
        """Validate environment setting."""
        valid_envs = {"development", "staging", "production"}
        v_lower = v.lower()
        if v_lower not in valid_envs:
            raise ValueError(f"environment must be one of {valid_envs}")
        return v_lower

    @field_validator("api_key_hash")
    @classmethod
    def validate_api_key_hash(cls, v: str) -> str:
        """Validate API key hash is not a placeholder."""
        dangerous_values = {
            "change-me",
            "change-me-in-production",
            "changeme",
            "default",
            "placeholder",
            "test",
            "demo"
        }
        if v.lower() in dangerous_values:
            raise ValueError(
                "api_key_hash appears to be a placeholder value. "
                "Please set a proper hashed API key via TERRASAFE_API_KEY_HASH environment variable."
            )
        # Check minimum length (bcrypt hashes are 60 chars)
        if len(v) < 60:
            raise ValueError(
                "api_key_hash appears too short to be a valid bcrypt hash. "
                "Expected at least 60 characters."
            )
        return v

    @property
    def max_file_size_bytes(self) -> int:
        """Convert max file size from MB to bytes."""
        return self.max_file_size_mb * 1024 * 1024

    def is_production(self) -> bool:
        """Check if running in production environment."""
        return self.environment == "production"

    def is_development(self) -> bool:
        """Check if running in development environment."""
        return self.environment == "development"


@lru_cache()
def get_settings() -> Settings:
    """
    Get cached settings instance.
    Uses lru_cache to ensure settings are loaded only once.
    """
    return Settings()
