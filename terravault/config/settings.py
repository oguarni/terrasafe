"""
Configuration management for TerraVault using Pydantic Settings.
Provides type-safe configuration with validation and environment variable support.
"""

import json
import logging
from functools import lru_cache
from typing import Optional, Dict, Any

try:
    import boto3
    from botocore.exceptions import ClientError  # pragma: no cover
except ImportError:
    boto3 = None  # type: ignore

from pydantic import Field, field_validator, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

logger = logging.getLogger(__name__)


class Settings(BaseSettings):
    """
    Application settings with validation and environment variable support.

    All settings can be overridden via environment variables.
    Sensitive values (like API keys) should never have defaults in production.
    """

    # API Configuration
    api_host: str = Field(default="127.0.0.1", description="API host address")
    api_port: int = Field(default=8000, ge=1, le=65535, description="API port")
    api_key_hash: Optional[str] = Field(default=None, description="Hashed API key (required for API mode)")
    api_cors_origins: list[str] = Field(
        default=["http://localhost:3000"],
        description="Allowed CORS origins"
    )
    api_trusted_hosts: list[str] = Field(
        default=["localhost", "127.0.0.1"],
        description="Allowed Host headers in production (used by TrustedHostMiddleware)"
    )

    # Single-service (Cloud Run) mode: let the API also serve the static SPA in
    # ./frontend at "/", absorbing the static-file role that Caddy plays in the VM
    # stack. Left false on the VM, where Caddy serves the frontend. The SPA defaults
    # its backend URL to window.location.origin, so same-origin serving needs no CORS.
    serve_frontend: bool = Field(
        default=False,
        description="Serve the bundled static frontend from the API container (Cloud Run single-service mode)"
    )
    frontend_dir: str = Field(
        default="frontend",
        description="Directory (relative to the working dir) holding the static frontend to serve"
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
        default="models/isolation_forest.pkl",
        description="Path to ML model file"
    )
    severity_overrides: Dict[str, str] = Field(
        default={},
        description="Override severity for specific rules, e.g. {'missing_logging': 'MEDIUM'}"
    )

    # Hybrid score weighting (rule_weight + ml_weight must sum to 1.0)
    rule_weight: float = Field(
        default=0.6,
        ge=0.0,
        le=1.0,
        description="Weight of the deterministic rule engine in the hybrid risk score (default 0.6)."
    )
    ml_weight: float = Field(
        default=0.4,
        ge=0.0,
        le=1.0,
        description="Weight of the Isolation Forest anomaly score in the hybrid risk score (default 0.4)."
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
    enable_docs: Optional[bool] = Field(
        default=None,
        description=(
            "Expose interactive API docs (/docs, /redoc, /openapi.json). "
            "When unset, defaults to enabled outside production and disabled in production. "
            "Set TERRAVAULT_ENABLE_DOCS=true to publish Swagger on a production portfolio site."
        )
    )

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        env_prefix="TERRAVAULT_",
        extra="ignore",
        protected_namespaces=()  # Allow model_ prefix in field names
    )

    @field_validator("log_level")
    @classmethod
    def validate_log_level(cls, v: str) -> str:
        valid_levels = {"DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"}
        v_upper = v.upper()
        if v_upper not in valid_levels:
            raise ValueError(f"log_level must be one of {valid_levels}")
        return v_upper

    @field_validator("log_format")
    @classmethod
    def validate_log_format(cls, v: str) -> str:
        valid_formats = {"json", "text"}
        v_lower = v.lower()
        if v_lower not in valid_formats:
            raise ValueError(f"log_format must be one of {valid_formats}")
        return v_lower

    @field_validator("environment")
    @classmethod
    def validate_environment(cls, v: str) -> str:
        valid_envs = {"development", "staging", "production"}
        v_lower = v.lower()
        if v_lower not in valid_envs:
            raise ValueError(f"environment must be one of {valid_envs}")
        return v_lower

    @field_validator("api_key_hash")
    @classmethod
    def validate_api_key_hash(cls, v: Optional[str]) -> Optional[str]:
        if v is None:
            return None
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
                "Please set a proper hashed API key via TERRAVAULT_API_KEY_HASH environment variable."
            )
        # Check minimum length (bcrypt hashes are 60 chars)
        if len(v) < 60:
            raise ValueError(
                "api_key_hash appears too short to be a valid bcrypt hash. "
                "Expected at least 60 characters."
            )
        return v

    @model_validator(mode="after")
    def validate_score_weights(self) -> "Settings":
        """Ensure the hybrid-score weights form a convex combination (sum to 1.0)."""
        total = self.rule_weight + self.ml_weight
        if abs(total - 1.0) > 1e-6:
            raise ValueError(
                f"rule_weight + ml_weight must sum to 1.0 (got {total:.3f})"
            )
        return self

    @property
    def max_file_size_bytes(self) -> int:
        return self.max_file_size_mb * 1024 * 1024

    def is_production(self) -> bool:
        return self.environment == "production"

    @property
    def docs_enabled(self) -> bool:
        """Whether to expose /docs, /redoc, and /openapi.json.

        Secure default: off in production unless explicitly enabled.
        """
        if self.enable_docs is None:
            return not self.is_production()
        return self.enable_docs

    def is_development(self) -> bool:
        return self.environment == "development"

    def _get_secret(self, secret_name: str) -> Dict[str, Any]:
        if not boto3:
            logger.warning("boto3 not installed, cannot fetch secrets from AWS Secrets Manager")
            return {}

        region_name = "us-east-1"

        session = boto3.session.Session()
        client = session.client(
            service_name='secretsmanager',
            region_name=region_name
        )

        try:
            get_secret_value_response = client.get_secret_value(
                SecretId=secret_name
            )
        except ClientError as e:  # pragma: no cover
            logger.error("Unable to fetch secret %s: %s", secret_name, e)
            raise

        if 'SecretString' in get_secret_value_response:
            secret_data: Dict[str, Any] = json.loads(get_secret_value_response['SecretString'])
            return secret_data
        return {}

    @property
    def database_url_resolved(self) -> str:
        if self.is_production() and not self.database_url:
            try:
                secret = self._get_secret("terravault/database")
                if secret:
                    user = secret.get('username', 'terravault_user')
                    # Use defaults if keys missing
                    password = secret.get('password', '')
                    host = secret.get('host', 'localhost')
                    port = secret.get('port', 5432)
                    dbname = secret.get('dbname', 'terravault')
                    return f"postgresql+asyncpg://{user}:{password}@{host}:{port}/{dbname}"
            except Exception as e:  # pylint: disable=broad-exception-caught
                logger.warning("Failed to resolve database credentials from secrets: %s", e)

        return self.database_url or ""


@lru_cache()
def get_settings() -> Settings:
    return Settings()
