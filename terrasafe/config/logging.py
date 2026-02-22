"""
Centralized logging configuration for TerraSafe.
Provides structured logging with correlation IDs for request tracing.
"""

import logging
import logging.config
import sys
import uuid
from contextvars import ContextVar
from typing import Any, Optional
import json
from datetime import datetime, timezone

# Context variable for correlation ID (for request tracing)
correlation_id: ContextVar[Optional[str]] = ContextVar('correlation_id', default=None)


class StructuredFormatter(logging.Formatter):
    """
    JSON formatter for structured logging.
    Includes correlation ID if available.
    """

    def format(self, record: logging.LogRecord) -> str:
        """Format log record as JSON."""
        log_data = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
            "module": record.module,
            "function": record.funcName,
            "line": record.lineno,
        }

        # Add correlation ID if available
        cid = correlation_id.get()
        if cid:
            log_data["correlation_id"] = cid

        # Add exception info if present
        if record.exc_info:
            log_data["exception"] = self.formatException(record.exc_info)

        # Add extra fields
        if hasattr(record, "extra_fields"):
            log_data.update(record.extra_fields)

        return json.dumps(log_data)


class TextFormatter(logging.Formatter):
    """
    Human-readable text formatter for development.
    """

    def __init__(self):
        super().__init__(
            fmt="%(asctime)s [%(levelname)s] %(name)s - %(message)s (%(filename)s:%(lineno)d)",
            datefmt="%Y-%m-%d %H:%M:%S"
        )


def setup_logging(
    log_level: str = "INFO",
    log_format: str = "json",
    log_file: Optional[str] = None
) -> None:
    """
    Configure logging for the application.

    Args:
        log_level: Logging level (DEBUG, INFO, WARNING, ERROR, CRITICAL)
        log_format: Format type ("json" or "text")
        log_file: Optional file path for log output
    """
    # Choose formatter based on format type
    formatter: logging.Formatter
    if log_format == "json":
        formatter = StructuredFormatter()
    else:
        formatter = TextFormatter()

    # Configure handlers
    handlers: dict[str, Any] = {
        "console": {
            "class": "logging.StreamHandler",
            "formatter": "default",
            "stream": sys.stdout,
        }
    }

    # Add file handler if log_file is specified
    if log_file:
        handlers["file"] = {
            "class": "logging.handlers.RotatingFileHandler",
            "formatter": "default",
            "filename": log_file,
            "maxBytes": 10485760,  # 10MB
            "backupCount": 5,
        }

    # Logging configuration
    config = {
        "version": 1,
        "disable_existing_loggers": False,
        "formatters": {
            "default": {
                "()": StructuredFormatter if log_format == "json" else TextFormatter,
            }
        },
        "handlers": handlers,
        "root": {
            "level": log_level,
            "handlers": list(handlers.keys()),
        },
        "loggers": {
            "terrasafe": {
                "level": log_level,
                "handlers": list(handlers.keys()),
                "propagate": False,
            },
            "uvicorn": {
                "level": log_level,
                "handlers": list(handlers.keys()),
                "propagate": False,
            },
            "uvicorn.access": {
                "level": "INFO",
                "handlers": list(handlers.keys()),
                "propagate": False,
            },
        },
    }

    logging.config.dictConfig(config)


def get_logger(name: str) -> logging.Logger:
    """
    Get a logger instance with the given name.

    Args:
        name: Logger name (typically __name__)

    Returns:
        Logger instance
    """
    return logging.getLogger(name)


def set_correlation_id(cid: Optional[str] = None) -> str:
    """
    Set correlation ID for the current context.
    If not provided, generates a new UUID.

    Args:
        cid: Optional correlation ID

    Returns:
        The correlation ID that was set
    """
    if cid is None:
        cid = str(uuid.uuid4())
    correlation_id.set(cid)
    return cid


def get_correlation_id() -> Optional[str]:
    """
    Get the current correlation ID.

    Returns:
        Current correlation ID or None
    """
    return correlation_id.get()


def clear_correlation_id() -> None:
    """Clear the correlation ID from the current context."""
    correlation_id.set(None)


class LoggerAdapter(logging.LoggerAdapter):
    """
    Logger adapter that automatically includes correlation ID and extra fields.
    """

    def process(self, msg: str, kwargs: Any) -> tuple[str, Any]:
        """Add correlation ID and extra fields to log record."""
        # Add correlation ID if available
        cid = correlation_id.get()
        if cid and "extra" not in kwargs:
            kwargs["extra"] = {}
        if cid:
            kwargs["extra"]["correlation_id"] = cid

        return msg, kwargs


def get_logger_with_context(name: str) -> LoggerAdapter:
    """
    Get a logger with automatic correlation ID injection.

    Args:
        name: Logger name (typically __name__)

    Returns:
        LoggerAdapter instance
    """
    logger = logging.getLogger(name)
    return LoggerAdapter(logger, {})
