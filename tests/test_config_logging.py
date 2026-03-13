"""Tests for terrasafe/config/logging.py"""
import json
import logging
import uuid
import pytest

from terrasafe.config.logging import (
    StructuredFormatter,
    TextFormatter,
    LoggerAdapter,
    setup_logging,
    get_logger,
    get_logger_with_context,
    set_correlation_id,
    get_correlation_id,
    clear_correlation_id,
)


@pytest.mark.unit
class TestStructuredFormatter:
    """Tests for StructuredFormatter (JSON output)."""

    def _make_record(self, message: str = "test message", level: int = logging.INFO) -> logging.LogRecord:
        record = logging.LogRecord(
            name="test.logger",
            level=level,
            pathname=__file__,
            lineno=1,
            msg=message,
            args=(),
            exc_info=None,
        )
        return record

    def test_produces_valid_json(self):
        """Formatted output must be parseable JSON."""
        clear_correlation_id()
        formatter = StructuredFormatter()
        record = self._make_record("hello")
        output = formatter.format(record)
        data = json.loads(output)
        assert isinstance(data, dict)

    def test_contains_required_fields(self):
        """JSON output must contain level, message, and timestamp."""
        clear_correlation_id()
        formatter = StructuredFormatter()
        record = self._make_record("check fields")
        data = json.loads(formatter.format(record))
        assert "level" in data
        assert "message" in data
        assert "timestamp" in data

    def test_includes_correlation_id_when_set(self):
        """When a correlation ID is set, it must appear in the JSON output."""
        set_correlation_id("test-cid-123")
        try:
            formatter = StructuredFormatter()
            record = self._make_record()
            data = json.loads(formatter.format(record))
            assert data.get("correlation_id") == "test-cid-123"
        finally:
            clear_correlation_id()

    def test_omits_correlation_id_when_not_set(self):
        """When no correlation ID is set, the field must be absent."""
        clear_correlation_id()
        formatter = StructuredFormatter()
        record = self._make_record()
        data = json.loads(formatter.format(record))
        assert "correlation_id" not in data

    def test_includes_exception_info(self):
        """When exc_info is set on the record, the JSON must include 'exception'."""
        clear_correlation_id()
        formatter = StructuredFormatter()
        try:
            raise ValueError("boom")
        except ValueError:
            import sys
            exc = sys.exc_info()
        record = self._make_record("error occurred")
        record.exc_info = exc
        data = json.loads(formatter.format(record))
        assert "exception" in data
        assert "ValueError" in data["exception"]


@pytest.mark.unit
class TestTextFormatter:
    """Tests for TextFormatter (human-readable output)."""

    def test_produces_level_in_brackets(self):
        """TextFormatter output must contain [LEVEL] pattern."""
        formatter = TextFormatter()
        record = logging.LogRecord(
            name="test",
            level=logging.WARNING,
            pathname=__file__,
            lineno=1,
            msg="some warning",
            args=(),
            exc_info=None,
        )
        output = formatter.format(record)
        assert "[WARNING]" in output


@pytest.mark.unit
class TestCorrelationId:
    """Tests for correlation ID lifecycle functions."""

    def setup_method(self):
        clear_correlation_id()

    def teardown_method(self):
        clear_correlation_id()

    def test_set_and_get_roundtrip(self):
        """set_correlation_id followed by get_correlation_id returns same value."""
        set_correlation_id("abc-123")
        assert get_correlation_id() == "abc-123"

    def test_clear_removes_id(self):
        """clear_correlation_id makes get_correlation_id return None."""
        set_correlation_id("some-id")
        clear_correlation_id()
        assert get_correlation_id() is None

    def test_auto_generates_uuid_when_called_without_arg(self):
        """set_correlation_id() with no argument generates a valid UUID."""
        generated = set_correlation_id()
        # Must be parseable as a UUID
        parsed = uuid.UUID(generated)
        assert str(parsed) == generated
        assert get_correlation_id() == generated


@pytest.mark.unit
class TestSetupLogging:
    """Tests for setup_logging() configuration function."""

    def test_json_mode_configures_structured_formatter(self):
        """setup_logging with json format should not raise and set root logger level."""
        setup_logging(log_level="DEBUG", log_format="json")
        root = logging.getLogger()
        assert root.level == logging.DEBUG

    def test_text_mode_configures_text_formatter(self):
        """setup_logging with text format should not raise."""
        setup_logging(log_level="WARNING", log_format="text")
        root = logging.getLogger()
        assert root.level == logging.WARNING


@pytest.mark.unit
class TestGetLogger:
    """Tests for get_logger and get_logger_with_context."""

    def test_get_logger_returns_logger_instance(self):
        """get_logger must return a logging.Logger."""
        logger = get_logger("terrasafe.test")
        assert isinstance(logger, logging.Logger)
        assert logger.name == "terrasafe.test"

    def test_get_logger_with_context_returns_adapter(self):
        """get_logger_with_context must return a LoggerAdapter instance."""
        adapter = get_logger_with_context("terrasafe.test.ctx")
        assert isinstance(adapter, LoggerAdapter)


@pytest.mark.unit
class TestLoggerAdapterProcess:
    """Tests for LoggerAdapter.process()"""

    def setup_method(self):
        clear_correlation_id()

    def teardown_method(self):
        clear_correlation_id()

    def test_process_adds_correlation_id(self):
        """process() injects correlation_id into kwargs['extra'] when CID is set."""
        set_correlation_id("req-abc-123")
        adapter = get_logger_with_context("terrasafe.test.adapter")
        msg, kwargs = adapter.process("hello", {})
        assert "extra" in kwargs
        assert kwargs["extra"]["correlation_id"] == "req-abc-123"

    def test_process_without_correlation_id(self):
        """process() leaves kwargs unchanged when no CID is set."""
        clear_correlation_id()
        adapter = get_logger_with_context("terrasafe.test.adapter")
        msg, kwargs = adapter.process("hello", {})
        assert "extra" not in kwargs or "correlation_id" not in kwargs.get("extra", {})

    def test_process_preserves_existing_extra(self):
        """process() adds correlation_id to an already-present extra dict."""
        set_correlation_id("cid-xyz")
        adapter = get_logger_with_context("terrasafe.test.adapter")
        kwargs = {"extra": {"my_key": "my_val"}}
        msg, new_kwargs = adapter.process("msg", kwargs)
        assert new_kwargs["extra"]["my_key"] == "my_val"
        assert new_kwargs["extra"]["correlation_id"] == "cid-xyz"


@pytest.mark.unit
class TestSetupLoggingFileHandler:
    """Tests for setup_logging() with file handler."""

    def test_setup_logging_with_file_handler(self, tmp_path):
        """setup_logging with log_file creates a file handler without errors."""
        log_file = str(tmp_path / "test.log")
        setup_logging(log_level="INFO", log_format="json", log_file=log_file)
        root = logging.getLogger()
        assert root.level == logging.INFO


@pytest.mark.unit
class TestStructuredFormatterExtraFields:
    """Tests for StructuredFormatter extra_fields support."""

    def test_structured_formatter_extra_fields(self):
        """Extra fields on the record are merged into JSON output."""
        import json as _json
        clear_correlation_id()
        formatter = StructuredFormatter()
        record = logging.LogRecord(
            name="test",
            level=logging.INFO,
            pathname=__file__,
            lineno=1,
            msg="test message",
            args=(),
            exc_info=None,
        )
        record.extra_fields = {"custom_key": "custom_val", "request_id": "42"}
        data = _json.loads(formatter.format(record))
        assert data.get("custom_key") == "custom_val"
        assert data.get("request_id") == "42"
