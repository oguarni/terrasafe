"""
Unit tests for HCL Parser - Infrastructure layer
"""
import pytest
from pathlib import Path
from unittest.mock import patch
from terrasafe.infrastructure.parser import HCLParser, TerraformParseError


@pytest.mark.unit
class TestHCLParser:
    """Test suite for HCL Parser"""

    def test_parse_nonexistent_file(self):
        """Test parsing a nonexistent file raises error"""
        parser = HCLParser()
        with pytest.raises(TerraformParseError) as exc_info:
            parser.parse("nonexistent_file.tf")
        assert "File not found" in str(exc_info.value)

    def test_parse_existing_terraform_file(self):
        """Test parsing an existing terraform file"""
        parser = HCLParser()
        # Using a real test file that exists
        tf_content, raw_content = parser.parse("test_files/vulnerable.tf")
        assert isinstance(tf_content, dict)
        assert isinstance(raw_content, str)
        assert len(raw_content) > 0

    def test_parse_secure_terraform_file(self):
        """Test parsing a secure terraform file"""
        parser = HCLParser()
        tf_content, raw_content = parser.parse("test_files/secure.tf")
        assert isinstance(tf_content, dict)
        assert isinstance(raw_content, str)

    def test_parse_file_read_error(self, tmp_path):
        """Test parsing when file cannot be read"""
        tf_file = tmp_path / "test.tf"
        tf_file.write_text('resource "aws_instance" "test" {}')
        parser = HCLParser()
        with patch('builtins.open', side_effect=IOError("Permission denied")):
            with pytest.raises(TerraformParseError) as exc_info:
                parser.parse(str(tf_file))
        assert "Cannot read file" in str(exc_info.value)

    def test_parse_invalid_hcl_syntax(self, tmp_path):
        """Test parsing invalid HCL syntax"""
        tf_file = tmp_path / "invalid.tf"
        tf_file.write_text("invalid hcl syntax {")
        parser = HCLParser()
        with pytest.raises(TerraformParseError) as exc_info:
            parser.parse(str(tf_file))
        # Check for enhanced error message
        assert "Invalid HCL/JSON syntax" in str(exc_info.value)

    def test_parse_json_fallback(self, tmp_path):
        """Test JSON fallback when HCL parsing fails"""
        tf_file = tmp_path / "test.tf.json"
        tf_file.write_text('{"resource": {"aws_s3_bucket": {"test": {"bucket": "example"}}}}')
        parser = HCLParser()
        with patch('hcl2.loads', side_effect=Exception("HCL parse error")):
            tf_content, raw_content = parser.parse(str(tf_file))
        assert isinstance(tf_content, dict)
        assert "resource" in tf_content

    def test_parse_both_formats_fail(self, tmp_path):
        """Test when both HCL and JSON parsing fail"""
        tf_file = tmp_path / "invalid.tf"
        tf_file.write_text("not valid json or hcl")
        parser = HCLParser()
        with patch('hcl2.loads', side_effect=Exception("HCL parse error")):
            with pytest.raises(TerraformParseError) as exc_info:
                parser.parse(str(tf_file))
        # Check for the enhanced error message
        assert "Invalid HCL/JSON syntax" in str(exc_info.value)
        assert "File appears to be neither valid HCL nor JSON" in str(exc_info.value)

    def test_parse_returns_raw_content(self):
        """Test that parser returns both parsed and raw content"""
        parser = HCLParser()
        tf_content, raw_content = parser.parse("test_files/secure.tf")
        assert tf_content is not None
        assert raw_content is not None
        assert len(raw_content) > 0

    def test_terraform_parse_error_message(self):
        """Test TerraformParseError exception"""
        error = TerraformParseError("Custom error message")
        assert str(error) == "Custom error message"

    def test_parse_simple_resource(self, tmp_path):
        """Test parsing a simple resource"""
        content = 'resource "aws_instance" "example" { ami = "ami-123" }'
        tf_file = tmp_path / "simple.tf"
        tf_file.write_text(content)
        parser = HCLParser()
        tf_content, raw_content = parser.parse(str(tf_file))
        assert raw_content == content

    def test_parse_empty_file_rejected(self, tmp_path):
        """Test that empty files are correctly rejected"""
        tf_file = tmp_path / "empty.tf"
        tf_file.write_text("")
        parser = HCLParser()
        with pytest.raises(TerraformParseError) as exc_info:
            parser.parse(str(tf_file))
        assert "empty" in str(exc_info.value).lower()

    def test_parser_encoding_utf8(self):
        """Test parser handles UTF-8 encoding"""
        parser = HCLParser()
        # Real files should be UTF-8 encoded
        tf_content, raw_content = parser.parse("test_files/vulnerable.tf")
        assert isinstance(raw_content, str)
        # Should not raise encoding errors
