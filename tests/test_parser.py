"""
Unit tests for HCL Parser - Infrastructure layer
"""
import pytest
import json
from pathlib import Path
from unittest.mock import patch, mock_open
from terrasafe.infrastructure.parser import HCLParser, TerraformParseError


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

    @patch('builtins.open', side_effect=IOError("Permission denied"))
    @patch('pathlib.Path.exists', return_value=True)
    def test_parse_file_read_error(self, mock_exists, mock_file):
        """Test parsing when file cannot be read"""
        parser = HCLParser()
        with pytest.raises(TerraformParseError) as exc_info:
            parser.parse("test.tf")
        assert "Cannot read file" in str(exc_info.value)

    @patch('builtins.open', new_callable=mock_open, read_data='invalid hcl syntax {')
    @patch('pathlib.Path.exists', return_value=True)
    def test_parse_invalid_hcl_syntax(self, mock_exists, mock_file):
        """Test parsing invalid HCL syntax"""
        parser = HCLParser()
        with pytest.raises(TerraformParseError) as exc_info:
            parser.parse("invalid.tf")
        assert "Invalid HCL or JSON syntax" in str(exc_info.value)

    @patch('builtins.open', new_callable=mock_open, read_data='{"resource": {"aws_s3_bucket": {"test": {"bucket": "example"}}}}')
    @patch('pathlib.Path.exists', return_value=True)
    @patch('hcl2.loads', side_effect=Exception("HCL parse error"))
    def test_parse_json_fallback(self, mock_hcl2, mock_exists, mock_file):
        """Test JSON fallback when HCL parsing fails"""
        parser = HCLParser()
        tf_content, raw_content = parser.parse("test.tf.json")
        assert isinstance(tf_content, dict)
        assert "resource" in tf_content

    @patch('builtins.open', new_callable=mock_open, read_data='not valid json or hcl')
    @patch('pathlib.Path.exists', return_value=True)
    @patch('hcl2.loads', side_effect=Exception("HCL parse error"))
    def test_parse_both_formats_fail(self, mock_hcl2, mock_exists, mock_file):
        """Test when both HCL and JSON parsing fail"""
        parser = HCLParser()
        with pytest.raises(TerraformParseError) as exc_info:
            parser.parse("invalid.tf")
        assert "Invalid HCL or JSON syntax" in str(exc_info.value)

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

    @patch('builtins.open', new_callable=mock_open, read_data='resource "aws_instance" "example" { ami = "ami-123" }')
    @patch('pathlib.Path.exists', return_value=True)
    def test_parse_simple_resource(self, mock_exists, mock_file):
        """Test parsing a simple resource"""
        parser = HCLParser()
        tf_content, raw_content = parser.parse("simple.tf")
        assert raw_content == 'resource "aws_instance" "example" { ami = "ami-123" }'

    @patch('builtins.open', new_callable=mock_open, read_data='')
    @patch('pathlib.Path.exists', return_value=True)
    def test_parse_empty_file(self, mock_exists, mock_file):
        """Test parsing an empty file"""
        parser = HCLParser()
        # Empty file should parse as empty dict
        tf_content, raw_content = parser.parse("empty.tf")
        assert raw_content == ''
        # hcl2.loads('') returns {}
        assert tf_content == {}

    def test_parser_encoding_utf8(self):
        """Test parser handles UTF-8 encoding"""
        parser = HCLParser()
        # Real files should be UTF-8 encoded
        tf_content, raw_content = parser.parse("test_files/vulnerable.tf")
        assert isinstance(raw_content, str)
        # Should not raise encoding errors
