"""Unit tests for the HCL parser infrastructure layer."""
from unittest.mock import patch

import pytest

from terrasafe.infrastructure.parser import (
    FileSizeLimitError,
    HCLParser,
    TerraformParseError,
)


pytestmark = pytest.mark.unit


@pytest.fixture
def parser():
    return HCLParser()


# ---------------------------------------------------------------------------
# Happy paths
# ---------------------------------------------------------------------------

def test_parse_valid_terraform_file_returns_dict_and_raw_string(tmp_path, parser, vulnerable_tf):
    tf_file = tmp_path / "vulnerable.tf"
    tf_file.write_bytes(vulnerable_tf)

    tf_content, raw_content = parser.parse(str(tf_file))

    assert isinstance(tf_content, dict)
    assert isinstance(raw_content, str)
    assert len(raw_content) > 0


def test_parse_falls_back_to_json_when_hcl_loader_fails(tmp_path, parser):
    tf_file = tmp_path / "test.tf.json"
    tf_file.write_text('{"resource": {"aws_s3_bucket": {"test": {"bucket": "example"}}}}')

    with patch('hcl2.loads', side_effect=Exception("HCL parse error")):
        tf_content, _ = parser.parse(str(tf_file))

    assert "resource" in tf_content


# ---------------------------------------------------------------------------
# Error paths — parametrized across failure modes
# ---------------------------------------------------------------------------

@pytest.mark.parametrize(
    "scenario, filename, content, expected_exc, expected_fragment",
    [
        pytest.param(
            "missing_file", "nonexistent_file.tf", None,
            TerraformParseError, "File not found",
            id="missing_file",
        ),
        pytest.param(
            "invalid_hcl", "invalid.tf", "invalid hcl syntax {",
            TerraformParseError, "Invalid HCL/JSON syntax",
            id="invalid_hcl_syntax",
        ),
        pytest.param(
            "empty_file", "empty.tf", "",
            TerraformParseError, "empty",
            id="empty_file_rejected",
        ),
    ],
)
def test_parse_raises_on_invalid_inputs(
    tmp_path, parser, scenario, filename, content, expected_exc, expected_fragment
):
    if content is None:
        target = filename
    else:
        tf_file = tmp_path / filename
        tf_file.write_text(content)
        target = str(tf_file)

    with pytest.raises(expected_exc, match=expected_fragment) as exc_info:
        parser.parse(target)

    assert expected_fragment.lower() in str(exc_info.value).lower()


def test_parse_rejects_file_exceeding_max_size(tmp_path):
    tf_file = tmp_path / "large.tf"
    tf_file.write_text("x" * 100)
    small_parser = HCLParser(max_file_size_bytes=10)

    with pytest.raises(FileSizeLimitError):
        small_parser.parse(str(tf_file))


def test_parse_rejects_non_utf8_binary_content(tmp_path, parser):
    tf_file = tmp_path / "binary.tf"
    tf_file.write_bytes(b"\xff\xfe binary content that is not utf-8 valid \x80\x81")

    with pytest.raises(TerraformParseError) as exc_info:
        parser.parse(str(tf_file))

    message = str(exc_info.value).lower()
    assert "encoding" in message or "utf" in message
