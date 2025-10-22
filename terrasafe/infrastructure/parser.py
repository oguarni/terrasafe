"""HCL Parser - Infrastructure layer"""
from pathlib import Path
from typing import Tuple, Dict, Any
import hcl2
import json
import logging

logger = logging.getLogger(__name__)


class TerraformParseError(Exception):
    """Raised when Terraform file parsing fails"""
    pass


class HCLParser:
    """Handles parsing of HCL files"""

    def parse(self, filepath: str) -> Tuple[Dict[str, Any], str]:
        """
        Parses a Terraform file, with fallbacks.
        Raises TerraformParseError if parsing fails.
        """
        path = Path(filepath)
        if not path.exists():
            raise TerraformParseError(f"File not found: {filepath}")

        try:
            with open(path, 'r', encoding='utf-8') as f:
                raw_content = f.read()
        except PermissionError as e:
            raise TerraformParseError(f"Permission denied reading file {filepath}: {e}")
        except UnicodeDecodeError as e:
            raise TerraformParseError(f"File encoding error in {filepath}: Not a valid UTF-8 text file")
        except Exception as e:
            raise TerraformParseError(f"Cannot read file {filepath}: {type(e).__name__} - {e}")

        try:
            tf_content = hcl2.loads(raw_content)
            return tf_content, raw_content
        except Exception as hcl_error:
            logger.debug(f"HCL2 parse failed: {hcl_error}")
            # Fallback to JSON parsing for .tf.json files
            try:
                tf_content = json.loads(raw_content)
                return tf_content, raw_content
            except json.JSONDecodeError as json_error:
                # Provide context from the file content
                content_preview = raw_content[:200].strip() if raw_content else "(empty file)"
                if len(content_preview) == 200:
                    content_preview += "..."
                error_msg = (
                    f"Invalid HCL/JSON syntax in {filepath}. "
                    f"File appears to be neither valid HCL nor JSON. "
                    f"HCL error: {str(hcl_error)[:100]}. "
                    f"JSON error: {str(json_error)[:100]}. "
                    f"File starts with: {content_preview}"
                )
                raise TerraformParseError(error_msg) from hcl_error
