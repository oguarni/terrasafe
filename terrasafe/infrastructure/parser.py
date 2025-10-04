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
        except Exception as e:
            raise TerraformParseError(f"Cannot read file: {e}")

        try:
            tf_content = hcl2.loads(raw_content)
            return tf_content, raw_content
        except Exception as hcl_error:
            logger.debug(f"HCL2 parse failed: {hcl_error}")
            # Fallback to JSON parsing for .tf.json files
            try:
                tf_content = json.loads(raw_content)
                return tf_content, raw_content
            except json.JSONDecodeError:
                raise TerraformParseError(f"Invalid HCL or JSON syntax in {filepath}") from hcl_error
