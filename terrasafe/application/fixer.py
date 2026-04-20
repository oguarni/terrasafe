"""Fixer orchestration - parses a Terraform file, runs remediation, writes output.

Owns file I/O and diff generation so the domain engine stays pure. Callers in
``cli.py`` use this to drive the ``--fix`` workflow end-to-end.
"""
import difflib
import logging
from pathlib import Path
from typing import Any, Dict, Optional

from ..domain.remediation import RemediationEngine, RemediationResult
from ..infrastructure.parser import HCLParser, TerraformParseError

logger = logging.getLogger(__name__)


class TerraformFixer:
    """Apply auto-remediation to a single Terraform file."""

    def __init__(self, parser: HCLParser, engine: RemediationEngine):
        self.parser = parser
        self.engine = engine

    def fix_file(self, filepath: str) -> Dict[str, Any]:
        """Parse + remediate; return a dict describing the outcome (no disk writes)."""
        try:
            tf_content, raw_content = self.parser.parse(filepath)
        except TerraformParseError as exc:
            logger.error("Parse failed for %s: %s", filepath, exc)
            return {
                "file": filepath,
                "error": str(exc),
                "error_type": "TerraformParseError",
                "patches": [],
                "diff": "",
                "has_changes": False,
                "original_content": "",
                "patched_content": "",
            }

        result: RemediationResult = self.engine.fix(raw_content, tf_content)
        diff_text = self._build_diff(filepath, raw_content, result.patched_content)

        return {
            "file": filepath,
            "original_content": raw_content,
            "patched_content": result.patched_content,
            "has_changes": result.has_changes,
            "diff": diff_text,
            "patches": [
                {
                    "rule": p.rule,
                    "description": p.description,
                    "resource": p.resource,
                    "manual_followup": p.manual_followup,
                }
                for p in result.patches
            ],
        }

    @staticmethod
    def _build_diff(filepath: str, original: str, patched: str) -> str:
        if original == patched:
            return ""
        return "".join(
            difflib.unified_diff(
                original.splitlines(keepends=True),
                patched.splitlines(keepends=True),
                fromfile=f"{filepath} (original)",
                tofile=f"{filepath} (fixed)",
                n=3,
            )
        )

    @staticmethod
    def write_output(
        filepath: str,
        patched_content: str,
        *,
        in_place: bool = False,
        output_path: Optional[str] = None,
        backup: bool = True,
    ) -> Dict[str, Optional[str]]:
        """Write patched content; return ``{"written": path, "backup": path|None}``.

        Resolution order for destination:
            1. ``output_path`` if supplied
            2. ``filepath`` when ``in_place`` is true (creates .bak unless ``backup=False``)
            3. ``<stem>.fixed.tf`` next to the input (default safe mode)
        """
        source = Path(filepath)
        backup_path: Optional[Path] = None

        if output_path:
            destination = Path(output_path)
        elif in_place:
            destination = source
            if backup:
                backup_path = source.with_suffix(source.suffix + ".bak")
                backup_path.write_text(
                    source.read_text(encoding="utf-8"), encoding="utf-8"
                )
        else:
            destination = source.with_suffix(".fixed" + source.suffix)

        destination.write_text(patched_content, encoding="utf-8")
        return {
            "written": str(destination),
            "backup": str(backup_path) if backup_path else None,
        }
