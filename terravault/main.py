"""
Backward-compatible entry point for TerraVault CLI.

The actual implementation lives in cli.py. This module re-exports
everything needed so that 'from terravault.main import ...' and
'python -m terravault.main' continue to work.
"""
# pylint: disable=unused-import
# Re-export all symbols that cli.py imports, so patches like
# @patch('terravault.main.IntelligentSecurityScanner') work correctly.
from pathlib import Path  # noqa: F401
from terravault.cli import main, logger  # noqa: F401
from terravault.cli_formatter import format_results_for_display  # noqa: F401
from terravault.application.scanner import IntelligentSecurityScanner  # noqa: F401
from terravault.infrastructure.parser import HCLParser  # noqa: F401
from terravault.infrastructure.ml_model import ModelManager, MLPredictor  # noqa: F401
from terravault.domain.security_rules import SecurityRuleEngine  # noqa: F401

if __name__ == "__main__":
    main()
