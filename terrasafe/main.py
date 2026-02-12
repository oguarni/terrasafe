"""
Backward-compatible entry point for TerraSafe CLI.

The actual implementation lives in cli.py. This module re-exports
everything needed so that 'from terrasafe.main import ...' and
'python -m terrasafe.main' continue to work.
"""
# Re-export all symbols that cli.py imports, so patches like
# @patch('terrasafe.main.IntelligentSecurityScanner') work correctly.
from terrasafe.cli import main, logger  # noqa: F401
from terrasafe.cli_formatter import format_results_for_display  # noqa: F401
from terrasafe.application.scanner import IntelligentSecurityScanner  # noqa: F401
from terrasafe.infrastructure.parser import HCLParser  # noqa: F401
from terrasafe.infrastructure.ml_model import ModelManager, MLPredictor  # noqa: F401
from terrasafe.domain.security_rules import SecurityRuleEngine  # noqa: F401
from pathlib import Path  # noqa: F401

if __name__ == "__main__":
    main()
