#!/usr/bin/env python3
"""
TerraSafe - Main CLI entry point
"""
import sys
import os
import json
import logging
from datetime import datetime, timezone
from pathlib import Path
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

from terrasafe.infrastructure.parser import HCLParser
from terrasafe.infrastructure.ml_model import ModelManager, MLPredictor
from terrasafe.domain.security_rules import SecurityRuleEngine
from terrasafe.application.scanner import IntelligentSecurityScanner
from terrasafe.cli_formatter import format_results_for_display

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)


def main():
    """Main entry point with unique output and scan history tracking."""
    if len(sys.argv) != 2:
        print("Usage: python -m terrasafe.main <terraform_file.tf>")
        print("\nExample:")
        print("  python -m terrasafe.main test_files/vulnerable.tf")
        sys.exit(1)

    filepath = sys.argv[1]

    # Dependency Injection (Clean Architecture)
    parser = HCLParser()
    rule_analyzer = SecurityRuleEngine()
    model_manager = ModelManager()
    ml_predictor = MLPredictor(model_manager)
    scanner = IntelligentSecurityScanner(parser, rule_analyzer, ml_predictor)

    print("🔐 TerraSafe - Intelligent Terraform Security Scanner")
    print("🤖 Using hybrid approach: Rules (60%) + ML Anomaly Detection (40%)")

    results = scanner.scan(filepath)

    print(format_results_for_display(results))

    # Construct unique output filename (scan_results_<stem>.json)
    input_stem = Path(filepath).stem
    json_output = Path(f"scan_results_{input_stem}.json")

    # Persist individual scan result
    try:
        with open(json_output, 'w') as f:
            json.dump(results, f, indent=2, default=str)
        print(f"\n📄 Scan results saved to {json_output}")
    except Exception as e:
        logger.error(f"Failed writing scan output {json_output}: {e}")

    # Append to consolidated history with rotation
    history_path = Path("scan_history.json")
    MAX_HISTORY_SIZE = int(os.getenv("TERRASAFE_MAX_HISTORY_SIZE", "100"))

    results_with_meta = dict(results)
    results_with_meta['timestamp'] = datetime.now(timezone.utc).isoformat()

    try:
        if history_path.exists():
            with open(history_path, 'r') as hf:
                history = json.load(hf)
                if not isinstance(history, dict) or 'scans' not in history:
                    history = {"scans": []}
        else:
            history = {"scans": []}

        # Add new scan and rotate if needed
        history['scans'].append(results_with_meta)

        # Keep only last MAX_HISTORY_SIZE scans
        if len(history['scans']) > MAX_HISTORY_SIZE:
            history['scans'] = history['scans'][-MAX_HISTORY_SIZE:]
            logger.info(f"Rotated scan history to keep last {MAX_HISTORY_SIZE} entries")

        with open(history_path, 'w') as hf:
            json.dump(history, hf, indent=2, default=str)
        print(f"📊 History updated in {history_path}")
    except Exception as e:
        logger.error(f"Failed updating history file: {e}")

    # Severity-based exit codes (Task 3)
    if results['score'] == -1:
        sys.exit(2)  # Parse/scan error
    elif results['score'] >= 90:
        sys.exit(3)  # Critical risk
    elif results['score'] >= 70:
        sys.exit(1)  # High risk
    else:
        sys.exit(0)  # Acceptable risk


if __name__ == "__main__":
    main()
