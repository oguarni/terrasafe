#!/usr/bin/env python3
"""
TerraVault - Main CLI entry point
"""
import sys
import os
import json
import logging
import argparse
from datetime import datetime, timezone
from pathlib import Path
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

from terravault.infrastructure.parser import HCLParser
from terravault.infrastructure.ml_model import ModelManager, MLPredictor
from terravault.domain.security_rules import SecurityRuleEngine
from terravault.application.scanner import IntelligentSecurityScanner
from terravault.cli_formatter import format_results_for_display
from terravault.sarif_formatter import results_to_sarif

logger = logging.getLogger(__name__)


def _build_scanner():
    parser = HCLParser()
    rule_analyzer = SecurityRuleEngine()
    model_manager = ModelManager()
    ml_predictor = MLPredictor(model_manager)
    return IntelligentSecurityScanner(parser, rule_analyzer, ml_predictor)


def _configure_logging(output_format: str) -> None:
    """Redirect logging to stderr in CI modes to keep stdout pure."""
    handler = logging.StreamHandler(sys.stderr if output_format in ("json", "sarif") else sys.stdout)
    handler.setFormatter(logging.Formatter('%(asctime)s - %(levelname)s - %(message)s'))
    root = logging.getLogger()
    root.handlers.clear()
    root.addHandler(handler)
    root.setLevel(logging.INFO)


def _save_history(results: dict, filepath: str) -> None:
    input_stem = Path(filepath).stem
    json_output = Path(f"scan_results_{input_stem}.json")
    try:
        with open(json_output, 'w', encoding='utf-8') as f:
            json.dump(results, f, indent=2, default=str)
        print(f"\n📄 Scan results saved to {json_output}")
    except (OSError, TypeError, ValueError) as e:
        logger.error("Failed writing scan output %s: %s", json_output, e)

    history_path = Path("scan_history.json")
    max_history_size = int(os.getenv("TERRAVAULT_MAX_HISTORY_SIZE", "100"))

    results_with_meta = dict(results)
    results_with_meta['timestamp'] = datetime.now(timezone.utc).isoformat()

    try:
        if history_path.exists():
            with open(history_path, 'r', encoding='utf-8') as hf:
                history = json.load(hf)
                if not isinstance(history, dict) or 'scans' not in history:
                    history = {"scans": []}
        else:
            history = {"scans": []}

        history['scans'].append(results_with_meta)
        if len(history['scans']) > max_history_size:
            history['scans'] = history['scans'][-max_history_size:]

        with open(history_path, 'w', encoding='utf-8') as hf:
            json.dump(history, hf, indent=2, default=str)
        print(f"📊 History updated in {history_path}")
    except (OSError, json.JSONDecodeError, TypeError, ValueError) as e:
        logger.error("Failed updating history file: %s", e)


def _text_exit_code(score: int, threshold: int) -> int:
    """Classic 4-level exit codes for text mode (single-file, backward-compat)."""
    if score == -1:
        return 2
    if score >= 90:
        return 3
    if score >= threshold:
        return 1
    return 0


def _ci_exit_code(results_list: list, threshold: int) -> int:
    """Binary exit codes for json/sarif CI mode."""
    has_error = any(r.get("score") == -1 for r in results_list)
    has_exceeded = any(r.get("score", 0) >= threshold for r in results_list if r.get("score", -1) != -1)
    if has_error:
        return 2
    if has_exceeded:
        return 1
    return 0


def main():
    parser = argparse.ArgumentParser(
        prog="python -m terravault.cli",
        description="TerraVault - Intelligent Terraform Security Scanner",
    )
    parser.add_argument(
        "files",
        nargs="+",
        metavar="file.tf",
        help="One or more Terraform files to scan",
    )
    parser.add_argument(
        "--output-format",
        choices=["text", "json", "sarif"],
        default="text",
        dest="output_format",
        help="Output format (default: text)",
    )
    parser.add_argument(
        "--threshold",
        type=int,
        default=70,
        metavar="N",
        help="Risk score threshold 0-100 (default: 70)",
    )
    parser.add_argument(
        "--no-history",
        action="store_true",
        dest="no_history",
        help="Skip writing scan_results_*.json and scan_history.json",
    )

    args = parser.parse_args()
    _configure_logging(args.output_format)

    output_format = args.output_format
    threshold = max(0, min(100, args.threshold))

    scanner = _build_scanner()

    if output_format == "text":
        # Single-file legacy mode (backward-compat)
        filepath = args.files[0]

        if output_format == "text":
            print("🔐 TerraVault - Intelligent Terraform Security Scanner")
            print("🤖 Using hybrid approach: Rules (60%) + ML Anomaly Detection (40%)")

        results = scanner.scan(filepath)
        print(format_results_for_display(results))

        if not args.no_history:
            _save_history(results, filepath)

        sys.exit(_text_exit_code(results['score'], threshold))

    else:
        # CI mode: multi-file, pure stdout JSON/SARIF
        all_results = []
        for fp in args.files:
            all_results.append(scanner.scan(fp))

        if output_format == "json":
            valid_scores = [r['score'] for r in all_results if r.get('score', -1) != -1]
            max_score = max(valid_scores) if valid_scores else 0
            passed = sum(1 for s in valid_scores if s < threshold)
            failed = sum(1 for s in valid_scores if s >= threshold)

            output = {
                "results": all_results,
                "summary": {
                    "total_files": len(all_results),
                    "passed": passed,
                    "failed": failed,
                    "max_score": max_score,
                    "threshold": threshold,
                },
            }
            sys.stdout.write(json.dumps(output, indent=2, default=str) + "\n")

        elif output_format == "sarif":
            sys.stdout.write(results_to_sarif(all_results) + "\n")

        sys.exit(_ci_exit_code(all_results, threshold))


if __name__ == "__main__":
    main()
