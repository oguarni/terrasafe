#!/usr/bin/env python3
"""
TerraSafe - Main CLI entry point
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

from terrasafe.infrastructure.parser import HCLParser
from terrasafe.infrastructure.ml_model import ModelManager, MLPredictor
from terrasafe.domain.security_rules import SecurityRuleEngine
from terrasafe.domain.remediation import RemediationEngine
from terrasafe.application.scanner import IntelligentSecurityScanner
from terrasafe.application.fixer import TerraformFixer
from terrasafe.cli_formatter import format_results_for_display
from terrasafe.sarif_formatter import results_to_sarif

logger = logging.getLogger(__name__)


def _build_scanner():
    parser = HCLParser()
    rule_analyzer = SecurityRuleEngine()
    model_manager = ModelManager()
    ml_predictor = MLPredictor(model_manager)
    return IntelligentSecurityScanner(parser, rule_analyzer, ml_predictor)


def _build_fixer():
    return TerraformFixer(HCLParser(), RemediationEngine())


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
    max_history_size = int(os.getenv("TERRASAFE_MAX_HISTORY_SIZE", "100"))

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


def _print_fix_summary(result: dict) -> None:
    """Print a human-readable summary of patches applied to one file."""
    filepath = result["file"]
    if result.get("error"):
        print(f"\n❌ {filepath}: {result['error']}")
        return

    patches = result.get("patches") or []
    if not patches:
        print(f"\n✅ {filepath}: no remediable issues detected")
        return

    print(f"\n🔧 {filepath}: {len(patches)} patch(es) applied")
    manual = 0
    for patch in patches:
        marker = "⚠️ " if patch["manual_followup"] else "✔️ "
        print(f"   {marker}[{patch['rule']}] {patch['description']}")
        if patch["manual_followup"]:
            manual += 1
    if manual:
        print(f"   → {manual} patch(es) need manual follow-up before terraform apply")


def _run_fix_mode(args) -> int:
    """Execute --fix flow. Returns CLI exit code.

    Exit codes:
        0 = success (or no changes needed)
        1 = changes applied successfully
        2 = parse error on at least one file
    """
    if args.fix_output and len(args.files) > 1:
        print(
            "❌ --fix-output only supports a single file. Use --in-place for multi-file fixes.",
            file=sys.stderr,
        )
        return 2

    fixer = _build_fixer()
    any_error = False
    any_change = False

    for filepath in args.files:
        result = fixer.fix_file(filepath)

        if result.get("error"):
            any_error = True
            _print_fix_summary(result)
            continue

        if not result["has_changes"]:
            _print_fix_summary(result)
            continue

        any_change = True
        if result["diff"]:
            print(result["diff"])
        _print_fix_summary(result)

        if args.dry_run:
            print(f"   (dry-run: {filepath} not written)")
            continue

        write_info = fixer.write_output(
            filepath,
            result["patched_content"],
            in_place=args.in_place,
            output_path=args.fix_output,
            backup=not args.no_backup,
        )
        print(f"   → wrote {write_info['written']}")
        if write_info["backup"]:
            print(f"   → backup at {write_info['backup']}")

    if any_error:
        return 2
    return 1 if any_change else 0


def main():
    parser = argparse.ArgumentParser(
        prog="python -m terrasafe.cli",
        description="TerraSafe - Intelligent Terraform Security Scanner",
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
    parser.add_argument(
        "--fix",
        action="store_true",
        help="Generate and apply HCL patches for detected vulnerabilities",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        dest="dry_run",
        help="With --fix: show the diff without writing any files",
    )
    parser.add_argument(
        "--in-place",
        action="store_true",
        dest="in_place",
        help="With --fix: overwrite the input file (creates .bak unless --no-backup)",
    )
    parser.add_argument(
        "--fix-output",
        metavar="PATH",
        dest="fix_output",
        help="With --fix: write patched content to PATH (single-file mode)",
    )
    parser.add_argument(
        "--no-backup",
        action="store_true",
        dest="no_backup",
        help="With --fix --in-place: skip creating the .bak backup",
    )

    args = parser.parse_args()
    _configure_logging(args.output_format)

    output_format = args.output_format
    threshold = max(0, min(100, args.threshold))

    if args.fix:
        sys.exit(_run_fix_mode(args))

    scanner = _build_scanner()

    if output_format == "text":
        # Single-file legacy mode (backward-compat)
        filepath = args.files[0]

        if output_format == "text":
            print("🔐 TerraSafe - Intelligent Terraform Security Scanner")
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
