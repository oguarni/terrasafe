#!/usr/bin/env python3
"""
TerraSafe - Main CLI entry point
"""
import sys
import json
import logging
from datetime import datetime
from pathlib import Path
from typing import Dict, Any

from terrasafe.infrastructure.parser import HCLParser
from terrasafe.infrastructure.ml_model import ModelManager, MLPredictor
from terrasafe.domain.security_rules import SecurityRuleEngine
from terrasafe.application.scanner import IntelligentSecurityScanner

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)


def format_results_for_display(results: Dict[str, Any]) -> str:
    """Formats scan results for console output."""
    if results['score'] == -1:
        return f"\n❌ Error scanning file: {results.get('error', 'Unknown error')}"

    output = ["\n" + "="*60, "🔍 TERRAFORM SECURITY SCAN RESULTS", "="*60, f"📁 File: {results['file']}", "-"*60]

    score = results['score']
    status = "✅ LOW RISK"
    color = "\033[92m"  # Green
    if score >= 90:
        status, color = "🚨 CRITICAL RISK", "\033[91m"  # Red
    elif score >= 70:
        status, color = "❌ HIGH RISK", "\033[91m"  # Red
    elif score >= 40:
        status, color = "⚠️  MEDIUM RISK", "\033[93m"  # Yellow

    output.append(f"\n{status}")
    output.append(f"{color}📊 Final Risk Score: {score}/100\033[0m")
    output.append(f"├─ Rule-based Score: {results['rule_based_score']}/100")
    output.append(f"├─ ML Anomaly Score: {results['ml_score']:.1f}/100")
    output.append(f"└─ Confidence: {results['confidence']}")

    # Feature analysis (if available)
    if 'features_analyzed' in results:
        output.append(f"\n🔬 Feature Analysis:")
        features = results['features_analyzed']
        output.append(f"   Open Ports: {features['open_ports']}")
        output.append(f"   Hardcoded Secrets: {features['hardcoded_secrets']}")
        output.append(f"   Public Access: {features['public_access']}")
        output.append(f"   Unencrypted Storage: {features['unencrypted_storage']}")

    # Performance metrics
    if 'performance' in results:
        perf = results['performance']
        output.append(f"\n⏱️  Performance:")
        output.append(f"   Scan Time: {perf['scan_time_seconds']}s")
        output.append(f"   File Size: {perf['file_size_kb']} KB")

    if results['vulnerabilities']:
        output.append("\n🚨 Detected Vulnerabilities:")
        output.append("-" * 60)
        for v in results['vulnerabilities']:
            output.append(f"\n{v['message']}")
            output.append(f"   📍 Resource: {v['resource']}")
            if v['remediation']:
                output.append(f"   💡 Fix: {v['remediation']}")
    else:
        output.append("\n\033[92m✅ No security issues detected!\033[0m")
        output.append("✓ All resources properly configured")
        output.append("✓ Encryption enabled where required")
        output.append("✓ Network access properly restricted")

    output.append("\n" + "="*60)
    return "\n".join(output)


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

    # Append to consolidated history (scan_history.json)
    history_path = Path("scan_history.json")
    # Add timestamp (ISO8601) without mutating original dict externally
    results_with_meta = dict(results)
    results_with_meta['timestamp'] = datetime.utcnow().isoformat() + 'Z'
    try:
        if history_path.exists():
            with open(history_path, 'r') as hf:
                history = json.load(hf)
                if not isinstance(history, dict) or 'scans' not in history:
                    history = {"scans": []}
        else:
            history = {"scans": []}
        history['scans'].append(results_with_meta)
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
