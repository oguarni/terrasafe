"""CLI output formatting module - Clean separation of concerns"""
from typing import Dict, Any


def format_results_for_display(results: Dict[str, Any]) -> str:
    """
    Formats scan results for console output.
    Single Responsibility: Only handles formatting, no business logic.
    """
    if results['score'] == -1:
        return f"\n❌ Error scanning file: {results.get('error', 'Unknown error')}"

    output = []
    output.append("\n" + "="*60)
    output.append("🔍 TERRAFORM SECURITY SCAN RESULTS")
    output.append("="*60)
    output.append(f"📁 File: {results['file']}")
    output.append("-"*60)

    score = results['score']
    status, color = _determine_risk_status(score)

    output.append(f"\n{status}")
    output.append(f"{color}📊 Final Risk Score: {score}/100\033[0m")
    output.append(f"├─ Rule-based Score: {results['rule_based_score']}/100")
    output.append(f"├─ ML Anomaly Score: {results['ml_score']:.1f}/100")
    output.append(f"└─ Confidence: {results['confidence']}")

    # Feature analysis section
    if 'features_analyzed' in results:
        output.extend(_format_features(results['features_analyzed']))

    # Performance metrics section
    if 'performance' in results:
        output.extend(_format_performance(results['performance']))

    # Vulnerabilities section
    if results.get('vulnerabilities'):
        output.extend(_format_vulnerabilities(results['vulnerabilities']))
    else:
        output.extend(_format_no_issues())

    output.append("\n" + "="*60)
    return "\n".join(output)


def _determine_risk_status(score: int) -> tuple[str, str]:
    """Determine risk status and color based on score."""
    if score >= 90:
        return "🚨 CRITICAL RISK", "\033[91m"  # Red
    elif score >= 70:
        return "❌ HIGH RISK", "\033[91m"  # Red
    elif score >= 40:
        return "⚠️  MEDIUM RISK", "\033[93m"  # Yellow
    else:
        return "✅ LOW RISK", "\033[92m"  # Green


def _format_features(features: Dict[str, int]) -> list[str]:
    """Format feature analysis section."""
    return [
        "\n🔬 Feature Analysis:",
        f"   Open Ports: {features['open_ports']}",
        f"   Hardcoded Secrets: {features['hardcoded_secrets']}",
        f"   Public Access: {features['public_access']}",
        f"   Unencrypted Storage: {features['unencrypted_storage']}"
    ]


def _format_performance(perf: Dict[str, Any]) -> list[str]:
    """Format performance metrics section."""
    return [
        "\n⏱️  Performance:",
        f"   Scan Time: {perf['scan_time_seconds']}s",
        f"   File Size: {perf['file_size_kb']} KB"
    ]


def _format_vulnerabilities(vulnerabilities: list) -> list[str]:
    """Format vulnerabilities section."""
    output = ["\n🚨 Detected Vulnerabilities:", "-" * 60]
    for vuln in vulnerabilities:
        output.append(f"\n{vuln['message']}")
        output.append(f"   📍 Resource: {vuln['resource']}")
        if vuln.get('remediation'):
            output.append(f"   💡 Fix: {vuln['remediation']}")
    return output


def _format_no_issues() -> list[str]:
    """Format section when no issues are found."""
    return [
        "\n\033[92m✅ No security issues detected!\033[0m",
        "✓ All resources properly configured",
        "✓ Encryption enabled where required",
        "✓ Network access properly restricted"
    ]