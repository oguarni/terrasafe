"""SARIF 2.1.0 output formatter for TerraSafe scan results."""
import json
from typing import Any, Dict, List


_SEVERITY_MAP = {
    "CRITICAL": "error",
    "HIGH": "error",
    "MEDIUM": "warning",
    "LOW": "note",
    "INFO": "note",
}


def results_to_sarif(results_list: List[Dict[str, Any]]) -> str:
    """
    Convert a list of per-file scan results to a SARIF 2.1.0 JSON string.

    Args:
        results_list: List of scan result dicts (one per file, as returned by scanner.scan())

    Returns:
        SARIF 2.1.0 JSON string
    """
    rules: Dict[str, Dict[str, Any]] = {}
    results: List[Dict[str, Any]] = []

    for file_result in results_list:
        if file_result.get("score") == -1:
            continue

        file_path = file_result.get("file", "unknown")
        vulnerabilities = file_result.get("vulnerabilities", [])

        for vuln in vulnerabilities:
            severity_raw = vuln.get("severity", "LOW").upper()
            message = vuln.get("message", "Security issue detected")
            resource = vuln.get("resource", "unknown")
            remediation = vuln.get("remediation", "")

            # Derive a stable rule ID from message text (first 60 chars, normalized)
            rule_id = _make_rule_id(message)

            if rule_id not in rules:
                sarif_level = _SEVERITY_MAP.get(severity_raw, "note")
                rules[rule_id] = {
                    "id": rule_id,
                    "name": rule_id,
                    "shortDescription": {"text": message[:60]},
                    "fullDescription": {"text": message},
                    "defaultConfiguration": {"level": sarif_level},
                    "help": {"text": remediation or message},
                    "properties": {"security-severity": _cvss_for_level(sarif_level)},
                }

            sarif_level = _SEVERITY_MAP.get(severity_raw, "note")
            results.append({
                "ruleId": rule_id,
                "level": sarif_level,
                "message": {
                    "text": f"{message} (resource: {resource})"
                    + (f" | Fix: {remediation}" if remediation else "")
                },
                "locations": [{
                    "physicalLocation": {
                        "artifactLocation": {
                            "uri": file_path,
                            "uriBaseId": "%SRCROOT%",
                        },
                        "region": {"startLine": 1},
                    }
                }],
            })

    sarif = {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name": "TerraSafe",
                    "version": "1.0.0",
                    "informationUri": "https://github.com/terrasafe/terrasafe",
                    "rules": list(rules.values()),
                }
            },
            "results": results,
            "artifacts": _build_artifacts(results_list),
        }],
    }
    return json.dumps(sarif, indent=2)


def _make_rule_id(message: str) -> str:
    """Derive a stable rule ID from a vulnerability message."""
    normalized = message.lower()
    # Keep alphanumeric and spaces, then title-case words joined by underscore
    words = "".join(c if c.isalnum() or c == " " else " " for c in normalized).split()
    return "TS_" + "_".join(w.upper() for w in words[:6])


def _cvss_for_level(level: str) -> str:
    mapping = {"error": "9.0", "warning": "6.0", "note": "3.0"}
    return mapping.get(level, "3.0")


def _build_artifacts(results_list: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    artifacts = []
    for r in results_list:
        if "file" in r:
            artifacts.append({
                "location": {
                    "uri": r["file"],
                    "uriBaseId": "%SRCROOT%",
                }
            })
    return artifacts
